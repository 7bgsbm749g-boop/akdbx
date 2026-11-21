"""Real processor frames, using public synthetic card data."""
import json
import time

import pytest

from akdbx import cli, extension_host
from akdbx.browser_card import BrowserCards, CardTargetError, DELIVERY
from akdbx.card_processor import adyen_url, document_url, stripe_element, supported_request
from test_card_chromium import STRIPE_CARD_ELEMENT_FRAME, STRIPE_CARD_FRAME, chrome, evaluate, pin, fill
from test_cards import CARD
from test_target import isolated_x11


URL='https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_test/6.3.0/securedFields.html'


def prepare(chrome, selector='#number', *, merchant_path='/processor', endpoint=URL, processor='adyen'):
    url=chrome.url.replace('/payment', merchant_path)+'#card-checkout'
    chrome.cdp.call('Page.navigate',{'url':url},chrome.session)
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        frames=[t for t in chrome.cdp.call('Target.getTargets')['targetInfos']
                if t['type']=='iframe' and t['url']==endpoint and t.get('parentId')==chrome.page]
        if len(frames)==1:
            frame=frames[0]
            session=chrome.cdp.call('Target.attachToTarget',{'targetId':frame['targetId'],'flatten':True})['sessionId']
            ready=chrome.cdp.call('Runtime.evaluate',{'expression':'!!document.querySelector('+json.dumps(selector)+')','returnByValue':True},session)
            if ready.get('result',{}).get('value'):
                chrome.cdp.call('Runtime.evaluate',{'expression':'document.querySelector('+json.dumps(selector)+').scrollIntoView({block:"center"})'},session)
                return dict(top_url=url,frame_url=endpoint,frame_id=frame['targetId'],
                    processor=processor,processor_protocol=1),session
        time.sleep(.05)
    pytest.fail('isolated processor frame did not load')


def child(chrome, session, expression):
    result=chrome.cdp.call('Runtime.evaluate',{'expression':expression,'returnByValue':True},session)
    assert 'exceptionDetails' not in result
    return result['result'].get('value')


def test_stripe_fills_three_exact_fields_and_handles_spaced_expiry(chrome):
    request, session = prepare(chrome, '#payment-numberInput', merchant_path='/stripe',
                               endpoint=STRIPE_CARD_FRAME, processor='stripe')

    assert not pin(chrome, 'cc-number', '#other-number', **request)['ok']
    child(chrome, session, "document.querySelector('#payment-numberInput').autocomplete = 'billing cc-number'")
    assert not pin(chrome, 'cc-number', '#payment-numberInput', **request)['ok']
    child(chrome, session, "document.querySelector('#payment-numberInput').autocomplete = 'cc-number'")
    expiry = pin(chrome, 'cc-exp', '#payment-expiryInput', **request)
    assert expiry['ok']
    assert fill(chrome, expiry, 'cc-exp', format='MM/YYYY')['delivery'] == 'not-started'

    for field, selector, expected, options in (
        ('cc-number', '#payment-numberInput', CARD['number'], {}),
        ('cc-exp', '#payment-expiryInput', '09 / 31', {'format': 'MM/YY'}),
        ('cc-csc', '#payment-cvcInput', CARD['csc'], {}),
    ):
        target = pin(chrome, field, selector, **request)
        assert target['ok']
        assert fill(chrome, target, field, **options) == {
            'ok': True, 'filled': field, 'card_delivery': DELIVERY,
        }
        assert child(chrome, session, f'document.querySelector({json.dumps(selector)}).value') == expected
        assert not fill(chrome, target, field, **options)['ok']
    assert child(chrome, session, "document.querySelector('#other-number').value === ''")
    assert not chrome.broker.typer.events


def test_stripe_refuses_changed_field_binding(chrome):
    selector = '#payment-numberInput'
    request, session = prepare(chrome, selector, merchant_path='/stripe',
                               endpoint=STRIPE_CARD_FRAME, processor='stripe')
    target = pin(chrome, 'cc-number', selector, **request)
    assert target['ok']
    child(chrome, session, f'document.querySelector({json.dumps(selector)}).name = "other"')
    assert fill(chrome, target)['delivery'] == 'not-started'
    assert child(chrome, session, f'document.querySelector({json.dumps(selector)}).value === ""')


def test_stripe_translated_merchant_keeps_native_hit_tests(chrome):
    selector = '#payment-numberInput'
    request, session = prepare(chrome, selector, merchant_path='/stripe',
                               endpoint=STRIPE_CARD_FRAME, processor='stripe')
    evaluate(chrome, """document.body.style.translate = '12px 15px';
        document.querySelector('iframe').style.transform = 'translate(13px, 11px)'""")
    center = child(chrome, session, """(() => {
        const box = document.querySelector('#payment-numberInput').getBoundingClientRect();
        return {x: box.left + box.width / 2, y: box.top + box.height / 2};
    })()""")
    for unsafe_style in (
        "f.style.transform = 'rotate(10deg)'",
        "f.style.translate = '0px 0px 10px'",
        """const point = POINT, box = f.getBoundingClientRect();
        const x = box.left + f.clientLeft + point.x;
        const y = box.top + f.clientTop + point.y;
        const cover = document.createElement('div');
        cover.id = 'cover';
        cover.style.cssText = 'position:fixed;z-index:3;pointer-events:none;width:8px;height:8px;background:white';
        cover.style.left = (x - 4) + 'px';
        cover.style.top = (y - 4) + 'px';
        document.documentElement.append(cover);
        """.replace('POINT', json.dumps(center)),
    ):
        target = pin(chrome, 'cc-number', selector, **request)
        assert target['ok']
        evaluate(chrome, "{ const f=document.querySelector('iframe'); " + unsafe_style + " }")
        assert fill(chrome, target)['delivery'] == 'not-started'
        assert child(chrome, session, f'document.querySelector({json.dumps(selector)}).value === ""')
        evaluate(chrome, """document.querySelector('iframe').style.cssText =
            'width:550px;height:300px;transform:translate(13px, 11px)';
            document.getElementById('cover')?.remove()""")
    target = pin(chrome, 'cc-number', selector, **request)
    assert target['ok']
    assert fill(chrome, target) == dict(ok=True, filled='cc-number', card_delivery=DELIVERY)


@pytest.mark.parametrize('url', [
    STRIPE_CARD_FRAME.replace('https:', 'http:'),
    STRIPE_CARD_FRAME.replace('js.stripe.com', 'js.stripe.com.evil.test'),
    STRIPE_CARD_FRAME.replace('js.stripe.com', 'js.stripe.com:444'),
    STRIPE_CARD_FRAME.replace('js.stripe.com', 'js.stripe.com:bad'),
    STRIPE_CARD_FRAME.replace('js.stripe.com', 'js.stripe.com:65536'),
    STRIPE_CARD_FRAME.replace('js.stripe.com', 'user@js.stripe.com'),
    STRIPE_CARD_FRAME.replace('accessory-target', 'loader-ui'),
    STRIPE_CARD_FRAME.replace('0123456789abcdef0123456789abcdef', 'not-a-hash'),
    STRIPE_CARD_FRAME.replace('.html#', '.html?unexpected=1#'),
    STRIPE_CARD_FRAME.replace('.html#', '.html?#'),
])
def test_stripe_accepts_only_the_production_card_endpoint(url):
    assert not supported_request('stripe', url, 'cc-number')


def test_stripe_does_not_support_other_card_fields():
    assert supported_request('stripe', STRIPE_CARD_FRAME, 'cc-number')
    assert not supported_request('stripe', STRIPE_CARD_FRAME, 'cc-name')


# ----- Stripe classic Card Element ---------------------------------------------
CARD_ELEMENT = {'cc-number': 'input[name="cardnumber"]', 'cc-exp': 'input[name="exp-date"]',
                'cc-csc': 'input[name="cvc"]'}


def card_element(chrome, selector='input[name="cardnumber"]'):
    return prepare(chrome, selector, merchant_path='/stripe-card',
                   endpoint=STRIPE_CARD_ELEMENT_FRAME, processor='stripe')


def card_element_empty(chrome, session):
    return child(chrome, session, "Array.from(document.querySelectorAll('input')).every(e => e.value === '')")


def test_stripe_card_element_fills_each_exact_field_once(chrome):
    request, session = card_element(chrome)
    for field, expected, options in (
        ('cc-number', CARD['number'], {}),
        ('cc-exp', '09/31', {'format': 'MM/YY'}),
        ('cc-csc', CARD['csc'], {}),
    ):
        selector = CARD_ELEMENT[field]
        target = pin(chrome, field, selector, **request)
        assert target['ok']
        assert fill(chrome, target, field, **options) == {
            'ok': True, 'filled': field, 'card_delivery': DELIVERY,
        }
        # The synthetic frame groups digits and spaces the expiry, as Stripe does.
        value = child(chrome, session, f'document.querySelector({json.dumps(selector)}).value')
        assert value.replace(' ', '') == expected
        assert not fill(chrome, target, field, **options)['ok']  # Single use.
    assert child(chrome, session, """Array.from(document.querySelectorAll('[name=hidden],#payment-numberInput'))
        .every(e => e.value === '')""")
    assert not chrome.broker.typer.events


@pytest.mark.parametrize('field,selector,mutation', [
    ('cc-number', 'form > input:first-child', None),                       # Decoy name="hidden".
    ('cc-number', 'form > input:last-of-type', None),                      # Payment Element binding.
    ('cc-number', 'form > input:first-child',
     "document.querySelector('form > input:first-child').autocomplete = 'cc-number'"),
    ('cc-csc', 'form > input:first-child',
     "document.querySelector('form > input:first-child').autocomplete = 'cc-csc'"),
    ('cc-exp', 'input[name="cardnumber"]', None),                         # Wrong field for the input.
    ('cc-name', 'input[name="cardnumber"]', None),
    ('cc-number', 'input[name="cardnumber"]', "document.querySelector('[name=cardnumber]').id = 'cardnumber'"),
    ('cc-number', 'input[name="cardnumber"]',
     "document.querySelector('[name=cardnumber]').autocomplete = 'billing cc-number'"),
    ('cc-number', 'input[name="cardnumber"]',
     "document.querySelector('[name=cardnumber]').type = 'tel'"),
    ('cc-number', 'input[name="cardnumber"]',
     "document.querySelector('form').append(Object.assign(document.createElement('input'), {name: 'cardnumber'}))"),
])
def test_stripe_card_element_refuses_decoys_and_every_other_input(chrome, field, selector, mutation):
    request, session = card_element(chrome)
    if mutation:
        child(chrome, session, mutation)
    assert not pin(chrome, field, selector, **request)['ok']
    assert not chrome.broker.card_targets.pins and card_element_empty(chrome, session)


def test_stripe_payment_element_refuses_card_element_inputs(chrome):
    request, session = prepare(chrome, '#payment-numberInput', merchant_path='/stripe',
                               endpoint=STRIPE_CARD_FRAME, processor='stripe')
    assert not pin(chrome, 'cc-number', 'input[name="cardnumber"]', **request)['ok']
    assert child(chrome, session, "document.querySelector('[name=cardnumber]').value === ''")


def test_stripe_card_element_refuses_wrong_expiry_format(chrome):
    request, session = card_element(chrome, CARD_ELEMENT['cc-exp'])
    for options in ({'format': 'MM/YYYY'}, {}):
        target = pin(chrome, 'cc-exp', CARD_ELEMENT['cc-exp'], **request)
        assert target['ok']
        result = fill(chrome, target, 'cc-exp', **options)
        assert not result['ok'] and result.get('delivery', 'not-started') == 'not-started'
        assert card_element_empty(chrome, session)


@pytest.mark.parametrize('location', ['processor', 'merchant'])
def test_stripe_card_element_covered_input_refuses_pin_and_fill(chrome, location):
    request, session = card_element(chrome)
    target = pin(chrome, 'cc-number', CARD_ELEMENT['cc-number'], **request)
    assert target['ok']
    cover = """(() => { const c = document.createElement('div');
      c.style.cssText = 'position:fixed;inset:0;background:white;z-index:2147483647;pointer-events:none';
      document.body.append(c); })()"""
    if location == 'processor':
        child(chrome, session, cover)
    else:
        evaluate(chrome, cover)
    result = fill(chrome, target)
    assert not result['ok'] and result['delivery'] == 'not-started'
    assert not pin(chrome, 'cc-number', CARD_ELEMENT['cc-number'], **request)['ok']
    assert card_element_empty(chrome, session) and not chrome.broker.typer.events


def test_stripe_frames_are_told_apart_by_exact_path():
    assert stripe_element(STRIPE_CARD_FRAME) == 'payment-element'
    assert stripe_element(STRIPE_CARD_ELEMENT_FRAME) == 'card-element'
    for field in ('cc-number', 'cc-exp', 'cc-csc'):
        assert supported_request('stripe', STRIPE_CARD_ELEMENT_FRAME, field)
    for field in ('cc-name', 'cc-exp-month', 'cc-exp-year'):
        assert not supported_request('stripe', STRIPE_CARD_ELEMENT_FRAME, field)


@pytest.mark.parametrize('url', [
    STRIPE_CARD_ELEMENT_FRAME.replace('https:', 'http:'),
    STRIPE_CARD_ELEMENT_FRAME.replace('js.stripe.com', 'js.stripe.com.evil.test'),
    STRIPE_CARD_ELEMENT_FRAME.replace('js.stripe.com', 'm.stripe.network'),
    STRIPE_CARD_ELEMENT_FRAME.replace('js.stripe.com', 'js.stripe.com:444'),
    STRIPE_CARD_ELEMENT_FRAME.replace('js.stripe.com', 'user@js.stripe.com'),
    STRIPE_CARD_ELEMENT_FRAME.replace('/v3/', '/v2/'),
    STRIPE_CARD_ELEMENT_FRAME.replace('elements-inner-card-', 'elements-inner-card-number-'),
    STRIPE_CARD_ELEMENT_FRAME.replace('elements-inner-card-', 'elements-inner-cardx-'),
    STRIPE_CARD_ELEMENT_FRAME.replace('fedcba9876543210fedcba9876543210', 'FEDCBA9876543210FEDCBA9876543210'),
    STRIPE_CARD_ELEMENT_FRAME.replace('fedcba9876543210fedcba9876543210', 'fedcba98765432'),
    STRIPE_CARD_ELEMENT_FRAME.replace('.html#', '.htm#'),
    STRIPE_CARD_ELEMENT_FRAME.replace('.html#', '.html?unexpected=1#'),
    STRIPE_CARD_ELEMENT_FRAME.replace('.html#', '.html?#'),
])
def test_stripe_card_element_accepts_only_the_production_endpoint(url):
    assert stripe_element(url) is None
    assert not supported_request('stripe', url, 'cc-number')


@pytest.mark.parametrize('frame_url', [
    STRIPE_CARD_ELEMENT_FRAME.replace('js.stripe.com', 'evil.example.net'),
    STRIPE_CARD_ELEMENT_FRAME.replace('elements-inner-card-', 'elements-inner-payment-'),
])
def test_wrong_card_element_origin_or_path_never_opens_transport(frame_url):
    calls = []
    cards = BrowserCards('/synthetic/profile', connector=lambda _: calls.append(True))
    request = dict(action='pin-card-target', card_protocol=1, page_id='page', frame_id='frame',
                   top_url='https://www.merchant.test/checkout', frame_url=frame_url,
                   selector='input[name="cardnumber"]', field='cc-number',
                   processor='stripe', processor_protocol=1)
    with pytest.raises(CardTargetError):
        cards.pin(request)
    assert not calls


def test_status_advertises_card_element_support():
    caps = BrowserCards('/synthetic/profile').capabilities()
    assert caps['stripe_card_element'] is True and 'stripe' in caps['card_processors']


def stripe_cli(monkeypatch, frame_url, capabilities, route=None):
    calls = []
    def request(_socket, payload, **kwargs):
        calls.append(payload)
        return dict(ok=True, cards_supported=True, card_protocol=1, card_delivery=DELIVERY,
                    card_processor_frames_protocol=1, card_processors=['adyen', 'computop', 'stripe'],
                    extension_protocol=1, **capabilities)
    monkeypatch.setattr(cli, 'request', request)
    code = cli.main(['pin-card-target', '--page-id', 'page', '--frame-id', 'frame',
        '--top-url', 'https://www.merchant.test/checkout', *(['--frame-url', frame_url] if frame_url else []),
        *(['--route', route] if route else []),
        '--selector', 'input[name="cardnumber"]', '--field', 'cc-number', '--processor', 'stripe'])
    return code, calls


@pytest.mark.parametrize('capabilities', [{}, {'stripe_card_element': 1}, {'stripe_card_element': 'true'}])
def test_cli_refuses_broker_without_card_element_before_pin(monkeypatch, capsys, capabilities):
    code, calls = stripe_cli(monkeypatch, STRIPE_CARD_ELEMENT_FRAME, capabilities)
    assert code == 1 and calls == [{'action': 'ping'}]
    assert 'Stripe Card Element' in capsys.readouterr().out


def test_cli_still_sends_payment_element_and_card_element_pins(monkeypatch, capsys):
    for frame_url, capabilities in ((STRIPE_CARD_FRAME, {}), (STRIPE_CARD_ELEMENT_FRAME, {'stripe_card_element': True})):
        _code, calls = stripe_cli(monkeypatch, frame_url, capabilities)
        assert len(calls) == 2 and calls[1]['processor'] == 'stripe' and calls[1]['frame_url'] == frame_url
    capsys.readouterr()


@pytest.mark.parametrize('capabilities', [{}, {'stripe_card_element': 1}, {'stripe_card_element': 'true'}])
def test_cli_extension_route_without_frame_url_refuses_an_older_broker(monkeypatch, capsys, capabilities):
    # The extension route takes no frame URL, so the CLI cannot tell the two
    # Stripe frames apart: an older broker would refuse only generically.
    code, calls = stripe_cli(monkeypatch, None, capabilities, route='extension')
    assert code == 1 and calls == [{'action': 'ping'}]
    out = json.loads(capsys.readouterr().out)
    assert out['ok'] is False and 'Stripe Card Element' in out['error'] and '--frame-url' in out['error']


def test_cli_extension_route_sends_stripe_pins_it_can_check(monkeypatch, capsys):
    for frame_url, capabilities in ((None, {'stripe_card_element': True}), (STRIPE_CARD_FRAME, {}),
                                    (STRIPE_CARD_ELEMENT_FRAME, {'stripe_card_element': True})):
        _code, calls = stripe_cli(monkeypatch, frame_url, capabilities, route='extension')
        assert len(calls) == 2 and calls[1]['processor'] == 'stripe' and calls[1]['route'] == 'extension'
        assert calls[1].get('frame_url') == frame_url
    code, calls = stripe_cli(monkeypatch, STRIPE_CARD_ELEMENT_FRAME, {}, route='extension')
    assert code == 1 and calls == [{'action': 'ping'}]
    capsys.readouterr()


# ----- the fill extension's user-click popup never serves the Card Element -----
def popup_probe(chrome, session, focus, before=None):
    """Run the built fill extension's content script in an isolated world of
    this document, focus one input and return the popup's probe (None refuses)."""
    frame = chrome.cdp.call('Page.getFrameTree', session=session)['frameTree']['frame']['id']
    context = chrome.cdp.call('Page.createIsolatedWorld', {'frameId': frame, 'worldName': 'akdbx-content-test'},
                              session)['executionContextId']
    def run(expression):
        result = chrome.cdp.call('Runtime.evaluate', {'expression': expression, 'contextId': context,
                                                      'returnByValue': True}, session)
        assert 'exceptionDetails' not in result, result
        return result['result'].get('value')
    run(extension_host._content_script())
    if before:
        child(chrome, session, before)
    run(f'document.querySelector({json.dumps(focus)}).focus()')
    assert run(f'document.activeElement === document.querySelector({json.dumps(focus)})')
    return run('globalThis.__akdbxContent.probe()')


def test_popup_probe_still_offers_the_payment_element(chrome):
    _request, session = prepare(chrome, '#payment-numberInput', merchant_path='/stripe',
                                endpoint=STRIPE_CARD_FRAME, processor='stripe')
    found = popup_probe(chrome, session, '#payment-numberInput')
    assert found['kind'] == 'card' and found['roles'] == ['cc-number', 'cc-exp', 'cc-csc'], found
    assert found['formats'] == {'cc-exp': 'MM/YY'}


COVER = """(() => { const c = document.createElement('div');
  c.style.cssText = 'position:fixed;inset:0;background:white;z-index:2147483647;pointer-events:none';
  document.body.append(c); })()"""


@pytest.mark.parametrize('case,before', [
    ('card-element', None),
    ('duplicate-name', "document.querySelector('form').append(Object.assign(document.createElement('input'), "
                       "{type: 'text', name: 'cardnumber', autocomplete: 'cc-number'}))"),
    ('wrong-autocomplete', "document.querySelector('[name=cardnumber]').autocomplete = 'fake'"),
    ('covered', COVER),
    ('top-level', None),
])
def test_popup_probe_refuses_every_card_element_input(chrome, case, before):
    if case == 'top-level':
        # A top-level document at the Card Element path has no merchant owner.
        chrome.cdp.call('Page.navigate', {'url': STRIPE_CARD_ELEMENT_FRAME}, chrome.session)
        deadline = time.monotonic() + 8
        while not evaluate(chrome, "location.hostname === 'js.stripe.com' && !!document.querySelector('[name=cvc]')"):
            assert time.monotonic() < deadline, 'top-level Card Element document did not load'
            time.sleep(.05)
        session = chrome.session
    else:
        _request, session = card_element(chrome)
    for selector in CARD_ELEMENT.values():
        assert popup_probe(chrome, session, selector, before if selector == CARD_ELEMENT['cc-number'] else None) is None
    assert card_element_empty(chrome, session)
    if case == 'card-element':
        # The verified processor pin route still fills the same frame.
        request, _ = card_element(chrome)
        target = pin(chrome, 'cc-number', CARD_ELEMENT['cc-number'], **request)
        assert target['ok'], target
        assert fill(chrome, target) == {'ok': True, 'filled': 'cc-number', 'card_delivery': DELIVERY}


@pytest.mark.parametrize('field,selector,formatting,key',[
    ('cc-number','#number',None,'number'),('cc-csc','#csc',None,'csc'),
    ('cc-exp','#expiry','MM/YY',None)])
def test_attested_oopif_fills_retained_field_without_secret_receipts(chrome,field,selector,formatting,key,capsys):
    request,session=prepare(chrome,selector)
    target=pin(chrome,field,selector,**request)
    assert target['ok']
    result=fill(chrome,target,field,**({'format':formatting} if formatting else {}))
    assert result==dict(ok=True,filled=field,card_delivery=DELIVERY)
    expected=CARD[key] if key else '09/31'
    assert child(chrome,session,'document.querySelector('+json.dumps(selector)+').value')==expected
    assert child(chrome,session,"address.value === '' && password.value === ''")
    assert chrome.broker.typer.events==[]
    assert CARD['number'] not in json.dumps(result)+capsys.readouterr().out
    assert not fill(chrome,target,field)['ok']


@pytest.mark.parametrize('mutation',[
    "f.style.display='none'", "f.style.opacity='0'", "f.style.transform='translateX(1px)'",
    "f.remove()", "f.outerHTML=f.outerHTML",
    "f.insertAdjacentHTML('beforebegin','<div id=newParent></div>');newParent.append(f)",
    "f.insertAdjacentHTML('afterend','<div style=\"position:fixed;inset:0;background:white\"></div>')",
    "f.contentDocument.getElementById('processor').style.display='none'",
    "f.contentDocument.getElementById('processor').setAttribute('sandbox','allow-scripts')",
    "history.pushState({},'', '/other-merchant-route')"])
def test_merchant_ancestor_changes_refuse_before_secret_dispatch(chrome,mutation):
    request,session=prepare(chrome)
    target=pin(chrome,**request);assert target['ok']
    evaluate(chrome,"const f=document.getElementById('merchant');"+mutation)
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']=='not-started'
    assert chrome.broker.typer.events==[]
    assert CARD['number'] not in str(result)


@pytest.mark.parametrize('owner',[
    "merchant.contentDocument.getElementById('processor')",'merchant','document.body'])
@pytest.mark.parametrize('effect',[
    'rotate:180deg','translate:1px','scale:-1','perspective:100px',
    'filter:opacity(0)','backdrop-filter:blur(1px)',
    'mask-image:linear-gradient(transparent,transparent)','clip-path:inset(100%)',
    '-webkit-mask-box-image-source:linear-gradient(transparent,transparent)',
    'clip:rect(0px,0px,0px,0px)','offset-path:path("M 0 0 L 100 100")'])
def test_unsupported_owner_and_ancestor_effects_never_receive_card(chrome,owner,effect):
    request,session=prepare(chrome)
    target=pin(chrome,**request);assert target['ok']
    evaluate(chrome,'('+owner+').style.cssText += '+json.dumps(';'+effect))
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']=='not-started'
    assert child(chrome,session,"number.value === ''")
    assert not pin(chrome,**request)['ok']
    assert not chrome.broker.card_targets.pins and chrome.broker.typer.events==[]


@pytest.mark.parametrize('location',['top','merchant','processor'])
def test_pointer_transparent_opaque_covers_refuse_pin_and_fill(chrome,location):
    request,session=prepare(chrome)
    target=pin(chrome,**request);assert target['ok']
    expression='''(()=>{
      const d=DOCUMENT, cover=d.createElement('div');
      cover.style.cssText='position:fixed;inset:0;background:magenta;z-index:2147483647;pointer-events:none';
      d.body.append(cover);
    })()'''
    if location=='processor':
        child(chrome,session,expression.replace('DOCUMENT','document'))
    else:
        evaluate(chrome,expression.replace('DOCUMENT','merchant.contentDocument' if location=='merchant' else 'document'))
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']=='not-started'
    assert child(chrome,session,"number.value === ''")
    assert not pin(chrome,**request)['ok']
    assert not chrome.broker.card_targets.pins and chrome.broker.typer.events==[]


@pytest.mark.parametrize('location',['number','document.body'])
def test_mask_box_on_processor_input_or_ancestor_never_receives_card(chrome,location):
    request,session=prepare(chrome)
    target=pin(chrome,**request);assert target['ok']
    child(chrome,session,location+".style.setProperty('-webkit-mask-box-image-source','linear-gradient(transparent,transparent)')")
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']=='not-started'
    assert child(chrome,session,"number.value === ''")
    assert not pin(chrome,**request)['ok']


def apply_hidden_blend(chrome, session, location):
    expression='''(()=>{
      const e=ELEMENT;
      e.parentElement.style.background='black';
      e.style.mixBlendMode='multiply';
      return e.ownerDocument.defaultView.getComputedStyle(e).mixBlendMode;
    })()'''
    if location in ('number','document.body'):
        result=child(chrome,session,expression.replace('ELEMENT',location))
    else:
        result=evaluate(chrome,expression.replace('ELEMENT',location))
    assert result=='multiply'


@pytest.mark.parametrize('location',[
    'number','document.body',"merchant.contentDocument.getElementById('processor')",
    'merchant','merchant.parentElement'])
@pytest.mark.parametrize('after_dispatch',[False,True])
def test_blended_processor_inputs_owners_and_ancestors_never_report_success(chrome,monkeypatch,location,after_dispatch):
    request,session=prepare(chrome)
    target=pin(chrome,**request);assert target['ok']
    if after_dispatch:
        transport=chrome.broker.card_targets.pins[target['target']]['cdp']
        original=transport.call
        def change_after_dispatch(method,params=None,session=None):
            result=original(method,params,session)
            if method=='Runtime.callFunctionOn' and 'this.fill(value' in params.get('functionDeclaration',''):
                apply_hidden_blend(chrome,child_session,location)
            return result
        child_session=session
        monkeypatch.setattr(transport,'call',change_after_dispatch)
    else:
        apply_hidden_blend(chrome,session,location)
        assert not pin(chrome,**request)['ok']
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']==('uncertain' if after_dispatch else 'not-started')
    assert child(chrome,session,'number.value')==(CARD['number'] if after_dispatch else '')
    assert CARD['number'] not in str(result) and chrome.broker.typer.events==[]
    assert not fill(chrome,target)['ok']
    assert not chrome.broker.card_targets.pins


def test_pointer_transparent_cover_after_write_is_uncertain(chrome):
    request,session=prepare(chrome)
    child(chrome,session,"""number.addEventListener('input',()=>{
      const cover=document.createElement('div');
      cover.style.cssText='position:fixed;inset:0;background:magenta;z-index:2147483647;pointer-events:none';
      document.body.append(cover);
    })""")
    target=pin(chrome,**request);assert target['ok']
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']=='uncertain'
    assert child(chrome,session,'number.value')==CARD['number']
    assert CARD['number'] not in str(result) and not fill(chrome,target)['ok']


def test_native_owner_hit_uses_scrolled_top_document_coordinates(chrome):
    request,session=prepare(chrome)
    evaluate(chrome,"document.body.style.minHeight='3000px';merchant.style.marginTop='400px';scrollTo(0,300)")
    assert evaluate(chrome,'scrollY')==300
    target=pin(chrome,**request);assert target['ok']
    assert fill(chrome,target)==dict(ok=True,filled='cc-number',card_delivery=DELIVERY)
    assert child(chrome,session,'number.value')==CARD['number']


def test_covered_rotated_processor_cannot_fool_axis_aligned_hit_test(chrome):
    request,session=prepare(chrome)
    target=pin(chrome,**request);assert target['ok']
    point=child(chrome,session,"(()=>{const r=number.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2,w:r.width,h:r.height};})()")
    geometry=evaluate(chrome,'''(()=>{
      const d=merchant.contentDocument, f=d.getElementById('processor');
      f.style.rotate='180deg';
      const r=f.getBoundingClientRect(), p=POINT;
      const actual={x:r.right-(f.clientLeft+p.x)*r.width/f.offsetWidth,
                    y:r.bottom-(f.clientTop+p.y)*r.height/f.offsetHeight};
      const guard={x:r.left+(f.clientLeft+p.x)*r.width/f.offsetWidth,
                   y:r.top+(f.clientTop+p.y)*r.height/f.offsetHeight};
      const cover=d.createElement('div');
      cover.style.cssText=`position:fixed;left:${actual.x-p.w/2-2}px;top:${actual.y-p.h/2-2}px;width:${p.w+4}px;height:${p.h+4}px;background:white;z-index:9999`;
      d.body.append(cover);
      return {actualCovered:d.elementFromPoint(actual.x,actual.y)===cover,
              wrongPointHitsFrame:d.elementFromPoint(guard.x,guard.y)===f};
    })()'''.replace('POINT',json.dumps(point)))
    assert geometry==dict(actualCovered=True,wrongPointHitsFrame=True)
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']=='not-started'
    assert child(chrome,session,"number.value === ''")


def test_slow_verification_does_not_consume_fresh_fill_deadline(chrome,monkeypatch):
    from akdbx import card_processor
    request,session=prepare(chrome)
    original=card_processor.check
    checks=0
    def slow_first_check(*args,**kwargs):
        nonlocal checks
        checks+=1
        if checks==1:time.sleep(4.2)
        return original(*args,**kwargs)
    monkeypatch.setattr(card_processor,'check',slow_first_check)
    target=pin(chrome,**request);assert target['ok']
    start=time.monotonic()
    result=fill(chrome,target)
    assert time.monotonic()-start<4
    assert result==dict(ok=True,filled='cc-number',card_delivery=DELIVERY)
    assert child(chrome,session,'number.value')==CARD['number']
    assert not fill(chrome,target)['ok']


def test_verification_cannot_issue_an_already_expired_pin(chrome,monkeypatch):
    from akdbx import card_processor
    request,session=prepare(chrome)
    now=[0]
    chrome.broker.card_targets.clock=lambda:now[0]
    original=card_processor.check
    def expired_check(*args,**kwargs):
        now[0]=31
        return original(*args,**kwargs)
    monkeypatch.setattr(card_processor,'check',expired_check)
    assert not pin(chrome,**request)['ok']
    assert not chrome.broker.card_targets.pins
    assert child(chrome,session,"number.value === ''")


@pytest.mark.parametrize('mutation',[
    "number.outerHTML='<input id=number autocomplete=cc-number>'", "number.disabled=true",
    "number.autocomplete='street-address'", "number.style.display='none'",
    "history.pushState({},'', '/changed-processor-route')"])
def test_processor_document_and_field_changes_refuse_without_writing(chrome,mutation):
    request,session=prepare(chrome)
    target=pin(chrome,**request);assert target['ok']
    child(chrome,session,mutation)
    assert not fill(chrome,target)['ok']
    assert child(chrome,session,"Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")


def test_other_tab_and_unattested_cross_origin_frames_are_refused(chrome):
    request,_=prepare(chrome)
    other=chrome.cdp.call('Target.createTarget',{'url':'about:blank','background':True})['targetId']
    try:
        assert not pin(chrome,**dict(request,page_id=other))['ok']
        assert not pin(chrome,**{k:v for k,v in request.items() if not k.startswith('processor')})['ok']
        assert not pin(chrome,**dict(request,frame_url=URL+'?changed'))['ok']
    finally:
        chrome.cdp.call('Target.closeTarget',{'targetId':other})


@pytest.mark.parametrize('field,selector,expression',[
    ('cc-number','#number',"number.addEventListener('input',()=>{number.value=number.value.replace(/(....)(?=.)/g,'$1 ');})"),
    ('cc-exp','#expiry',"expiry.addEventListener('input',()=>{expiry.value=expiry.value.replace('/',' / ');})")])
def test_processor_whitespace_formatting_keeps_receipts_secret_free(chrome,field,selector,expression):
    request,session=prepare(chrome,selector)
    child(chrome,session,expression)
    target=pin(chrome,field,selector,**request);assert target['ok']
    result=fill(chrome,target,field,**({'format':'MM/YY'} if field=='cc-exp' else {}))
    assert result==dict(ok=True,filled=field,card_delivery=DELIVERY)
    assert CARD['number'] not in str(result)


def test_processor_rejection_is_uncertain_and_never_retried(chrome):
    request,session=prepare(chrome)
    child(chrome,session,"number.addEventListener('input',()=>{number.value='';})")
    target=pin(chrome,**request);assert target['ok']
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']=='uncertain'
    assert not fill(chrome,target)['ok']


def test_merchant_change_after_dispatch_is_uncertain_and_pin_is_consumed(chrome,monkeypatch):
    request,session=prepare(chrome)
    target=pin(chrome,**request);assert target['ok']
    transport=chrome.broker.card_targets.pins[target['target']]['cdp']
    original=transport.call
    def change_after_dispatch(method,params=None,session=None):
        result=original(method,params,session)
        if method=='Runtime.callFunctionOn' and 'this.fill(value' in params.get('functionDeclaration',''):
            evaluate(chrome,"history.pushState({},'', '/merchant-changed-after-dispatch')")
        return result
    monkeypatch.setattr(transport,'call',change_after_dispatch)
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']=='uncertain'
    assert child(chrome,session,'number.value')==CARD['number']
    assert CARD['number'] not in str(result)
    assert not fill(chrome,target)['ok']


def test_processor_deadline_and_tab_visibility_still_gate_dispatch(chrome):
    request,session=prepare(chrome)
    target=pin(chrome,**request);assert target['ok']
    result=fill(chrome,target,start_deadline=chrome.broker.clock()-1)
    assert not result['ok'] and result['delivery']=='not-started'
    assert child(chrome,session,"number.value === ''")
    target=pin(chrome,**request);assert target['ok']
    other=chrome.cdp.call('Target.createTarget',{'url':'about:blank'})['targetId']
    try:
        assert not fill(chrome,target)['ok']
        assert child(chrome,session,"number.value === ''")
    finally:
        chrome.cdp.call('Target.closeTarget',{'targetId':other})


@pytest.mark.parametrize('url',[
    URL.replace('https:','http:'),URL.replace('adyen.com','adyen.com.evil.test'),
    URL.replace('checkoutshopper-live.adyen.com','checkoutshopper-test.adyen.com'),
    URL.replace('checkoutshopper-live.adyen.com','user@checkoutshopper-live.adyen.com'),
    URL.replace('adyen.com/','adyen.com:444/'),URL.replace('securedFields.html','other.html'),
    URL+'#fragment',URL.replace('/6.3.0/','/../')])
def test_processor_origin_and_endpoint_allowlist_is_exact(url):
    assert not adyen_url(url)


@pytest.mark.parametrize('frame,expected',[
    ({'url':'https://merchant.test/'},'https://merchant.test/'),
    ({'url':'https://merchant.test/','urlFragment':'#/checkout'},'https://merchant.test/#/checkout'),
    ({'url':'https://merchant.test/#/checkout','urlFragment':'#/checkout'},'https://merchant.test/#/checkout')])
def test_browser_hash_routes_preserve_the_exact_document_url(frame,expected):
    assert document_url(frame)==expected


@pytest.mark.parametrize('frame',[
    {'url':'https://merchant.test/','urlFragment':'not-a-fragment'},
    {'url':'https://merchant.test/#/other','urlFragment':'#/checkout'}])
def test_conflicting_browser_fragments_are_not_silently_ignored(frame):
    with pytest.raises(ValueError):document_url(frame)


@pytest.mark.parametrize('changes',[
    {'processor':'other'},{'processor':None},{'processor_protocol':True},
    {'processor_protocol':2},{'frame_url':'https://evil.test/pay'},
    {'frame_url':'https://merchant.test/pay'}])
def test_malformed_processor_requests_never_open_transport(changes):
    calls=[]
    cards=BrowserCards('/synthetic/profile',connector=lambda _:calls.append(True))
    request=dict(action='pin-card-target',card_protocol=1,page_id='page',frame_id='frame',
        top_url='https://merchant.test/pay',frame_url=URL,selector='#number',field='cc-number',
        processor='adyen',processor_protocol=1)
    request.update(changes)
    with pytest.raises(CardTargetError):cards.pin(request)
    assert not calls


@pytest.mark.parametrize('capabilities',[
    {},{'card_processor_frames_protocol':True,'card_processors':['adyen']},
    {'card_processor_frames_protocol':1,'card_processors':'adyen'},
    {'card_processor_frames_protocol':1,'card_processors':['other']}])
def test_cli_refuses_old_or_malformed_broker_before_processor_pin(monkeypatch,capsys,capabilities):
    calls=[]
    def request(_socket,payload,**kwargs):
        calls.append(payload)
        return dict(ok=True,cards_supported=True,card_protocol=1,card_delivery=DELIVERY,**capabilities)
    monkeypatch.setattr(cli,'request',request)
    assert cli.main(['pin-card-target','--page-id','page','--frame-id','frame',
        '--top-url','https://merchant.test/pay','--frame-url',URL,'--selector','#number',
        '--field','cc-number','--processor','adyen'])==1
    assert calls==[{'action':'ping'}]
    assert 'pin request not sent' in capsys.readouterr().out
