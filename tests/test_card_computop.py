"""Computop-shaped OOPIFs on isolated TLS sites; public synthetic cards only."""
import json
import time

import pytest

from akdbx import cli
from akdbx.browser_card import BrowserCards, CardTargetError, DELIVERY
from akdbx.card_processor import computop_url
from test_card_chromium import chrome, evaluate, pin, fill
from test_card_processor import child
from test_cards import CARD
from test_target import isolated_x11

URL = 'https://www.computop-paygate.com/payssl.aspx'


def prepare(chrome):
    url = chrome.url.replace('/payment', '/computop') + '#checkout'
    chrome.cdp.call('Page.navigate', {'url': url}, chrome.session)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        frames = [t for t in chrome.cdp.call('Target.getTargets')['targetInfos']
                  if t['type'] == 'iframe' and t['url'] == URL and t.get('parentId') == chrome.page]
        if len(frames) == 1:
            frame = frames[0]
            session = chrome.cdp.call('Target.attachToTarget',
                {'targetId': frame['targetId'], 'flatten': True})['sessionId']
            if child(chrome, session, "!!document.querySelector('#cccvc')"):
                return dict(top_url=url, frame_url=URL, frame_id=frame['targetId'],
                            processor='computop', processor_protocol=1), session
        time.sleep(.05)
    pytest.fail('isolated Computop frame did not load')


@pytest.mark.parametrize('field,selector,formatting,expected', [
    ('cc-name', '#creditCardHolder', None, CARD['name']),
    ('cc-number', '#_KKnr', None, CARD['number']),
    ('cc-exp', '#expiry_date', 'MM/YY', '09/31'),
    ('cc-csc', '#cccvc', None, CARD['csc']),
])
def test_computop_fills_only_the_attested_field(chrome, field, selector, formatting, expected, capsys):
    request, session = prepare(chrome)
    target = pin(chrome, field, selector, **request)
    assert target['ok']
    result = fill(chrome, target, field, **({'format': formatting} if formatting else {}))
    assert result == dict(ok=True, filled=field, card_delivery=DELIVERY)
    assert child(chrome, session, 'document.querySelector(' + json.dumps(selector) + ').value') == expected
    assert child(chrome, session, 'unrelated.value') == ''
    assert chrome.broker.typer.events == []
    assert CARD['number'] not in str(result) + capsys.readouterr().out
    assert not fill(chrome, target, field)['ok']


@pytest.mark.parametrize('mutation', [
    "_KKnr.id='other'", "_KKnr.name='other'", "_KKnr.type='tel'",
    "_KKnr.autocomplete='cc-number'", "_KKnr.autocomplete='off off'",
    "_KKnr.removeAttribute('autocomplete')", "_KKnr.readOnly=true",
    "_KKnr.disabled=true", "_KKnr.style.filter='opacity(0)'",
    "_KKnr.insertAdjacentHTML('afterend','<input id=_KKnr name=_KKnr autocomplete=off>')",
    "const n=_KKnr; document.body.append(n)",
])
@pytest.mark.parametrize('after_pin', [False, True])
def test_changed_or_unrecognised_computop_field_is_not_filled(chrome, mutation, after_pin):
    request, session = prepare(chrome)
    target = pin(chrome, 'cc-number', '#_KKnr', **request) if after_pin else None
    if target:
        assert target['ok']
    child(chrome, session, mutation)
    if target:
        result = fill(chrome, target)
        assert not result['ok'] and result['delivery'] == 'not-started'
    else:
        assert not pin(chrome, 'cc-number', '#_KKnr', **request)['ok']
    assert child(chrome, session, "Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")


@pytest.mark.parametrize('after_pin', [False, True])
def test_computop_replacement_requires_a_fresh_pin(chrome, after_pin):
    request, session = prepare(chrome)
    target = pin(chrome, 'cc-number', '#_KKnr', **request) if after_pin else None
    if target:
        assert target['ok']
    child(chrome, session, "window.originalNumber=_KKnr;_KKnr.replaceWith(_KKnr.cloneNode())")
    if after_pin:
        result = fill(chrome, target)
        assert not result['ok'] and result['delivery'] == 'not-started'
        assert child(chrome, session, '_KKnr.value') == ''
    else:
        # A fresh pin captures the current legitimate input, not its history.
        target = pin(chrome, 'cc-number', '#_KKnr', **request)
        assert target['ok']
        assert fill(chrome, target) == dict(ok=True, filled='cc-number', card_delivery=DELIVERY)
        assert child(chrome, session, '_KKnr.value') == CARD['number']
    assert child(chrome, session, 'originalNumber.value') == ''


@pytest.mark.parametrize('location', ['top', 'merchant', 'processor'])
def test_computop_opaque_pointer_ignoring_covers_refuse(chrome, location):
    request, session = prepare(chrome)
    target = pin(chrome, 'cc-number', '#_KKnr', **request)
    assert target['ok']
    cover = "const c=document.createElement('div');c.style='position:fixed;inset:0;background:black;pointer-events:none;z-index:999999';document.body.append(c)"
    if location == 'processor':
        child(chrome, session, cover)
    elif location == 'top':
        evaluate(chrome, cover)
    else:
        evaluate(chrome, "const d=merchant.contentDocument,c=d.createElement('div');c.style='position:fixed;inset:0;background:black;pointer-events:none;z-index:999999';d.body.append(c)")
    result = fill(chrome, target)
    assert not result['ok'] and result['delivery'] == 'not-started'
    assert child(chrome, session, '_KKnr.value') == ''


@pytest.mark.parametrize('mutation', [
    "_KKnr.name='changed'", "_KKnr.autocomplete='on'", "_KKnr.id='changed'",
    "document.body.style.mixBlendMode='multiply'",
])
def test_computop_post_dispatch_changes_are_uncertain(chrome, mutation):
    request, session = prepare(chrome)
    child(chrome, session, "_KKnr.addEventListener('input',()=>{" + mutation + "})")
    target = pin(chrome, 'cc-number', '#_KKnr', **request)
    assert target['ok']
    result = fill(chrome, target)
    assert not result['ok'] and result['delivery'] == 'uncertain'
    assert CARD['number'] not in str(result)
    assert not fill(chrome, target)['ok']


def test_computop_requires_explicit_processor_and_known_field(chrome):
    request, session = prepare(chrome)
    assert not pin(chrome, 'cc-number', '#unrelated', **request)['ok']
    assert not pin(chrome, 'cc-csc', '#_KKnr', **request)['ok']
    plain = {k: v for k, v in request.items() if not k.startswith('processor')}
    assert not pin(chrome, 'cc-number', '#_KKnr', **plain)['ok']
    assert not pin(chrome, 'cc-number', '#_KKnr', **dict(request, processor='adyen'))['ok']
    assert child(chrome, session, "Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")


def test_computop_expiry_refuses_four_digit_year_before_dispatch(chrome):
    request, session = prepare(chrome)
    target = pin(chrome, 'cc-exp', '#expiry_date', **request)
    assert target['ok']
    result = fill(chrome, target, 'cc-exp', format='MM/YYYY')
    assert not result['ok'] and result['delivery'] == 'not-started'
    assert child(chrome, session, 'expiry_date.value') == ''


@pytest.mark.parametrize('mutation', [
    "p.remove()", "p.method='get'", "p.target='other'", "p.action='https://evil.test/pay'",
    "p.after(p.cloneNode())", "f.name='other'", "f.src='about:blank'",
])
@pytest.mark.parametrize('after_pin', [False, True])
def test_computop_blank_iframe_requires_retained_unique_post_form(chrome, mutation, after_pin):
    request, session = prepare(chrome)
    target = pin(chrome, 'cc-number', '#_KKnr', **request) if after_pin else None
    if target:
        assert target['ok']
    evaluate(chrome, "const d=merchant.contentDocument,p=d.getElementById('processorPost'),f=d.getElementById('processor');" + mutation)
    if target:
        result = fill(chrome, target)
        assert not result['ok'] and result['delivery'] == 'not-started'
    else:
        assert not pin(chrome, 'cc-number', '#_KKnr', **request)['ok']


def test_computop_post_form_change_during_dispatch_is_uncertain(chrome, monkeypatch):
    request, session = prepare(chrome)
    target = pin(chrome, 'cc-number', '#_KKnr', **request)
    assert target['ok']
    transport = chrome.broker.card_targets.pins[target['target']]['cdp']
    original = transport.call
    def change_form(method, params=None, session=None):
        result = original(method, params, session)
        if method == 'Runtime.callFunctionOn' and 'this.fill(value' in params.get('functionDeclaration', ''):
            evaluate(chrome, "merchant.contentDocument.getElementById('processorPost').remove()")
        return result
    monkeypatch.setattr(transport, 'call', change_form)
    result = fill(chrome, target)
    assert not result['ok'] and result['delivery'] == 'uncertain'
    assert child(chrome, session, '_KKnr.value') == CARD['number']
    assert not fill(chrome, target)['ok']


@pytest.mark.parametrize('url', [
    URL.replace('https:', 'http:'), URL.replace('www.', ''),
    URL.replace('.com/', '.com.evil.test/'), URL.replace('www.', 'test.'),
    URL.replace('https://', 'https://user@'), URL.replace('.com/', '.com:444/'),
    URL + '?changed=1', URL + '#changed', URL.replace('payssl.aspx', 'other.aspx'),
])
def test_computop_only_allows_exact_production_endpoint(url):
    assert computop_url(URL)
    assert not computop_url(url)


@pytest.mark.parametrize('changes', [
    {'field': 'cc-exp-year'}, {'processor_protocol': True}, {'processor_protocol': 2},
    {'frame_url': URL + '?other'}, {'processor': 'adyen'},
])
def test_computop_invalid_request_never_opens_transport(changes):
    calls = []
    cards = BrowserCards('/synthetic/profile', connector=lambda _: calls.append(True))
    request = dict(action='pin-card-target', card_protocol=1, page_id='page', frame_id='frame',
        top_url='https://merchant.test/pay', frame_url=URL, selector='#_KKnr', field='cc-number',
        processor='computop', processor_protocol=1)
    request.update(changes)
    with pytest.raises(CardTargetError):
        cards.pin(request)
    assert not calls


@pytest.mark.parametrize('processors', [None, 'computop', ['adyen']])
def test_computop_cli_requires_current_broker_capability(monkeypatch, capsys, processors):
    calls = []
    def request(_socket, payload, **kwargs):
        calls.append(payload)
        return dict(ok=True, cards_supported=True, card_protocol=1, card_delivery=DELIVERY,
                    card_processor_frames_protocol=1, card_processors=processors)
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['pin-card-target', '--page-id', 'page', '--frame-id', 'frame',
        '--top-url', 'https://merchant.test/pay', '--frame-url', URL, '--selector', '#_KKnr',
        '--field', 'cc-number', '--processor', 'computop']) == 1
    assert calls == [{'action': 'ping'}]
    assert 'pin request not sent' in capsys.readouterr().out
