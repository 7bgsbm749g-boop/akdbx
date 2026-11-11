"""Real out-of-process Adyen-shaped frames, using public synthetic card data."""
import json
import time

import pytest

from akdbx import cli
from akdbx.browser_card import BrowserCards, CardTargetError, DELIVERY
from akdbx.card_processor import adyen_url, document_url
from test_card_chromium import chrome, evaluate, pin, fill
from test_cards import CARD
from test_target import isolated_x11


URL='https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_test/6.3.0/securedFields.html'


def prepare(chrome, selector='#number'):
    url=chrome.url.replace('/payment','/processor')+'#card-checkout'
    chrome.cdp.call('Page.navigate',{'url':url},chrome.session)
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        frames=[t for t in chrome.cdp.call('Target.getTargets')['targetInfos']
                if t['type']=='iframe' and t['url']==URL and t.get('parentId')==chrome.page]
        if len(frames)==1:
            frame=frames[0]
            session=chrome.cdp.call('Target.attachToTarget',{'targetId':frame['targetId'],'flatten':True})['sessionId']
            ready=chrome.cdp.call('Runtime.evaluate',{'expression':'!!document.querySelector('+json.dumps(selector)+')','returnByValue':True},session)
            if ready.get('result',{}).get('value'):
                chrome.cdp.call('Runtime.evaluate',{'expression':'document.querySelector('+json.dumps(selector)+').scrollIntoView({block:"center"})'},session)
                return dict(top_url=url,frame_url=URL,frame_id=frame['targetId'],
                    processor='adyen',processor_protocol=1),session
        time.sleep(.05)
    pytest.fail('isolated processor frame did not load')


def child(chrome, session, expression):
    result=chrome.cdp.call('Runtime.evaluate',{'expression':expression,'returnByValue':True},session)
    assert 'exceptionDetails' not in result
    return result['result'].get('value')


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
