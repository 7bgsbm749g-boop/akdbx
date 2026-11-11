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
