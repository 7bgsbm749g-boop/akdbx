"""Explicit off-field delivery uses only synthetic credentials and isolated Chrome."""
import json

import pytest

from akdbx import cli, browser_password
from akdbx.browser_password import BrowserPasswords, DELIVERY
from akdbx.target import TargetError, X11Typer, failure
from test_browser_password import prepare, fill
from test_target_chromium import synthetic_chromium
from test_target import isolated_x11
from test_writes import begin, commit, deployed, reopened, template


@pytest.mark.parametrize('hint',['off',' OFF ','\tOff\n'])
@pytest.mark.parametrize('purpose',['current-password','new-password'])
def test_off_field_requires_both_explicit_declarations(synthetic_chromium,tmp_path,monkeypatch,hint,purpose):
    """Default and purpose-only calls refuse, while an explicit pin fills unchanged DOM."""
    broker,entry,request=prepare(synthetic_chromium,tmp_path)
    _,_,cdp,session,_,_=synthetic_chromium
    cdp.evaluate('password.setAttribute("autocomplete",'+json.dumps(hint)+')',session)
    monkeypatch.setattr(broker.typer,'deliver',lambda *a,**k:pytest.fail('keyboard password delivery'))
    try:
        assert broker.dispatch(request)==failure()
        assert broker.dispatch({**request,'password_purpose':purpose})==failure()
        pin=broker.dispatch({**request,'password_purpose':purpose,'allow_autocomplete_off':True})
        assert pin['ok'],pin
        assert fill(broker,pin)==dict(ok=True,filled='password',target_delivery=DELIVERY)
        assert cdp.evaluate('password.value',session)==entry.password
        assert cdp.evaluate('username.value',session)==''
        assert cdp.evaluate('password.getAttribute("autocomplete")',session)==hint
        assert not fill(broker,pin)['ok']
    finally:broker.passwords.close()


@pytest.mark.parametrize('hint',['off off','off current-password','cc-csc','username','new-password','section-x off','off webauthn'])
def test_off_opt_in_does_not_accept_malformed_or_conflicting_hints(synthetic_chromium,tmp_path,hint):
    """The extra opt-in is limited to an exact single off token."""
    broker,_,request=prepare(synthetic_chromium,tmp_path)
    _,_,cdp,session,_,_=synthetic_chromium
    cdp.evaluate('password.setAttribute("autocomplete",'+json.dumps(hint)+')',session)
    try:
        assert broker.dispatch({**request,'password_purpose':'current-password','allow_autocomplete_off':True})==failure()
        assert cdp.evaluate("password.value === '' && username.value === ''",session)
    finally:broker.passwords.close()


@pytest.mark.parametrize('change',[
    "password.autocomplete='on'", "password.autocomplete='on';password.autocomplete='off'",
    "username.focus();password.focus()", "password.type='text'", "password.hidden=true",
    "password.disabled=true", "password.readOnly=true", "location.hash='other'",
    "password.outerHTML='<input id=password type=password autocomplete=off>'"])
def test_off_pin_refuses_changed_retained_target(synthetic_chromium,tmp_path,change):
    """Attribute, visibility, focus, navigation and replacement races cannot receive a secret."""
    broker,_,request=prepare(synthetic_chromium,tmp_path)
    _,_,cdp,session,_,_=synthetic_chromium
    cdp.evaluate("password.autocomplete='off'",session)
    try:
        pin=broker.dispatch({**request,'password_purpose':'current-password','allow_autocomplete_off':True})
        assert pin['ok'],pin
        cdp.evaluate(change,session)
        assert not fill(broker,pin)['ok']
        assert cdp.evaluate("password.value === '' && username.value === ''",session)
    finally:broker.passwords.close()


@pytest.mark.parametrize('changes',[
    {'allow_autocomplete_off':False},{'allow_autocomplete_off':1},
    {'allow_autocomplete_off':'true'},{'allow_autocomplete_off':None},
    {'password_purpose':None},{'mode':'username'},
    {'mode':'login','username_selector':'#username'}])
def test_invalid_off_declarations_refuse_before_browser_io(monkeypatch,changes):
    """No untyped opt-in or unsupported mode may open a browser connection."""
    monkeypatch.setattr(browser_password,'CDP',lambda *a,**k:pytest.fail('invalid opt-in opened CDP'))
    request=dict(action='pin-password-target',password_protocol=1,page_id='p',frame_id='f',
        top_url='https://example.test/login',selector='#password',mode='password',
        password_purpose='current-password',allow_autocomplete_off=True)
    request.update(changes)
    with pytest.raises(TargetError):BrowserPasswords().pin(request)
    request.pop('password_purpose')
    with pytest.raises(TargetError):BrowserPasswords().pin(request)


def argv():
    """Return an explicit off-field CLI request containing no credentials."""
    return ['pin-password-target','--page-id','p','--frame-id','f','--top-url','https://example.test/login',
        '--selector','#password','--password-purpose','new-password','--allow-autocomplete-off']


@pytest.mark.parametrize('capability',[None,True,0,2,'1'])
def test_cli_refuses_unsupported_off_capability(monkeypatch,capsys,capability):
    """A new CLI sends only ping to an older or malformed-capability broker."""
    calls=[]
    def rpc(socket,payload,**kwargs):
        calls.append(payload)
        return dict(ok=True,password_fill_protocol=1,password_fill_delivery=DELIVERY,
            password_purpose_protocol=1,password_autocomplete_off_protocol=capability)
    monkeypatch.setattr(cli,'request',rpc)
    assert cli.main(argv())==1
    assert calls==[{'action':'ping'}]
    assert 'target request not sent' in capsys.readouterr().out


def test_cli_sends_explicit_off_opt_in_to_capable_broker(monkeypatch,capsys):
    """Transmit the two declarations without changing a pin receipt."""
    calls=[]
    def rpc(socket,payload,**kwargs):
        calls.append(payload)
        if payload['action']=='ping':
            return dict(ok=True,password_fill_protocol=1,password_fill_delivery=DELIVERY,
                password_purpose_protocol=1,password_autocomplete_off_protocol=1)
        return dict(ok=True,target='a'*64,expires_in=30,target_delivery=DELIVERY)
    monkeypatch.setattr(cli,'request',rpc)
    assert cli.main(argv())==0
    assert calls[-1]['allow_autocomplete_off'] is True
    assert calls[-1]['password_purpose']=='new-password'
    assert json.loads(capsys.readouterr().out)['target_delivery']==DELIVERY


def test_cli_requires_password_purpose_before_rpc(monkeypatch,capsys):
    """Do not send an undeclared off-field pin to any broker."""
    monkeypatch.setattr(cli,'request',lambda *a,**k:pytest.fail('invalid CLI performed RPC'))
    args=argv();i=args.index('--password-purpose');del args[i:i+2]
    assert cli.main(args)==2
    assert '--password-purpose' in capsys.readouterr().err


def test_generated_password_and_confirmation_fill_off_fields_and_commit(synthetic_chromium,tmp_path,deployed,monkeypatch):
    """Generated credentials reach both verified fields and encrypted persistence only."""
    _,entry,request=prepare(synthetic_chromium,tmp_path)
    _,_,cdp,session,_,_=synthetic_chromium
    broker,_,path,_=deployed
    broker.vault.find_entries(title='Synthetic site',first=True).url=entry.url
    broker.typer=X11Typer();broker.passwords=BrowserPasswords(tmp_path/'synthetic-chromium-profile')
    monkeypatch.setattr(broker.typer,'deliver',lambda *a,**k:pytest.fail('keyboard generated-password delivery'))
    cdp.evaluate("password.autocomplete='off';document.body.insertAdjacentHTML('beforeend','<input id=confirmation type=password autocomplete=off>')",session)
    try:
        generated=begin(broker,'generate-password');assert generated['ok'],generated
        secret=broker.writes.get(generated['write_handle']).password
        for field,ref in generated['fill_handles'].items():
            selector='#password' if field=='password' else '#confirmation'
            cdp.evaluate('document.querySelector('+json.dumps(selector)+').focus()',session)
            pin=broker.dispatch({**request,'selector':selector,'password_purpose':'new-password','allow_autocomplete_off':True})
            assert pin['ok'],pin
            receipt=broker.dispatch(dict(action='fill-generated',handle=ref,target_url=entry.url,target=pin['target'],target_protocol=1))
            assert receipt==dict(ok=True,filled='password',target_delivery=DELIVERY)
            assert cdp.evaluate('document.querySelector('+json.dumps(selector)+').value',session)==secret
            assert cdp.evaluate('document.querySelector('+json.dumps(selector)+').getAttribute("autocomplete")',session)=='off'
        assert commit(broker,generated)['ok']
        assert reopened(path).find_entries(title='Synthetic site',first=True).password==secret
    finally:broker.passwords.close()
