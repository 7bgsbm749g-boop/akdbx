"""Namecheap-like unannotated fields, with synthetic credentials and desktop only."""
import json

import pytest

from akdbx import cli
from akdbx.browser_password import BrowserPasswords, DELIVERY
from akdbx.target import X11Typer, failure
from test_browser_password import prepare, fill
from test_target_chromium import synthetic_chromium
from test_target import isolated_x11
from test_writes import begin, commit, deployed, reopened, template


@pytest.mark.parametrize('hint', [None, '', 'on', ' ON '])
@pytest.mark.parametrize('purpose', ['current-password', 'new-password'])
def test_unannotated_field_needs_explicit_purpose(synthetic_chromium, tmp_path, monkeypatch, hint, purpose):
    """Require an explicit purpose and DOM-only delivery for unannotated fields."""
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    script = "password.removeAttribute('autocomplete')" if hint is None else "password.setAttribute('autocomplete'," + json.dumps(hint) + ')'
    cdp.evaluate(script, session)
    def no_keyboard(*args, **kwargs):
        """Fail if the password path attempts keyboard delivery."""
        pytest.fail('explicit password purpose attempted keyboard delivery')
    monkeypatch.setattr(broker.typer, 'deliver', no_keyboard)
    try:
        assert broker.dispatch(request) == failure()
        assert cdp.evaluate('password.value', session) == ''
        pin = broker.dispatch({**request, 'password_purpose': purpose})
        assert pin['ok'], pin
        assert fill(broker, pin) == dict(ok=True, filled='password', target_delivery=DELIVERY)
        assert cdp.evaluate('password.value', session) == entry.password
        assert cdp.evaluate('username.value', session) == ''
        assert cdp.evaluate("password.getAttribute('autocomplete')", session) == hint
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('hint', ['off', 'cc-csc', 'username', 'on on', 'current-password current-password', 'new-password', 'section-x on'])
def test_purpose_does_not_override_conflicting_or_malformed_hints(synthetic_chromium, tmp_path, hint):
    """Reject conflicting, disabled, and malformed autocomplete hints."""
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    cdp.evaluate("password.setAttribute('autocomplete'," + json.dumps(hint) + ')', session)
    try:
        assert broker.dispatch({**request, 'password_purpose': 'current-password'}) == failure()
        assert cdp.evaluate("password.value === '' && username.value === ''", session)
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('change', ["password.type='text'", "password.hidden=true", "password.disabled=true", "password.readOnly=true", "document.body.insertAdjacentHTML('beforeend','<input id=password type=password>')"])
def test_purpose_keeps_field_type_visibility_and_uniqueness_guards(synthetic_chromium, tmp_path, change):
    """Keep unsafe or ambiguous fields unpinnable with a declared purpose."""
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    cdp.evaluate("password.removeAttribute('autocomplete');" + change, session)
    try:
        assert broker.dispatch({**request, 'password_purpose': 'current-password'}) == failure()
        assert cdp.evaluate("Array.from(document.querySelectorAll('input')).every(e=>!e.value)", session)
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('change', ["password.setAttribute('autocomplete','on')", "password.setAttribute('autocomplete','on');password.removeAttribute('autocomplete')", "username.focus()", "password.type='text'", "location.hash='other'"])
def test_unannotated_pin_revalidates_before_fill(synthetic_chromium, tmp_path, change):
    """Reject a retained pin after field, focus, or navigation changes."""
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    cdp.evaluate("password.removeAttribute('autocomplete')", session)
    try:
        pin = broker.dispatch({**request, 'password_purpose': 'current-password'})
        assert pin['ok'], pin
        cdp.evaluate(change, session)
        assert not fill(broker, pin)['ok']
        assert cdp.evaluate("password.value === '' && username.value === ''", session)
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('purpose', [None, '', True, [], {}, 'off', 'username'])
def test_invalid_purpose_is_rejected_before_browser_io(monkeypatch, purpose):
    """Validate purpose values before connecting to the browser."""
    from akdbx import browser_password
    from akdbx.target import TargetError
    def no_connection(*args):
        """Fail if an invalid declaration opens a browser connection."""
        pytest.fail('invalid declaration opened a browser connection')
    monkeypatch.setattr(browser_password, 'CDP', no_connection)
    request=dict(action='pin-password-target', password_protocol=1, page_id='page', frame_id='frame',
                 top_url='https://example.test/login', selector='#password', mode='password', password_purpose=purpose)
    with pytest.raises(TargetError):
        browser_password.BrowserPasswords().pin(request)


@pytest.mark.parametrize('capability', [None, True, 2])
def test_cli_does_not_send_purpose_to_unsupported_broker(monkeypatch, capsys, capability):
    """Send only a capability probe when the broker lacks protocol support."""
    calls=[]
    def request(socket, payload, **kwargs):
        """Record RPCs and advertise the selected unsupported capability."""
        calls.append(payload)
        return dict(ok=True, password_fill_protocol=1, password_fill_delivery=DELIVERY, password_purpose_protocol=capability)
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['pin-password-target','--page-id','page','--frame-id','frame','--top-url','https://example.test/login','--selector','#password','--password-purpose','current-password']) == 1
    assert calls == [{'action':'ping'}]
    assert 'target request not sent' in capsys.readouterr().out


def test_cli_sends_explicit_purpose_and_preserves_pin_receipt(monkeypatch, capsys):
    """Transmit a supported declaration without changing the pin receipt."""
    calls=[]
    def request(socket, payload, **kwargs):
        """Record RPCs and return supported capabilities or a synthetic pin."""
        calls.append(payload)
        if payload['action']=='ping':
            return dict(ok=True, password_fill_protocol=1, password_fill_delivery=DELIVERY, password_purpose_protocol=1)
        return dict(ok=True,target='a'*64,expires_in=30,target_delivery=DELIVERY)
    monkeypatch.setattr(cli,'request',request)
    assert cli.main(['pin-password-target','--page-id','page','--frame-id','frame','--top-url','https://example.test/login','--selector','#password','--password-purpose','current-password']) == 0
    assert calls[-1]['password_purpose']=='current-password'
    assert json.loads(capsys.readouterr().out)['target_delivery']==DELIVERY


@pytest.mark.parametrize('mode', ['username', 'login'])
def test_purpose_is_password_only_in_cli_and_broker(monkeypatch, capsys, mode):
    """Reject purpose declarations outside password mode before RPC or CDP."""
    from akdbx import browser_password
    from akdbx.target import TargetError
    def forbidden(*args, **kwargs):
        """Fail if an unsupported mode performs external I/O."""
        pytest.fail('unsupported purpose mode performed RPC or browser I/O')
    monkeypatch.setattr(cli, 'request', forbidden)
    monkeypatch.setattr(browser_password, 'CDP', forbidden)
    flags=['--mode',mode]+(['--username-selector','#username'] if mode=='login' else [])
    assert cli.main(['pin-password-target','--page-id','page','--frame-id','frame','--top-url','https://example.test/login','--selector','#password','--password-purpose','current-password',*flags]) == 2
    assert '--password-purpose requires --mode password' in capsys.readouterr().err
    request=dict(action='pin-password-target',password_protocol=1,page_id='page',frame_id='frame',top_url='https://example.test/login',selector='#password',mode=mode,password_purpose='current-password')
    if mode=='login':
        request['username_selector']='#username'
    with pytest.raises(TargetError):
        browser_password.BrowserPasswords().pin(request)


def test_generated_password_and_confirmation_use_declared_new_purpose(synthetic_chromium, tmp_path, deployed, monkeypatch):
    """Fill generated and confirmation fields through declared DOM pins only."""
    _, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    broker, _, path, _ = deployed
    broker.vault.find_entries(title='Synthetic site', first=True).url=entry.url
    broker.typer=X11Typer()
    broker.passwords=BrowserPasswords(tmp_path / 'synthetic-chromium-profile')
    def no_keyboard(*args, **kwargs):
        """Fail if generated-password delivery falls back to the keyboard."""
        pytest.fail('generated password used keyboard delivery')
    monkeypatch.setattr(broker.typer,'deliver',no_keyboard)
    cdp.evaluate("password.removeAttribute('autocomplete');document.body.insertAdjacentHTML('beforeend','<input id=confirmation type=password autocomplete=on>')",session)
    try:
        generated=begin(broker,'generate-password')
        assert generated['ok'],generated
        secret=broker.writes.get(generated['write_handle']).password
        for field,ref in generated['fill_handles'].items():
            selector='#password' if field=='password' else '#confirmation'
            cdp.evaluate('document.querySelector('+json.dumps(selector)+').focus()',session)
            pin=broker.dispatch({**request,'selector':selector,'password_purpose':'new-password'})
            assert pin['ok'],pin
            result=broker.dispatch(dict(action='fill-generated',handle=ref,target_url=entry.url,target=pin['target'],target_protocol=1))
            assert result==dict(ok=True,filled='password',target_delivery=DELIVERY)
            assert cdp.evaluate('document.querySelector('+json.dumps(selector)+').value',session)==secret
        assert commit(broker,generated)['ok']
        assert reopened(path).find_entries(title='Synthetic site',first=True).password==secret
    finally:
        broker.passwords.close()
