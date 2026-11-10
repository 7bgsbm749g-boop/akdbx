"""Autocomplete grammar regressions on synthetic pages and isolated Chromium."""
import json
import subprocess

import pytest

from akdbx.browser_password import BrowserPasswords, DELIVERY, FILL
from akdbx.target import X11Typer, failure
from test_browser_password import fill, prepare
from test_target import isolated_x11
from test_target_chromium import synthetic_chromium, wait_for
from test_writes import begin, commit, deployed, reopened, template


def attributes(cdp, session, password='current-password webauthn', username='username webauthn'):
    """Declare synthetic markup before pinning; delivery must never rewrite it."""
    cdp.evaluate('password.setAttribute("autocomplete",' + json.dumps(password) + ');'
                 'username.setAttribute("autocomplete",' + json.dumps(username) + ');', session)


@pytest.mark.parametrize('mode, password, username', [
    pytest.param('password', 'current-password webauthn', 'username', id='google-password'),
    ('password', 'new-password webauthn', 'username'),
    ('password', '\tCURRENT-PASSWORD \n WEBAUTHN\f', 'username'),
    ('password', 'section-login current-password webauthn', 'username'),
    ('password', 'section-reset billing new-password webauthn', 'username'),
    ('login', 'SECTION-login SHIPPING CURRENT-PASSWORD WEBAUTHN', 'section-login shipping username webauthn'),
    ('username', 'new-password', 'section-login username webauthn'),
])
def test_autocomplete_token_lists_fill_exact_retained_nodes(synthetic_chromium, tmp_path, monkeypatch,
                                                          mode, password, username):
    broker, entry, request = prepare(synthetic_chromium, tmp_path, mode)
    _, _, cdp, session, _, _ = synthetic_chromium
    attributes(cdp, session, password, username)
    cdp.evaluate('window.attributeChanges=[];new MutationObserver(records=>attributeChanges.push(...records))'
                 '.observe(document,{attributes:true,subtree:true});', session)
    def no_keys(*args, **kwargs):
        pytest.fail('autocomplete delivery used a keyboard backend')
    monkeypatch.setattr(broker.typer, 'deliver', no_keys)
    try:
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        assert fill(broker, pin, mode) == dict(ok=True, filled=mode, target_delivery=DELIVERY)
        assert cdp.evaluate('password.value', session) == (entry.password if mode != 'username' else '')
        assert cdp.evaluate('username.value', session) == (entry.username if mode != 'password' else '')
        assert cdp.evaluate('password.getAttribute("autocomplete")', session) == password
        assert cdp.evaluate('username.getAttribute("autocomplete")', session) == username
        assert cdp.evaluate('attributeChanges.length', session) == 0
        assert cdp.evaluate('document.activeElement.id', session) == ('password' if mode == 'password' else 'username')
        assert not fill(broker, pin, mode)['ok']
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('mode, field, values', [
    ('password', 'password', (
        '', 'on', 'off', 'webauthn', 'current-passwordwebauthn',
        'current-password off', 'off current-password',
        'current-password cc-csc', 'cc-csc current-password',
        'current-password new-password', 'current-password current-password',
        'webauthn current-password', 'current-password webauthn webauthn',
        'section-x section-y current-password webauthn',
        'shipping section-x current-password', 'section-x shipping billing current-password',
        'home current-password webauthn', 'username webauthn',
        'current-password webauthn unknown', 'current-password\u00a0webauthn',
        'current-password\vwebauthn', 'section-' + 'x' * 4096 + ' current-password webauthn',
    )),
    ('login', 'username', (
        'current-password webauthn', 'username current-password', 'cc-csc username',
        'home username webauthn', 'webauthn username', 'username\u00a0webauthn',
    )),
])
def test_invalid_autocomplete_tokens_never_authorize_a_pin(synthetic_chromium, tmp_path,
                                                          mode, field, values):
    broker, _, request = prepare(synthetic_chromium, tmp_path, mode)
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        for value in values:
            attributes(cdp, session, **{field: value})
            assert broker.dispatch(request) == failure(), value
            assert cdp.evaluate('password.value.length + username.value.length', session) == 0
            assert cdp.evaluate(field + '.getAttribute("autocomplete")', session) == value
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('race', ['autocomplete', 'autocomplete-duplicate', 'type', 'replacement', 'focus-restored', 'navigation', 'omnibox'])
def test_token_list_pin_keeps_final_synchronous_safety_checks(synthetic_chromium, tmp_path, monkeypatch, race):
    broker, _, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    attributes(cdp, session)
    try:
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        retained = broker.passwords.pins[pin['target']][1]
        call = retained.connection.call
        def change_at_boundary(method, params=None, target_session=None, **kwargs):
            if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == FILL:
                if race == 'omnibox':
                    subprocess.run(['xdotool', 'key', 'ctrl+l'], check=True, timeout=5)
                    wait_for(cdp, session, '!document.hasFocus()')
                else:
                    cdp.evaluate({
                        'autocomplete': 'password.autocomplete="current-password cc-csc"',
                        'autocomplete-duplicate': 'password.setAttribute("autocomplete","current-password current-password webauthn")',
                        'type': 'password.type="text"',
                        'replacement': 'password.outerHTML=\'<input id=password type=password autocomplete="current-password webauthn">\'',
                        'focus-restored': 'username.focus();password.focus()',
                        'navigation': 'history.pushState(null,"","/other");history.replaceState(null,"","/login")',
                    }[race], session)
            return call(method, params, target_session, **kwargs)
        monkeypatch.setattr(retained.connection, 'call', change_at_boundary)
        def no_keys(*args, **kwargs):
            pytest.fail('refused token-list fill used a keyboard backend')
        monkeypatch.setattr(broker.typer, 'deliver', no_keys)
        assert fill(broker, pin) == failure()
        assert cdp.evaluate('password.value.length + username.value.length', session) == 0
    finally:
        broker.passwords.close()


def test_generated_password_and_confirmation_accept_token_lists(synthetic_chromium, tmp_path, deployed):
    _, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    broker, _, path, _ = deployed
    broker.vault.find_entries(title='Synthetic site', first=True).url = entry.url
    broker.typer = X11Typer()
    broker.passwords = BrowserPasswords(tmp_path / 'synthetic-chromium-profile')
    attributes(cdp, session, 'section-reset new-password webauthn')
    cdp.evaluate('document.body.insertAdjacentHTML("beforeend",\'<input id=confirmation type=password autocomplete="section-reset new-password webauthn">\')', session)
    try:
        generated = begin(broker, 'generate-password')
        assert generated['ok'], generated
        secret = broker.writes.get(generated['write_handle']).password
        for field, ref in generated['fill_handles'].items():
            selector = '#password' if field == 'password' else '#confirmation'
            cdp.evaluate('document.querySelector(' + json.dumps(selector) + ').focus()', session)
            pin = broker.dispatch({**request, 'selector': selector})
            assert pin['ok'], pin
            result = broker.dispatch(dict(action='fill-generated', handle=ref, target_url=entry.url,
                                          target=pin['target'], target_protocol=1))
            assert result == dict(ok=True, filled='password', target_delivery=DELIVERY)
            assert cdp.evaluate('document.querySelector(' + json.dumps(selector) + ').value', session) == secret
        assert commit(broker, generated)['ok']
        assert reopened(path).find_entries(title='Synthetic site', first=True).password == secret
    finally:
        broker.passwords.close()
