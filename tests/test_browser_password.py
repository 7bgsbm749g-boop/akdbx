"""Synthetic-only real Chromium regression and race tests. Never uses :99."""
import json
import os
from pathlib import Path
import subprocess

import pytest

from akdbx.broker import Broker
from akdbx.browser_password import BrowserPasswords, DELIVERY, endpoint
from akdbx.target import X11Typer, failure
from test_broker import Entry, Vault
from test_target import isolated_x11
from test_target_chromium import synthetic_chromium, wait_for


def prepare(browser, tmp_path, mode='password'):
    lab, process, cdp, session, window, _ = browser
    url = cdp.evaluate('location.href', session)
    cdp.evaluate("username.value='';password.value='';" + ('username' if mode != 'password' else 'password') + '.focus()', session)
    lab.activate(window)
    entry = Entry(username='Synthetic.User+42@example.test', password='Synthetic-ONLY!$`\\Aa19 Ω', url=url)
    broker = Broker(Vault([entry]), X11Typer(), password_browser_profile=tmp_path / 'synthetic-chromium-profile')
    page = next(t for t in cdp.call('Target.getTargets')['targetInfos'] if t['type'] == 'page' and t['url'] == url)
    frame = cdp.call('Page.getFrameTree', session=session)['frameTree']['frame']['id']
    request = dict(action='pin-password-target', password_protocol=1, page_id=page['targetId'], frame_id=frame,
                   top_url=url, selector='#username' if mode == 'username' else '#password', mode=mode)
    if mode == 'login':
        request['username_selector'] = '#username'
    return broker, entry, request


def fill(broker, pin, mode='password'):
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    return broker.dispatch(dict(action='fill', handle=handle, mode=mode, target=pin['target'], target_protocol=1))


def navigate_suffix(browser, suffix):
    """Navigate only the synthetic page; retain its exact public URL."""
    _, _, cdp, session, _, _ = browser
    url = cdp.evaluate('location.origin + "/login"', session) + suffix
    cdp.call('Page.navigate', {'url': url}, session)
    wait_for(cdp, session, 'location.href === ' + json.dumps(url) + " && document.readyState === 'complete'")
    return url


@pytest.mark.parametrize(('mode', 'suffix'), [
    ('password', '#signin'), ('password', '#account%2Fpassword'),
    ('password', '?step=password#signin'), ('password', '#'),
    ('username', '#signin'), ('login', '#signin'),
])
def test_exact_fragment_url_fills_only_retained_fields(synthetic_chromium, tmp_path, monkeypatch, mode, suffix):
    url = navigate_suffix(synthetic_chromium, suffix)
    broker, entry, request = prepare(synthetic_chromium, tmp_path, mode)
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        frame = cdp.call('Page.getFrameTree', session=session)['frameTree']['frame']
        # Real CDP splits the fragment, while Target and location.href retain it.
        assert frame['url'] + frame['urlFragment'] == url
        assert '#' not in frame['url']
        assert request['top_url'] == url
        def no_keys(*args, **kwargs):
            pytest.fail('fragment password delivery attempted keyboard fallback')
        monkeypatch.setattr(broker.typer, 'deliver', no_keys)
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        assert fill(broker, pin, mode) == dict(ok=True, filled=mode, target_delivery=DELIVERY)
        assert cdp.evaluate('password.value', session) == ('' if mode == 'username' else entry.password)
        assert cdp.evaluate('username.value', session) == ('' if mode == 'password' else entry.username)
        assert cdp.evaluate('location.href', session) == url
    finally:
        broker.passwords.close()


def test_fragment_pin_refuses_missing_different_or_decoded_fragment(synthetic_chromium, tmp_path):
    url = navigate_suffix(synthetic_chromium, '#account%2Fpassword')
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        for wrong_url in [url.split('#')[0], url.replace('%2F', '/'), url + '-other']:
            assert broker.dispatch({**request, 'top_url': wrong_url}) == failure()
        assert cdp.evaluate("Array.from(document.querySelectorAll('input')).every(e=>!e.value)", session)
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('restore', [False, True])
@pytest.mark.parametrize('boundary', ['after-pin', 'before-setter'])
def test_fragment_navigation_and_restoration_invalidate_pin(synthetic_chromium, tmp_path, monkeypatch, restore, boundary):
    from akdbx.browser_password import FILL
    url = navigate_suffix(synthetic_chromium, '#signin')
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        def navigate():
            # Restoring the exact URL must not resurrect the navigation-tainted pin.
            cdp.evaluate("location.hash='other'" + (";history.replaceState(null,''," + json.dumps(url) + ')' if restore else ''), session)
        if boundary == 'after-pin':
            navigate()
        else:
            retained = broker.passwords.pins[pin['target']][1]
            call = retained.connection.call
            def change_before_setter(method, params=None, target_session=None, **kwargs):
                if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == FILL:
                    navigate()
                return call(method, params, target_session, **kwargs)
            monkeypatch.setattr(retained.connection, 'call', change_before_setter)
        def no_keys(*args, **kwargs):
            pytest.fail('fragment race attempted keyboard fallback')
        monkeypatch.setattr(broker.typer, 'deliver', no_keys)
        assert not fill(broker, pin)['ok']
        assert cdp.evaluate("Array.from(document.querySelectorAll('input')).every(e=>!e.value)", session)
        if restore:
            assert cdp.evaluate('location.href', session) == url
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('mode', ['password', 'username', 'login'])
def test_saved_values_go_to_exact_elements_without_keys_or_tab(synthetic_chromium, tmp_path, mode):
    broker, entry, request = prepare(synthetic_chromium, tmp_path, mode)
    lab, process, cdp, session, window, version = synthetic_chromium
    try:
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        result = fill(broker, pin, mode)
        assert result == dict(ok=True, filled=mode, target_delivery=DELIVERY), result
        assert cdp.evaluate('username.value', session) == (entry.username if mode != 'password' else '')
        assert cdp.evaluate('password.value', session) == (entry.password if mode != 'username' else '')
        # Direct DOM assignment does not move focus, even in login mode.
        assert cdp.evaluate('document.activeElement.id', session) == ('password' if mode == 'password' else 'username')
        assert not fill(broker, pin, mode)['ok']
        print(json.dumps(dict(browser=version, mode=mode, exact_values=True, no_tab=True, temporary_profile=True)))
    finally:
        broker.passwords.close()


def test_reproduce_old_transport_in_real_omnibox_then_refuse_it(synthetic_chromium, tmp_path):
    lab, process, cdp, session, window, version = synthetic_chromium
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    try:
        # Reproduce the former production boundary with public synthetic text.
        # Do not press Enter or submit the synthetic omnibox content anywhere.
        subprocess.run(['xdotool', 'key', 'ctrl+l'], check=True, timeout=5)
        wait_for(cdp, session, '!document.hasFocus()')
        typer = X11Typer()
        identity = typer.capture(process.pid, window.id)
        typer.deliver(identity, ['SYNTHETIC-OMNIBOX-REPRO-ONLY'], lambda: True)
        assert cdp.evaluate('password.value.length + username.value.length', session) == 0
        subprocess.run(['import', '-window', 'root', str(tmp_path / 'old-transport-omnibox.png')], check=True, timeout=5)
        # The repaired Broker refuses this same X11 pin before any password key.
        pin = broker.dispatch(dict(action='pin-target', pid=process.pid, window=window.id, target_protocol=1))
        assert pin['ok']
        assert fill(broker, pin) == failure()
        # DOM pins also refuse while the omnibox owns input focus.
        assert broker.dispatch(request) == failure()
        print(json.dumps(dict(browser=version, old_window_pin_accepted_omnibox=True,
                              repaired_x11_password_refused=True, dom_pin_in_omnibox_refused=True)))
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('change', [
    "username.focus()",  # wrong DOM field
    "password.type='text'", "password.autocomplete='cc-csc'", "password.autocomplete='off'", "password.disabled=true", "password.readOnly=true",
    "password.style.display='none'", "password.setAttribute('inert','')",
    "password.outerHTML='<input id=password type=password>'",  # replacement
    "password.id='other';document.body.insertAdjacentHTML('beforeend','<input id=password type=password>')",
    "document.body.insertAdjacentHTML('beforeend','<input id=password type=password>')",  # ambiguous
    "history.pushState(null,'','/other')",  # same document navigation
    "history.pushState(null,'','/other');history.replaceState(null,'','/login')",
    "const old=password;old.remove();document.body.append(old);old.focus()",
    "username.focus();password.focus()",  # restored focus must not resurrect pin
])
def test_changes_after_pin_refuse_without_secret_in_any_field(synthetic_chromium, tmp_path, change):
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        cdp.evaluate(change, session)
        assert not fill(broker, pin)['ok']
        assert cdp.evaluate("Array.from(document.querySelectorAll('input')).every(e=>!e.value)", session)
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('change', ['omnibox', 'tab', 'reload', 'navigate', 'close'])
def test_browser_focus_and_document_races(synthetic_chromium, tmp_path, change):
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        if change == 'omnibox':
            subprocess.run(['xdotool', 'key', 'ctrl+l'], check=True, timeout=5)
            wait_for(cdp, session, '!document.hasFocus()')
        elif change == 'tab':
            new = cdp.call('Target.createTarget', {'url': 'about:blank'})['targetId']
            cdp.call('Target.activateTarget', {'targetId': new})
            wait_for(cdp, session, '!document.hasFocus()')
        elif change == 'close':
            cdp.call('Target.closeTarget', {'targetId': request['page_id']})
        else:
            if change == 'reload':
                cdp.call('Page.reload', session=session)
            else:
                cdp.call('Page.navigate', {'url': entry.url.replace('/login', '/other')}, session)
            wait_for(cdp, session, "document.readyState==='complete'")
        assert not fill(broker, pin)['ok']
        if change != 'close':
            assert cdp.evaluate("Array.from(document.querySelectorAll('input')).every(e=>!e.value)", session)
    finally:
        broker.passwords.close()


def test_wrong_origin_mode_selector_frame_and_unsupported_profile(synthetic_chromium, tmp_path):
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        for changes in [dict(top_url='https://other.invalid/'), dict(selector='#username'), dict(frame_id='wrong'),
                        dict(selector='input'), dict(password_protocol=True), dict(endpoint='ws://127.0.0.1:1')]:
            assert not broker.dispatch({**request, **changes})['ok']
        pin = broker.dispatch(request)
        entry.url = 'https://other.invalid/'
        assert not fill(broker, pin)['ok']
        assert cdp.evaluate('password.value', session) == ''
        entry.url = request['top_url']
        pin = broker.dispatch(request)
        assert not fill(broker, pin, 'login')['ok']
        unsupported = Broker(Vault([entry]), X11Typer())
        assert unsupported.dispatch(request) == failure()
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('suffix', ['', '#reset'])
def test_generated_password_and_confirmation_use_dom_and_only_success_counts(synthetic_chromium, tmp_path, deployed, suffix):
    from test_writes import begin, commit, reopened
    if suffix:
        navigate_suffix(synthetic_chromium, suffix)
    _, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    broker, _, path, _ = deployed
    saved = broker.vault.find_entries(title='Synthetic site', first=True)
    saved.url = entry.url
    broker.typer = X11Typer()
    broker.passwords = BrowserPasswords(tmp_path / 'synthetic-chromium-profile')
    try:
        generated = begin(broker, 'generate-password')
        assert generated['ok'], generated
        # Use real production generation and persistence; only the vault is synthetic.
        secret = broker.writes.get(generated['write_handle']).password
        cdp.evaluate("document.body.insertAdjacentHTML('beforeend','<input id=confirmation type=password autocomplete=new-password>')", session)
        for field, ref in generated['fill_handles'].items():
            selector = '#password' if field == 'password' else '#confirmation'
            cdp.evaluate('document.querySelector(' + json.dumps(selector) + ').focus()', session)
            pin = broker.dispatch({**request, 'selector': selector})
            assert pin['ok'], pin
            result = broker.dispatch(dict(action='fill-generated', handle=ref, target_url=entry.url,
                                          target=pin['target'], target_protocol=1))
            assert result == dict(ok=True, filled='password', target_delivery=DELIVERY), result
            assert cdp.evaluate('document.querySelector(' + json.dumps(selector) + ').value', session) == secret
        assert commit(broker, generated)['ok']
        assert reopened(path).find_entries(title='Synthetic site', first=True).password == secret
        # A focus race must not count as a successful generated fill or permit commit.
        generated = begin(broker, 'generate-password')
        cdp.evaluate('password.focus()', session)
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        cdp.evaluate('username.focus()', session)
        result = broker.dispatch(dict(action='fill-generated', handle=generated['fill_handles']['password'],
                                      target_url=entry.url, target=pin['target'], target_protocol=1))
        assert not result['ok']
        assert not broker.writes.get(generated['write_handle']).filled
        assert not commit(broker, generated)['ok']
    finally:
        broker.passwords.close()


from test_writes import deployed, template


@pytest.mark.parametrize('race', ['focus', 'replacement', 'omnibox'])
def test_change_after_python_preflight_before_renderer_assignment(synthetic_chromium, tmp_path, race, monkeypatch):
    from akdbx.browser_password import FILL
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        retained = broker.passwords.pins[pin['target']][1]
        call = retained.connection.call
        def switch_at_boundary(method, params=None, target_session=None, **kwargs):
            if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == FILL:
                if race == 'omnibox':
                    subprocess.run(['xdotool', 'key', 'ctrl+l'], check=True, timeout=5)
                    wait_for(cdp, session, '!document.hasFocus()')
                else:
                    cdp.evaluate('username.focus()' if race == 'focus' else
                                 "password.outerHTML='<input id=password type=password>'", session)
            return call(method, params, target_session, **kwargs)
        monkeypatch.setattr(retained.connection, 'call', switch_at_boundary)
        def no_keys(*args, **kwargs):
            pytest.fail('DOM password delivery attempted keyboard fallback')
        monkeypatch.setattr(broker.typer, 'deliver', no_keys)
        assert not fill(broker, pin)['ok']
        assert cdp.evaluate("Array.from(document.querySelectorAll('input')).every(e=>!e.value)", session)
    finally:
        broker.passwords.close()


def test_login_does_not_run_username_handlers_before_password_assignment(synthetic_chromium, tmp_path):
    broker, entry, request = prepare(synthetic_chromium, tmp_path, 'login')
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        cdp.evaluate("username.addEventListener('input',()=>{window.passwordAtUsernameEvent=password.value;username.focus()})", session)
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        assert fill(broker, pin, 'login')['ok']
        assert cdp.evaluate('window.passwordAtUsernameEvent', session) == entry.password
        assert cdp.evaluate('password.value', session) == entry.password
    finally:
        broker.passwords.close()


def test_renderer_refuses_fill_queued_past_start_deadline(synthetic_chromium, tmp_path, monkeypatch):
    import time
    from akdbx.browser_password import FILL
    broker, entry, request = prepare(synthetic_chromium, tmp_path)
    _, _, cdp, session, _, _ = synthetic_chromium
    try:
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        retained = broker.passwords.pins[pin['target']][1]
        call = retained.connection.call
        def block_renderer(method, params=None, target_session=None, **kwargs):
            if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == FILL:
                # Synthetic page task holds the renderer while the actual
                # production fill waits in its CDP queue. No secret is sent
                # through the observer connection or returned from delivery.
                cdp.evaluate('setTimeout(()=>{const end=performance.now()+500;while(performance.now()<end){}},0)', session)
            return call(method, params, target_session, **kwargs)
        monkeypatch.setattr(retained.connection, 'call', block_renderer)
        handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
        result = broker.dispatch(dict(action='fill', handle=handle, mode='password', target=pin['target'],
                                      target_protocol=1, start_deadline=time.monotonic()+0.2))
        assert not result['ok'], result
        assert cdp.evaluate('password.value', session) == ''
    finally:
        broker.passwords.close()
