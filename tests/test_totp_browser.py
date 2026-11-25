"""Shared real CDP and extension TOTP contract; disposable synthetic browsers only."""
import json
import time
from types import SimpleNamespace

import pytest

from akdbx.broker import Broker
from akdbx.browser_password import DELIVERY as CDP_DELIVERY, FILL
from akdbx.extension_route import DELIVERY as EXT_DELIVERY
from akdbx.target import failure
from test_broker import Entry, Vault
from test_target import isolated_x11  # noqa: F401
from test_target_chromium import synthetic_chromium  # noqa: F401
from test_extension_browser import harness, private_dir, certificates  # noqa: F401
from totp_vectors import URI, KEY


@pytest.fixture(params=['cdp', 'extension'])
def browser(request, tmp_path):
    if request.param == 'extension':
        h = request.getfixturevalue('harness')
        broker = h.broker
        evaluate = h.lab.evaluate
        url = evaluate('location.href')
        listing = h.frames(url)
        spec = dict(page_id=listing['page_id'], frame_id=listing['main_frame_id'], route='extension')
        handle = lambda: broker.dispatch(dict(action='search'))['entries'][0]['handle']
        delivery = EXT_DELIVERY
        entry = broker.vault.entries[0]
        transport = h
    else:
        lab, process, cdp, session, window, _ = request.getfixturevalue('synthetic_chromium')
        evaluate = lambda expression: cdp.evaluate(expression, session)
        url = evaluate('location.href')
        entry = Entry(url=url)
        broker = Broker(Vault([entry]), object(), password_browser_profile=tmp_path / 'synthetic-chromium-profile')
        page = next(t for t in cdp.call('Target.getTargets')['targetInfos'] if t['type'] == 'page' and t['url'] == url)
        frame = cdp.call('Page.getFrameTree', session=session)['frameTree']['frame']['id']
        spec = dict(page_id=page['targetId'], frame_id=frame)
        handle = lambda: broker.dispatch(dict(action='search'))['entries'][0]['handle']
        delivery = CDP_DELIVERY
        transport = cdp, session
    entry.otp = URI
    broker.wall_clock = lambda: 1111111111
    spec.update(action='pin-password-target', password_protocol=1, top_url=url, selector='#otp', mode='totp')
    def field(attributes='type=text autocomplete=one-time-code', tag='input'):
        evaluate('document.body.innerHTML = ' + json.dumps(f'<{tag} id="otp" {attributes}></{tag}><input id="other">') +
                 ';document.getElementById("otp").focus();window.keyEvents=0;document.addEventListener("keydown",()=>keyEvents++)')
    field()
    def pin(**extra):
        return broker.dispatch({**spec, **extra})
    def fill(pin, **extra):
        return broker.dispatch(dict(action='fill-totp', handle=handle(), target_url=url,
                                    target=pin['target'], target_protocol=1, **extra))
    yield SimpleNamespace(broker=broker, entry=entry, evaluate=evaluate, field=field, pin=pin, fill=fill,
                          spec=spec, url=url, handle=handle, delivery=delivery, route=request.param, transport=transport)
    broker.passwords.close()


@pytest.mark.parametrize('type_', ['text', 'tel', 'number', 'password'])
def test_whole_codes_preserve_leading_zero_and_never_return_secret(browser, type_, capsys, caplog):
    b = browser
    for digits, now, expected in [(6, 1111111111, '050471'), (8, 1111111100, '07081804')]:
        b.entry.otp = URI + '&digits=' + str(digits)
        b.broker.wall_clock = lambda: now
        b.field(f'type={type_} aria-label="One-time password" autocomplete=one-time-code maxlength={digits} pattern="[0-9]{{{digits}}}"')
        pin = b.pin()
        assert pin['ok'], pin
        result = b.fill(pin)
        assert result == dict(ok=True, filled='totp', target_delivery=b.delivery), result
        # A digest/equality stays in the synthetic renderer; no code is read back.
        assert b.evaluate('otp.value === ' + json.dumps(expected))
        assert b.evaluate('other.value === "" && document.activeElement === otp && keyEvents === 0')
        assert not b.fill(pin)['ok']  # target replay with a fresh search handle
        assert KEY not in json.dumps(result) and expected not in json.dumps(result)
    assert capsys.readouterr() == ('', '') and not caplog.records


def test_unsupported_and_split_controls_never_receive_code(browser):
    b = browser
    for attributes, tag in [
        ('type=email', 'input'), ('type=hidden', 'input'), ('', 'textarea'),
        ('type=text autocomplete=current-password', 'input'), ('type=text autocomplete=cc-csc', 'input'),
        ('type=text name=password', 'input'), ('type=text disabled', 'input'), ('type=text readonly', 'input'),
        ('type=text maxlength=1', 'input'), ('type=text maxlength=5', 'input'),
        ('type=text minlength=8', 'input'), ('type=text pattern="[A-Z]{6}"', 'input'),
        ('type=number min=100000', 'input'), ('type=text inputmode=email', 'input'),
    ]:
        b.field(attributes, tag)
        pin = b.pin()
        if pin['ok']:
            assert not b.fill(pin)['ok'], attributes
        assert b.evaluate('document.getElementById("otp").value === ""'), attributes


@pytest.mark.parametrize('change', [
    'other.focus()', 'other.focus();otp.focus()',
    'otp.outerHTML="<input id=otp>";otp.focus()',
    'otp.autocomplete="current-password"',
    'otp.maxLength=1;otp.maxLength=6',
    'history.pushState(null,"","/other")',
    'otp.style.display="none"',
])
def test_retained_node_focus_metadata_and_navigation_fail_closed(browser, change):
    b = browser
    pin = b.pin()
    assert pin['ok'], pin
    b.evaluate(change)
    assert not b.fill(pin)['ok']
    assert b.evaluate('otp.value === "" && other.value === "" && keyEvents === 0')


def test_wrong_entry_or_asserted_frame_url_refused_before_reading_otp(browser, monkeypatch):
    import akdbx.broker as module
    b = browser
    def never_read(*args):
        pytest.fail('wrong origin/URL or pin mode accessed OTP configuration')
    monkeypatch.setattr(module, 'read_configuration', never_read)
    monkeypatch.setattr(module, 'read_pending', never_read)
    for asserted, entry_url in [('https://evil.example.net/challenge', b.url),
                                (b.url, 'https://evil.example.net/login'), (b.url + '#different', b.url)]:
        b.entry.url = entry_url
        pin = b.pin()
        assert pin['ok'], pin
        result = b.broker.dispatch(dict(action='fill-totp', handle=b.handle(), target_url=asserted,
                                       target=pin['target'], target_protocol=1))
        assert not result['ok']
    assert b.evaluate('otp.value === "" && keyEvents === 0')


def test_cross_mode_refusal_consumes_pin_without_credential_access(browser, monkeypatch):
    import akdbx.broker as module
    b = browser
    monkeypatch.setattr(module, 'read_configuration', lambda *_: pytest.fail('password pin read OTP configuration'))
    for mode in ['password', 'login', 'username']:
        pin = b.pin()
        assert pin['ok']
        result = b.broker.dispatch(dict(action='fill', mode=mode, handle=b.handle(),
                                       target=pin['target'], target_protocol=1))
        assert result == failure()
        assert b.fill(pin) == failure()  # The rejected mode consumed this live pin.
    b.field('type=password autocomplete=current-password')
    pin = b.pin(mode='password')
    assert pin['ok'], pin
    assert b.fill(pin) == failure()
    assert b.evaluate('otp.value === "" && keyEvents === 0')


@pytest.mark.parametrize('changed_clock', [1111111140, 1111111100])
def test_near_expiry_expired_deadline_and_post_dispatch_clock_change(browser, monkeypatch, changed_clock):
    b = browser
    b.broker.wall_clock = lambda: 59
    pin = b.pin()
    assert b.fill(pin)['retry_after'] == 1
    b.broker.wall_clock = lambda: 1111111111
    pin = b.pin()
    assert not b.fill(pin, start_deadline=time.monotonic() - 1)['ok']
    assert b.evaluate('otp.value === ""')
    pin = b.pin()
    backend = b.broker.extension if b.route == 'extension' else b.broker.passwords
    name = 'deliver_password' if b.route == 'extension' else 'deliver'
    deliver = getattr(backend, name)
    def clock_jumps(*args, **kwargs):
        deliver(*args, **kwargs)
        b.broker.wall_clock = lambda: changed_clock
    monkeypatch.setattr(backend, name, clock_jumps)
    assert b.fill(pin) == failure(True)
    assert not b.fill(pin)['ok']


def test_pending_enrollment_uses_same_dom_guards(browser, monkeypatch):
    from akdbx.totp import parse_setup
    import akdbx.broker as module
    b = browser
    seen = []
    def pending(entry):
        seen.append(entry)
        return parse_setup(URI)
    monkeypatch.setattr(module, 'read_pending', pending)
    monkeypatch.setattr(module, 'read_configuration', lambda *_: pytest.fail('pending fill used saved OTP'))
    pin = b.pin()
    assert b.fill(pin, pending=True)['ok']
    assert seen == [b.entry] and b.evaluate('otp.value === "050471"')


def test_bad_code_and_field_format_are_refused_before_secret_dispatch(browser, monkeypatch):
    import akdbx.broker as module
    b = browser
    attempted = []
    if b.route == 'extension':
        [channel] = b.broker.extension.channels.values()
        call = channel.call
        def never_fill(op, *args, **kwargs):
            if op == 'fill':
                attempted.append(op)
            return call(op, *args, **kwargs)
        monkeypatch.setattr(channel, 'call', never_fill)
    else:
        # Wrap each captured pin's connection after pinning below.
        pass
    for attributes, code in [('type=text maxlength=5', '050471'), ('type=text', 'not-a-code'),
                              ('type=text pattern="[A-Z]{6}"', '050471'), ('type=text pattern=""', '050471')]:
        b.field(attributes)
        pin = b.pin()
        assert pin['ok'], pin
        if b.route == 'cdp':
            retained = b.broker.passwords.pins[pin['target']][1]
            call = retained.connection.call
            def never_fill(method, params=None, *args, **kwargs):
                if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == FILL:
                    attempted.append(method)
                return call(method, params, *args, **kwargs)
            monkeypatch.setattr(retained.connection, 'call', never_fill)
        monkeypatch.setattr(module, 'code_at', lambda *_, code=code: code)
        assert not b.fill(pin)['ok']
        assert attempted == [], 'known bad format dispatched a code'
        assert b.evaluate('otp.value === ""')


def test_card_hints_never_authorize_a_totp_pin(browser):
    b = browser
    for hint in ['name=cardnumber', 'aria-label="Card number"', 'name=cvc', 'name=cvv',
                 'aria-label="Security CVC"', 'name=cc-csc', 'name=credit_card',
                 'aria-label="Card security code"', 'name=CVV2', 'name=CVC2']:
        b.field('type=text ' + hint)
        assert b.pin() == failure(), hint
        assert b.evaluate('otp.value === "" && keyEvents === 0')


def test_accepted_code_can_advance_the_challenge_during_input(browser):
    b = browser
    b.evaluate('window.acceptedCode=false;otp.addEventListener("input",event=>{'
               'acceptedCode=event.target.value === "050471";event.target.remove();other.focus()},{once:true})')
    pin = b.pin()
    assert pin['ok'], pin
    assert b.fill(pin) == dict(ok=True, filled='totp', target_delivery=b.delivery)
    assert b.evaluate('acceptedCode && !document.getElementById("otp") && document.activeElement === other && keyEvents === 0')
    assert b.fill(pin) == failure()


def test_renderer_queue_cannot_outlive_totp_dispatch_deadline(browser, monkeypatch):
    b = browser
    pin = b.pin()
    assert pin['ok']
    block = 'setTimeout(()=>{const until=performance.now()+500;while(performance.now()<until){}},0)'
    if b.route == 'extension':
        [channel] = b.broker.extension.channels.values()
        call = channel.call
        def delay(op, *args, **kwargs):
            if op == 'fill':
                b.evaluate(block)
            return call(op, *args, **kwargs)
        monkeypatch.setattr(channel, 'call', delay)
    else:
        retained = b.broker.passwords.pins[pin['target']][1]
        call = retained.connection.call
        def delay(method, params=None, *args, **kwargs):
            if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == FILL:
                b.evaluate(block)
            return call(method, params, *args, **kwargs)
        monkeypatch.setattr(retained.connection, 'call', delay)
    result = b.fill(pin, start_deadline=time.monotonic() + .2)
    assert not result['ok'], result
    assert b.evaluate('otp.value === "" && keyEvents === 0')


@pytest.mark.parametrize('changed_clock', [1111111139, 1111111100])
def test_clock_change_before_dispatch_refuses_without_any_input(browser, monkeypatch, changed_clock):
    b = browser
    pin = b.pin()
    assert pin['ok'], pin
    backend = b.broker.extension if b.route == 'extension' else b.broker.passwords
    name = 'deliver_password' if b.route == 'extension' else 'deliver'
    deliver = getattr(backend, name)
    def clock_jumps(*args, **kwargs):
        b.broker.wall_clock = lambda: changed_clock
        deliver(*args, **kwargs)
    monkeypatch.setattr(backend, name, clock_jumps)
    assert b.fill(pin) == failure()
    assert b.evaluate('otp.value === "" && keyEvents === 0')


def test_expiry_during_page_notification_is_uncertain_and_never_retried(browser):
    b = browser
    b.evaluate('otp.addEventListener("input",()=>{const end=performance.now()+500;while(performance.now()<end){}},{once:true})')
    pin = b.pin()
    assert pin['ok'], pin
    result = b.fill(pin, start_deadline=time.monotonic() + .25)
    assert result == failure(True), result
    assert b.evaluate('otp.value === "050471" && keyEvents === 0')
    assert not b.fill(pin)['ok']
