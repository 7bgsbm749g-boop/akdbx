"""Real Chromium DOM delivery on native Windows; synthetic values only.

Every credential and card value reaches the page through the production broker
route. The page reports SHA-256 digests, so no test reads back a field value.
The browser is headless with a new private profile: it never takes the desktop
foreground and never touches an existing profile.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid

import pytest

if sys.platform != 'win32':
    pytest.skip('native Windows APIs required', allow_module_level=True)

from pykeepass import PyKeePass

from akdbx import password_frames, windows_rpc as rpc
from akdbx.broker import Broker, open_vault_with_password
from akdbx.browser_card import DELIVERY as CARD_DELIVERY, failure as card_failure
from akdbx.browser_password import DELIVERY, FILL
from akdbx.cards import FIELDS, MARKER
from akdbx.target import failure
from akdbx.windows_unlock import start_windows_unlock_server
from test_broker import Entry, Vault
from test_windows_native import native_https_config, private_dir, synthetic_vault  # noqa: F401
from test_windows_unlock import certificates  # noqa: F401
from windows_chromium_lab import ORIGIN, browser_binary, chromium_lab

USERNAME = 'Synthetic.User+42@example.test'
PASSWORD = 'Synthetic-ONLY!$`\\Aa19 Ω'
# A public payment test number, never a real card.
CARD = dict(name='Synthetic Cardholder', number='4111111111111111', month='09', year='2031', csc='123')
EMPTY = hashlib.sha256(b'').hexdigest()


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


class NoKeys:
    """A window backend that fails the test if any keyboard delivery starts."""

    def capture(self, pid, window):
        return ('synthetic-window', pid, window)

    def deliver(self, *args, **kwargs):
        pytest.fail('a DOM-only credential reached the keyboard backend')


class CardEntry(Entry):
    def get_custom_property(self, key):
        return {MARKER: 'v1', **{field: CARD[k] for k, field in FIELDS.items()}}.get(key)


@pytest.fixture
def lab(private_dir, certificates):
    if browser_binary() is None:
        message = 'the Windows DOM route tests require Chrome or Edge'
        if os.environ.get('AKDBX_REQUIRE_WINDOWS_CHROMIUM') == '1':
            pytest.fail(message)
        pytest.skip(message)
    with chromium_lab(private_dir, *certificates) as value:
        yield value


def broker_for(lab, *, url=ORIGIN + '/login', **options):
    entry = Entry(username=USERNAME, password=PASSWORD, url=url)
    return Broker(Vault([entry]), NoKeys(), password_browser_profile=lab.profile, **options)


def pin_request(lab, url, selector='#password', mode='password', **extra):
    request = dict(action='pin-password-target', password_protocol=1, page_id=lab.page_id,
                   frame_id=lab.main_frame, top_url=url, selector=selector, mode=mode, **extra)
    if mode == 'login':
        request['username_selector'] = '#username'
    return request


def fill(broker, pin, mode='password'):
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    return broker.dispatch(dict(action='fill', handle=handle, mode=mode, target=pin['target'], target_protocol=1))


def focus(lab, field):
    lab.evaluate(f'document.getElementById({json.dumps(field)}).focus()')
    lab.wait(f'document.hasFocus() && document.activeElement.id === {json.dumps(field)}')


@pytest.mark.parametrize('mode', ['password', 'username', 'login'])
def test_saved_values_reach_only_the_pinned_fields_without_keys_or_tab(lab, mode):
    url = lab.evaluate('location.href')
    broker = broker_for(lab)
    focus(lab, 'password' if mode == 'password' else 'username')
    try:
        pin = broker.dispatch(pin_request(lab, url, '#username' if mode == 'username' else '#password', mode))
        assert pin['ok'] and set(pin) == {'ok', 'target', 'expires_in', 'target_delivery'}, pin
        assert pin['expires_in'] == 30 and pin['target_delivery'] == DELIVERY
        assert fill(broker, pin, mode) == dict(ok=True, filled=mode, target_delivery=DELIVERY)
        assert lab.digest('password') == (EMPTY if mode == 'username' else sha(PASSWORD))
        assert lab.digest('username') == (EMPTY if mode == 'password' else sha(USERNAME))
        assert all(lab.digest(field) == EMPTY for field in ('new-password', 'confirmation', 'plain', 'other'))
        # Direct DOM assignment does not move focus, even in login mode.
        assert lab.evaluate('document.activeElement.id') == ('password' if mode == 'password' else 'username')
        events = lab.evaluate('syntheticEvents')
        assert {event['field'] for event in events} == {'password': {'password'}, 'username': {'username'},
                                                        'login': {'username', 'password'}}[mode]
        assert not any(event['trusted'] for event in events)
        # The target token is single-use.
        assert fill(broker, pin, mode) == failure()
        print(json.dumps(dict(browser=lab.version, mode=mode, exact_values=True, no_keys=True, temporary_profile=True)))
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('mode', ['password', 'login'])
def test_window_pin_never_receives_a_password(mode):
    broker = Broker(Vault([Entry(username=USERNAME, password=PASSWORD)]), NoKeys())
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    pin = broker.dispatch(dict(action='pin-target', pid=os.getpid(), window=0x1234, target_protocol=1))
    assert pin['ok'] and pin['target_delivery'] == 'win32-char-v1'
    result = broker.dispatch(dict(action='fill', handle=handle, mode=mode, target=pin['target'], target_protocol=1))
    assert result == failure()
    status = broker.dispatch({'action': 'ping'})
    assert status['target_fill_modes'] == ['username', 'totp', 'sms-code'] and status['password_browser_configured'] is False


@pytest.mark.parametrize('case', ['other-path', 'http', 'fragment', 'page-id', 'frame-id', 'ambiguous-selector',
                                  'missing-selector', 'text-field', 'unannotated', 'wrong-token', 'unfocused',
                                  'extra-field', 'old-protocol'])
def test_pin_refuses_a_destination_it_cannot_prove(lab, case):
    url = lab.evaluate('location.href')
    broker = broker_for(lab)
    focus(lab, {'unfocused': 'username', 'unannotated': 'plain', 'wrong-token': 'new-password'}.get(case, 'password'))
    request = pin_request(lab, url)
    request.update({
        'other-path': dict(top_url=ORIGIN + '/signup'), 'http': dict(top_url=url.replace('https:', 'http:')),
        'fragment': dict(top_url=url + '#signin'), 'page-id': dict(page_id='0' * 32),
        'frame-id': dict(frame_id='0' * 32), 'ambiguous-selector': dict(selector='input[type=password]'),
        'missing-selector': dict(selector='#absent'), 'text-field': dict(selector='#username'),
        'unannotated': dict(selector='#plain'),
        # The field's own hint contradicts the purpose that the caller attests.
        'wrong-token': dict(selector='#new-password', password_purpose='current-password'),
        'unfocused': {}, 'extra-field': dict(value='synthetic'), 'old-protocol': dict(password_protocol=0),
    }[case])
    try:
        assert broker.dispatch(request) == failure()
        assert not broker.passwords.pins and lab.untouched()
    finally:
        broker.passwords.close()


def test_explicit_purpose_pins_a_password_field_without_a_hint(lab):
    url = lab.evaluate('location.href')
    broker = broker_for(lab)
    focus(lab, 'plain')
    try:
        assert broker.dispatch(pin_request(lab, url, '#plain')) == failure()
        pin = broker.dispatch(pin_request(lab, url, '#plain', password_purpose='current-password'))
        assert pin['ok'], pin
        assert fill(broker, pin)['ok']
        assert lab.digest('plain') == sha(PASSWORD) and lab.digest('password') == EMPTY
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('change', ['focus', 'fragment', 'restored-fragment', 'removed', 'retyped', 'expired',
                                    'before-setter'])
def test_change_after_pin_refuses_and_writes_nothing(lab, monkeypatch, change):
    url = lab.evaluate('location.href')
    now = [1000.0]
    broker = broker_for(lab, clock=lambda: now[0])
    focus(lab, 'password')
    try:
        pin = broker.dispatch(pin_request(lab, url))
        assert pin['ok'], pin
        if change == 'focus':
            lab.evaluate("document.getElementById('username').focus()")
        elif change == 'fragment':
            lab.evaluate("location.hash = 'other'")
        elif change == 'restored-fragment':
            # Restoring the exact URL must not resurrect a navigation-tainted pin.
            lab.evaluate("location.hash = 'other'; history.replaceState(null, '', " + json.dumps(url) + ')')
        elif change == 'removed':
            lab.evaluate("document.getElementById('password').remove()")
        elif change == 'retyped':
            lab.evaluate("document.getElementById('password').type = 'text'")
        elif change == 'expired':
            now[0] += 30
        else:
            retained = broker.passwords.pins[pin['target']][1]
            call = retained.connection.call

            def move_before_setter(method, params=None, session=None, **options):
                if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == FILL:
                    lab.evaluate("document.getElementById('username').focus()")
                return call(method, params, session, **options)
            monkeypatch.setattr(retained.connection, 'call', move_before_setter)
        assert not fill(broker, pin)['ok']
        assert lab.untouched()
    finally:
        broker.passwords.close()


def test_credential_of_another_site_never_enters_this_page(lab):
    url = lab.evaluate('location.href')
    broker = broker_for(lab, url='https://signup.example.org/login')
    focus(lab, 'password')
    try:
        pin = broker.dispatch(pin_request(lab, url))
        assert pin['ok'], pin
        assert fill(broker, pin) == failure()
        assert lab.untouched()
    finally:
        broker.passwords.close()


def child_frame(lab, origin):
    frames = password_frames.forest(lab.observer, lab.session, lab.page_id)[0]
    found = [(frame_id, record) for frame_id, record in frames.items()
             if record['frame'].get('securityOrigin') == origin and record['frame'].get('parentId')]
    assert len(found) == 1, sorted(frames)
    return found[0]


def frame_evaluate(lab, frame_id, record, expression, *, gesture=False, await_promise=False):
    world = lab.observer.call('Page.createIsolatedWorld', dict(frameId=frame_id, worldName='akdbx-test-observer'),
                              record['session'])['executionContextId']
    result = lab.observer.call('Runtime.evaluate', dict(expression=expression, contextId=world, returnByValue=True,
                                                        userGesture=gesture, awaitPromise=await_promise),
                               record['session'])
    assert 'exceptionDetails' not in result, result
    return result['result'].get('value')


FRAME_DIGEST = '''(async () => { const data = new TextEncoder().encode(document.getElementById('password').value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join(''); })()'''


def test_same_site_child_frame_route_and_cross_site_refusal(lab):
    top = lab.navigate('/framed')
    origin = 'https://auth.example.com'
    lab.wait("document.getElementById('login-frame').contentWindow.length === 0")
    deadline = time.monotonic() + 10
    while True:
        try:
            frame_id, record = child_frame(lab, origin)
            if frame_evaluate(lab, frame_id, record, "document.readyState === 'complete' && !!document.getElementById('password')"):
                break
        except AssertionError:
            pass
        assert time.monotonic() < deadline, 'synthetic child frame did not load'
        time.sleep(.05)
    broker = broker_for(lab, url=origin + '/login')
    try:
        listing = broker.dispatch(dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=top))
        assert listing['ok'] and listing['page_id'] == lab.page_id, listing
        listed = [frame for frame in listing['frames'] if frame['frame_id'] == frame_id]
        assert len(listed) == 1 and listed[0]['origin'] == origin and listed[0]['eligible'], listing
        assert listed[0]['visible_fields']['password'] >= 1
        frame_evaluate(lab, frame_id, record, "document.getElementById('password').focus()", gesture=True)
        request = dict(action='pin-password-target', password_protocol=1, page_id=lab.page_id, frame_id=frame_id,
                       top_url=top, selector='#password', mode='password', frame_protocol=1, frame_origin=origin)
        # The frame's exact origin is part of the pin: a parent-site claim refuses.
        assert broker.dispatch({**request, 'frame_origin': ORIGIN}) == failure()
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        assert fill(broker, pin) == dict(ok=True, filled='password', target_delivery=DELIVERY)
        assert frame_evaluate(lab, frame_id, record, FRAME_DIGEST, await_promise=True) == sha(PASSWORD)
    finally:
        broker.passwords.close()
    # A real login frame inside a page of another site is never eligible.
    top = lab.navigate('/hostile')
    deadline = time.monotonic() + 10
    while True:
        try:
            frame_id, record = child_frame(lab, 'https://evil.example.net')
            if frame_evaluate(lab, frame_id, record, "!!document.getElementById('password')"):
                break
        except AssertionError:
            pass
        assert time.monotonic() < deadline, 'synthetic hostile frame did not load'
        time.sleep(.05)
    broker = broker_for(lab, url='https://evil.example.net/login')
    try:
        frame_evaluate(lab, frame_id, record, "document.getElementById('password').focus()", gesture=True)
        refused = broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=lab.page_id,
                                       frame_id=frame_id, top_url=top, selector='#password', mode='password',
                                       frame_protocol=1, frame_origin='https://evil.example.net'))
        assert refused == failure()
        assert frame_evaluate(lab, frame_id, record, FRAME_DIGEST, await_promise=True) == EMPTY
    finally:
        broker.passwords.close()


def test_generated_password_fills_both_fields_then_commits_and_signs_in(lab, synthetic_vault):
    """The account-creation flow against a real encrypted Windows save."""
    url = lab.navigate('/signup')
    broker = Broker(open_vault_with_password(synthetic_vault, 'synthetic master'), NoKeys(),
                    password_browser_profile=lab.profile)
    broker.writes.public_base = 'https://localhost:9443'
    metadata = dict(title='Synthetic signup', username=USERNAME, url=url, group='')
    try:
        staged = broker.dispatch(dict(action='generate-entry', metadata=metadata))
        assert staged['ok'] and set(staged['fill_handles']) == {'password', 'confirmation'}, staged
        assert set(staged) == {'ok', 'write_handle', 'state', 'fill_handles'}
        # Not yet filled: the vault must not change.
        early = broker.dispatch(dict(action='commit-password', write_handle=staged['write_handle'], site_accepted=True))
        assert not early['ok'] and 'both fills' in early['error']
        for reference, field in (('password', 'new-password'), ('confirmation', 'confirmation')):
            focus(lab, field)
            pin = broker.dispatch(pin_request(lab, url, '#' + field))
            assert pin['ok'], pin
            filled = broker.dispatch(dict(action='fill-generated', handle=staged['fill_handles'][reference],
                                          target_url=url, target=pin['target'], target_protocol=1))
            assert filled == dict(ok=True, filled='password', target_delivery=DELIVERY), filled
        generated = lab.digest('new-password')
        assert generated == lab.digest('confirmation') and generated != EMPTY
        assert lab.digest('password') == EMPTY and lab.digest('username') == EMPTY
        # A fill reference is single-use, and a site that did not accept saves nothing.
        assert not broker.dispatch(dict(action='commit-password', write_handle=staged['write_handle'],
                                        site_accepted=False))['ok']
        saved = broker.dispatch(dict(action='commit-password', write_handle=staged['write_handle'], site_accepted=True))
        assert saved == dict(ok=True, state='saved'), saved
        assert broker.dispatch(dict(action='write-status', write_handle=staged['write_handle']))['state'] == 'saved'
        persisted = PyKeePass(str(synthetic_vault), password='synthetic master')
        entry = next(entry for entry in persisted.entries if entry.title == 'Synthetic signup')
        assert sha(entry.password) == generated and len(entry.password) == 24
        assert next(e for e in persisted.entries if e.title == 'Synthetic').password == 'synthetic password'
        # Sign in with the saved entry through one login pin; no Tab.
        url = lab.navigate('/login')
        focus(lab, 'username')
        found = broker.dispatch(dict(action='search', query='signup.example.com'))['entries']
        assert [item['username'] for item in found] == [USERNAME]
        pin = broker.dispatch(pin_request(lab, url, mode='login'))
        assert pin['ok'], pin
        signed = broker.dispatch(dict(action='fill', handle=found[0]['handle'], mode='login',
                                      target=pin['target'], target_protocol=1))
        assert signed == dict(ok=True, filled='login', target_delivery=DELIVERY)
        assert lab.digest('password') == generated and lab.digest('username') == sha(USERNAME)
        print(json.dumps(dict(browser=lab.version, generated_fill=True, committed=True, login_fill=True)))
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('outcome', ['cancelled', 'wrong-site', 'reused-reference'])
def test_rejected_generated_reset_never_changes_the_vault(lab, synthetic_vault, outcome):
    url = lab.navigate('/signup')
    before = synthetic_vault.read_bytes()
    broker = Broker(open_vault_with_password(synthetic_vault, 'synthetic master'), NoKeys(),
                    password_browser_profile=lab.profile)
    broker.writes.public_base = 'https://localhost:9443'
    try:
        selected = broker.dispatch(dict(action='search', query='Synthetic'))['entries'][0]
        staged = broker.dispatch(dict(action='generate-password', handle=selected['handle'],
                                      metadata={k: selected[k] for k in ('title', 'username', 'url', 'group')}))
        assert staged['ok'], staged
        focus(lab, 'new-password')
        pin = broker.dispatch(pin_request(lab, url, '#new-password'))
        assert pin['ok'], pin
        reference = staged['fill_handles']['password']
        if outcome == 'cancelled':
            assert broker.dispatch(dict(action='cancel-write', write_handle=staged['write_handle']))['state'] == 'cancelled'
        # The saved entry belongs to example.test, not to this page's site.
        target_url = url if outcome != 'reused-reference' else 'https://example.test/reset'
        first = broker.dispatch(dict(action='fill-generated', handle=reference, target_url=target_url,
                                     target=pin['target'], target_protocol=1))
        assert not first['ok'], first
        if outcome == 'reused-reference':
            # The origin matched the entry but not the pinned page, and the
            # reference was consumed by that one attempt.
            again = broker.dispatch(dict(action='fill-generated', handle=reference, target_url=target_url,
                                         target=pin['target'], target_protocol=1))
            assert not again['ok'] and 'unknown or expired' in again['error']
        assert lab.untouched()
        assert not broker.dispatch(dict(action='commit-password', write_handle=staged['write_handle'],
                                        site_accepted=True))['ok']
        assert synthetic_vault.read_bytes() == before
    finally:
        broker.passwords.close()


def test_card_save_through_private_page_then_dom_fill(lab, synthetic_vault, native_https_config):
    origin, certificate, key, submit = native_https_config
    broker = Broker(None, NoKeys(), card_browser_profile=lab.profile)
    server, unlock_url = start_windows_unlock_server(broker, synthetic_vault, None, origin, certificate, key)
    url = lab.navigate('/card')
    try:
        assert submit(unlock_url, {'password': 'synthetic master'})[0] == 200
        status = broker.dispatch({'action': 'ping'})
        assert status['cards_supported'] and status['card_delivery'] == CARD_DELIVERY and status['card_browser_configured']
        staged = broker.dispatch(dict(action='create-card', card_protocol=1, metadata=dict(title='Synthetic Visa', group='')))
        assert staged['ok'] and staged['state'] == 'pending', staged
        # The agent resumes on the private save result; the callback has no card data.
        delivered = []
        broker.card_save_notifications._sender = lambda url, payload: delivered.append((url, payload))
        waiting = broker.dispatch({'action': 'subscribe-card-save', 'write_handle': staged['write_handle'],
                                   'notification_protocol': 1, 'webhook_url': 'https://hooks.example.test/synthetic-token'})
        assert waiting['ok'] and waiting['state'] == 'subscribed' and waiting['expires_in'] is None, waiting
        assert submit(staged['private_url'], dict(CARD, confirmed='yes'))[0] == 200
        assert broker.dispatch(dict(action='write-status', write_handle=staged['write_handle']))['state'] == 'saved'
        deadline = time.monotonic() + 5
        while not delivered and time.monotonic() < deadline:
            time.sleep(.02)
        assert [(url, payload['event'], payload['state']) for url, payload in delivered] == [
            ('https://hooks.example.test/synthetic-token', 'akdbx.card-save', 'saved')]
        # A fixed shape with random identifiers only: no card or entry data.
        assert set(delivered[0][1]) == {'event', 'state', 'subscription_id', 'event_id'}
        assert CARD['number'] not in json.dumps(delivered) and CARD['name'] not in json.dumps(delivered)
        persisted = PyKeePass(str(synthetic_vault), password='synthetic master')
        saved = next(entry for entry in persisted.entries if entry.title == 'Synthetic Visa')
        assert saved.get_custom_property(FIELDS['number']) == CARD['number']
        assert all(saved._element.find('./String[Key="' + name + '"]/Value').get('Protected') == 'True'
                   for name in FIELDS.values())
        found = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries']
        assert [(item['title'], item['brand'], item['last_four']) for item in found] == [('Synthetic Visa', 'visa', '1111')]
        # Only the long values can be compared: a random handle can hold a short digit run.
        assert CARD['number'] not in json.dumps([found, staged]) and CARD['name'] not in json.dumps([found, staged])
        assert set(staged) == {'ok', 'state', 'write_handle', 'private_url', 'expires_in', 'expires_at'}

        def card_pin(selector, field):
            return dict(action='pin-card-target', card_protocol=1, page_id=lab.page_id, frame_id=lab.main_frame,
                        top_url=url, frame_url=url, selector=selector, field=field)

        def card_fill(handle, pin, field, **extra):
            return broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=pin['target'],
                                        field=field, start_deadline=broker.clock() + 3, **extra))
        for selector, field, extra, expected in (('#number', 'cc-number', {}, CARD['number']),
                                                 ('#name', 'cc-name', {}, CARD['name']),
                                                 ('#expiry', 'cc-exp', {'format': 'MM/YY'}, '09/31'),
                                                 ('#csc', 'cc-csc', {}, CARD['csc'])):
            handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
            pin = broker.dispatch(card_pin(selector, field))
            assert pin == dict(ok=True, target=pin.get('target'), expires_in=30, field=field, card_delivery=CARD_DELIVERY), pin
            assert card_fill(handle, pin, field, **extra) == dict(ok=True, filled=field, card_delivery=CARD_DELIVERY)
            assert lab.digest(selector[1:]) == sha(expected)
        assert lab.digest('address') == EMPTY and lab.digest('password') == EMPTY
        # A non-card field, a password field and a login fill all refuse.
        for selector in ('#address', '#password'):
            assert broker.dispatch(card_pin(selector, 'cc-number')) == card_failure()
        handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
        focus(lab, 'password')
        assert not broker.dispatch(dict(action='fill', handle=handle, mode='password',
                                        target='0' * 64, target_protocol=1))['ok']
        assert lab.digest('password') == EMPTY
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()
        broker.card_save_notifications.close()


def test_installed_cli_creates_an_account_then_signs_in(lab, synthetic_vault, native_https_config, tmp_path):
    """The exact commands an agent runs, through the real broker process and pipe."""
    origin, certificate, key, submit = native_https_config
    pipe = rpc.PREFIX + 'akdbx-test-' + uuid.uuid4().hex
    command = [sys.executable, '-m', 'akdbx.cli', '--socket', pipe, '--unlock-origin', origin]
    transcript = []
    log = (tmp_path / 'broker.log').open('wb')

    def run(*arguments, expect=0):
        result = subprocess.run([*command, *arguments], capture_output=True, text=True, timeout=30)
        transcript.append(result.stdout + result.stderr)
        assert result.returncode == expect, (arguments[0], result.returncode, result.stdout, result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else {}

    with subprocess.Popen([*command, 'serve', str(synthetic_vault), '--tls-cert', str(certificate), '--tls-key', str(key),
                           '--password-browser-profile', str(lab.profile),
                           '--notification-state', str(synthetic_vault.parent / 'unlock-notifications.json')],
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log) as server:
        try:
            deadline = time.monotonic() + 15
            while subprocess.run([*command, 'status'], capture_output=True, timeout=10).returncode != 0:
                assert server.poll() is None, 'Windows CLI broker exited during startup'
                assert time.monotonic() < deadline, 'Windows CLI broker did not become ready'
                time.sleep(.05)
            locked = run('status')
            assert locked['locked'] and locked['password_fill_delivery'] == DELIVERY
            assert locked['password_browser_configured'] is True and locked['password_fill_protocol'] == 1
            assert locked['generated_entry_protocol'] == 1 and locked['target_fill_delivery'] == 'win32-char-v1'
            # A locked vault generates nothing and returns the private link.
            url = lab.navigate('/signup')
            create = ['generate-entry', '--title', 'Synthetic signup', '--username', USERNAME, '--url', url, '--group', '']
            assert run(*create, expect=1)['error'] == 'vault locked'
            assert submit(locked['unlock_url'], {'password': 'synthetic master'})[0] == 200
            assert run('status')['writes_available'] is True

            staged = run(*create)
            listing = run('list-password-frames', '--top-url', url)
            assert listing['page_id'] == lab.page_id and listing['main_frame_id'] == lab.main_frame
            pin_arguments = ['pin-password-target', '--page-id', listing['page_id'], '--frame-id',
                             listing['main_frame_id'], '--top-url', url]
            for reference, field in (('password', 'new-password'), ('confirmation', 'confirmation')):
                focus(lab, field)
                pin = run(*pin_arguments, '--selector', '#' + field, '--mode', 'password')
                assert run('fill-generated', staged['fill_handles'][reference], '--target-url', url,
                           '--target', pin['target']) == dict(ok=True, filled='password', target_delivery=DELIVERY)
            generated = lab.digest('new-password')
            assert generated == lab.digest('confirmation') and generated != EMPTY
            assert run('commit-password', '--site-accepted', '--', staged['write_handle']) == dict(ok=True, state='saved')
            assert run('write-status', staged['write_handle'])['state'] == 'saved'

            # Sign in with the saved entry.
            url = lab.navigate('/login')
            listing = run('list-password-frames', '--top-url', url)
            pin_arguments = ['pin-password-target', '--page-id', listing['page_id'], '--frame-id',
                             listing['main_frame_id'], '--top-url', url]
            focus(lab, 'username')
            found = run('search', 'signup.example.com')['entries']
            assert [item['username'] for item in found] == [USERNAME]
            pin = run(*pin_arguments, '--selector', '#password', '--mode', 'login', '--username-selector', '#username')
            assert run('fill', found[0]['handle'], '--mode', 'login', '--target', pin['target']) == dict(
                ok=True, filled='login', target_delivery=DELIVERY)
            assert lab.digest('password') == generated and lab.digest('username') == sha(USERNAME)

            # Refusal paths: a used pin, a used handle, a wrong page and a wrong mode.
            lab.evaluate("document.getElementById('password').value = ''; document.getElementById('username').value = ''")
            focus(lab, 'password')
            fresh = run('search', 'signup.example.com')['entries'][0]['handle']
            assert run('fill', fresh, '--mode', 'password', '--target', pin['target'], expect=1)['delivery'] == 'not-started'
            assert run(*pin_arguments[:-1], url + '-other', '--selector', '#password', expect=1)['delivery'] == 'not-started'
            username_pin = run(*pin_arguments, '--selector', '#password', '--mode', 'password')
            fresh = run('search', 'signup.example.com')['entries'][0]['handle']
            assert run('fill', fresh, '--mode', 'login', '--target', username_pin['target'], expect=1)['delivery'] == 'not-started'
            assert lab.untouched()
        finally:
            server.terminate()
            server.wait(timeout=10)
            log.close()
    saved = next(entry for entry in PyKeePass(str(synthetic_vault), password='synthetic master').entries
                 if entry.title == 'Synthetic signup')
    assert sha(saved.password) == generated
    output = '\n'.join(transcript) + (tmp_path / 'broker.log').read_text(errors='replace')
    for secret in (saved.password, 'synthetic master', 'synthetic password'):
        assert secret not in output
    print(json.dumps(dict(browser=lab.version, cli_generate_fill_commit=True, cli_login_fill=True,
                          refusals=4, secrets_in_output=0)))


def test_autocomplete_off_requires_explicit_pin(lab):
    url = lab.evaluate('location.href')
    broker = broker_for(lab)
    lab.evaluate("document.getElementById('password').autocomplete='off'")
    focus(lab, 'password')
    request = pin_request(lab, url, password_purpose='current-password')
    try:
        assert broker.dispatch(request) == failure()
        pin = broker.dispatch({**request, 'allow_autocomplete_off': True})
        assert pin['ok'] and fill(broker, pin)['ok']
        assert lab.digest('password') == sha(PASSWORD) and lab.digest('username') == EMPTY
    finally:
        broker.passwords.close()


def test_identity_notifies_page_only_on_request(lab):
    from test_extension_browser import IdentityEntry, identity_fill
    broker = Broker(Vault([IdentityEntry(title='Synthetic phone')]), NoKeys(), password_browser_profile=lab.profile)
    url = lab.evaluate('location.href')
    lab.evaluate("""document.body.innerHTML='<input id="mail" type="email" autocomplete="email">';
                    window.notified=[];
                    for(const type of ['input','change']) mail.addEventListener(type,e=>notified.push(e.type));
                    mail.focus()""")
    try:
        for options, events in [({}, ''), ({'notify_page': True}, 'input,change')]:
            lab.evaluate("mail.value='';mail.focus()")
            pin = broker.dispatch(dict(action='pin-identity-target', identity_protocol=1, page_id=lab.page_id,
                                       frame_id=lab.main_frame, top_url=url, frame_url=url, field='email',
                                       selector='#mail'))
            assert pin['ok'], pin
            assert identity_fill(broker, pin['target'], field='email', **options)['ok']
            assert lab.digest('mail') == sha('synthetic-only@example.test')
            assert lab.evaluate("notified.join(',')") == events
    finally:
        broker.identity_targets.close()


def test_read_capture_saves_protected_field_and_pending_totp(lab, synthetic_vault, native_https_config):
    from totp_vectors import KEY
    origin, certificate, key, submit = native_https_config
    import io
    from akdbx import windows_security as security
    url = lab.evaluate('location.href')
    login = dict(title='Windows OTP', username='test', url=url, group='')
    vault = PyKeePass(str(synthetic_vault), password='synthetic master')
    vault.add_entry(vault.root_group, login['title'], login['username'], 'synthetic-password', url=url)
    buffer = io.BytesIO()
    vault.save(buffer)
    security.replace_private(synthetic_vault, buffer.getvalue())
    broker = Broker(None, NoKeys(), password_browser_profile=lab.profile)
    server, unlock_url = start_windows_unlock_server(broker, synthetic_vault, None, origin, certificate, key)
    values = dict(title='Windows capture', username='synthetic-user', url=url, group='')
    try:
        assert submit(unlock_url, {'password': 'synthetic master'})[0] == 200
        lab.evaluate("""document.body.innerHTML='<code id="shown" tabindex="0"></code>';shown.focus()""")

        def read(value):
            lab.evaluate('shown.textContent=' + json.dumps(value))
            focus(lab, 'shown')
            pin = broker.dispatch(pin_request(lab, url, '#shown', 'read', capture_protocol=1))
            assert pin['ok'], pin
            return pin['target']

        result = broker.dispatch(dict(action='capture-secret', capture_protocol=1, target=read('synthetic-token'),
                                      create=True, field='client_secret', metadata=values))
        assert result['ok'] and 'synthetic-token' not in json.dumps(result)
        entry = PyKeePass(str(synthetic_vault), password='synthetic master').find_entries(title=values['title'], first=True)
        assert entry.get_custom_property('client_secret') == 'synthetic-token'
        assert entry.is_custom_property_protected('client_secret')

        selected = broker.dispatch(dict(action='search', query=login['title']))['entries'][0]
        result = broker.dispatch(dict(action='capture-totp', totp_capture_protocol=1, target=read(KEY),
                                      handle=selected['handle'], metadata=login))
        assert result['state'] == 'pending' and KEY not in json.dumps(result)
        selected = broker.dispatch(dict(action='search', query=login['title']))['entries'][0]
        result = broker.dispatch(dict(action='commit-totp', totp_capture_protocol=1, handle=selected['handle'],
                                      metadata=login, decision='site-accepted'))
        assert result['state'] == 'saved'
        stored = PyKeePass(str(synthetic_vault), password='synthetic master').find_entries(title=login['title'], first=True)
        assert KEY in stored.otp
    finally:
        broker.passwords.close()
        server.shutdown()
        server.server_close()
