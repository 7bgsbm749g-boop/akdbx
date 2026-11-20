"""The extension route in a real browser on native Windows; synthetic values only.

A disposable headless profile loads the built extension. A uniquely named test
host is registered under the browser's own native-messaging registry key for
the duration of the test, then removed: for Helium that is Chromium's key, so
the test also proves where Helium looks. The broker runs on a test pipe with a
synthetic vault. Values reach pages only through the extension route; the
pages report SHA-256 digests, so no test reads back a field value. The test
observer uses the disposable profile's debugging port only to prepare pages.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid

import pytest

if sys.platform != 'win32':
    pytest.skip('native Windows APIs required', allow_module_level=True)

from akdbx import extension_host, extension_route as route
from akdbx.broker import Broker, serve
from akdbx.browser_card import failure as card_failure
from akdbx.target import failure
from test_broker import Entry, Vault
from test_windows_chromium import CardEntry, NoKeys, CARD
from test_windows_native import private_dir  # noqa: F401
from test_windows_unlock import certificates  # noqa: F401
from windows_chromium_lab import ORIGIN, chromium_lab

USERNAME = 'Synthetic.User+42@example.test'
PASSWORD = 'Synthetic-ONLY!$`\\Aa19 Ω'
EMPTY = hashlib.sha256(b'').hexdigest()
STRIPE_PATH = '/v3/elements-inner-accessory-target-' + 'b' * 32 + '.html'
STRIPE = 'https://js.stripe.com' + STRIPE_PATH
DIGEST = '''<script>
window.syntheticEvents = [];
document.addEventListener('input', e => syntheticEvents.push({field: e.target.id, trusted: e.isTrusted}));
async function digest(id) {
  const data = new TextEncoder().encode(document.getElementById(id).value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}
</script>'''
PAGES = {
    '/masked': '''<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number">
<input id="csc" type="password" autocomplete="cc-csc"></form>''' + DIGEST,
    '/hidden': '''<!doctype html><meta charset="utf-8"><form><input id="username" autocomplete="username">
<input id="password" type="password" autocomplete="current-password" style="opacity:0"></form>''' + DIGEST,
    '/checkout': f'''<!doctype html><meta charset="utf-8"><h1>Merchant</h1>
<iframe id="stripe" src="{STRIPE}" style="width:400px;height:200px;border:0"></iframe>
<iframe id="fake" src="https://evil.example.net{STRIPE_PATH}" style="width:400px;height:200px;border:0"></iframe>''',
    STRIPE_PATH: '''<!doctype html><meta charset="utf-8"><style>input{display:block;width:200px;height:24px}</style>
<input id="payment-numberInput" name="number" autocomplete="cc-number">
<input id="payment-expiryInput" name="expiry" autocomplete="cc-exp">''' + DIGEST,
}


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def extension_browser():
    """The browser to test: AKDBX_TEST_EXTENSION_BROWSER, else Helium, Edge or Chrome.

    Google Chrome 137 and later ignore --load-extension, so a disposable Chrome
    profile cannot load the unpacked extension; Helium and Edge still can.
    """
    override = os.environ.get('AKDBX_TEST_EXTENSION_BROWSER')
    if override:
        return Path(override)
    local, programs = os.environ.get('LOCALAPPDATA', ''), os.environ.get('ProgramFiles', '')
    for candidate in (Path(local) / r'imput\Helium\Application\chrome.exe',
                      Path(os.environ.get('ProgramFiles(x86)', '')) / r'Microsoft\Edge\Application\msedge.exe',
                      Path(programs) / r'Google\Chrome\Application\chrome.exe'):
        if candidate.is_file():
            return candidate
    return None


def browser_kind(binary):
    text = str(binary).lower()
    return 'helium' if 'helium' in text else 'edge' if 'msedge' in text else 'chrome'


class Harness:
    def __init__(self, lab, broker, kind):
        self.lab, self.broker, self.kind = lab, broker, kind

    @property
    def hub(self):
        return self.broker.extension

    def frames(self, url):
        return self.broker.dispatch(dict(action='list-password-frames', password_protocol=1, frame_protocol=1,
                                         top_url=url, route='extension'))

    def focus(self, field):
        self.lab.evaluate(f'document.getElementById({json.dumps(field)}).focus()')
        self.lab.wait(f'document.activeElement.id === {json.dumps(field)}')

    def service_worker(self):
        observer = self.lab.observer
        targets = observer.call('Target.getTargets')['targetInfos']
        worker = next(t for t in targets if t['type'] == 'service_worker'
                      and t['url'].startswith(route.EXTENSION_ORIGIN))
        return observer.call('Target.attachToTarget', dict(targetId=worker['targetId'], flatten=True))['sessionId']

    def worker_call(self, expression):
        session = self.service_worker()
        return self.lab.observer.evaluate(expression, session, await_promise=True)

    def frame_session(self, url):
        observer = self.lab.observer
        for _ in range(100):
            frames = [t for t in observer.call('Target.getTargets')['targetInfos'] if t['type'] == 'iframe' and t['url'] == url]
            if frames:
                return observer.call('Target.attachToTarget', dict(targetId=frames[0]['targetId'], flatten=True))['sessionId']
            time.sleep(.05)
        raise AssertionError('processor frame target missing')


@pytest.fixture
def harness(private_dir, certificates, monkeypatch):
    binary = extension_browser()
    if binary is None:
        if os.environ.get('AKDBX_REQUIRE_EXTENSION_BROWSER') == '1':
            pytest.fail('the extension route tests require Helium, Chrome or Edge')
        pytest.skip('the extension route tests require Helium, Chrome or Edge')
    import winreg
    kind = browser_kind(binary)
    suffix = uuid.uuid4().hex[:10]
    host_name = 'org.akdbx.test_' + suffix
    pipe = Path(r'\\.\pipe\akdbx-test-extension-' + suffix)
    extension = extension_host.build(Path(private_dir) / 'extension', host_name=host_name)
    launcher = Path(private_dir) / 'host.cmd'
    launcher.write_text(extension_host._launcher_text(kind, sys.executable, str(pipe)), encoding='utf-8', newline='')
    manifest = Path(private_dir) / (host_name + '.json')
    manifest.write_text(json.dumps(extension_host._manifest(launcher, host_name)), encoding='utf-8')
    key = extension_host.WINDOWS_KEYS[kind] + '\\' + host_name
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
        winreg.SetValueEx(handle, '', 0, winreg.REG_SZ, str(manifest))
    entries = [Entry(username=USERNAME, password=PASSWORD, url=ORIGIN + '/login'), CardEntry(title='Synthetic card'),
               Entry(title='Other', username='other@example.test', password=PASSWORD, url='https://other.example.org/')]
    broker = Broker(Vault(entries), NoKeys())
    stop = threading.Event()
    server = threading.Thread(target=serve, args=(pipe, broker, stop), daemon=True)
    server.start()
    try:
        with chromium_lab(private_dir, *certificates, pages=PAGES, binary=binary, extension=extension,
                          hosts=('js.stripe.com',)) as lab:
            deadline = time.monotonic() + 60
            while not broker.extension.channels:
                assert time.monotonic() < deadline, 'the extension host did not attach to the broker'
                time.sleep(.1)
            [channel] = broker.extension.channels.values()
            assert channel.browser == kind
            # The popup shows a code computed from its own key; it must equal
            # the code the broker's pairing page shows for the key it received.
            workers = [t for t in lab.observer.call('Target.getTargets')['targetInfos']
                       if t['type'] == 'service_worker' and t['url'].startswith(route.EXTENSION_ORIGIN)]
            worker = lab.observer.call('Target.attachToTarget', dict(targetId=workers[0]['targetId'], flatten=True))
            state = lab.observer.evaluate('popupState()', worker['sessionId'], await_promise=True)
            assert state['paired'] is False and state['code'] == route.pairing_code(channel.digest)
            # Pair through the hub; the private page itself has its own tests.
            token = next(t for t, (digest, _) in broker.extension.pairings.items() if digest == channel.digest)
            assert broker.extension.approve(token)
            # Reload so the declared content script runs in the test page.
            lab.navigate('/login')
            yield Harness(lab, broker, kind)
    finally:
        stop.set()
        server.join(5)
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
        except OSError:
            pass


def search(broker):
    return broker.dispatch(dict(action='search', query='signup.example.com'))['entries'][0]['handle']


def test_agent_route_fills_the_pinned_password_through_the_extension(harness):
    lab, broker = harness.lab, harness.broker
    url = lab.evaluate('location.href')
    listing = harness.frames(url)
    assert listing['ok'] and listing['route'] == 'extension', listing
    harness.focus('password')
    pin = broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                               frame_id=listing['main_frame_id'], top_url=url, selector='#password', mode='password',
                               route='extension'))
    assert pin['ok'] and pin['target_delivery'] == route.DELIVERY, pin
    receipt = broker.dispatch(dict(action='fill', handle=search(broker), mode='password', target=pin['target'],
                                   target_protocol=1))
    assert receipt == dict(ok=True, filled='password', target_delivery=route.DELIVERY)
    assert lab.digest('password') == sha(PASSWORD) and lab.digest('username') == EMPTY
    assert not any(e['trusted'] for e in lab.evaluate('syntheticEvents'))
    # Login mode fills both retained fields without Tab or focus changes.
    harness.focus('username')
    pin = broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                               frame_id=listing['main_frame_id'], top_url=url, selector='#password', mode='login',
                               username_selector='#username', route='extension'))
    assert broker.dispatch(dict(action='fill', handle=search(broker), mode='login', target=pin['target'],
                                target_protocol=1))['ok']
    assert lab.digest('username') == sha(USERNAME) and lab.evaluate('document.activeElement.id') == 'username'
    print(json.dumps(dict(browser=lab.version, kind=harness.kind, route='extension', exact_values=True)))


def test_agent_route_refuses_wrong_origin_wrong_frame_and_hidden_fields(harness):
    lab, broker = harness.lab, harness.broker
    # Wrong origin: a credential of another site never fills this page.
    url = lab.navigate('/signup')
    listing = harness.frames(url)
    harness.focus('password')
    pin = broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                               frame_id=listing['main_frame_id'], top_url=url, selector='#password', mode='password',
                               route='extension'))
    assert pin['ok'], pin
    other = broker.dispatch(dict(action='search', query='other.example.org'))['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill', handle=other, mode='password', target=pin['target'],
                                target_protocol=1)) == failure()
    assert lab.untouched()
    # Wrong frame: a login frame of another site inside this page.
    url = lab.navigate('/hostile')
    listing = harness.frames(url)
    child = next(f for f in listing['frames'] if f['depth'] == 1)
    assert child['origin'] == 'https://evil.example.net' and child['eligible'] is False
    assert broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                frame_id=child['frame_id'], top_url=url, selector='#password', mode='password',
                                frame_protocol=1, frame_origin='https://evil.example.net', route='extension')) == failure()
    # Hidden field: a transparent password input is never pinned.
    url = lab.navigate('/hidden')
    listing = harness.frames(url)
    harness.focus('password')
    assert broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                frame_id=listing['main_frame_id'], top_url=url, selector='#password', mode='password',
                                route='extension')) == failure()
    assert lab.digest('password') == EMPTY


def test_cards_go_only_to_the_supported_processor_frame_below_the_merchant(harness):
    lab, broker = harness.lab, harness.broker
    url = lab.navigate('/checkout')
    lab.wait("document.readyState === 'complete'")
    session = harness.frame_session(STRIPE)
    lab.observer.evaluate("document.getElementById('payment-numberInput').focus()", session)
    frames = harness.frames(url)
    by_origin = {f['origin']: f for f in frames['frames']}
    stripe = by_origin['https://js.stripe.com']
    fake = by_origin['https://evil.example.net']

    def pin(frame, **extra):
        return broker.dispatch(dict(action='pin-card-target', card_protocol=1, page_id=frames['page_id'],
                                    frame_id=frame['frame_id'], top_url=url, selector='#payment-numberInput',
                                    field='cc-number', route='extension', **extra))
    stripe_route = dict(processor='stripe', processor_protocol=1)
    assert pin(fake, **stripe_route) == card_failure()   # Same markup, wrong host.
    assert pin(stripe) == card_failure()                 # Cross-origin without the processor route.
    target = pin(stripe, **stripe_route)
    assert target['ok'] and target['card_delivery'] == route.DELIVERY, target
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    receipt = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                   field='cc-number'))
    assert receipt == dict(ok=True, filled='cc-number', card_delivery=route.DELIVERY)
    assert lab.observer.evaluate("digest('payment-numberInput')", session, await_promise=True) == sha(CARD['number'])


def test_user_click_route_fills_the_focused_login_and_skips_hidden_fields(harness):
    lab, broker = harness.lab, harness.broker
    lab.navigate('/login')
    harness.focus('username')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'] and found['kind'] == 'login', found
    assert [set(e) for e in found['entries']] == [{'index', 'title', 'username'}]
    assert PASSWORD not in json.dumps(found)
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result == {'ok': True}
    assert lab.digest('username') == sha(USERNAME) and lab.digest('password') == sha(PASSWORD)
    # A reused selection fills nothing.
    again = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert again['ok'] is False
    # Hidden focused field: no match is offered and nothing is filled.
    lab.navigate('/hidden')
    harness.focus('password')
    hidden = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert hidden['ok'] is False and lab.digest('password') == EMPTY


def test_user_click_route_reports_a_locked_broker(harness):
    lab, broker = harness.lab, harness.broker
    vault, broker.vault = broker.vault, None
    try:
        lab.navigate('/login')
        harness.focus('password')
        state = harness.worker_call('popupState()')
        assert state['connected'] and state['paired'] and state['locked'] is True
        tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
        found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
        assert found['ok'] is False and found['error'] == 'vault locked'
    finally:
        broker.vault = vault


def test_user_click_route_fills_a_masked_security_code_as_a_card(harness):
    lab = harness.lab
    lab.navigate('/masked')
    harness.focus('csc')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'] and found['kind'] == 'card', found
    assert set(found['entries'][0]) == {'index', 'title', 'brand', 'last_four'}
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result == {'ok': True}
    assert lab.digest('csc') == sha(CARD['csc']) and lab.digest('number') == sha(CARD['number'])


def test_user_click_route_refuses_a_field_changed_after_the_probe(harness):
    lab = harness.lab
    lab.navigate('/login')
    harness.focus('username')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'], found
    lab.evaluate("document.getElementById('password').type = 'text'")
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result['ok'] is False
    assert lab.digest('username') == EMPTY and lab.digest('password') == EMPTY
