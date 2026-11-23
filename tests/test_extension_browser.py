"""The extension route in a real browser on native Windows or Linux; synthetic values only.

A disposable headless profile loads the built extension. A uniquely named test
host is registered for the duration of the test, then removed: on Windows under
the browser's own native-messaging registry key (for Helium that is Chromium's
key, so the test also proves where Helium looks), on Linux in the profile's
NativeMessagingHosts folder. The broker runs on a test pipe or Unix socket with
a synthetic vault. Values reach pages only through the extension route; the
pages report SHA-256 digests, so no test reads back a field value. The test
observer uses the disposable profile's debugging port only to prepare pages.

On Linux, set AKDBX_TEST_EXTENSION_BROWSER to a Chromium that still loads an
unpacked extension (Chromium or Chrome for Testing; Google Chrome 137+ does
not), and AKDBX_TEST_BROWSER_NO_SANDBOX=1 on a host without user namespaces.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import uuid

import pytest

if sys.platform != 'win32' and not sys.platform.startswith('linux'):
    pytest.skip('native Windows or Linux required', allow_module_level=True)

from akdbx import broker_identity, extension_host, extension_route as route
from akdbx.broker import Broker, serve
from akdbx.local_https import start_local_unlock_server
from akdbx.browser_card import failure as card_failure
from akdbx.cards import FIELDS, MARKER
from akdbx.target import failure
from test_broker import Entry, Vault
from test_windows_unlock import certificates  # noqa: F401
from windows_chromium_lab import FORM, ORIGIN, chromium_lab

CARD = dict(name='Synthetic Cardholder', number='4111111111111111', month='09', year='2031', csc='123')


class NoKeys:
    """A window backend that fails the test if any keyboard delivery starts."""

    def capture(self, pid, window):
        return ('synthetic-window', pid, window)

    def deliver(self, *args, **kwargs):
        pytest.fail('a DOM-only credential reached the keyboard backend')


class CardEntry(Entry):
    def get_custom_property(self, key):
        return {MARKER: 'v1', **{field: CARD[k] for k, field in FIELDS.items()}}.get(key)


if sys.platform == 'win32':
    from test_windows_native import private_dir  # noqa: F401
else:
    @pytest.fixture
    def private_dir(tmp_path):
        path = tmp_path / 'private'
        path.mkdir(mode=0o700)
        return path

USERNAME = 'Synthetic.User+42@example.test'
PASSWORD = 'Synthetic-ONLY!$`\\Aa19 Ω'
EMPTY = hashlib.sha256(b'').hexdigest()
STRIPE_PATH = '/v3/elements-inner-accessory-target-' + 'b' * 32 + '.html'
STRIPE = 'https://js.stripe.com' + STRIPE_PATH
CARD_ELEMENT_PATH = '/v3/elements-inner-card-' + 'd' * 32 + '.html'
CARD_ELEMENT = 'https://js.stripe.com' + CARD_ELEMENT_PATH + '#__shared_params__[version]=v3&componentName=card'
DIGEST = '''<script>
window.syntheticEvents = [];
document.addEventListener('input', e => syntheticEvents.push({field: e.target.id, trusted: e.isTrusted}));
async function digest(id) {
  const data = new TextEncoder().encode(document.getElementById(id).value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}
</script>'''
SECRET = 'SynthCapture-0123456789abcdefOnly'
SECRET_STYLE = '<style>body{margin:0}code,input{display:block;margin:4px;font:16px monospace}</style>'
COVER = 'position:fixed;left:0;top:0;width:900px;height:300px;background:#fff;pointer-events:none'
LOGIN_FRAME = ('<!doctype html><meta charset="utf-8"><h1>Outer page</h1>'
               '<iframe id="login-frame" src="https://auth.example.com/login" style="width:600px;height:300px;border:0;{}">'
               '</iframe><iframe id="decoy" src="https://auth.example.com/decoy" style="width:200px;height:100px;border:0">'
               '</iframe>')
PAGES = {
    '/secret': f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<p>Copy it now.</p><code id="secret" tabindex="0">{SECRET}</code>',
    # A click-through cover: elementFromPoint ignores it, CDP's hit test does not.
    '/secret-covered': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                        f'<div style="{COVER}"></div>'),
    '/secret-covered-important': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}'
                                  f'<code id="secret" tabindex="0">{SECRET}</code>'
                                  f'<div style="{COVER} !important"></div>'),
    # The same cover inside a closed shadow root: the user style sheet does not reach it.
    '/secret-shadow-cover': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                             '<div id="host"></div><script>host.attachShadow({mode: "closed"}).innerHTML = '
                             f'`<div style="{COVER}"></div>`;</script>'),
    '/secret-shadow-important': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                                 '<div id="host"></div><script>host.attachShadow({mode: "closed"}).innerHTML = '
                                 f'`<div style="{COVER} !important"></div>`;</script>'),
    '/card-covered': ('<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number" '
                      f'style="width:200px;height:30px"></form><div style="{COVER}"></div>' + DIGEST),
    # A floating label above, not over, the field centre: benign, both routes fill it.
    '/card-label': ('<!doctype html><meta charset="utf-8"><form><div style="position:relative">'
                    '<input id="number" autocomplete="cc-number" style="width:220px;height:44px">'
                    '<label for="number" style="position:absolute;left:8px;top:2px;font-size:10px;pointer-events:none">'
                    'Card number</label></div></form>' + DIGEST),
    '/framed-visible': LOGIN_FRAME.format(''),
    '/framed-hidden': LOGIN_FRAME.format('opacity:0'),
    '/decoy': '<!doctype html><meta charset="utf-8"><p>decoy</p>',
    # Covers that elementFromPoint skips even with pointer-events on: the inert attribute, CSS
    # interactivity, and a pseudo-element in a closed shadow root with a more specific !important rule.
    '/secret-inert': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                      f'<div inert style="{COVER.replace(";pointer-events:none", "")}"></div>'),
    '/secret-interactivity': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                              f'<div style="{COVER.replace("pointer-events:none", "interactivity:inert !important")}"></div>'),
    '/secret-shadow-pseudo': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                              '<div id="host"></div><script>host.attachShadow({mode: "closed"}).innerHTML = '
                              '`<style>#c::before{content:"";position:fixed;left:0;top:0;width:900px;height:300px;'
                              'background:#fff;pointer-events:none !important}</style><div id="c"></div>`;</script>'),
    '/card-inert': ('<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number" '
                    f'style="width:200px;height:30px"></form><div inert style="{COVER.replace(";pointer-events:none", "")}"></div>'
                    + DIGEST),
    # A secret in a same-site child frame, with and without a cover over the frame in the top page.
    '/framed-secret': ('<!doctype html><meta charset="utf-8"><iframe id="keys" src="https://auth.example.com/secret" '
                       'style="width:700px;height:200px;border:0"></iframe>'),
    '/framed-secret-covered': ('<!doctype html><meta charset="utf-8"><iframe id="keys" src="https://auth.example.com/secret" '
                               'style="width:700px;height:200px;border:0"></iframe>'
                               '<div style="position:absolute;left:0;top:0;width:700px;height:200px;background:#fff"></div>'),
    # An attacker with pages on the login origin: the login page stops the first (genuine) owner
    # probe, and a visible decoy on the same origin relays its own probe through the top page.
    '/login-suppress': FORM + '''<script>let first = true;
addEventListener('message', event => {
  if (event.data && event.data.akdbx_owner && first) {
    first = false;
    event.stopImmediatePropagation();
  }
}, true);</script>''',
    '/decoy-relay': '''<!doctype html><meta charset="utf-8"><p>decoy</p><script>
addEventListener('message', event => {
  if (event.data && event.data.akdbx_owner) parent.postMessage({relay: event.data.akdbx_owner}, '*');
}, true);</script>''',
    '/framed-suppress': '''<!doctype html><meta charset="utf-8"><h1>Outer page</h1>
<iframe id="decoy" src="https://auth.example.com/decoy-relay" style="width:600px;height:300px;border:0"></iframe>
<iframe id="login" src="https://auth.example.com/login-suppress" style="width:600px;height:300px;border:0;opacity:0"></iframe>
<script>
addEventListener('message', event => {
  if (event.data && event.data.relay) login.contentWindow.postMessage({akdbx_owner: event.data.relay}, 'https://auth.example.com');
});
</script>''',
    # A hostile page: the real login frame is transparent inside a closed shadow root, and the page
    # forwards the nonce that its own visible decoy frame receives to the login frame.
    '/framed-forward': '''<!doctype html><meta charset="utf-8"><h1>Outer page</h1>
<iframe id="decoy" src="/decoy" style="width:600px;height:300px;border:0"></iframe><div id="host"></div>
<script>
const root = host.attachShadow({mode: 'closed'});
root.innerHTML = '<iframe src="https://auth.example.com/login" style="width:600px;height:300px;border:0;opacity:0"></iframe>';
const login = root.querySelector('iframe');
decoy.addEventListener('load', () => decoy.contentWindow.addEventListener('message', event => {
  if (event.data && event.data.akdbx_owner) login.contentWindow.postMessage(event.data, 'https://auth.example.com');
}, true));
</script>''',
    '/replacing': '''<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number">
<input id="expiry" autocomplete="cc-exp" maxlength="5"></form>
<script>number.addEventListener('input', () => { const fresh = expiry.cloneNode(); expiry.replaceWith(fresh); });</script>''' + DIGEST,
    '/clearing': '''<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number">
<input id="expiry" autocomplete="cc-exp" maxlength="5"></form>
<script>number.addEventListener('input', () => { expiry.value = ''; });</script>''' + DIGEST,
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
    '/card-element': f'''<!doctype html><meta charset="utf-8"><h1>Merchant</h1>
<iframe name="__privateStripeFrame5551" title="Secure card payment input frame" src="{CARD_ELEMENT}"
 style="width:400px;height:240px;border:0"></iframe>''',
    # Synthetic classic Card Element: no ids, two decoys named "hidden".
    CARD_ELEMENT_PATH: '''<!doctype html><meta charset="utf-8"><style>input{display:block;width:200px;height:24px}</style>
<form><input name="hidden" autocomplete="fake">
<input type="text" name="cardnumber" autocomplete="cc-number" placeholder="Card number">
<input type="text" name="exp-date" autocomplete="cc-exp" placeholder="MM / YY">
<input type="text" name="cvc" autocomplete="cc-csc" placeholder="CVC">
<input name="hidden" autocomplete="fake"></form>
<script>
async function digestName(name, index = 0) {
  const data = new TextEncoder().encode(document.getElementsByName(name)[index].value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}
</script>''',
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
    if sys.platform != 'win32':
        return None
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
    def __init__(self, lab, broker, kind, unlock_origin=None, identity=None):
        self.lab, self.broker, self.kind = lab, broker, kind
        self.unlock_origin, self.identity = unlock_origin, identity

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
    if sys.platform != 'win32':
        certificates[1].chmod(0o600)  # The Linux page refuses a key other users could read.
    binary = extension_browser()
    if binary is None:
        if os.environ.get('AKDBX_REQUIRE_EXTENSION_BROWSER') == '1':
            pytest.fail('the extension route tests require Helium, Chrome or Edge')
        pytest.skip('the extension route tests require Helium, Chrome or Edge')
    kind = browser_kind(binary)
    suffix = uuid.uuid4().hex[:10]
    host_name = 'org.akdbx.test_' + suffix
    pipe = (Path(r'\\.\pipe\akdbx-test-extension-' + suffix) if sys.platform == 'win32'
            else Path(private_dir) / 'run' / 'broker.sock')
    # The broker's own HTTPS page on loopback, as `akdbx serve --tls-cert` runs it: the built origin.
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        unlock_port = probe.getsockname()[1]
    unlock_origin = f'https://localhost:{unlock_port}'
    extension = extension_host.build(Path(private_dir) / 'extension', host_name=host_name, unlock_origin=unlock_origin)
    launcher = Path(private_dir) / ('host.cmd' if sys.platform == 'win32' else 'host.sh')
    launcher.write_text(extension_host._launcher_text(kind, sys.executable, str(pipe)), encoding='utf-8', newline='')
    native_hosts = None
    if sys.platform == 'win32':
        import winreg
        manifest = Path(private_dir) / (host_name + '.json')
        manifest.write_text(json.dumps(extension_host._manifest(launcher, host_name)), encoding='utf-8')
        key = extension_host.WINDOWS_KEYS[kind] + '\\' + host_name
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
            winreg.SetValueEx(handle, '', 0, winreg.REG_SZ, str(manifest))
    else:
        launcher.chmod(0o700)
        native_hosts = {host_name: extension_host._manifest(launcher, host_name)}
    entries = [Entry(username=USERNAME, password=PASSWORD, url=ORIGIN + '/login'), CardEntry(title='Synthetic card'),
               Entry(title='Other', username='other@example.test', password=PASSWORD, url='https://other.example.org/'),
               Entry(title='Auth', username=USERNAME, password=PASSWORD, url='https://auth.example.com/login')]
    broker = Broker(Vault(entries), NoKeys())
    unlock, _ = start_local_unlock_server(broker, Path(private_dir) / 'vault.kdbx', None, unlock_origin, *certificates)
    identity = broker_identity.IdentityStore(Path(private_dir) / 'identity').announce(unlock_origin)
    broker.extension.set_identity(identity)
    stop = threading.Event()
    server = threading.Thread(target=serve, args=(pipe, broker, stop), daemon=True)
    server.start()
    try:
        with chromium_lab(private_dir, *certificates, pages=PAGES, binary=binary, extension=extension,
                          hosts=('js.stripe.com',), native_hosts=native_hosts) as lab:
            deadline = time.monotonic() + 60
            while not broker.extension.channels:
                assert time.monotonic() < deadline, 'the extension host did not attach to the broker'
                time.sleep(.1)
            [channel] = broker.extension.channels.values()
            assert channel.browser == kind
            # The loaded extension reports its own manifest version to the broker.
            assert channel.version == route.EXTENSION_VERSION
            assert broker.dispatch(dict(action='ping'))['extension_browsers'] == [
                dict(browser=kind, paired=False, version=route.EXTENSION_VERSION, version_status='current')]
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
            yield Harness(lab, broker, kind, unlock_origin, identity)
    finally:
        stop.set()
        server.join(5)
        unlock.shutdown()
        unlock.server_close()
        broker.unlock_notifications.close()
        if sys.platform == 'win32':
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            except OSError:
                pass


def test_the_service_worker_binds_the_first_broker_key_from_the_https_identity_page(harness):
    """The MV3 worker itself reads /.well-known/akdbx-identity: CSP connect-src, host permission and the
    page's Origin allowlist all let it through, and the key is stored only after that read verifies."""
    statement = harness.identity.message()['statement']
    read = "chrome.storage.local.get('broker_trust').then(found => found.broker_trust ?? null)"
    deadline = time.monotonic() + 30
    record = harness.worker_call(read)
    while record is None and time.monotonic() < deadline:
        time.sleep(.2)
        record = harness.worker_call(read)
    build = harness.worker_call('globalThis.AKDBX_BUILD_ID')  # The ID that config.js of this build holds.
    assert isinstance(build, str) and len(build) == 22
    assert record == {'v': 1, 'public_key': harness.identity.message()['public_key'], 'key_id': statement['key_id'],
                      'origin': harness.unlock_origin, 'seq': statement['seq'], 'build': build}
    state = harness.worker_call('popupState()')
    assert state['origin'] == harness.unlock_origin and state['trust_error'] is None and state['trust_reset'] is False


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


def test_card_element_fills_its_three_inputs_and_never_a_decoy(harness):
    lab, broker = harness.lab, harness.broker
    url = lab.navigate('/card-element')
    lab.wait("document.readyState === 'complete'")
    session = harness.frame_session(CARD_ELEMENT)
    frames = harness.frames(url)
    frame = {f['origin']: f for f in frames['frames']}['https://js.stripe.com']
    stripe_route = dict(processor='stripe', processor_protocol=1)

    def pin(selector, field):
        return broker.dispatch(dict(action='pin-card-target', card_protocol=1, page_id=frames['page_id'],
                                    frame_id=frame['frame_id'], top_url=url, selector=selector, field=field,
                                    route='extension', **stripe_route))
    assert pin('form > input:first-child', 'cc-number') == card_failure()   # Decoy.
    assert pin('input[name="cardnumber"]', 'cc-exp') == card_failure()      # Wrong field.
    for name, field, options, expected in (('cardnumber', 'cc-number', {}, CARD['number']),
                                           ('exp-date', 'cc-exp', {'format': 'MM/YY'}, '09/31'),
                                           ('cvc', 'cc-csc', {}, CARD['csc'])):
        target = pin(f'input[name="{name}"]', field)
        assert target['ok'] and target['card_delivery'] == route.DELIVERY, target
        handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
        receipt = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                       field=field, **options))
        assert receipt == dict(ok=True, filled=field, card_delivery=route.DELIVERY)
        assert lab.observer.evaluate(f"digestName('{name}')", session, await_promise=True) == sha(expected)
    for index in (0, 1):
        assert lab.observer.evaluate(f"digestName('hidden', {index})", session, await_promise=True) == EMPTY


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


def test_user_click_route_reports_a_page_that_clears_a_filled_field(harness):
    lab = harness.lab
    lab.navigate('/clearing')
    harness.focus('number')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'] and found['kind'] == 'card', found
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result['ok'] is False and 'incomplete' in result['error']


def test_user_click_route_reports_a_page_that_replaces_a_filled_field(harness):
    lab = harness.lab
    lab.navigate('/replacing')
    harness.focus('number')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'] and found['kind'] == 'card', found
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result['ok'] is False and 'incomplete' in result['error']


@pytest.fixture
def pairing_page(harness, certificates):
    """The broker's real Windows loopback HTTPS handler, for a browser form submit."""
    import ssl
    from akdbx.web_unlock import UnlockState, handler_for
    from akdbx.windows_unlock import WindowsHTTPServer
    broker = harness.broker
    state = UnlockState(broker, None, None, lambda *_: pytest.fail('the broker is already unlocked'))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*certificates)
    server = WindowsHTTPServer(('127.0.0.1', 0), handler_for(state), context, '')
    server.local_origin = f'https://127.0.0.1:{server.server_port}'
    server.write_manager = broker.writes
    previous = broker.writes.public_base
    broker.writes.public_base = server.local_origin
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.local_origin
    finally:
        broker.writes.public_base = previous
        server.shutdown()
        server.server_close()
        thread.join(3)


def test_pairing_page_form_submit_pairs_the_extension_in_a_real_browser(harness, pairing_page):
    """Regression: the page's referrer policy made the browser send Origin: null on POST."""
    lab, broker = harness.lab, harness.broker
    master = 'Synthetic master Ω 42'
    broker.vault.password = master
    broker.extension.approved.clear()
    [channel] = broker.extension.channels.values()
    url = broker.extension._pairing_info(channel.digest)['url']
    assert url.startswith(pairing_page + '/extension/pair?token=')
    lab.observer.call('Page.navigate', {'url': url}, lab.session)
    lab.wait("document.readyState === 'complete' && !!document.querySelector('form')")
    assert lab.evaluate('document.body.innerText').count(route.pairing_code(channel.digest)) == 1
    lab.evaluate(f"""document.getElementById('password').value = {json.dumps(master)};
        document.querySelector('input[name=confirmed]').checked = true;
        document.querySelector('form button:not([type=button])').click();""")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if lab.evaluate("document.readyState === 'complete' && !document.querySelector('form')"):
                break
        except AssertionError:
            pass  # The page is navigating.
        time.sleep(.1)
    text = lab.evaluate('document.body.innerText')
    assert 'paired with akdbx' in text, text
    assert broker.extension.approved == [channel.digest]


# ----- secret capture, frame owners and unmasked hit tests (0.32.0) ---------------------
def read_pin(harness, url, **extra):
    listing = harness.frames(url)
    request = dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                   frame_id=listing['main_frame_id'], top_url=url, selector='#secret', mode='read', capture_protocol=1,
                   route='extension')
    request.update(extra)
    return harness.broker.dispatch(request)


def trusted(harness):
    """The worker binds the broker identity key over HTTPS; reads need it for the signed connection."""
    deadline = time.monotonic() + 30
    read = "chrome.storage.local.get('broker_trust').then(found => found.broker_trust ?? null)"
    while harness.worker_call(read) is None:
        assert time.monotonic() < deadline, 'the extension did not bind the broker identity key'
        time.sleep(.2)


def read_value(harness, pin, origin=ORIGIN):
    """Run the broker's own extension read for a pin token; the test compares digests only."""
    from akdbx.totp import https_origin
    trusted(harness)
    broker = harness.broker
    target = broker.extension.take(pin['target'], 'read')
    assert target is not None
    try:
        value = broker.extension.read(target, {https_origin(origin)}, lambda: True, broker.clock() + 4)
    except Exception:
        return None
    finally:
        target.close()
    return sha(value)


def test_secret_capture_reads_the_focused_secret_through_the_extension(harness):
    lab = harness.lab
    url = lab.navigate('/secret')
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert pin['ok'] and pin['target_delivery'] == route.DELIVERY, pin
    assert read_value(harness, pin) == sha(SECRET)
    # A read pin is single-use, and a fill command cannot take it.
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert harness.broker.dispatch(dict(action='fill', handle=search(harness.broker), mode='password',
                                        target=pin['target'], target_protocol=1))['ok'] is False
    assert harness.broker.extension.take(pin['target'], 'read') is None


def test_secret_capture_refuses_unfocused_selected_and_changed_secrets(harness):
    lab = harness.lab
    url = lab.navigate('/secret')
    assert read_pin(harness, url) == failure()  # Not focused.
    harness.focus('secret')
    lab.evaluate("getSelection().selectAllChildren(document.getElementById('secret'))")
    assert read_pin(harness, url) == failure()  # A selection would reach PRIMARY on X11.
    lab.evaluate('getSelection().removeAllRanges()')
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert pin['ok'], pin
    lab.evaluate("document.getElementById('secret').textContent = 'SynthOther-replaced'")
    assert read_value(harness, pin) is None


@pytest.mark.parametrize('page', ['/secret-covered', '/secret-covered-important', '/secret-shadow-cover',
                                  '/secret-shadow-important', '/secret-inert', '/secret-interactivity',
                                  '/secret-shadow-pseudo'])
def test_secret_capture_refuses_a_click_through_cover(harness, page):
    lab = harness.lab
    url = lab.navigate(page)
    harness.focus('secret')
    assert read_pin(harness, url) == failure()
    # The page keeps its own styles: the unmasking ends with the check.
    assert lab.evaluate("[...document.querySelectorAll('div')].every(d => getComputedStyle(d).pointerEvents === 'none' "
                        "|| d.id === 'host' || d.hasAttribute('inert') || getComputedStyle(d).interactivity === 'inert')")
    assert lab.evaluate("[...document.querySelectorAll('div[inert]')].every(d => d.getAttribute('inert') === '')")


def card_pin(harness, url):
    listing = harness.frames(url)
    return harness.broker.dispatch(dict(action='pin-card-target', card_protocol=1, page_id=listing['page_id'],
                                        frame_id=listing['main_frame_id'], top_url=url, selector='#number',
                                        field='cc-number', route='extension'))


def test_card_pins_refuse_a_click_through_cover_and_keep_a_floating_label(harness):
    lab, broker = harness.lab, harness.broker
    assert card_pin(harness, lab.navigate('/card-covered')) == card_failure()
    assert card_pin(harness, lab.navigate('/card-inert')) == card_failure()
    target = card_pin(harness, lab.navigate('/card-label'))
    assert target['ok'], target
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    receipt = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                   field='cc-number'))
    assert receipt == dict(ok=True, filled='cc-number', card_delivery=route.DELIVERY)
    assert lab.digest('number') == sha(CARD['number'])
    # A cover added after the pin refuses the fill.
    target = card_pin(harness, lab.navigate('/card-label'))
    lab.evaluate(f"document.body.insertAdjacentHTML('beforeend', '<div style=\"{COVER}\"></div>')")
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                field='cc-number')) == card_failure()
    assert lab.digest('number') == EMPTY


def same_site_frame(harness, url, ready='password'):
    """An isolated world in the same-site login frame (same process as the top, so no own target)."""
    lab = harness.lab
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        tree = lab.observer.call('Page.getFrameTree', session=lab.session)['frameTree']
        found = [c['frame']['id'] for c in tree.get('childFrames', []) if c['frame']['url'] == url]
        if found:
            world = lab.observer.call('Page.createIsolatedWorld', dict(frameId=found[0], worldName='akdbx-test-observer'),
                                      lab.session)['executionContextId']

            def evaluate(expression, await_promise=False):
                response = lab.observer.call('Runtime.evaluate', dict(expression=expression, contextId=world,
                                                                      returnByValue=True, awaitPromise=await_promise),
                                             lab.session)
                assert 'exceptionDetails' not in response, response['exceptionDetails'].get('text')
                return response['result'].get('value')
            if evaluate(f"document.readyState === 'complete' && (!{json.dumps(ready)} || !!document.getElementById({json.dumps(ready)}))"):
                return evaluate
        time.sleep(.05)
    raise AssertionError('same-site login frame missing')


FRAME_DIGEST = ("crypto.subtle.digest('SHA-256', new TextEncoder().encode(document.getElementById('password').value))"
                ".then(h => Array.from(new Uint8Array(h), b => b.toString(16).padStart(2, '0')).join(''))")


def frame_password_pin(harness, url):
    lab, broker = harness.lab, harness.broker
    lab.wait("document.readyState === 'complete'")
    frame = same_site_frame(harness, 'https://auth.example.com/login')
    frame("window.focus(); document.getElementById('password').focus()")
    listing = harness.frames(url)
    login = next(f for f in listing['frames'] if f['origin'] == 'https://auth.example.com' and f['visible_fields']
                 and f['visible_fields']['password'])
    return frame, broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                         frame_id=login['frame_id'], top_url=url, selector='#password', mode='password',
                                         frame_protocol=1, frame_origin='https://auth.example.com', route='extension'))


def auth_handle(broker):
    return broker.dispatch(dict(action='search', query='auth.example.com'))['entries'][0]['handle']


def test_a_child_frame_login_needs_a_visible_iframe_owner(harness):
    lab, broker = harness.lab, harness.broker
    session, pin = frame_password_pin(harness, lab.navigate('/framed-visible'))
    assert pin['ok'], pin
    receipt = broker.dispatch(dict(action='fill', handle=auth_handle(broker), mode='password', target=pin['target'],
                                   target_protocol=1))
    assert receipt == dict(ok=True, filled='password', target_delivery=route.DELIVERY)
    assert session(FRAME_DIGEST, True) == sha(PASSWORD)
    # The owner <iframe> is transparent: the field inside looks visible to its own document only.
    session, pin = frame_password_pin(harness, lab.navigate('/framed-hidden'))
    assert pin == failure()
    assert session(FRAME_DIGEST, True) == EMPTY
    # The owner is hidden after the pin: the fill refuses.
    session, pin = frame_password_pin(harness, lab.navigate('/framed-visible'))
    assert pin['ok'], pin
    lab.evaluate("document.getElementById('login-frame').style.opacity = '0'")
    assert broker.dispatch(dict(action='fill', handle=auth_handle(broker), mode='password', target=pin['target'],
                                target_protocol=1)) == failure()
    assert session(FRAME_DIGEST, True) == EMPTY


def test_a_page_cannot_lend_a_decoy_iframe_to_a_hidden_login_frame(harness):
    lab = harness.lab
    url = lab.navigate('/framed-forward')
    lab.wait("document.getElementById('decoy').contentDocument?.readyState === 'complete'")
    frame, pin = frame_password_pin(harness, url)
    assert pin == failure()
    assert frame(FRAME_DIGEST, True) == EMPTY


def test_a_read_pin_never_takes_a_selector_that_could_test_the_secret(harness):
    """The pin call comes through the host unsealed: the extension itself refuses attribute selectors."""
    lab = harness.lab
    url = lab.navigate('/secret')
    harness.focus('secret')
    listing = harness.frames(url)
    tab = int(listing['page_id'].split('.')[1])
    for selector in ('#secret', '#secret:not([id=x])', 'code[id^="se"]', 'body:has(code) #secret'):
        call = json.dumps(dict(tab_id=tab, document_id=listing['main_frame_id'], top_url=url, frame_url=None,
                               kind='read', spec=dict(selector=selector, frame_origin=None)))
        result = harness.worker_call(f'pin({call}).then(r => (r.ok && release({{tab_id: {tab}, document_id: '
                                     f'{json.dumps(listing["main_frame_id"])}, pin_id: r.pin_id}}), r.ok))')
        assert result is (selector == '#secret'), selector


def framed_read_pin(harness, url):
    lab = harness.lab
    lab.wait("document.readyState === 'complete'")
    frame = same_site_frame(harness, 'https://auth.example.com/secret', ready='secret')
    frame("window.focus(); document.getElementById('secret').focus()")
    listing = harness.frames(url)
    keys = next(f for f in listing['frames'] if f['origin'] == 'https://auth.example.com')
    return read_pin(harness, url, frame_id=keys['frame_id'], frame_protocol=1, frame_origin='https://auth.example.com')


def test_a_child_frame_secret_is_read_only_when_its_frame_is_on_top(harness):
    lab = harness.lab
    pin = framed_read_pin(harness, lab.navigate('/framed-secret'))
    assert pin['ok'], pin
    assert read_value(harness, pin, 'https://auth.example.com') == sha(SECRET)
    assert framed_read_pin(harness, lab.navigate('/framed-secret-covered')) == failure()
    # A cover added after the pin refuses the read.
    pin = framed_read_pin(harness, lab.navigate('/framed-secret'))
    assert pin['ok'], pin
    lab.evaluate("document.body.insertAdjacentHTML('beforeend', '<div style=\"position:absolute;left:0;top:0;"
                 "width:700px;height:200px;background:#fff\"></div>')")
    assert read_value(harness, pin, 'https://auth.example.com') is None


def test_a_page_cannot_stop_an_owner_probe_to_lend_a_decoy(harness):
    lab = harness.lab
    url = lab.navigate('/framed-suppress')
    same_site_frame(harness, 'https://auth.example.com/decoy-relay', ready='')  # Both frames loaded.
    frame = same_site_frame(harness, 'https://auth.example.com/login-suppress')
    frame("window.focus(); document.getElementById('password').focus()")
    listing = harness.frames(url)
    login = next(f for f in listing['frames'] if f['origin'] == 'https://auth.example.com' and f['visible_fields']
                 and f['visible_fields']['password'])
    pin = harness.broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                       frame_id=login['frame_id'], top_url=url, selector='#password', mode='password',
                                       frame_protocol=1, frame_origin='https://auth.example.com', route='extension'))
    assert pin == failure()
