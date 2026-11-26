"""Real Firefox native messaging and DOM delivery, with a disposable profile.

Set AKDBX_TEST_FIREFOX and AKDBX_TEST_GECKODRIVER to run. The only registration
is a unique test host, removed at teardown. Only synthetic values enter Firefox;
the observer checks hashes rather than reading field values.
"""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import sys
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import uuid
import zipfile

import pytest

BINARY = os.environ.get('AKDBX_TEST_FIREFOX')
DRIVER = shutil.which(os.environ.get('AKDBX_TEST_GECKODRIVER', 'geckodriver'))
if not BINARY or not DRIVER:
    if os.environ.get('AKDBX_REQUIRE_FIREFOX_BROWSER') == '1':
        raise RuntimeError('the Firefox gate requires explicit Firefox and geckodriver paths')
    pytest.skip('set the Firefox test binary paths', allow_module_level=True)

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

import qr_fixture
from akdbx import broker_identity, extension_host
from akdbx.broker import Broker, open_vault_with_password, serve
from akdbx.extension_route import CAPTURE_DELIVERY, DELIVERY
from akdbx.target import failure as pin_refused
from akdbx.totp_capture import PENDING_FIELD, QR_REFUSED
from test_extension_route import CARD, MASTER, CardEntry, IdentityEntry, template  # noqa: F401
from popup_fixtures import ADDRESS_FORM, ADDRESS_TITLE, DECOYS, FILLED, AddressEntry
from akdbx.local_https import start_local_unlock_server
from test_broker import Entry, Vault
from test_windows_unlock import certificates  # noqa: F401

@pytest.fixture
def private_dir(tmp_path):
    if os.name == 'nt':
        from akdbx.windows_security import ensure_private_directory
        # Python 3.12's mode-0700 pytest folders use OWNER RIGHTS ACEs. Use
        # the broker's explicit per-user DACL for this native integration lab.
        folder = Path(os.environ['LOCALAPPDATA']) / ('akdbx-firefox-' + uuid.uuid4().hex)
        ensure_private_directory(folder)
    else:
        folder = tmp_path.resolve() / 'p'
        folder.mkdir(mode=0o700)
    try:
        yield folder
    finally:
        shutil.rmtree(folder)

PASSWORD = 'SYNTHETIC-Firefox-Only-42!'
DIGEST = """<script>async function digest(id) {
const field = document.getElementById(id) || document.getElementsByName(id)[0];
const bytes = new TextEncoder().encode(field.value);
const hash = await crypto.subtle.digest('SHA-256', bytes);
return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2,'0')).join('');
} window.keyEvents=0;document.addEventListener('keydown',()=>keyEvents++);</script>"""


class NoKeys:
    def capture(self, *args):
        pytest.fail('Firefox must not capture a window target')

    def deliver(self, *args, **kwargs):
        pytest.fail('Firefox must not fall back to keyboard delivery')


# These public endpoint shapes are served by a loopback TLS fixture. The proxy
# never resolves a name or makes an upstream connection.
PROCESSORS = {
    'adyen': ('https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_test/6.3.0/securedFields.html',
              'number', '<input id=number autocomplete=cc-number>'),
    'computop': ('https://www.computop-paygate.com/payssl.aspx',
                 '_KKnr', '<form><input id=_KKnr name=_KKnr autocomplete=off maxlength=30></form>'),
    'stripe': ('https://js.stripe.com/v3/elements-inner-accessory-target-' + 'b' * 32 + '.html',
               'payment-numberInput', '<input id=payment-numberInput name=number autocomplete=cc-number>'),
    'stripe-card': ('https://js.stripe.com/v3/elements-inner-card-' + 'd' * 32 + '.html',
                    'cardnumber', '<input name=cardnumber autocomplete=cc-number>'),
}


def _b32(raw):
    return base64.b32encode(raw).decode('ascii').rstrip('=')


# Setup QR codes (capture-totp --qr): a fresh synthetic key on every run, which
# no receipt, CLI output or log may contain. evil.example.net is another origin,
# served by the same loopback fixture through the proxy.
QR_KEY, QR_OTHER_KEY, QR_NEXT_KEY = (_b32(secrets.token_bytes(20)) for _ in range(3))
QR_SECRETS = (QR_KEY, QR_OTHER_KEY, QR_NEXT_KEY, QR_KEY.lower())
CROSS_ORIGIN = 'https://evil.example.net'
QR_TITLE = 'Synthetic Firefox QR'


def qr_uri(key, kind='totp'):
    return f'otpauth://{kind}/Synthetic:synthetic-firefox?secret={key}&issuer=Synthetic'


QR_ROWS, QR_NEXT_ROWS, QR_OTHER_ROWS = (qr_fixture.rows(qr_uri(k)) for k in (QR_KEY, QR_NEXT_KEY, QR_OTHER_KEY))
QR_PNG = qr_fixture.png(QR_ROWS)
QR_FILES = {  # path: (PNG bytes, extra headers)
    '/qr/key.png': (QR_PNG, {}),
    '/qr/key-cors.png': (QR_PNG, {'Access-Control-Allow-Origin': '*'}),
    '/qr/next.png': (qr_fixture.png(QR_NEXT_ROWS), {}),
    '/qr/two.png': (qr_fixture.png([a + b for a, b in zip(QR_ROWS, QR_OTHER_ROWS)]), {}),
    '/qr/hotp.png': (qr_fixture.png(qr_fixture.rows(qr_uri(QR_KEY, 'hotp'))), {}),
    # A URL on the page's own origin whose image comes from another origin, without and with CORS.
    '/qr/redirect.png': (b'', {'Location': CROSS_ORIGIN + '/qr/key.png'}),
    '/qr/redirect-cors.png': (b'', {'Location': CROSS_ORIGIN + '/qr/key-cors.png'}),
}
QR_CANVAS = '''<canvas id=qr></canvas><script>
var ROWS = __ROWS__, NEXT_ROWS = __NEXT_ROWS__;  // var: WebDriver scripts see window properties only.
function draw(rows) {
  const canvas = document.getElementById('qr'), scale = 4, context = canvas.getContext('2d');
  canvas.width = canvas.height = rows.length * scale;
  for (let y = 0; y < rows.length; y++) for (let x = 0; x < rows.length; x++) {
    context.fillStyle = rows[y][x] === '1' ? '#000' : '#fff';
    context.fillRect(x * scale, y * scale, scale, scale);
  }
}
// After the pin: draw a picture fully transparent, so the pixels stay the same.
// From another origin (no CORS) that still taints the canvas.
function overdraw(src) {
  return new Promise((done, failed) => {
    const picture = new Image();
    picture.onload = () => {
      const context = document.getElementById('qr').getContext('2d');
      context.globalAlpha = 0; context.drawImage(picture, 0, 0); context.globalAlpha = 1;
      done(true);
    };
    picture.onerror = failed;
    picture.src = src;
  });
}
draw(ROWS); window.ready = true;</script>'''.replace('__ROWS__', json.dumps(QR_ROWS)).replace(
    '__NEXT_ROWS__', json.dumps(QR_NEXT_ROWS))
# The site's own check of the code from the app, for fill-totp --pending.
QR_VERIFY = '''<label>Verify the code from the app <input id=otp autocomplete=one-time-code inputmode=numeric></label>
<script>
const KEY = __KEY__;
function unb32(s) {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of s) bits += a.indexOf(c).toString(2).padStart(5, '0');
  return new Uint8Array(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
}
async function code(step) {
  const key = await crypto.subtle.importKey('raw', unb32(KEY), {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
  const counter = new DataView(new ArrayBuffer(8)); counter.setUint32(4, step);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter.buffer));
  const o = h[19] & 15, n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}
document.getElementById('otp').addEventListener('input', async e => {
  const value = e.target.value;
  if (value.length !== 6) return;
  const step = Math.floor(Date.now() / 30000);
  document.body.dataset.result = value === await code(step) || value === await code(step - 1) ? 'accepted' : 'rejected';
});
</script>'''.replace('__KEY__', json.dumps(QR_KEY))
QR_PAGES = {
    '/qr-img': '<img id=qr src="/qr/key.png" alt="QR code">',
    '/qr-canvas': QR_CANVAS,
    '/qr-svg': qr_fixture.svg(QR_ROWS).replace('<svg ', '<svg id="qr" ', 1),
    '/qr-cross-origin': f'<img id=qr src="{CROSS_ORIGIN}/qr/key.png" alt="QR code">',
    '/qr-cross-origin-cors': f'<img id=qr crossorigin=anonymous src="{CROSS_ORIGIN}/qr/key-cors.png" alt="QR code">',
    '/qr-redirect': '<img id=qr src="/qr/redirect.png" alt="QR code">',
    # CORS mode: another origin that allows the read keeps the canvas origin-clean after the redirect.
    '/qr-redirect-cors': '<img id=qr crossorigin=anonymous src="/qr/redirect-cors.png" alt="QR code">',
    # The page draws another origin's image (no CORS) into its own canvas: the canvas is tainted.
    '/qr-canvas-tainted': f'''<canvas id=qr></canvas><script>
const picture = new Image();
picture.onload = () => {{
  const canvas = document.getElementById('qr');
  canvas.width = picture.naturalWidth; canvas.height = picture.naturalHeight;
  canvas.getContext('2d').drawImage(picture, 0, 0);
  window.ready = true;
}};
picture.src = '{CROSS_ORIGIN}/qr/key.png';</script>''',
    '/qr-two': '<img id=qr src="/qr/two.png" alt="QR codes">',
    '/qr-hotp': '<img id=qr src="/qr/hotp.png" alt="QR code">',
}


def fixture_markup(path):
    if path in QR_PAGES:
        return ('<style>body{margin:0;font:14px sans-serif}img,canvas,svg{display:block;margin:8px}</style>'
                '<p>Scan this QR code with your authenticator app.</p>' + QR_PAGES[path] + QR_VERIFY)
    for name, (endpoint, _, markup) in PROCESSORS.items():
        if path == '/computop' and name == 'computop':
            return (f'<iframe id=processor name=PGForm style="width:500px;height:150px"></iframe>'
                    f'<form method=post target=PGForm action="{endpoint}"></form>'
                    '<script>document.forms[0].submit()</script>')
        if path == '/' + name:
            return f'<iframe id=processor src="{endpoint}" style="width:500px;height:150px"></iframe>'
        if path == urlsplit(endpoint).path:
            return markup
    if path == '/address':
        return ADDRESS_FORM
    if path == '/fields':
        return ('<input id=number autocomplete=cc-number><input id=given autocomplete=given-name>'
                '<input id=new-password type=password autocomplete=new-password>'
                '<code id=secret tabindex=0>synthetic-token-abcdefghijklmnop</code>'
                '<code id=setup tabindex=0>JBSWY3DPEHPK3PXP</code>')
    fields = ('<input id=username autocomplete=username>' +
              ('<input id=child type=password autocomplete=current-password>' if path == '/frame' else
               '<input id=password type=password autocomplete=current-password>'
               '<input id=hidden type=password style="display:none">'
               '<iframe id=frame src=/frame style="width:500px;height:150px"></iframe>'))
    return fields + '<input id=otp type=text autocomplete=one-time-code maxlength=6>'


@pytest.fixture
def firefox_lab(private_dir, certificates, request):
    cert, key = private_dir / 'cert.pem', private_dir / 'key.pem'
    if os.name == 'nt':
        from akdbx.windows_security import write_new
        write_new(cert, certificates[0].read_bytes())
        write_new(key, certificates[1].read_bytes())
    else:
        cert.write_bytes(certificates[0].read_bytes())
        key.write_bytes(certificates[1].read_bytes())
        key.chmod(0o600)

    class Page(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path in QR_FILES:
                data, headers = QR_FILES[self.path]
                self.send_response(302 if 'Location' in headers else 200)
                for name, value in {'Content-Type': 'image/png', **headers}.items():
                    self.send_header(name, value)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            body = ('<!doctype html><meta charset=utf-8>' + fixture_markup(self.path) + DIGEST).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            # Computop's merchant form targets an initially blank iframe.
            if self.path != '/payssl.aspx' or self.headers.get('Content-Length') != '0':
                self.send_error(400)
                return
            self.do_GET()

    page = ThreadingHTTPServer(('127.0.0.1', 0), Page)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    page.socket = context.wrap_socket(page.socket, server_side=True)
    page_thread = threading.Thread(target=page.serve_forever, daemon=True)
    page_thread.start()
    url = f'https://localhost:{page.server_port}/login'

    class FixtureProxy(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_CONNECT(self):
            hosts = {urlsplit(endpoint).hostname for endpoint in [CROSS_ORIGIN, *(item[0] for item in PROCESSORS.values())]}
            if self.path not in {host + ':443' for host in hosts}:
                self.send_error(403)
                return
            self.send_response_only(200)
            self.end_headers()
            self.connection.settimeout(10)
            with context.wrap_socket(self.connection, server_side=True) as tls:
                Page(tls, self.client_address, self.server)

    proxy = ThreadingHTTPServer(('127.0.0.1', 0), FixtureProxy)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    broker = None
    stop, errors = threading.Event(), []
    worker = driver = unlock = service = manifest = registration = None
    mode = getattr(request, 'param', None)
    vault_path = private_dir / 'synthetic.kdbx'
    try:
        if mode in ('writable', 'qr', 'qr-enhanced'):
            data = request.getfixturevalue('template').read_bytes()
            if os.name == 'nt':
                from akdbx.windows_security import write_new
                write_new(vault_path, data)
            else:
                vault_path.write_bytes(data)
                vault_path.chmod(0o600)
            if mode != 'writable':  # The entry whose setup QR code the tests capture.
                from pykeepass import PyKeePass
                kdbx = PyKeePass(str(vault_path), password=MASTER)
                kdbx.add_entry(kdbx.find_groups(name='Web', first=True), QR_TITLE, 'synthetic-firefox',
                               'synthetic-qr-site-password', url=url)
                kdbx.save()
            vault = open_vault_with_password(vault_path, MASTER)
        else:
            vault = Vault([Entry(username='synthetic@example.test', password=PASSWORD, url=url)])
        broker = Broker(vault, NoKeys())
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        origin = f'https://localhost:{port}'
        unlock, _ = start_local_unlock_server(broker, private_dir / 'unused.kdbx', None, origin, cert, key)
        broker.extension.set_identity(broker_identity.IdentityStore(private_dir / 'identity').announce(origin))
        unique = uuid.uuid4().hex
        endpoint = Path('\\\\.\\pipe\\akdbx-firefox-' + unique) if os.name == 'nt' else private_dir / 'r' / 's'

        def run():
            try:
                serve(endpoint, broker, stop)
            except Exception as error:
                errors.append(type(error).__name__)
        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        name = 'org.akdbx.firefox_test_' + unique
        folder = extension_host.build(private_dir / 'extension', browser='firefox', host_name=name,
                                      unlock_origin=origin)
        launcher = private_dir / ('host.cmd' if os.name == 'nt' else 'host.sh')
        launcher.write_text(extension_host._launcher_text('firefox', sys.executable, str(endpoint),
                            None if os.name == 'nt' else extension_host.package_root()), newline='')
        if os.name != 'nt':
            launcher.chmod(0o700)
        manifest_path = ((private_dir if os.name == 'nt' else extension_host.linux_manifest_dir('firefox')) /
                         (name + '.json'))
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open('x') as stream:
            manifest = manifest_path
            json.dump(extension_host._manifest(launcher, name, browser='firefox'), stream)
        if os.name == 'nt':
            import winreg
            registration = extension_host.WINDOWS_KEYS['firefox'] + '\\' + name
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, registration) as handle:
                winreg.SetValueEx(handle, '', 0, winreg.REG_SZ, str(manifest))
        addon = private_dir / 'extension.xpi'
        if mode == 'signed':
            # The exact archive that `akdbx extension sign` uploads to AMO, with its signed-build version.
            addon.write_bytes(extension_host.xpi_bytes(extension_host.firefox_signing_files(
                origin, extension_host.signed_version(1), host_name=name)))
        else:
            with zipfile.ZipFile(addon, 'w') as archive:
                for path in folder.iterdir():
                    archive.write(path, path.name)
        options = Options()
        extension_uuid = str(uuid.uuid4())
        options.set_preference('extensions.webextensions.uuids', json.dumps({'akdbx@akdbx.org': extension_uuid}))
        options.set_preference('extensions.webextOptionalPermissionPrompts', False)
        options.binary_location = BINARY
        options.add_argument('-headless')
        options.set_preference('network.proxy.type', 1)
        options.set_preference('network.proxy.ssl', '127.0.0.1')
        options.set_preference('network.proxy.ssl_port', proxy.server_port)
        options.set_preference('network.proxy.failover_direct', False)
        options.set_preference('network.proxy.no_proxies_on', 'localhost,127.0.0.1')
        options.accept_insecure_certs = True  # Only the synthetic fixture's self-signed certificate.
        env = dict(os.environ)
        if os.environ.get('AKDBX_FIREFOX_NO_SANDBOX') == '1':
            env['MOZ_DISABLE_CONTENT_SANDBOX'] = '1'
        service_args = ['--allow-system-access'] if mode in ('popup', 'settings', 'qr-enhanced') else []
        if service_args:
            env["MOZ_REMOTE_ALLOW_SYSTEM_ACCESS"] = "1"
        service = Service(service_args=service_args, executable_path=DRIVER, log_output=str(private_dir / 'geckodriver.log'),
                          env=env)
        driver = webdriver.Firefox(options=options, service=service)
        driver.set_page_load_timeout(20)
        driver.set_script_timeout(10)
        driver.get(origin)
        driver.install_addon(str(addon), temporary=True)
        deadline = time.monotonic() + 20
        # Native attachment registers the channel before it creates the pairing.
        token = None
        while not errors and time.monotonic() < deadline:
            with broker.extension._lock:
                if len(broker.extension.channels) == 1:
                    channel, = broker.extension.channels.values()
                    assert channel.browser == 'firefox'
                    token = next((t for t, (digest, _) in broker.extension.pairings.items()
                                  if digest == channel.digest), None)
            if token is not None:
                break
            time.sleep(.05)
        assert token is not None and not errors, 'Firefox did not establish a pairing'
        assert broker.extension.approve(token)
        driver.get(url)
        yield SimpleNamespace(driver=driver, broker=broker, url=url, vault=vault_path,
                              settings=f'moz-extension://{extension_uuid}/options.html')
    finally:
        try:
            if driver:
                driver.quit()
        finally:
            if service:
                service.stop()
            if registration:
                import winreg
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registration)
            if manifest:
                manifest.unlink(missing_ok=True)
            stop.set()
            if worker:
                worker.join(5)
            if unlock:
                unlock.shutdown()
                unlock.server_close()
            proxy.shutdown()
            proxy.server_close()
            proxy_thread.join(5)
            page.shutdown()
            page.server_close()
            page_thread.join(5)
            if broker:
                broker.unlock_notifications.close()
    assert not errors and (worker is None or not worker.is_alive()), errors


def test_firefox_local_host_document_pins_and_secret_delivery(firefox_lab):
    driver, broker, url = firefox_lab.driver, firefox_lab.broker, firefox_lab.url
    listing = broker.dispatch(dict(action='list-password-frames', password_protocol=1,
                                   frame_protocol=1, top_url=url, route='extension'))
    assert listing['ok'] and len(listing['frames']) == 2
    top = listing['main_frame_id']
    child = next(frame['frame_id'] for frame in listing['frames'] if frame['depth'] == 1)
    assert '-' in top and '-' in child  # Firefox's actual document UUIDs, not mock frame IDs.

    def pin(frame, selector, mode='password'):
        request = dict(action='pin-password-target', password_protocol=1,
            page_id=listing['page_id'], frame_id=frame, top_url=url, selector=selector,
            mode=mode, route='extension')
        if mode == 'login':
            request['username_selector'] = '#username'
        if frame != top:
            request.update(frame_protocol=1, frame_origin='https://' + urlsplit(url).netloc)
        return broker.dispatch(request)

    def fill(target, mode='password'):
        handle = broker.dispatch(dict(action='search', query='localhost'))['entries'][0]['handle']
        return broker.dispatch(dict(action='fill', handle=handle, mode=mode, target=target,
                                    target_protocol=1))

    def digest(field):
        return driver.execute_async_script('const done=arguments[arguments.length-1];digest(arguments[0]).then(done)', field)

    driver.find_element('id', 'password').click()
    target = pin(top, '#password')
    assert target['ok'] and fill(target['target'])['ok']
    expected = hashlib.sha256(PASSWORD.encode()).hexdigest()
    assert digest('password') == expected
    assert not pin(top, '#hidden')['ok']
    driver.switch_to.frame(driver.find_element('id', 'frame'))
    driver.find_element('id', 'username').click()
    target = pin(child, '#child', 'login')
    assert target['ok'] and fill(target['target'], 'login')['ok']
    assert digest('username') == hashlib.sha256(b'synthetic@example.test').hexdigest()
    assert digest('child') == expected
    driver.switch_to.default_content()
    driver.find_element('id', 'password').click()
    target = pin(top, '#password')
    assert target['ok']
    driver.refresh()
    driver.find_element('id', 'password').click()
    assert not fill(target['target'])['ok']


@pytest.mark.parametrize('firefox_lab', ['signed'], indirect=True)
def test_firefox_runs_the_archive_that_extension_sign_submits_as_a_current_build(firefox_lab):
    """AMO signs the uploaded archive unchanged; Firefox loads it, and the broker calls its version current."""
    broker, url = firefox_lab.broker, firefox_lab.url
    version = extension_host.signed_version(1)
    assert len(version.rsplit('.', 1)[1]) == 9  # Firefox accepts nine digits in a version part.
    browsers = broker.dispatch({'action': 'ping'})['extension_browsers']
    assert browsers == [dict(browser='firefox', paired=True, version=version, version_status='current')]
    listing = broker.dispatch(dict(action='list-password-frames', password_protocol=1,
                                   frame_protocol=1, top_url=url, route='extension'))
    assert listing['ok'] and len(listing['frames']) == 2  # Not refused as a stale or other build.
    firefox_lab.driver.find_element('id', 'password').click()
    target = broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                  frame_id=listing['main_frame_id'], top_url=url, selector='#password',
                                  mode='password', route='extension'))
    handle = broker.dispatch(dict(action='search', query='localhost'))['entries'][0]['handle']
    assert target['ok'] and broker.dispatch(dict(action='fill', handle=handle, mode='password',
                                                 target=target['target'], target_protocol=1))['ok']
    assert firefox_lab.driver.execute_async_script(
        'const done=arguments[arguments.length-1];digest(arguments[0]).then(done)', 'password') == \
        hashlib.sha256(PASSWORD.encode()).hexdigest()


def test_firefox_totp_uses_exact_main_and_child_documents_without_keyboard(firefox_lab):
    from akdbx.extension_route import DELIVERY
    from totp_vectors import URI
    driver, broker, url = firefox_lab.driver, firefox_lab.broker, firefox_lab.url
    broker.vault.entries[0].otp = URI
    broker.wall_clock = lambda: 1111111111
    listing = broker.dispatch(dict(action='list-password-frames', password_protocol=1,
                                   frame_protocol=1, top_url=url, route='extension'))
    assert listing['ok']
    top = listing['main_frame_id']
    child = next(frame['frame_id'] for frame in listing['frames'] if frame['depth'] == 1)
    for frame in (top, child):
        target_url = url
        if frame == child:
            element = driver.find_element('id', 'frame')
            target_url = element.get_attribute('src')
            driver.switch_to.frame(element)
        driver.find_element('id', 'otp').click()
        request = dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                       frame_id=frame, top_url=url, selector='#otp', mode='totp', route='extension')
        if frame == child:
            request.update(frame_protocol=1, frame_origin='https://' + urlsplit(url).netloc)
        pin = broker.dispatch(request)
        assert pin['ok'], pin
        handle = broker.dispatch(dict(action='search', query='localhost'))['entries'][0]['handle']
        receipt = broker.dispatch(dict(action='fill-totp', handle=handle, target_url=target_url,
                                       target=pin['target'], target_protocol=1))
        assert receipt == dict(ok=True, filled='totp', target_delivery=DELIVERY)
        digest = driver.execute_async_script('const done=arguments[arguments.length-1];digest("otp").then(done)')
        assert digest == hashlib.sha256(b'050471').hexdigest()
        assert driver.execute_script('return window.keyEvents') == 0


def navigate(lab, path):
    url = lab.url.replace('/login', '/' + path)
    lab.driver.get(url)
    frames = lab.broker.dispatch(dict(action='list-password-frames', password_protocol=1,
                                 frame_protocol=1, top_url=url, route='extension'))
    assert frames['ok'], frames
    target = dict(page_id=frames['page_id'], frame_id=frames['main_frame_id'], top_url=url, route='extension')
    return target, frames['frames']


def field_digest(driver, field):
    return driver.execute_async_script('const done=arguments[1]; digest(arguments[0]).then(done)', field)


def fill_card(lab, pin):
    entry, = lab.broker.dispatch(dict(action='search-cards', card_protocol=1))['entries']
    return lab.broker.dispatch(dict(action='fill-card', card_protocol=1, handle=entry['handle'],
                                   target=pin['target'], field='cc-number'))


@pytest.mark.parametrize('processor', [None, *PROCESSORS])
def test_firefox_card_delivery(firefox_lab, processor):
    lab = firefox_lab
    lab.broker.vault.entries.append(CardEntry(title='Test card', uuid='test-card'))
    target, frames = navigate(lab, processor or 'fields')
    field = 'number'
    if processor:
        endpoint, field, _ = PROCESSORS[processor]
        frame = next(f for f in frames if f['origin'] == 'https://' + urlsplit(endpoint).hostname)
        target['frame_id'] = frame['frame_id']
        lab.driver.switch_to.frame(lab.driver.find_element('id', 'processor'))
    selector = '[name=cardnumber]' if processor == 'stripe-card' else '#' + field
    request = dict(action='pin-card-target', card_protocol=1, field='cc-number', selector=selector, **target)
    if processor:
        assert not lab.broker.dispatch(request)['ok']
        request.update(processor=processor.split('-')[0], processor_protocol=1)
    pin = lab.broker.dispatch(request)
    assert pin['ok'], pin
    receipt = fill_card(lab, pin)
    assert receipt == dict(ok=True, filled='cc-number', card_delivery=DELIVERY)
    assert field_digest(lab.driver, field) == hashlib.sha256(CARD['number'].encode()).hexdigest()


def test_firefox_identity_page_events(firefox_lab):
    lab = firefox_lab
    lab.broker.vault.entries.append(IdentityEntry(title='Home', uuid='test-home'))
    target, _ = navigate(lab, 'fields')
    lab.driver.execute_script("""window.events = [];
        for (const type of ['input', 'change']) given.addEventListener(type, e => window.events.push(e.type));""")
    lab.driver.find_element('id', 'given').click()
    for notify in (False, True):
        pin = lab.broker.dispatch(dict(action='pin-identity-target', identity_protocol=1,
                                      selector='#given', field='given-name', **target))
        assert pin['ok'], pin
        entry, = lab.broker.dispatch(dict(action='search-identities', identity_protocol=1, query='Home'))['entries']
        options = dict(notify_page=True) if notify else {}
        receipt = lab.broker.dispatch(dict(action='fill-identity', identity_protocol=1, handle=entry['handle'],
                                          target=pin['target'], field='given-name', **options))
        assert receipt == dict(ok=True, filled='given-name', identity_delivery=DELIVERY)
        assert field_digest(lab.driver, 'given') == hashlib.sha256(b'Synthetic').hexdigest()
        assert lab.driver.execute_script('return window.events') == (['input', 'change'] if notify else [])


@pytest.mark.parametrize('firefox_lab', ['writable'], indirect=True)
def test_firefox_generated_password_and_capture(firefox_lab, private_dir):
    from pykeepass import PyKeePass

    lab = firefox_lab
    target, _ = navigate(lab, 'fields')
    metadata = dict(title='Synthetic Firefox', username='test', url=target['top_url'], group='Web')

    def pin(field, mode):
        lab.driver.execute_script('document.getElementById(arguments[0]).focus()', field)
        options = dict(capture_protocol=1) if mode == 'read' else {}
        result = lab.broker.dispatch(dict(action='pin-password-target', password_protocol=1,
                                         selector='#' + field, mode=mode, **target, **options))
        assert result['ok'], result
        return result['target']

    def saved():
        vault = PyKeePass(str(private_dir / 'synthetic.kdbx'), password=MASTER)
        return vault.find_entries(title=metadata['title'], first=True)

    def select():
        entry, = lab.broker.dispatch(dict(action='search', query=metadata['title']))['entries']
        return entry['handle']

    staged = lab.broker.dispatch(dict(action='generate-entry', metadata=metadata, single_field=True))
    assert staged['ok'], staged
    receipt = lab.broker.dispatch(dict(action='fill-generated', handle=staged['fill_handles']['password'],
                                      target_url=target['top_url'], target=pin('new-password', 'password'),
                                      target_protocol=1))
    assert receipt == dict(ok=True, filled='password', target_delivery=DELIVERY)
    assert lab.broker.dispatch(dict(action='commit-password', write_handle=staged['write_handle'], site_accepted=True))['ok']
    generated_digest = field_digest(lab.driver, 'new-password')
    assert generated_digest != hashlib.sha256(b'').hexdigest()
    assert generated_digest == hashlib.sha256(saved().password.encode()).hexdigest()

    receipt = lab.broker.dispatch(dict(action='capture-secret', capture_protocol=1, field='client_secret',
                                      handle=select(), metadata=metadata, target=pin('secret', 'read')))
    assert receipt['ok'] and receipt['capture_delivery'] == CAPTURE_DELIVERY, receipt
    assert saved().get_custom_property('client_secret') == 'synthetic-token-abcdefghijklmnop'

    receipt = lab.broker.dispatch(dict(action='capture-totp', totp_capture_protocol=1, handle=select(),
                                      metadata=metadata, target=pin('setup', 'read')))
    assert receipt == dict(ok=True, state='pending', totp_configured=False, metadata=metadata,
                           capture_delivery=CAPTURE_DELIVERY)
    committed = lab.broker.dispatch(dict(action='commit-totp', totp_capture_protocol=1, handle=select(),
                                        metadata=metadata, decision='site-accepted'))
    assert committed['ok'], committed
    key = parse_qs(urlsplit(saved().otp).query)['secret'][0]
    assert hashlib.sha256(key.encode()).digest() == hashlib.sha256(b'JBSWY3DPEHPK3PXP').digest()


def click_popup_entry(lab, text=None):
    """Open the toolbar popup and click one entry with Firefox's own WebDriver click (a trusted click).

    ``text``: the entry that shows it; None: the popup must list exactly one entry.
    """
    from selenium.webdriver.support.ui import WebDriverWait

    driver = lab.driver
    with driver.context(driver.CONTEXT_CHROME):
        driver.execute_script("window.CustomizableUI.addWidgetToArea('akdbx_akdbx_org-browser-action', 'nav-bar')")
        widget = driver.find_element('id', 'akdbx_akdbx_org-browser-action')
        widget.find_element('css selector', '.unified-extensions-item-action-button').click()
        # The toolbar panel is a XUL browser. WebDriver's switch_to.frame only
        # accepts HTML frames. Use Firefox's own WebDriver click in the panel.
        popup_url = lab.settings.replace('options.html', 'popup.html')
        popup = WebDriverWait(driver, 8).until(lambda d: d.execute_script("""
            return [...document.querySelectorAll('browser.webextension-popup-browser')]
                .find(b => b.getBoundingClientRect().width > 0 &&
                    b.browsingContext?.currentWindowGlobal?.documentURI.spec === arguments[0]) || null;
        """, popup_url))
        clicked = driver.execute_async_script("""
            const [panel, text, done] = arguments;
            (async () => {
                const doc = panel.browsingContext.currentWindowGlobal;
                const actor = doc.getActor("MarionetteCommands");
                const all = await actor.findElements("css selector", "#entries button", {all:true, timeout:5000});
                const buttons = text === null ? all : await actor.findElements("xpath",
                    `//ul[@id="entries"]//button[contains(., ${JSON.stringify(text)})]`, {all:true, timeout:5000});
                if (buttons.length !== 1) return "expected one matching entry, found " + buttons.length;
                // Firefox 153 reads capabilities through toJSON(); newer releases use Map.get().
                const capabilities = Object.assign(new Map([["moz:webdriverClick", true]]),
                    {toJSON() { return {"moz:webdriverClick": true}; }});
                await actor.clickElement(buttons[0], capabilities);
                return "clicked";
            })().then(done, e => done(String(e)));
        """, popup, text)
        assert clicked == 'clicked', clicked


@pytest.mark.parametrize('firefox_lab', ['popup'], indirect=True)
def test_firefox_user_click_popup(firefox_lab):
    from selenium.webdriver.support.ui import WebDriverWait

    driver = firefox_lab.driver
    assert field_digest(driver, 'password') == hashlib.sha256(b'').hexdigest()
    driver.find_element('id', 'username').click()
    click_popup_entry(firefox_lab)
    WebDriverWait(driver, 5).until(lambda d: field_digest(d, 'password') == hashlib.sha256(PASSWORD.encode()).hexdigest())


@pytest.mark.parametrize('firefox_lab', ['popup'], indirect=True)
def test_firefox_popup_fills_an_address_with_the_identity_pin_rules(firefox_lab):
    """A trusted click in Firefox's popup: the focused address field and its partners get the agent identity
    pin's checks and --notify-page events; another address part and hidden, outside or mistyped fields stay empty."""
    from selenium.webdriver.support.ui import WebDriverWait

    driver = firefox_lab.driver
    firefox_lab.broker.vault.entries.append(AddressEntry(uuid='address', title=ADDRESS_TITLE))
    driver.get(firefox_lab.url.replace('/login', '/address'))
    driver.find_element('id', 'given').click()
    click_popup_entry(firefox_lab, ADDRESS_TITLE)
    WebDriverWait(driver, 5).until(lambda d: 'change:mail' in d.execute_script('return addressEvents'))
    sha = lambda value: hashlib.sha256(value.encode()).hexdigest()  # noqa: E731
    assert {field: field_digest(driver, field) for field in FILLED} == {f: sha(v) for f, v in FILLED.items()}
    assert {field: field_digest(driver, field) for field in DECOYS} == {field: sha('') for field in DECOYS}
    assert driver.execute_script('return addressEvents') == [f'{kind}:{field}' for field in FILLED
                                                             for kind in ('input', 'change')]
    assert driver.execute_script('return window.keyEvents') == 0


@pytest.mark.parametrize('firefox_lab', ['popup'], indirect=True)
def test_firefox_popup_fills_a_texted_code_once(firefox_lab, private_dir):
    """A trusted click on a text in Firefox's popup fills its code once into the focused one-time-code field."""
    from selenium.webdriver.support.ui import WebDriverWait
    from akdbx.sms import SmsInbox

    driver, broker = firefox_lab.driver, firefox_lab.broker
    broker.sms = SmsInbox(private_dir / 'sms' / 'sources.json')
    token = broker.sms.add_source('iphone', 'shortcut')
    assert broker.sms.receive(token, 'Google', 'G-482913 is your Google verification code.') == 'kept'
    driver.find_element('id', 'otp').click()
    click_popup_entry(firefox_lab, 'Text from Google')
    code = hashlib.sha256(b'482913').hexdigest()
    WebDriverWait(driver, 8).until(lambda d: field_digest(d, 'otp') == code)
    assert broker.dispatch(dict(action='sms-wait', sms_protocol=1))['messages'] == []
    assert driver.execute_script('return window.keyEvents') == 0
    assert driver.execute_script('return document.activeElement.id') == 'otp'


@pytest.mark.parametrize('firefox_lab', ['settings'], indirect=True)
def test_firefox_enhanced_card_cover(firefox_lab):
    from selenium.webdriver.support.ui import WebDriverWait

    lab = firefox_lab
    lab.driver.get(lab.settings)
    toggle = lab.driver.find_element('id', 'enhanced')
    wait = WebDriverWait(lab.driver, 5)
    wait.until(lambda _: toggle.is_enabled())
    toggle.click()
    wait.until(lambda _: toggle.is_enabled() and toggle.is_selected())
    target, _ = navigate(lab, 'fields')
    # Native widget paint can hide the challenge colour even on an uncovered input.
    lab.driver.execute_script("number.style.appearance = 'none'")
    request = dict(action='pin-card-target', card_protocol=1, field='cc-number', selector='#number', **target)
    lab.broker.vault.entries.append(CardEntry(title='Test card', uuid='test-card'))

    pin = lab.broker.dispatch(request)
    assert pin['ok'], pin
    assert fill_card(lab, pin) == dict(ok=True, filled='cc-number', card_delivery=DELIVERY)
    assert field_digest(lab.driver, 'number') == hashlib.sha256(CARD['number'].encode()).hexdigest()
    lab.driver.execute_script("number.value = ''")
    pin = lab.broker.dispatch(request)
    assert pin['ok'], pin
    lab.driver.execute_script("""const cover = document.createElement('div');
        cover.style.cssText = 'position:fixed;inset:0;background:white;pointer-events:none';
        document.body.append(cover)""")
    assert not lab.broker.dispatch(request)['ok']
    assert not fill_card(lab, pin)['ok']
    assert field_digest(lab.driver, 'number') == hashlib.sha256(b'').hexdigest()


def test_firefox_card_in_clipped_drawer(firefox_lab):
    target, _ = navigate(firefox_lab, 'fields')
    firefox_lab.driver.execute_script("""
        const drawer = document.createElement('div');
        drawer.style.cssText = 'width:400px;padding:20px;clip-path:inset(-10px)';
        const input = document.querySelector('#number');
        input.replaceWith(drawer);
        drawer.append(input);
    """)
    request = dict(action='pin-card-target', card_protocol=1, field='cc-number', selector='#number', **target)
    firefox_lab.broker.vault.entries.append(CardEntry(title='Test card', uuid='test-card'))
    pin = firefox_lab.broker.dispatch(request)
    assert pin['ok'], pin
    assert fill_card(firefox_lab, pin) == dict(ok=True, filled='cc-number', card_delivery=DELIVERY)
    assert field_digest(firefox_lab.driver, 'number') == hashlib.sha256(CARD['number'].encode()).hexdigest()
    firefox_lab.driver.execute_script("number.value = ''")
    pin = firefox_lab.broker.dispatch(request)
    assert pin['ok'], pin
    firefox_lab.driver.execute_script("""
        const drawer = document.querySelector('#number').parentNode;
        const host = document.createElement('div');
        drawer.replaceWith(host);
        host.append(drawer);
        host.attachShadow({mode:'closed'}).append(document.createElement('slot'));
    """)
    refused = firefox_lab.broker.dispatch(request)
    assert not refused['ok']
    assert not fill_card(firefox_lab, pin)['ok']
    assert field_digest(firefox_lab.driver, 'number') == hashlib.sha256(b'').hexdigest()


def test_firefox_sms_code_fills_exact_main_and_child_documents_once(firefox_lab, private_dir):
    """fill-sms-code through Firefox's own document UUIDs; the code never reaches the agent or the keyboard."""
    from akdbx.browser_card import failure
    from akdbx.sms import SmsInbox
    driver, broker, url = firefox_lab.driver, firefox_lab.broker, firefox_lab.url
    broker.sms = SmsInbox(private_dir / 'sms' / 'sources.json')
    token = broker.sms.add_source('iphone', 'shortcut')
    refused = failure(kind='code')

    def text():
        assert broker.sms.receive(token, 'Google', 'G-482913 is your Google verification code.') == 'kept'
        return inbox()[0]

    def inbox():
        return [m['id'] for m in broker.dispatch(dict(action='sms-wait', sms_protocol=1))['messages']]

    def pin(frame, frame_url, selector='#otp'):
        return broker.dispatch(dict(action='pin-code-target', sms_protocol=1, page_id=listing['page_id'],
                                    frame_id=frame, top_url=url, frame_url=frame_url, selector=selector,
                                    field='one-time-code', route='extension'))

    def fill(message, target):
        return broker.dispatch(dict(action='fill-sms-code', sms_protocol=1, message=message, target=target['target'],
                                    target_protocol=1, start_deadline=broker.clock() + 4))

    def digest(field):
        return driver.execute_async_script('const done=arguments[arguments.length-1];digest(arguments[0]).then(done)',
                                           field)
    listing = broker.dispatch(dict(action='list-password-frames', password_protocol=1,
                                   frame_protocol=1, top_url=url, route='extension'))
    assert listing['ok'], listing
    top = listing['main_frame_id']
    child = next(frame['frame_id'] for frame in listing['frames'] if frame['depth'] == 1)
    for frame in (top, child):
        frame_url = url
        if frame == child:
            element = driver.find_element('id', 'frame')
            frame_url = element.get_attribute('src')
            driver.switch_to.frame(element)
        driver.find_element('id', 'otp').click()
        assert pin(frame, url + '?other') == refused  # Not this frame's exact URL.
        target = pin(frame, frame_url)
        assert target == dict(ok=True, target=target['target'], expires_in=30, field='one-time-code',
                              code_delivery=DELIVERY)
        message = text()
        receipt = fill(message, target)
        assert receipt == dict(ok=True, filled='one-time-code', code_delivery=DELIVERY)
        assert digest('otp') == hashlib.sha256(b'482913').hexdigest() and '482913' not in json.dumps(receipt)
        assert driver.execute_script('return window.keyEvents') == 0
        # Replay: the text and the pin were each used once.
        assert fill(message, target) == dict(ok=False, error='unknown or expired SMS message')
        driver.switch_to.default_content()
    # A hidden field never pins; a pin of a page that reloaded never fills, and its text stays.
    assert pin(top, url, '#hidden') == refused
    driver.find_element('id', 'otp').click()
    target = pin(top, url)
    assert target['ok'], target
    driver.refresh()
    driver.find_element('id', 'otp').click()
    message = text()
    assert fill(message, target) == refused and inbox() == [message]
    assert digest('otp') == hashlib.sha256(b'').hexdigest()


# ----- capture-totp --qr: setup QR codes decoded by the Firefox content script -----

def qr_values(lab):
    return dict(title=QR_TITLE, username='synthetic-firefox', url=lab.url, group='Web')


def qr_open(lab, page):
    """Open a QR page and wait until its code shows (an image loaded, a canvas drawn)."""
    from selenium.webdriver.support.ui import WebDriverWait
    target, _ = navigate(lab, page)
    WebDriverWait(lab.driver, 10).until(lambda d: d.execute_script("""
        const e = document.getElementById('qr');
        return e instanceof HTMLImageElement ? e.complete && e.naturalWidth > 0 :
            e instanceof HTMLCanvasElement ? window.ready === true : e !== null"""))
    return target


def qr_focus(lab, selector):
    """Focus the element by script, as the skill says (a picture is not focusable on its own)."""
    from selenium.webdriver.support.ui import WebDriverWait
    lab.driver.execute_script('const e = document.querySelector(arguments[0]); e.tabIndex = -1; e.focus();', selector)
    WebDriverWait(lab.driver, 5).until(lambda d: d.execute_script(
        'return document.hasFocus() && document.activeElement === document.querySelector(arguments[0])', selector))


def qr_pin(lab, target, selector='#qr', **extra):
    qr_focus(lab, selector)
    request = dict(action='pin-password-target', password_protocol=1, selector=selector, mode='read',
                   capture_protocol=1, read_kind='qr', **target, **extra)
    return lab.broker.dispatch({k: v for k, v in request.items() if v is not None})


def qr_handle(lab):
    found = [e for e in lab.broker.dispatch(dict(action='search', query=QR_TITLE))['entries'] if e['title'] == QR_TITLE]
    assert len(found) == 1
    return found[0]


def qr_capture(lab, token):
    return lab.broker.dispatch(dict(action='capture-totp', totp_capture_protocol=1, target=token,
                                    handle=qr_handle(lab)['handle'], metadata=qr_values(lab), read_kind='qr'))


def qr_stored(lab):
    from pykeepass import PyKeePass
    entry = PyKeePass(str(lab.vault), password=MASTER).find_entries(title=QR_TITLE, first=True)
    props = entry.custom_properties
    return entry.otp, props.get(PENDING_FIELD), (entry.is_custom_property_protected(PENDING_FIELD)
                                                 if PENDING_FIELD in props else None)


def qr_nothing_saved(lab):
    assert qr_stored(lab) == (None, None, None)
    assert 'totp_pending' not in qr_handle(lab)
    return True


def qr_clean(*items):
    text = json.dumps(items, default=str)
    for value in QR_SECRETS:
        assert value not in text
    return True


def qr_fill_pending(lab, target):
    """Fill a code of the pending key into the page's verify field, then wait for the site's own check."""
    from selenium.webdriver.support.ui import WebDriverWait
    for _ in range(2):
        lab.driver.execute_script("otp.value = ''; delete document.body.dataset.result")
        qr_focus(lab, '#otp')
        pin = lab.broker.dispatch(dict(action='pin-password-target', password_protocol=1, selector='#otp',
                                       mode='totp', **target))
        assert pin['ok'], pin
        filled = lab.broker.dispatch(dict(action='fill-totp', handle=qr_handle(lab)['handle'], target=pin['target'],
                                          target_protocol=1, target_url=target['top_url'], pending=True))
        if 'retry_after' not in filled:
            result = WebDriverWait(lab.driver, 5).until(lambda d: d.execute_script(
                'return document.body.dataset.result || null'))
            return filled, result
        time.sleep(filled['retry_after'] + .2)
    raise AssertionError('authenticator code stayed near expiry')


def enhanced_security(lab):
    """Turn on Enhanced security in the options page: Firefox grants the add-on <all_urls> host access."""
    from selenium.webdriver.support.ui import WebDriverWait
    lab.driver.get(lab.settings)
    toggle = lab.driver.find_element('id', 'enhanced')
    wait = WebDriverWait(lab.driver, 5)
    wait.until(lambda _: toggle.is_enabled())
    toggle.click()
    wait.until(lambda _: toggle.is_enabled() and toggle.is_selected())
    assert lab.driver.execute_async_script(
        "browser.permissions.contains({origins: ['<all_urls>']}).then(arguments[0])") is True


def qr_capture_and_commit(lab, page):
    target = qr_open(lab, page)
    pinned = qr_pin(lab, target)
    assert pinned == dict(ok=True, target=pinned.get('target'), expires_in=30, target_delivery=DELIVERY), pinned
    captured = qr_capture(lab, pinned['target'])
    assert captured == dict(ok=True, state='pending', totp_configured=False, metadata=qr_values(lab),
                            capture_delivery=CAPTURE_DELIVERY), captured
    otp, pending, protected = qr_stored(lab)
    assert otp is None and pending.startswith('otpauth://totp/') and 'secret=' + QR_KEY in pending and protected is True
    assert qr_handle(lab).get('totp_pending') is True
    assert qr_capture(lab, pinned['target'])['ok'] is False  # The pin was single use.
    filled, result = qr_fill_pending(lab, target)
    assert filled == dict(ok=True, filled='totp', target_delivery=DELIVERY) and result == 'accepted', (filled, result)
    saved = lab.broker.dispatch(dict(action='commit-totp', totp_capture_protocol=1, handle=qr_handle(lab)['handle'],
                                     metadata=qr_values(lab), decision='site-accepted'))
    assert saved == dict(ok=True, state='saved', replaced=False, metadata=qr_values(lab)), saved
    otp, pending, _ = qr_stored(lab)
    assert pending is None and 'secret=' + QR_KEY in otp
    listed = qr_handle(lab)
    assert listed['totp_configured'] is True and 'totp_pending' not in listed
    assert lab.driver.execute_script('return window.keyEvents') == 0
    return [pinned, captured, filled, saved, listed]


# Another origin's image with or without CORS, a URL on the page's origin that redirects to another origin
# (without or with CORS), a canvas that drew another origin's image, and two codes in one image: the pin refuses.
QR_REFUSED_PAGES = ['qr-cross-origin', 'qr-cross-origin-cors', 'qr-redirect', 'qr-redirect-cors', 'qr-canvas-tainted',
                    'qr-two']


def qr_refusals(lab):
    for page in QR_REFUSED_PAGES:
        target = qr_open(lab, page)
        refused = qr_pin(lab, target)
        assert refused == pin_refused(), (page, refused)
        assert qr_nothing_saved(lab) and qr_clean(refused)


def qr_tainted_after_pin(lab):
    """The capture never compares another origin's pixels: a canvas tainted after the pin refuses, same pixels or not.

    The page draws a picture fully transparent over the pinned canvas. From its own origin the canvas stays
    origin-clean and the capture saves the key; from another origin it is tainted and the capture refuses,
    though the pixels did not change.
    """
    for source, saved in (('/qr/key.png', True), (CROSS_ORIGIN + '/qr/key.png', False)):
        pinned = qr_pin(lab, qr_open(lab, 'qr-canvas'))
        assert pinned['ok'], pinned
        assert lab.driver.execute_script('return overdraw(arguments[0])', source) is True
        captured = qr_capture(lab, pinned['target'])
        assert captured['ok'] is saved and (saved or captured == dict(ok=False, error=QR_REFUSED)), (source, captured)
        assert qr_clean(captured)


@pytest.mark.parametrize('firefox_lab', ['qr'], indirect=True)
@pytest.mark.parametrize('page', ['qr-img', 'qr-canvas', 'qr-svg'])
def test_firefox_qr_code_on_the_page_origin_saves_a_pending_key_that_commit_promotes(firefox_lab, page, caplog, capsys):
    import logging
    caplog.set_level(logging.DEBUG)
    receipts = qr_capture_and_commit(firefox_lab, page)
    out = capsys.readouterr()
    assert qr_clean(*receipts, out.out, out.err, caplog.text)


@pytest.mark.parametrize('firefox_lab', ['qr'], indirect=True)
def test_firefox_qr_pin_refuses_other_origins_and_two_codes(firefox_lab):
    qr_refusals(firefox_lab)
    qr_tainted_after_pin(firefox_lab)


@pytest.mark.parametrize('firefox_lab', ['qr-enhanced'], indirect=True)
def test_firefox_qr_with_all_urls_host_access_still_reads_only_the_pages_own_pixels(firefox_lab, caplog, capsys):
    """Enhanced security grants <all_urls>: the content script could then read a tainted canvas's pixels."""
    import logging
    caplog.set_level(logging.DEBUG)
    lab = firefox_lab
    enhanced_security(lab)
    qr_refusals(lab)
    # Every pin and read now also takes the pixel challenge.
    receipts = qr_capture_and_commit(lab, 'qr-img')
    for page in ('qr-canvas', 'qr-svg'):
        pinned = qr_pin(lab, qr_open(lab, page))
        assert pinned['ok'], (page, pinned)
        captured = qr_capture(lab, pinned['target'])
        assert captured == dict(ok=True, state='pending', totp_configured=True, metadata=qr_values(lab),
                                capture_delivery=CAPTURE_DELIVERY), (page, captured)
        receipts += [pinned, captured]
        assert lab.driver.execute_script("return getComputedStyle(document.getElementById('qr')).boxShadow") == 'none'
    # A click-through cover passes the DOM hit test; the screenshot still shows it.
    target = qr_open(lab, 'qr-img')
    lab.driver.execute_script("document.body.insertAdjacentHTML('beforeend', '<div style=\"position:absolute;left:40px;"
                              "top:80px;width:60px;height:60px;background:#fff;pointer-events:none\"></div>')")
    refused = qr_pin(lab, target)
    assert refused == pin_refused(), refused
    qr_tainted_after_pin(lab)
    out = capsys.readouterr()
    assert qr_clean(*receipts, refused, out.out, out.err, caplog.text)


@pytest.mark.parametrize('firefox_lab', ['qr'], indirect=True)
def test_firefox_qr_capture_refuses_a_code_that_is_not_totp_or_that_changed(firefox_lab):
    lab = firefox_lab
    # One readable code: the broker, not the page, decides what it holds.
    target = qr_open(lab, 'qr-hotp')
    pinned = qr_pin(lab, target)
    assert pinned['ok'], pinned
    refused = qr_capture(lab, pinned['target'])
    assert refused == dict(ok=False, error=QR_REFUSED) and qr_clean(refused)
    # The page draws another code into the same canvas: no DOM change, other pixels.
    target = qr_open(lab, 'qr-canvas')
    pinned = qr_pin(lab, target)
    assert pinned['ok'], pinned
    lab.driver.execute_script('draw(NEXT_ROWS)')
    assert qr_capture(lab, pinned['target']) == dict(ok=False, error=QR_REFUSED)
    # The page points the image at another code.
    target = qr_open(lab, 'qr-img')
    pinned = qr_pin(lab, target)
    assert pinned['ok'], pinned
    lab.driver.execute_script("document.getElementById('qr').src = '/qr/next.png'")
    lab.driver.execute_script("return document.getElementById('qr').decode()")
    assert qr_capture(lab, pinned['target']) == dict(ok=False, error=QR_REFUSED)
    # An inline SVG whose paint changes.
    target = qr_open(lab, 'qr-svg')
    pinned = qr_pin(lab, target)
    assert pinned['ok'], pinned
    lab.driver.execute_script("document.querySelector('#qr g').setAttribute('fill', '#333')")
    assert qr_capture(lab, pinned['target']) == dict(ok=False, error=QR_REFUSED)
    # A text read pin is not a QR pin, and a QR pin is never a secret capture.
    pinned = qr_pin(lab, target)
    assert pinned['ok'], pinned
    secret = lab.broker.dispatch(dict(action='capture-secret', capture_protocol=1, target=pinned['target'],
                                      field='client_secret', metadata=qr_values(lab), handle=qr_handle(lab)['handle']))
    assert secret['ok'] is False and 'refused' in secret['error'], secret
    assert qr_nothing_saved(lab)
