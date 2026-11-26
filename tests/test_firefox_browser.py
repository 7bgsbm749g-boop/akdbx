"""Real Firefox native messaging and DOM delivery, with a disposable profile.

Set AKDBX_TEST_FIREFOX and AKDBX_TEST_GECKODRIVER to run. The only registration
is a unique test host, removed at teardown. Only synthetic values enter Firefox;
the observer checks hashes rather than reading field values.
"""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
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

from akdbx import broker_identity, extension_host
from akdbx.broker import Broker, open_vault_with_password, serve
from akdbx.extension_route import CAPTURE_DELIVERY, DELIVERY
from test_extension_route import CARD, MASTER, CardEntry, IdentityEntry, template  # noqa: F401
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


def fixture_markup(path):
    for name, (endpoint, _, markup) in PROCESSORS.items():
        if path == '/computop' and name == 'computop':
            return (f'<iframe id=processor name=PGForm style="width:500px;height:150px"></iframe>'
                    f'<form method=post target=PGForm action="{endpoint}"></form>'
                    '<script>document.forms[0].submit()</script>')
        if path == '/' + name:
            return f'<iframe id=processor src="{endpoint}" style="width:500px;height:150px"></iframe>'
        if path == urlsplit(endpoint).path:
            return markup
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
            if self.path not in {urlsplit(item[0]).hostname + ':443' for item in PROCESSORS.values()}:
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
    try:
        if getattr(request, 'param', None) == 'writable':
            path = private_dir / 'synthetic.kdbx'
            data = request.getfixturevalue('template').read_bytes()
            if os.name == 'nt':
                from akdbx.windows_security import write_new
                write_new(path, data)
            else:
                path.write_bytes(data)
                path.chmod(0o600)
            vault = open_vault_with_password(path, MASTER)
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
        service_args = ['--allow-system-access'] if getattr(request, 'param', None) in ('popup', 'settings') else []
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
        yield SimpleNamespace(driver=driver, broker=broker, url=url, settings=f'moz-extension://{extension_uuid}/options.html')
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


@pytest.mark.parametrize('firefox_lab', ['popup'], indirect=True)
def test_firefox_user_click_popup(firefox_lab):
    from selenium.webdriver.support.ui import WebDriverWait

    driver = firefox_lab.driver
    assert field_digest(driver, 'password') == hashlib.sha256(b'').hexdigest()
    driver.find_element('id', 'username').click()
    with driver.context(driver.CONTEXT_CHROME):
        driver.execute_script("window.CustomizableUI.addWidgetToArea('akdbx_akdbx_org-browser-action', 'nav-bar')")
        widget = driver.find_element('id', 'akdbx_akdbx_org-browser-action')
        widget.find_element('css selector', '.unified-extensions-item-action-button').click()
        # The toolbar panel is a XUL browser. WebDriver's switch_to.frame only
        # accepts HTML frames. Use Firefox's own WebDriver click in the panel.
        popup_url = firefox_lab.settings.replace('options.html', 'popup.html')
        popup = WebDriverWait(driver, 8).until(lambda d: d.execute_script("""
            return [...document.querySelectorAll('browser.webextension-popup-browser')]
                .find(b => b.getBoundingClientRect().width > 0 &&
                    b.browsingContext?.currentWindowGlobal?.documentURI.spec === arguments[0]) || null;
        """, popup_url))
        clicked = driver.execute_async_script("""
            const [panel, done] = arguments;
            (async () => {
                const doc = panel.browsingContext.currentWindowGlobal;
                const actor = doc.getActor("MarionetteCommands");
                const buttons = await actor.findElements("css selector", "#entries button", {all:true, timeout:5000});
                if (buttons.length !== 1) return "expected one matching entry";
                await actor.clickElement(buttons[0], new Map([["moz:webdriverClick", true]]));
                return "clicked";
            })().then(done, e => done(String(e)));
        """, popup)
        assert clicked == 'clicked', clicked
    WebDriverWait(driver, 5).until(lambda d: field_digest(d, 'password') == hashlib.sha256(PASSWORD.encode()).hexdigest())


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
