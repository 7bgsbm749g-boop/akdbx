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
from urllib.parse import urlsplit
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
from akdbx.broker import Broker, serve
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
const bytes = new TextEncoder().encode(document.getElementById(id).value);
const hash = await crypto.subtle.digest('SHA-256', bytes);
return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2,'0')).join('');
} window.keyEvents=0;document.addEventListener('keydown',()=>keyEvents++);</script>"""


class NoKeys:
    def capture(self, *args):
        pytest.fail('Firefox must not capture a window target')

    def deliver(self, *args, **kwargs):
        pytest.fail('Firefox must not fall back to keyboard delivery')


@pytest.fixture
def firefox_lab(private_dir, certificates):
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
            body = ('<!doctype html><meta charset=utf-8>' +
                    ('<input id=child type=password autocomplete=current-password>' if self.path == '/frame' else
                     '<input id=password type=password autocomplete=current-password>'
                     '<input id=hidden type=password style="display:none">'
                     '<iframe id=frame src=/frame style="width:500px;height:150px"></iframe>') +
                    '<input id=otp type=text autocomplete=one-time-code maxlength=6>' + DIGEST).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    page = ThreadingHTTPServer(('127.0.0.1', 0), Page)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    page.socket = context.wrap_socket(page.socket, server_side=True)
    page_thread = threading.Thread(target=page.serve_forever, daemon=True)
    page_thread.start()
    url = f'https://localhost:{page.server_port}/login'
    broker = Broker(Vault([Entry(username='synthetic@example.test', password=PASSWORD, url=url)]), NoKeys())
    stop, errors = threading.Event(), []
    worker = driver = unlock = service = manifest = registration = None
    try:
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
        options.binary_location = BINARY
        options.add_argument('-headless')
        options.accept_insecure_certs = True  # Only the synthetic fixture's self-signed certificate.
        env = dict(os.environ)
        if os.environ.get('AKDBX_FIREFOX_NO_SANDBOX') == '1':
            env['MOZ_DISABLE_CONTENT_SANDBOX'] = '1'
        service = Service(executable_path=DRIVER, log_output=str(private_dir / 'geckodriver.log'),
                          env=env)
        driver = webdriver.Firefox(options=options, service=service)
        driver.set_page_load_timeout(20)
        driver.set_script_timeout(10)
        driver.get(origin)
        driver.install_addon(str(addon), temporary=True)
        deadline = time.monotonic() + 20
        while not broker.extension.channels and not errors and time.monotonic() < deadline:
            time.sleep(.05)
        assert not errors and len(broker.extension.channels) == 1, errors
        channel = next(iter(broker.extension.channels.values()))
        assert channel.browser == 'firefox'
        token = next(token for token, (digest, _) in broker.extension.pairings.items() if digest == channel.digest)
        assert broker.extension.approve(token)
        driver.get(url)
        yield SimpleNamespace(driver=driver, broker=broker, url=url)
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
            page.shutdown()
            page.server_close()
            page_thread.join(5)
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

    def pin(frame, selector):
        request = dict(action='pin-password-target', password_protocol=1,
            page_id=listing['page_id'], frame_id=frame, top_url=url, selector=selector,
            mode='password', route='extension')
        if frame != top:
            request.update(frame_protocol=1, frame_origin='https://' + urlsplit(url).netloc)
        return broker.dispatch(request)

    def fill(target):
        handle = broker.dispatch(dict(action='search', query='localhost'))['entries'][0]['handle']
        return broker.dispatch(dict(action='fill', handle=handle, mode='password', target=target,
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
    driver.find_element('id', 'child').click()
    target = pin(child, '#child')
    assert target['ok'] and fill(target['target'])['ok']
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
