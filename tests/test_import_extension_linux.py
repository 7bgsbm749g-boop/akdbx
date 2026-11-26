"""User-initiated native import from a real browser into a disposable encrypted vault."""
import contextlib
import hashlib
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlencode, urlsplit
import zipfile

import pytest

from akdbx import browser_import
from akdbx.broker import Broker
from akdbx.local_https import start_local_unlock_server
from akdbx.totp import parse_setup
from test_local_https import free_port, post
from test_target import isolated_x11
from test_windows_unlock import certificates
from test_writes import MASTER, begin, reopened, template


def xdo(*args):
    return subprocess.run(['xdotool', *args], text=True, capture_output=True,
                          check=True, timeout=12).stdout.strip()


@contextlib.contextmanager
def launch(browser, binary, folder, profile, url):
    if browser == 'firefox':
        from selenium import webdriver
        from selenium.webdriver.firefox.service import Service
        options = webdriver.FirefoxOptions()
        options.binary_location = binary
        options.accept_insecure_certs = True
        package = folder.with_suffix('.xpi')
        with zipfile.ZipFile(package, 'w') as archive:
            for path in folder.iterdir():
                archive.write(path, path.name)
        with webdriver.Firefox(options=options, service=Service(shutil.which(os.environ.get('AKDBX_TEST_GECKODRIVER', 'geckodriver')))) as driver:
            driver.install_addon(str(package), temporary=True)
            driver.get(url)
            yield
    else:
        with subprocess.Popen([binary, '--user-data-dir=' + str(profile), '--load-extension=' + str(folder),
                               '--disable-extensions-except=' + str(folder), '--no-sandbox',
                               '--no-first-run', '--no-default-browser-check', '--ignore-certificate-errors', url],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
            try:
                yield
            finally:
                process.terminate()
                try:
                    process.wait(8)
                except subprocess.TimeoutExpired:
                    process.kill()


@pytest.mark.parametrize('browser', ['chrome', 'firefox'])
def test_toolbar_capture_and_private_save(browser, tmp_path, template, certificates, isolated_x11, monkeypatch):
    binary = os.environ.get('AKDBX_TEST_FIREFOX' if browser == 'firefox' else 'AKDBX_TEST_EXTENSION_BROWSER')
    if not binary:
        pytest.skip('set the path to a real extension-capable browser')
    fixture = json.loads(Path(__file__).with_name('synthetic_qr.json').read_text())
    # The page exposes only QR pixels. It has no setup link or code element.
    class Page(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(('''<canvas id="qr"></canvas><script>
                const rows = ROWS, c = document.querySelector('canvas'), ctx = c.getContext('2d');
                c.width = c.height = rows.length * 4;
                rows.forEach((row,y) => Array.from(row).forEach((bit,x) => {
                  ctx.fillStyle = bit === '1' ? 'black' : 'white'; ctx.fillRect(x*4,y*4,4,4);
                })); document.title = 'Synthetic QR ready';</script>'''.replace(
                    'ROWS', json.dumps(fixture['rows']))).encode())

        def log_message(self, *args):
            pass

    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'config'))
    monkeypatch.setenv('PYTHONPATH', str(Path(browser_import.__file__).parents[1]))
    cert, key = certificates
    key.chmod(0o600)
    page = ThreadingHTTPServer(('127.0.0.1', 0), Page)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    page.socket = tls.wrap_socket(page.socket, server_side=True)
    source = f'https://localhost:{page.server_port}/setup'
    thread = threading.Thread(target=page.serve_forever, daemon=True)
    thread.start()
    with contextlib.ExitStack() as cleanup:
        cleanup.callback(thread.join, 5)
        cleanup.callback(page.server_close)
        cleanup.callback(page.shutdown)
        database = tmp_path / 'test.kdbx'
        vault = reopened(template)
        vault.find_entries(title='Synthetic site', first=True).url = source
        vault.save(str(database))
        broker = Broker(None, object())
        cleanup.callback(broker.unlock_notifications.close)
        port = free_port()
        origin = f'https://localhost:{port}'
        capture = tmp_path / 'run' / 'u'
        server, url = start_local_unlock_server(broker, database, None, origin, cert, key, capture_socket=capture)
        cleanup.callback(server.server_close)
        cleanup.callback(server.shutdown)
        def submit(path, fields):
            return post(port, cert, path, urlencode(fields), f'localhost:{port}', origin)[0]
        assert submit('/?' + urlsplit(url).query, {'password': MASTER}) == 200
        prepared = begin(broker, 'setup-totp')
        before = database.read_bytes()
        folder = tmp_path / 'addon'
        browser_import.build_extension(folder, browser)
        # A shortcut invokes the browser's toolbar action, including its normal activeTab grant.
        manifest = folder / 'manifest.json'
        spec = json.loads(manifest.read_bytes())
        assert set(spec['permissions']) == {'activeTab', 'scripting', 'nativeMessaging'}
        spec['commands'] = {'_execute_action': {'suggested_key': {'default': 'Alt+Shift+Y'}}}
        manifest.write_text(json.dumps(spec))
        # In this disposable build the form driver enters the test link and presses Capture
        # when the browser opens the toolbar popup. It calls the shipped click handler.
        popup = folder / 'popup.html'
        popup.write_text(popup.read_text().replace('</body>', '<script src="test-form.js"></script></body>'))
        form_driver = folder / 'test-form.js'
        form_driver.write_text('document.querySelector("#destination").value=' + json.dumps(prepared['private_url'])
                               + '; document.querySelector("#capture").click();')
        cleanup.callback(form_driver.unlink)
        profile = tmp_path / 'profile'
        tool = Path(sys.executable).with_name('akdbx-browser-import')
        args = [str(tool), 'install-host', '--browser', browser, '--origin', origin, '--socket', str(capture)]
        if browser == 'chrome':
            digest = hashlib.sha256(os.fsencode(folder)).hexdigest()[:32]
            extension_id = ''.join(chr(97 + int(n, 16)) for n in digest)
            profile.mkdir(mode=0o700)
            args += ['--extension-id', extension_id, '--manifest-dir', str(profile / 'NativeMessagingHosts')]
        subprocess.run(args, check=True, capture_output=True)
        with launch(browser, binary, folder, profile, source):
            window = xdo('search', '--sync', '--onlyvisible', '--name', 'Synthetic QR ready').splitlines()[-1]
            xdo('windowfocus', '--sync', window, 'key', 'alt+shift+y')

            op = broker.writes.get(prepared['write_handle'])
            deadline = time.monotonic() + 10
            while not op.import_candidates and time.monotonic() < deadline:
                time.sleep(.1)
            captured = len(op.import_candidates)
            assert captured == 1, 'toolbar capture did not reach the private review'
        assert database.read_bytes() == before
        review = '/totp/review?' + urlsplit(prepared['private_url']).query
        with contextlib.closing(HTTPSConnection('localhost', port, timeout=10,
                                              context=ssl.create_default_context(cafile=str(cert)))) as client:
            client.request('GET', review)
            response = client.getresponse()
            assert response.status == 200
            nonce = re.search(rb'name="nonce" value="([^"]+)"', response.read()).group(1).decode()
        assert submit(review, {'choice': '0', 'confirmed': 'yes', 'nonce': nonce}) == 200
        entry = reopened(database).find_entries(title='Synthetic site', first=True)
        assert parse_setup(entry.otp).secret == parse_setup(fixture['uri']).secret
