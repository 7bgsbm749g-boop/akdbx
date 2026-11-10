"""Real Chromium input regression, synthetic page/profile on a new Xvfb only.

CDP only prepares/observes the synthetic form. All nonempty input goes through
our production Broker/X11Typer fill path. This intentionally tests the transport under repair,
not a browser driver's text-insertion path. Never attaches to an existing app.
"""
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time
from urllib.parse import quote

import pytest

from akdbx.broker import Broker
from akdbx.target import DELIVERY, X11Typer
from test_broker import Entry, Vault
from test_target import isolated_x11


class PipeCDP:
    def __init__(self, write_fd, read_fd, process):
        self.write_fd, self.read_fd, self.process = write_fd, read_fd, process
        self.buffer, self.counter = b'', 0

    def call(self, method, params=None, session=None, timeout=15):
        self.counter += 1
        request = dict(id=self.counter, method=method, params=params or {})
        if session:
            request['sessionId'] = session
        os.write(self.write_fd, json.dumps(request).encode() + b'\0')
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            while b'\0' in self.buffer:
                data, self.buffer = self.buffer.split(b'\0', 1)
                response = json.loads(data)
                if response.get('id') == self.counter:
                    assert 'error' not in response, response.get('error')
                    return response['result']
            assert self.process.poll() is None, 'isolated Chromium exited'
            if select.select([self.read_fd], [], [], min(1, deadline - time.monotonic()))[0]:
                data = os.read(self.read_fd, 65536)
                assert data, 'isolated Chromium debugging pipe closed'
                self.buffer += data
        raise AssertionError('isolated Chromium CDP response timed out')

    def evaluate(self, expression, session):
        response = self.call('Runtime.evaluate', dict(expression=expression, returnByValue=True), session)
        assert 'exceptionDetails' not in response
        return response['result'].get('value')


@pytest.fixture
def synthetic_chromium(isolated_x11, tmp_path):
    binary = shutil.which('google-chrome') or shutil.which('chromium')
    if not binary:
        pytest.skip('optional synthetic browser regression requires Chromium')
    lab = isolated_x11
    # No existing profile, desktop or debugging endpoint is ever inspected.
    child_read, agent_write = os.pipe()
    agent_read, child_write = os.pipe()
    profile = tmp_path / 'synthetic-chromium-profile'
    html = '''<!doctype html><title>Agentic synthetic transport lab</title>
    <label>Username<input id="username" autocomplete="username"></label>
    <label>Password<input id="password" type="password" autocomplete="new-password"></label>
    <script>window.syntheticEvents=[];
    document.addEventListener('input', e=>syntheticEvents.push({field:e.target.id,trusted:e.isTrusted}));</script>'''
    certificate, key = tmp_path / 'lab.crt', tmp_path / 'lab.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=127.0.0.1', '-keyout', str(key), '-out', str(certificate)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            data = html.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    url = 'https://127.0.0.1:' + str(server.server_port) + '/login'
    profile.mkdir(mode=0o700)
    args = [binary, '--user-data-dir=' + str(profile), '--no-first-run', '--no-default-browser-check',
            '--disable-background-networking', '--disable-component-update', '--disable-sync',
            '--disable-extensions', '--ozone-platform=x11', '--disable-gpu', '--disable-dev-shm-usage', '--renderer-process-limit=1',
            '--remote-debugging-pipe', '--remote-debugging-port=0', '--ignore-certificate-errors', url]
    # A tiny exec shim binds only the child's fd 3/4, without changing the
    # parent's descriptors or sharing any canonical browser connection.
    shim = 'import os,sys;os.dup2(int(sys.argv[1]),3);os.dup2(int(sys.argv[2]),4);os.execv(sys.argv[3],sys.argv[3:])'
    environment = {**os.environ, 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/nonexistent/akdbx-synthetic-bus', 'NO_AT_BRIDGE': '1'}
    environment.pop('AT_SPI_BUS_ADDRESS', None)
    log = (tmp_path / 'synthetic-chromium.log').open('wb')
    process = subprocess.Popen([sys.executable, '-c', shim, str(child_read), str(child_write), *args],
                               pass_fds=(child_read, child_write), env=environment,
                               stdout=subprocess.DEVNULL, stderr=log, start_new_session=True, umask=0o077)
    os.close(child_read)
    os.close(child_write)
    cdp = PipeCDP(agent_write, agent_read, process)
    try:
        session = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            pages = [t for t in cdp.call('Target.getTargets')['targetInfos'] if t['type'] == 'page']
            if pages:
                session = cdp.call('Target.attachToTarget', dict(targetId=pages[0]['targetId'], flatten=True))['sessionId']
                if cdp.evaluate("document.readyState === 'complete' && !!document.getElementById('password')", session):
                    break
            time.sleep(.05)
        assert session, 'synthetic Chromium page did not initialize'
        from Xlib import Xatom
        root = lab.display.screen().root
        pid_atom = lab.display.intern_atom('_NET_WM_PID')
        candidates = []
        for window in root.query_tree().children:
            prop = window.get_full_property(pid_atom, Xatom.CARDINAL)
            if (prop is not None and list(prop.value) == [process.pid] and window.get_wm_class()
                    and window.get_attributes().map_state == lab.X.IsViewable):
                candidates.append(window)
        assert len(candidates) == 1, 'isolated Chromium client window identity is ambiguous'
        window = candidates[0]
        lab.activate(window)
        version = cdp.call('Browser.getVersion')['product']
        yield lab, process, cdp, session, window, version
    except Exception:
        log.flush()
        # Synthetic launch diagnostics only. Never runs against a real profile.
        diagnostic = (tmp_path / 'synthetic-chromium.log').read_text(errors='replace')[-3000:]
        print('Isolated Chromium diagnostic:', diagnostic)
        raise
    finally:
        try:
            if process.poll() is None:
                cdp.call('Browser.close', timeout=3)
        except Exception:
            pass
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            import signal
            try:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # start_new_session=True makes this the fixture's exact
                    # disposable process group, never the shared browser.
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            except ProcessLookupError:
                process.wait(timeout=5)
        os.close(agent_write)
        os.close(agent_read)
        log.close()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)


def wait_for(cdp, session, expression):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if cdp.evaluate(expression, session):
            return
        time.sleep(.02)
    raise AssertionError('directed X11 keys did not reach the expected synthetic Chromium field')


def test_x11_window_pins_refuse_password_and_login(synthetic_chromium):
    lab, process, cdp, session, window, version = synthetic_chromium
    broker = Broker(Vault([Entry()]), X11Typer())
    for mode in ['password', 'login']:
        cdp.evaluate("username.value='';password.value='';password.focus()", session)
        lab.activate(window)
        handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
        pin = broker.dispatch(dict(action='pin-target', pid=process.pid, window=window.id, target_protocol=1))
        assert pin['ok']
        result = broker.dispatch(dict(action='fill', mode=mode, handle=handle, target=pin['target'], target_protocol=1))
        assert not result['ok'] and result['delivery'] == 'not-started'
        assert cdp.evaluate("username.value === '' && password.value === ''", session)


def test_totp_reaches_only_focused_synthetic_chromium_field(synthetic_chromium):
    lab, process, cdp, session, window, _ = synthetic_chromium
    class TotpEntry(Entry):
        # Public RFC test vector, never an enrolled account or real key.
        otp = 'otpauth://totp/synthetic?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    broker = Broker(Vault([TotpEntry()]), X11Typer(), wall_clock=lambda: 1111111111)
    cdp.evaluate("username.value='';password.value='';password.focus()", session)
    lab.activate(window)
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    pin = broker.dispatch(dict(action='pin-target', pid=process.pid, window=window.id, target_protocol=1))
    assert pin['ok']
    response = broker.dispatch(dict(action='fill-totp', handle=handle, target=pin['target'],
                                    target_protocol=1, target_url='https://example.com/challenge'))
    assert response == dict(ok=True, filled='totp', target_delivery=DELIVERY)
    wait_for(cdp, session, "password.value === '050471'")
    assert cdp.evaluate('username.value.length', session) == 0
    assert cdp.evaluate('document.activeElement.id', session) == 'password'
