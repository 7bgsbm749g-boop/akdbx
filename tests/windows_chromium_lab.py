"""A disposable headless Chromium for native Windows (and Linux extension) DOM-route tests.

Synthetic page, profile, certificate and credentials only. The browser runs
headless in a new private user-data directory, so it never takes the desktop
foreground and never reads an existing profile. The observer connection only
prepares and inspects the synthetic page: every credential reaches the page
through the production broker route under test.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
import time

FORM = '''<!doctype html><meta charset="utf-8"><title>akdbx synthetic lab</title>
<form id="signup"><label>Account<input id="username" autocomplete="username"></label>
<label>Password<input id="password" type="password" autocomplete="current-password"></label>
<label>New password<input id="new-password" type="password" autocomplete="new-password"></label>
<label>Repeat<input id="confirmation" type="password" autocomplete="new-password"></label>
<input id="plain" type="password"><input id="other" autocomplete="username"></form>
<p id="result"></p>
<script>
window.syntheticEvents = [];
document.addEventListener('input', e => syntheticEvents.push({field: e.target.id, trusted: e.isTrusted}));
// The page reports only digests and equality; a test never reads a field value.
async function digest(id) {
  const data = new TextEncoder().encode(document.getElementById(id).value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}
</script>'''
FRAME = '''<!doctype html><meta charset="utf-8"><title>akdbx synthetic frame lab</title>
<h1>Outer page</h1><iframe id="login-frame" src="{}" style="width:600px;height:300px;border:0"></iframe>'''
CARD = '''<!doctype html><meta charset="utf-8"><title>akdbx synthetic card lab</title>
<style>input{display:block;width:230px;height:25px;margin:5px}</style>
<input id="address" autocomplete="street-address"><input id="number" autocomplete="cc-number">
<input id="name" autocomplete="cc-name"><input id="expiry" autocomplete="cc-exp">
<input id="csc" autocomplete="cc-csc"><input id="password" type="password" autocomplete="current-password">
<script>
window.syntheticEvents = [];
document.addEventListener('input', e => syntheticEvents.push({field: e.target.id, trusted: e.isTrusted}));
async function digest(id) {
  const data = new TextEncoder().encode(document.getElementById(id).value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}
</script>'''
# One loopback TLS server answers for every synthetic hostname.
HOSTS = ('signup.example.com', 'auth.example.com', 'evil.example.net')
ORIGIN = 'https://signup.example.com'


def browser_binary():
    """Locate an installed Chromium browser by fixed path, never through PATH."""
    override = os.environ.get('AKDBX_TEST_BROWSER')
    if override:
        return Path(override)
    roots = [os.environ.get(name) for name in ('ProgramFiles', 'ProgramFiles(x86)', 'LOCALAPPDATA')]
    for relative in (r'Google\Chrome\Application\chrome.exe', r'Microsoft\Edge\Application\msedge.exe'):
        for root in roots:
            if root and (Path(root) / relative).is_file():
                return Path(root) / relative
    return None


class Observer:
    """Test-side CDP client. It never carries a credential into the page."""

    def __init__(self, url):
        import websocket
        self.socket = websocket.create_connection(url, timeout=10, suppress_origin=True,
                                                  http_no_proxy=['127.0.0.1'])
        self.counter = 0

    def call(self, method, params=None, session=None, timeout=15):
        self.counter += 1
        request = dict(id=self.counter, method=method, params=params or {})
        if session:
            request['sessionId'] = session
        self.socket.send(json.dumps(request))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.socket.settimeout(max(.01, deadline - time.monotonic()))
            response = json.loads(self.socket.recv())
            if response.get('id') == self.counter:
                assert 'error' not in response, response.get('error')
                return response['result']
        raise AssertionError('synthetic Chromium CDP response timed out')

    def evaluate(self, expression, session, *, await_promise=False):
        response = self.call('Runtime.evaluate', dict(expression=expression, returnByValue=True,
                                                      awaitPromise=await_promise), session)
        assert 'exceptionDetails' not in response, response['exceptionDetails'].get('text')
        return response['result'].get('value')

    def close(self):
        try:
            self.socket.close()
        except Exception:
            pass


class Lab:
    def __init__(self, process, observer, session, page_id, profile, origin, version):
        self.process, self.observer, self.session = process, observer, session
        self.page_id, self.profile, self.origin, self.version = page_id, profile, origin, version

    def evaluate(self, expression, **options):
        return self.observer.evaluate(expression, self.session, **options)

    def navigate(self, path):
        url = self.origin + path
        self.observer.call('Page.navigate', {'url': url}, self.session)
        self.wait('location.href === ' + json.dumps(url) + " && document.readyState === 'complete'")
        return url

    def wait(self, expression, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.evaluate(expression):
                return
            time.sleep(.02)
        raise AssertionError('synthetic page did not reach the expected state: ' + expression)

    @property
    def main_frame(self):
        return self.observer.call('Page.getFrameTree', session=self.session)['frameTree']['frame']['id']

    def digest(self, field):
        return self.evaluate(f'digest({json.dumps(field)})', await_promise=True)

    def untouched(self):
        return self.evaluate("Array.from(document.querySelectorAll('input')).every(e => !e.value)")


@contextmanager
def chromium_lab(directory, certificate, key, *, pages=None, binary=None, extension=None, hosts=(), native_hosts=None,
                 restart=False):
    """Serve the synthetic pages over loopback TLS and run one private browser.

    ``restart``: start the browser again on the profile that an earlier run in ``directory`` left.
    """
    binary = binary or browser_binary()
    assert binary is not None, 'a Chromium browser is required'
    documents = {'/login': FORM, '/signup': FORM, '/card': CARD,
                 '/framed': FRAME.format('https://auth.example.com/login'),
                 '/hostile': FRAME.format('https://evil.example.net/login'), **(pages or {})}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = documents.get(self.path.split('?', 1)[0].split('#', 1)[0])
            if body is None:
                self.send_error(404)
                return
            # A page is HTML text; another resource is (bytes, content type, extra headers).
            body, kind, headers = body if isinstance(body, tuple) else (body, 'text/html; charset=utf-8', {})
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(302 if 'Location' in headers else 200)
            self.send_header('Content-Type', kind)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = ORIGIN
    rules = ','.join(f'MAP {host} 127.0.0.1:{server.server_port}' for host in (*HOSTS, *hosts))
    # A test extension replaces --disable-extensions; Chrome 137+ also needs the
    # load switch re-enabled for an unpacked extension in a disposable profile.
    extension_args = (['--disable-extensions'] if extension is None else
                      ['--load-extension=' + str(extension), '--disable-extensions-except=' + str(extension),
                       '--disable-features=DisableLoadExtensionCommandLineSwitch'])
    profile = Path(directory) / 'synthetic-profile'
    if restart:
        assert profile.is_dir(), 'no earlier browser profile to restart'
        (profile / 'DevToolsActivePort').unlink(missing_ok=True)  # The port file of the closed browser.
    elif os.name == 'nt':
        import win32file
        from akdbx import windows_security as security
        # Private and inheritable: the browser's own port file gets the same DACL.
        win32file.CreateDirectoryW(str(profile), security.private_attributes(directory=True))
    else:
        profile.mkdir(mode=0o700)
    if extension is not None and not restart:
        # Developer mode on, as in every profile where a user loaded the unpacked extension: without it
        # Chromium blocks the unpacked extension when it reloads (chrome.runtime.reload()).
        (profile / 'Default').mkdir()
        (profile / 'Default' / 'Preferences').write_text(json.dumps({'extensions': {'ui': {'developer_mode': True}}}),
                                                         encoding='utf-8')
    # Linux only: a host without unprivileged user namespaces cannot start
    # Chromium's sandbox; the disposable synthetic profile may then run without it.
    sandbox = ['--no-sandbox'] if os.name != 'nt' and os.environ.get('AKDBX_TEST_BROWSER_NO_SANDBOX') == '1' else []
    # Optional extra switches for one run, for example --force-color-profile=display-p3-d65 to render as a
    # colour-managed display would.
    sandbox += os.environ.get('AKDBX_TEST_BROWSER_EXTRA_ARGS', '').split()
    if native_hosts:
        # Linux Chromium reads user-level native-messaging hosts from the profile folder.
        (profile / 'NativeMessagingHosts').mkdir(mode=0o700, exist_ok=restart)
        for name, manifest in native_hosts.items():
            (profile / 'NativeMessagingHosts' / (name + '.json')).write_text(json.dumps(manifest), encoding='utf-8')
    log = (Path(directory) / 'synthetic-chromium.log').open('wb')
    process = subprocess.Popen(
        [str(binary), '--headless=new', '--user-data-dir=' + str(profile), '--remote-debugging-port=0',
         '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
         '--disable-component-update', '--disable-sync', *extension_args, *sandbox, '--disable-gpu',
         '--window-size=1200,900', '--no-proxy-server', '--host-resolver-rules=' + rules,
         '--ignore-certificate-errors', origin + '/login'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
        # Linux: the production endpoint check refuses a group-writable port file.
        **({} if os.name == 'nt' else {'umask': 0o077}))
    observer = None
    try:
        # The browser creates its port file before it writes the complete
        # header, and holds it open while it writes. Existence is not
        # readiness: wait with the production validator, unweakened, and retry
        # only this startup phase of the owned synthetic browser. The published
        # port can also precede a responsive WebSocket server.
        from akdbx.browser_password import endpoint
        deadline = time.monotonic() + 60
        while observer is None:
            assert process.poll() is None, 'synthetic Chromium exited during startup'
            assert time.monotonic() < deadline, 'synthetic Chromium did not open its debugging endpoint'
            try:
                observer = Observer(endpoint(profile))
            except Exception:
                time.sleep(.05)
        session = page_id = None
        while time.monotonic() < deadline:
            pages_found = [t for t in observer.call('Target.getTargets')['targetInfos'] if t['type'] == 'page']
            if pages_found:
                page_id = pages_found[0]['targetId']
                session = observer.call('Target.attachToTarget', dict(targetId=page_id, flatten=True))['sessionId']
                if observer.evaluate("document.readyState === 'complete' && !!document.getElementById('password')", session):
                    break
            time.sleep(.05)
        assert session, 'synthetic Chromium page did not initialize'
        version = observer.call('Browser.getVersion')['product']
        yield Lab(process, observer, session, page_id, profile, origin, version)
    finally:
        try:
            if observer is not None and process.poll() is None:
                observer.call('Browser.close', timeout=3)
        except Exception:
            pass
        if observer is not None:
            observer.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # This exact disposable process only; never a shared browser.
            process.kill()
            process.wait(timeout=10)
        log.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
