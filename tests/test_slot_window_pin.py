"""TOTP fills into an agent desktop slot's Chrome when the broker runs on another X display.

The broker's own display (DISPLAY) is one disposable Xvfb. The slot's Chrome
runs on a second disposable Xvfb that requires its own Xauthority cookie, with
the slot's profile directory under the broker's --browser-profile-root, as an
agent desktop starts it. `pin-target --browser-slot` must find that Chrome and
its display itself and pin its window there; wrong slots, PIDs, windows and
focus changes refuse before any key. A synthetic page checks each code with
WebCrypto against its own synthetic key: that is the non-secret "accepted"
signal. Synthetic keys only; never a real profile, desktop or vault.
"""
import base64
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from pykeepass import PyKeePass

from akdbx import cli
from akdbx.broker import Broker, open_vault_with_password
from akdbx.browser_password import CDP, endpoint
from akdbx.target import DELIVERY, X11Typer, failure
from akdbx.totp import parse_setup
from akdbx.totp_capture import PENDING_FIELD
from test_target import isolated_x11  # noqa: F401  (fixture)
from test_writes import MASTER, template  # noqa: F401  (fixture)


def b32(raw):
    return base64.b32encode(raw).decode('ascii').rstrip('=')


PENDING_KEY = b32(secrets.token_bytes(20))
ENROLLED_KEY = b32(secrets.token_bytes(20))
SECRETS = (PENDING_KEY, ENROLLED_KEY)


def code_page(key):
    return f'''<!doctype html><meta charset="utf-8"><title>Synthetic two-factor</title>
<style>body{{margin:0;font:14px sans-serif}}input{{display:block;margin:8px}}</style>
<label>Authentication code <input id=otp autocomplete=one-time-code inputmode=numeric></label>
<script>
const KEY = {json.dumps(key)};
function unb32(s) {{
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of s) bits += a.indexOf(c).toString(2).padStart(5, '0');
  return new Uint8Array(bits.match(/.{{8}}/g).map(b => parseInt(b, 2)));
}}
async function code(step) {{
  const key = await crypto.subtle.importKey('raw', unb32(KEY), {{name: 'HMAC', hash: 'SHA-1'}}, false, ['sign']);
  const counter = new DataView(new ArrayBuffer(8)); counter.setUint32(4, step);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter.buffer));
  const o = h[19] & 15, n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}}
document.getElementById('otp').addEventListener('input', async e => {{
  const value = e.target.value;
  if (value.length !== 6) return;
  const step = Math.floor(Date.now() / 30000);
  const ok = value === await code(step) || value === await code(step - 1);
  document.body.dataset.result = ok ? 'accepted' : 'rejected';
}});
</script>'''


PAGES = {'/settings/two_factor/verify': code_page(PENDING_KEY), '/sessions/two-factor': code_page(ENROLLED_KEY)}
VERIFY = 'https://login.example.com/settings/two_factor/verify'
SIGN_IN = 'https://login.example.com/sessions/two-factor'
TITLE = 'Synthetic GitHub'


def uri(key):
    return parse_setup(key, label='synthetic-octocat').uri()


def xauthority(path, number=None):
    """One MIT-MAGIC-COOKIE-1 entry for this host and display `number` (any display if None)."""
    def field(data):
        return struct.pack('>H', len(data)) + data
    entry = (struct.pack('>H', 256) + field(socket.gethostname().encode())
             + field(b'' if number is None else str(number).encode())
             + field(b'MIT-MAGIC-COOKIE-1') + field(secrets.token_bytes(16)))
    path.write_bytes(entry)
    path.chmod(0o600)


def free_display():
    for number in range(180, 260):
        if not os.path.exists(f'/tmp/.X11-unix/X{number}') and not os.path.exists(f'/tmp/.X{number}-lock'):
            return number
    pytest.skip('no free X display number for the synthetic slot display')


def wait_for_cookie_server(xvfb, number, auth, monkeypatch):
    """Return once the server takes a connection with the cookie; else stop it and fail."""
    from Xlib import display as xdisplay
    deadline = time.monotonic() + 10
    while True:
        try:
            with monkeypatch.context() as patch:
                patch.setenv('XAUTHORITY', str(auth))
                xdisplay.Display(f':{number}').close()
            return
        except Exception:
            if xvfb.poll() is not None or time.monotonic() > deadline:
                if xvfb.poll() is None:
                    os.killpg(xvfb.pid, signal.SIGKILL)  # This test's own disposable X server.
                xvfb.wait(timeout=5)
                raise AssertionError('synthetic slot X server did not accept its cookie')
            time.sleep(.05)


@pytest.fixture
def slot_lab(isolated_x11, tmp_path, template, monkeypatch, request):  # noqa: F811
    binary = shutil.which('google-chrome') or shutil.which('chromium')
    if not binary or not shutil.which('openssl'):
        pytest.skip('slot window pins need Chrome/Chromium, Xvfb and openssl')
    broker_display = os.environ['DISPLAY']
    # The slot's own X server, which requires its cookie (as agent desktops run Xvfb :N -auth FILE).
    number = free_display()
    auth = tmp_path / 'slot-Xauthority'
    xauthority(auth, number)
    xvfb = subprocess.Popen(['Xvfb', f':{number}', '-screen', '0', '800x600x24', '-nolisten', 'tcp', '-auth', str(auth)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    def stop_xvfb():
        # Runs whatever fails later in this fixture (TLS, Chrome start): the exact child is never left running.
        if xvfb.poll() is None:
            os.killpg(xvfb.pid, signal.SIGKILL)  # This fixture's own disposable X server.
        xvfb.wait(timeout=5)
    request.addfinalizer(stop_xvfb)
    wait_for_cookie_server(xvfb, number, auth, monkeypatch)
    # Discovery sees only this test's two displays, never a real desktop of the host.
    from akdbx import browser_slots
    real_servers = browser_slots.x11_servers
    monkeypatch.setattr(browser_slots, 'x11_servers',
                        lambda: [name for name in real_servers() if name in {broker_display, f':{number}'}])
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=example.com',
                    '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=15)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            body = PAGES.get(self.path.split('?')[0], '<!doctype html>blank').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)

    class TLSServer(ThreadingHTTPServer):
        def get_request(self):
            client, address = self.socket.accept()
            client.settimeout(2)
            try:
                return tls.wrap_socket(client, server_side=True), address
            except BaseException:
                client.close()
                raise

    server = TLSServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    root = tmp_path / 'slot profiles'  # An operator root with a space (Chrome's title joins its arguments).
    root.mkdir(mode=0o700)
    profile = root / 'slot2'
    profile.mkdir(mode=0o700)
    (root / 'slot3').mkdir(mode=0o700)  # A slot whose Chrome is not running.
    os.symlink(f'{socket.gethostname()}-{os.getpid()}', root / 'slot3' / 'SingletonLock')
    environment = {**os.environ, 'DISPLAY': f':{number}', 'XAUTHORITY': str(auth),
                   'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/nonexistent/akdbx-slot-test', 'NO_AT_BRIDGE': '1'}
    environment.pop('AT_SPI_BUS_ADDRESS', None)
    log = (tmp_path / 'chrome.log').open('wb')
    chrome = subprocess.Popen([binary, f'--user-data-dir={profile}', '--no-first-run', '--no-default-browser-check',
                               '--disable-background-networking', '--disable-component-update', '--disable-sync',
                               '--disable-extensions', '--disable-gpu', '--disable-dev-shm-usage',
                               '--remote-debugging-port=0', '--no-proxy-server', '--ozone-platform=x11',
                               f'--host-resolver-rules=MAP login.example.com 127.0.0.1:{server.server_port}',
                               '--ignore-certificate-errors', '--window-position=0,0', '--window-size=640,480', VERIFY],
                              env=environment, stdout=subprocess.DEVNULL, stderr=log, start_new_session=True, umask=0o077)
    cdp = slot_x = None
    try:
        from Xlib import X, Xatom
        from Xlib.error import XError
        deadline = time.monotonic() + 60
        while cdp is None and time.monotonic() < deadline:
            assert chrome.poll() is None, 'synthetic slot Chrome exited'
            try:
                endpoint(profile)
                cdp = CDP(profile)
            except Exception:
                time.sleep(.05)
        assert cdp is not None, 'synthetic slot Chrome did not open its debugging endpoint'
        page = None
        while page is None and time.monotonic() < deadline:
            pages = [t for t in cdp.call('Target.getTargets')['targetInfos'] if t['type'] == 'page']
            page = pages[0]['targetId'] if pages else None
            time.sleep(.05)
        session = cdp.call('Target.attachToTarget', dict(targetId=page, flatten=True))['sessionId']
        # The test's own long-lived view of the slot display, with the slot's cookie (not the broker's
        # deadline-bound slot connection).
        from Xlib import display as xdisplay
        with monkeypatch.context() as patch:
            patch.setenv('XAUTHORITY', str(auth))
            slot_x = xdisplay.Display(f':{number}')
        xroot = slot_x.screen().root
        pid_atom = slot_x.intern_atom('_NET_WM_PID')
        window = None
        while window is None and time.monotonic() < deadline:
            for candidate in xroot.query_tree().children:
                try:
                    prop = candidate.get_full_property(pid_atom, Xatom.CARDINAL)
                    if (prop is not None and list(prop.value) == [chrome.pid] and candidate.get_wm_class()
                            and candidate.get_attributes().map_state == X.IsViewable):
                        window = candidate
                except XError:
                    continue
            time.sleep(.05)
        assert window is not None, 'synthetic slot Chrome window not found'
        # A second, foreign window on the slot display (owned by this test process).
        other = xroot.create_window(500, 400, 80, 80, 0, slot_x.screen().root_depth)
        other.set_wm_class('synthetic', 'Synthetic')
        other.change_property(slot_x.intern_atom('WM_CLIENT_MACHINE'), Xatom.STRING, 8, os.uname().nodename.encode())
        other.change_property(pid_atom, Xatom.CARDINAL, 32, [os.getpid()])
        other.map()

        def activate(w):
            xroot.change_property(slot_x.intern_atom('_NET_ACTIVE_WINDOW'), Xatom.WINDOW, 32, [w.id])
            w.set_input_focus(X.RevertToParent, X.CurrentTime)
            slot_x.sync()

        path = tmp_path / 'synthetic.kdbx'
        shutil.copyfile(template, path)
        vault = PyKeePass(str(path), password=MASTER)
        web = vault.find_groups(name='Web', first=True)
        entry = vault.add_entry(web, TITLE, 'synthetic-octocat', 'synthetic-github-password', url='https://login.example.com/login')
        entry.otp = uri(ENROLLED_KEY)
        entry.set_custom_property(PENDING_FIELD, uri(PENDING_KEY), protect=True)
        vault.save()
        broker = Broker(open_vault_with_password(path, MASTER), X11Typer(), browser_profile_root=root)
        yield SimpleNamespace(broker=broker, cdp=cdp, session=session, chrome=chrome, window=window, other=other,
                              activate=activate, number=number, broker_display=broker_display, auth=auth, root=root,
                              broker_x=isolated_x11)
    except Exception:
        log.flush()
        print('Synthetic slot Chrome diagnostic:', (tmp_path / 'chrome.log').read_text(errors='replace')[-3000:])
        raise
    finally:
        if slot_x is not None:
            slot_x.close()
        if cdp is not None:
            try:
                cdp.call('Browser.close')
            except Exception:
                pass
            cdp.close()
        for process in (chrome, xvfb):
            try:
                process.wait(timeout=8) if process is chrome else process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)  # This fixture's own disposable process group.
                process.wait(timeout=5)
        log.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def evaluate(lab, expression, gesture=False):
    result = lab.cdp.call('Runtime.evaluate', dict(expression=expression, returnByValue=True, userGesture=gesture), lab.session)
    assert 'exceptionDetails' not in result, result
    return result['result'].get('value')


def open_page(lab, url):
    lab.cdp.call('Page.navigate', dict(url=url), lab.session)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if evaluate(lab, 'location.href') == url and evaluate(lab, "document.readyState === 'complete' && !!window.otp"):
                return
        except Exception:
            pass
        time.sleep(.05)
    raise AssertionError('synthetic code page did not load')


def focus_code_field(lab):
    evaluate(lab, "otp.value = ''; delete document.body.dataset.result")
    lab.activate(lab.window)
    evaluate(lab, 'window.focus(); otp.focus()', gesture=True)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if evaluate(lab, "document.hasFocus() && document.activeElement === otp"):
            return
        time.sleep(.02)
    raise AssertionError('synthetic code field did not receive focus')


def handle(lab):
    return [e for e in lab.broker.dispatch(dict(action='search', query=TITLE))['entries'] if e['title'] == TITLE][0]['handle']


def pin(lab, slot='slot2', pid=None, window=None):
    request = dict(action='pin-target', pid=lab.chrome.pid if pid is None else pid,
                   window=lab.window.id if window is None else window, target_protocol=1)
    if slot is not None:
        request['browser_slot'] = slot
    return lab.broker.dispatch(request)


def fill(lab, target, url, pending):
    request = dict(action='fill-totp', handle=handle(lab), target=target, target_protocol=1, target_url=url)
    if pending:
        request['pending'] = True
    return lab.broker.dispatch(request)


def fill_code(lab, url, pending):
    """Pin the slot window and fill a fresh code; wait out a code near expiry."""
    for _ in range(2):
        focus_code_field(lab)
        pinned = pin(lab)
        assert pinned == dict(ok=True, target=pinned['target'], pid=lab.chrome.pid, window=lab.window.id,
                              expires_in=30, target_delivery=DELIVERY, browser_slot='slot2'), pinned
        response = fill(lab, pinned['target'], url, pending)
        if 'retry_after' not in response:
            return response
        time.sleep(response['retry_after'] + .2)
    raise AssertionError('authenticator code stayed near expiry')


def result(lab):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = evaluate(lab, 'document.body.dataset.result || null')
        if value:
            return value
        time.sleep(.05)
    return None


def field_empty(lab):
    time.sleep(.3)
    return evaluate(lab, "otp.value === '' && !document.body.dataset.result")


def clean(*items):
    text = json.dumps(items)
    return not any(value in text for value in SECRETS)


def test_the_broker_display_does_not_see_the_slot_window(slot_lab):
    """The reported failure: a plain pin opens the broker's own display, where this window is not."""
    lab = slot_lab
    assert lab.broker_display != f':{lab.number}'
    open_page(lab, VERIFY)
    focus_code_field(lab)
    assert pin(lab, slot=None) == failure()
    assert field_empty(lab)


def test_pending_and_enrolled_codes_fill_the_slot_chrome(slot_lab):
    lab = slot_lab
    open_page(lab, VERIFY)
    filled = fill_code(lab, VERIFY, pending=True)
    assert filled == dict(ok=True, filled='totp', target_delivery=DELIVERY), filled
    assert result(lab) == 'accepted'
    open_page(lab, SIGN_IN)
    later = fill_code(lab, SIGN_IN, pending=False)
    assert later == dict(ok=True, filled='totp', target_delivery=DELIVERY) and result(lab) == 'accepted'
    assert clean(filled, later)


def test_wrong_slot_pid_window_and_display_refuse_before_any_key(slot_lab):
    lab = slot_lab
    open_page(lab, VERIFY)
    focus_code_field(lab)
    # Another process's PID, though the window is the slot Chrome's.
    assert pin(lab, pid=os.getpid()) == failure()
    # The foreign window on the slot display, with its owner's PID or the slot Chrome's.
    assert pin(lab, pid=os.getpid(), window=lab.other.id) == failure()
    assert pin(lab, window=lab.other.id) == failure()
    # A window of the broker's own display, under the slot's Chrome PID.
    assert pin(lab, window=lab.broker_x.windows[0].id) == failure()
    # Unknown, invalid and not-running slots name their cause.
    assert pin(lab, slot='slot7') == dict(ok=False, error='browser slot unknown: slot7 (slots: slot2, slot3)')
    assert pin(lab, slot='../slot2') == dict(ok=False, error='browser slot invalid: use a slot name such as slot1')
    assert pin(lab, slot='slot3') == dict(
        ok=False, error='browser slot not running: slot3 has no verified Chrome on a local X display; start the slot and pin again')
    assert field_empty(lab)


def test_a_focus_change_after_the_pin_refuses_the_fill(slot_lab):
    lab = slot_lab
    open_page(lab, VERIFY)
    for _ in range(2):
        focus_code_field(lab)
        pinned = pin(lab)
        assert pinned['ok']
        lab.activate(lab.other)  # Another window takes the slot display's focus.
        response = fill(lab, pinned['target'], VERIFY, pending=True)
        if 'retry_after' not in response:
            break
        time.sleep(response['retry_after'] + .2)  # A code near expiry refuses first; try with a fresh one.
    assert response['ok'] is False and response['delivery'] == 'not-started'
    lab.activate(lab.window)
    assert field_empty(lab)
    # A slot pin is single use, and it binds the slot's display: it never types on the broker's.
    response = fill(lab, pinned['target'], VERIFY, pending=True)
    assert response['ok'] is False and field_empty(lab)


def test_a_broker_without_slots_refuses_a_slot_pin(slot_lab, tmp_path):
    lab = slot_lab
    plain = Broker(lab.broker.vault, X11Typer())
    assert plain.dispatch(dict(action='pin-target', pid=lab.chrome.pid, window=lab.window.id, target_protocol=1,
                               browser_slot='slot2')) == dict(
        ok=False, error='browser slot not supported: this broker has no --browser-profile-root; omit --browser-slot')


def test_cli_slot_pin_and_pending_fill(slot_lab, monkeypatch, capsys):
    lab = slot_lab
    monkeypatch.setattr(cli, 'request', lambda socket, payload, **kwargs: lab.broker.dispatch(payload))
    monkeypatch.setenv('AGENT_DESKTOP_SLOT', 'slot2')
    open_page(lab, VERIFY)
    # The desktop's variable alone does not make a window pin a slot pin: a native app needs a plain one.
    focus_code_field(lab)
    assert cli.main(['pin-target', '--pid', str(lab.chrome.pid), '--window', str(lab.window.id)]) == 1
    assert 'browser_slot' not in capsys.readouterr().out
    for _ in range(2):
        focus_code_field(lab)
        assert cli.main(['pin-target', '--pid', str(lab.chrome.pid), '--window', str(lab.window.id),
                         '--browser-slot', 'slot2']) == 0
        pinned = json.loads(capsys.readouterr().out)
        assert pinned['browser_slot'] == 'slot2'
        assert cli.main(['search', TITLE]) == 0
        found = json.loads(capsys.readouterr().out)['entries'][0]['handle']
        code = cli.main(['fill-totp', found, '--pending', '--target-url', VERIFY, '--target', pinned['target']])
        out = capsys.readouterr()
        if code == 0:
            break
        time.sleep(json.loads(out.out).get('retry_after', 0) + .2)
    assert code == 0 and clean(out.out, out.err) and result(lab) == 'accepted'


def test_a_slot_display_needs_its_cookie_and_a_local_peer_of_this_user(slot_lab):
    """Without the cookie the slot's X server refuses; a slot connection never leaves a Unix socket."""
    from Xlib import display as xdisplay, error
    from akdbx.target import _slot_auth
    lab = slot_lab
    previous = os.environ.pop('XAUTHORITY', None)
    try:
        with pytest.raises(Exception):
            xdisplay.Display(f':{lab.number}').close()  # No cookie: refused.
    finally:
        if previous is not None:
            os.environ['XAUTHORITY'] = previous
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(error.XauthError):
            _slot_auth(tcp, lab.number)  # No cookie for anything but a local Unix peer of this user.
    finally:
        tcp.close()


def test_a_unix_peer_of_another_user_gets_no_cookie(monkeypatch):
    """The SO_PEERCRED user is checked before any cookie file is looked up."""
    from Xlib import error
    from akdbx import browser_slots, target

    class ForeignPeer:
        family = socket.AF_UNIX

        def getsockopt(self, *_):
            return struct.pack('3i', 4242, os.getuid() + 1, 0)

    def no_lookup(_):
        raise AssertionError('cookie file looked up for a foreign peer')
    monkeypatch.setattr(browser_slots, 'x11_cookie_file', no_lookup)
    with pytest.raises(error.XauthError):
        target._slot_auth(ForeignPeer(), 101)


def test_a_silent_x_server_ends_at_the_deadline(monkeypatch):
    """A server that accepts and never answers cannot hold a slot connection (and the vault lock)."""
    from akdbx import target
    monkeypatch.setattr(target, 'SLOT_X_DEADLINE', 1.0)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for number in range(900, 1000):
        if os.path.exists(f'/tmp/.X11-unix/X{number}'):
            continue
        try:
            listener.bind(f'\0/tmp/.X11-unix/X{number}')  # python-xlib's abstract fallback name.
            break
        except OSError:
            continue
    else:
        pytest.skip('no free abstract X socket name')
    listener.listen(1)
    accepted = []
    worker = threading.Thread(target=lambda: accepted.append(listener.accept()[0]), daemon=True)
    worker.start()
    started = time.monotonic()
    try:
        with pytest.raises(Exception):
            target._connect(f':{number}').close()
        assert time.monotonic() - started < 5
    finally:
        listener.close()
        for connection in accepted:
            connection.close()


def test_the_cookie_comes_from_the_connected_server_also_with_displayfd(tmp_path, monkeypatch):
    """An Xvfb that picks its own number (-displayfd) has no :N in argv; its -auth still gives the cookie."""
    import select
    from akdbx import target
    auth = tmp_path / 'displayfd-Xauthority'
    xauthority(auth)
    read_fd, write_fd = os.pipe()
    xvfb = subprocess.Popen(['Xvfb', '-displayfd', str(write_fd), '-screen', '0', '320x240x24', '-nolisten', 'tcp',
                             '-auth', str(auth)], pass_fds=(write_fd,), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    os.close(write_fd)
    try:
        try:
            assert select.select([read_fd], [], [], 10)[0], 'synthetic X server did not start'
            number = int(os.read(read_fd, 32).decode().strip())
        finally:
            os.close(read_fd)
        wait_for_cookie_server(xvfb, number, auth, monkeypatch)
        monkeypatch.delenv('XAUTHORITY', raising=False)  # Only the server's own -auth can give the cookie.
        connection = target._connect(f':{number}')
        try:
            assert connection.screen().root.id > 0
        finally:
            connection.close()
    finally:
        if xvfb.poll() is None:
            os.killpg(xvfb.pid, signal.SIGKILL)
        xvfb.wait(timeout=5)
