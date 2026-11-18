"""Real-desktop Windows acceptance check. Synthetic credentials only.

Run from the checkout on an interactive Windows desktop, as a standard user:

    .\\.venv\\Scripts\\python.exe tests\\windows_desktop_check.py --report evidence\\windows-desktop.json

The check starts the installed ``akdbx`` CLI broker on a private test pipe and a
synthetic vault, unlocks it over loopback HTTPS, and fills native Win32 edit
controls and local browser fixtures with directed ``WM_CHAR`` delivery. It takes
the foreground several times; do not type or hold keys while it runs. Fixtures
report only SHA-256 digests of field contents; the report never contains values.
Pytest does not collect this file.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes as W
import hashlib
import hmac
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import platform
import queue
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import urlencode, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WM_APP = 0x8000

MASTER = 'synthetic desktop master ✓'
TOTP_SECRET = 'JBSWY3DPEHPK3PXP'
ENTRIES = {
    'Desktop ASCII': ('synthetic.user@example.test',
                      'Synth3tic !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ pass', 'https://native.test'),
    'Desktop Unicode': ('séverine-用户', 'pässwörd-Ωμέγα-日本語-😀-𝄞', 'https://unicode.test'),
    'Desktop TOTP': ('totp-user', 'synthetic totp password', 'https://totp.test'),
    'Desktop Generated': ('generated-user', 'synthetic old generated', 'https://generated.test'),
    'Desktop Import': ('import-user', 'synthetic old import', 'https://import.test'),
    'Browser Login': ('browser-user@example.test', 'Br0wser-pässwörd-😀 !@#', 'https://browser.test'),
}
IMPORTED = 'synthetic imported ✓ pässwörd'

user32 = ctypes.WinDLL('user32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32.GetForegroundWindow.restype = W.HWND
user32.GetWindowThreadProcessId.argtypes = [W.HWND, ctypes.POINTER(W.DWORD)]
user32.GetWindowThreadProcessId.restype = W.DWORD
user32.AttachThreadInput.argtypes = [W.DWORD, W.DWORD, W.BOOL]
user32.SetForegroundWindow.argtypes = [W.HWND]
user32.BringWindowToTop.argtypes = [W.HWND]
user32.ShowWindow.argtypes = [W.HWND, ctypes.c_int]
user32.SetFocus.argtypes = [W.HWND]
user32.SetFocus.restype = W.HWND
user32.GetFocus.restype = W.HWND
user32.IsWindow.argtypes = [W.HWND]


def digest(value: str) -> str:
    # Browsers report the field after each UTF-16 unit, so a value can briefly
    # end in half of a surrogate pair.
    return hashlib.sha256(value.encode('utf-8', errors='surrogatepass')).hexdigest()


def totp(secret: str, moment: float) -> str:
    key = base64.b32decode(secret)
    mac = hmac.new(key, struct.pack('>Q', int(moment // 30)), 'sha1').digest()
    offset = mac[-1] & 15
    return f'{(struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7fffffff) % 1000000:06d}'


def window_owner(hwnd) -> tuple[int, int]:
    pid = W.DWORD()
    thread = user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return thread, pid.value


def bring_to_front(hwnd, focus=None) -> bool:
    """Take the foreground for a fixture window, as a user click would."""
    foreground = user32.GetForegroundWindow()
    current = kernel32.GetCurrentThreadId()
    other = window_owner(foreground)[0] if foreground else 0
    attached = bool(other and other != current and user32.AttachThreadInput(current, other, True))
    try:
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        user32.BringWindowToTop(hwnd)
        user32.SetForegroundWindow(hwnd)
        if focus:
            user32.SetFocus(focus)
    finally:
        if attached:
            user32.AttachThreadInput(current, other, False)
    return user32.GetForegroundWindow() == hwnd


# --------------------------------------------------------------------------
# Native Win32 fixture process: a top-level window with four Unicode EDITs.
# --------------------------------------------------------------------------

def native_fixture(tag: str, x: int) -> None:
    import win32api
    import win32con
    import win32gui

    commands: queue.Queue[str] = queue.Queue()
    edits: list[int] = []
    state = {'hwnd': None}

    def respond(payload):
        sys.stdout.write(json.dumps(payload) + '\n')
        sys.stdout.flush()

    def handle(command):
        name, _, argument = command.strip().partition(' ')
        hwnd = state['hwnd']
        if name == 'info':
            respond({'pid': os.getpid(), 'hwnd': hwnd, 'edits': edits})
        elif name == 'focus':
            # The harness takes the foreground; this thread then moves focus.
            focus = edits[int(argument)]
            user32.SetFocus(focus)
            respond({'foreground': user32.GetForegroundWindow() == hwnd,
                     'focused': user32.GetFocus() == focus})
        elif name == 'report':
            fields = [win32gui.GetWindowText(edit) for edit in edits]
            respond({'fields': [{'sha256': digest(value), 'units': len(value.encode('utf-16-le', errors='surrogatepass')) // 2}
                                for value in fields]})
        elif name == 'clear':
            for edit in edits:
                win32gui.SetWindowText(edit, '')
            respond({'cleared': True})
        elif name == 'hang':
            respond({'hanging': True})
            time.sleep(float(argument))
        elif name == 'quit':
            respond({'quit': True})
            win32gui.DestroyWindow(hwnd)

    def procedure(hwnd, message, wparam, lparam):
        if message == WM_APP:
            while True:
                try:
                    handle(commands.get_nowait())
                except queue.Empty:
                    break
            return 0
        if message == win32con.WM_DESTROY:
            win32gui.PostQuitMessage(0)
            return 0
        return win32gui.DefWindowProc(hwnd, message, wparam, lparam)

    instance = win32api.GetModuleHandle(None)
    window_class = win32gui.WNDCLASS()
    window_class.hInstance = instance
    window_class.lpszClassName = 'AkdbxDesktopFixture' + tag
    window_class.lpfnWndProc = procedure
    window_class.hbrBackground = win32con.COLOR_WINDOW + 1
    win32gui.RegisterClass(window_class)
    hwnd = win32gui.CreateWindowEx(0, window_class.lpszClassName, f'AKDBX native fixture {tag}',
                                   win32con.WS_OVERLAPPEDWINDOW | win32con.WS_VISIBLE,
                                   x, 160, 460, 260, 0, 0, instance, None)
    state['hwnd'] = hwnd
    for index, extra in enumerate((0, win32con.ES_PASSWORD, win32con.ES_PASSWORD, 0)):
        edits.append(win32gui.CreateWindowEx(
            win32con.WS_EX_CLIENTEDGE, 'EDIT', '',
            win32con.WS_CHILD | win32con.WS_VISIBLE | win32con.WS_TABSTOP | win32con.ES_AUTOHSCROLL | extra,
            16, 16 + index * 48, 410, 32, hwnd, 100 + index, instance, None))

    def reader():
        for line in sys.stdin:
            commands.put(line)
            win32gui.PostMessage(hwnd, WM_APP, 0, 0)
        win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)

    threading.Thread(target=reader, daemon=True).start()
    win32gui.PumpMessages()


class NativeFixture:
    def __init__(self, tag: str, x: int):
        self.process = subprocess.Popen(
            [sys.executable, '-I', str(Path(__file__).resolve()), '--native-fixture', tag, '--x', str(x)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding='utf-8')
        info = self.send('info')
        self.pid, self.hwnd, self.edits = info['pid'], info['hwnd'], info['edits']

    def send(self, command: str) -> dict:
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError('native fixture exited')
        return json.loads(line)

    def report(self) -> list[dict]:
        return self.send('report')['fields']

    def close(self):
        try:
            self.send('quit')
            self.process.wait(5)
        except Exception:
            self.process.kill()


# --------------------------------------------------------------------------
# Browser fixture: a loopback login page that reports digests of its fields.
# --------------------------------------------------------------------------

PAGE = """<!doctype html><meta charset=utf-8><title>%TITLE%</title>
<style>body{font:16px system-ui;margin:24px}input{display:block;width:420px;margin:10px 0;padding:6px}</style>
<p>AKDBX synthetic login fixture</p>
<input id=u autocomplete=off placeholder=username>
<input id=p type=password autocomplete=new-password placeholder=password>
<input id=t autocomplete=one-time-code inputmode=numeric placeholder=code>
<script>
let want = 'u';
const send = (body) => fetch('/event', {method: 'POST', body: JSON.stringify(body)});
for (const id of ['u', 'p', 't']) {
  const el = document.getElementById(id);
  el.addEventListener('input', () => send({field: id, value: el.value}));
  el.addEventListener('focus', () => send({focus: id}));
}
setInterval(async () => {
  const r = await fetch('/want'); want = (await r.json()).want;
  const el = document.getElementById(want);
  if (document.activeElement !== el) el.focus();
  send({focus: document.activeElement && document.activeElement.id, page_focus: document.hasFocus()});
}, 100);
</script>"""


class BrowserFixture:
    def __init__(self, title: str):
        self.title = title
        self.want = 'u'
        self.values: dict[str, tuple[str, int]] = {}
        self.focus = None
        self.page_focus = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, body: bytes, kind: str):
                self.send_response(200)
                self.send_header('Content-Type', kind)
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == '/want':
                    self.reply(json.dumps({'want': fixture.want}).encode(), 'application/json')
                else:
                    self.reply(PAGE.replace('%TITLE%', fixture.title).encode(), 'text/html; charset=utf-8')

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])) or b'{}')
                if 'value' in data:
                    value = data['value']
                    fixture.values[data['field']] = (digest(value), len(value.encode('utf-16-le', errors='surrogatepass')) // 2)
                if 'focus' in data:
                    fixture.focus = data['focus']
                if 'page_focus' in data:
                    fixture.page_focus = bool(data['page_focus'])
                self.reply(b'{}', 'application/json')

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_port}/'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def find_window(title: str, timeout: float = 20.0):
    import win32gui
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = []
        def visit(hwnd, _):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd) == title:
                found.append(hwnd)
            return True
        win32gui.EnumWindows(visit, None)
        if found:
            return found[0]
        time.sleep(0.2)
    return None


def file_version(path: Path) -> str:
    try:
        import win32api
        info = win32api.GetFileVersionInfo(str(path), '\\')
        ms, ls = info['FileVersionMS'], info['FileVersionLS']
        return f'{ms >> 16}.{ms & 0xffff}.{ls >> 16}.{ls & 0xffff}'
    except Exception:
        return 'unknown'


# --------------------------------------------------------------------------
# Harness.
# --------------------------------------------------------------------------

class Harness:
    def __init__(self, root: Path):
        from akdbx import windows_security as security
        from akdbx import windows_rpc as rpc
        self.security = security
        self.root = root
        self.browser_root = root.with_name(root.name + '-browsers')
        self.checks: list[dict] = []
        self.transcript: list[str] = []
        self.secrets = [MASTER, TOTP_SECRET, IMPORTED] + [entry[1] for entry in ENTRIES.values()]
        self.pipe = rpc.PREFIX + 'akdbx-desktop-' + uuid.uuid4().hex[:12]
        cli = Path(sys.executable).with_name('akdbx.exe')
        self.cli_path = cli if cli.exists() else None
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        self.origin = f'https://127.0.0.1:{self.port}'

    # Records ---------------------------------------------------------------
    def check(self, item: str, name: str, ok: bool, detail: str = '') -> bool:
        self.checks.append({'item': item, 'check': name, 'ok': bool(ok), 'detail': detail})
        print(('PASS ' if ok else 'FAIL ') + f'[{item}] {name}' + (f' — {detail}' if detail else ''), flush=True)
        return bool(ok)

    def cli(self, *arguments: str) -> tuple[int, dict | None, str]:
        command = ([str(self.cli_path)] if self.cli_path else [sys.executable, '-m', 'akdbx.cli'])
        result = subprocess.run([*command, '--socket', self.pipe, '--unlock-origin', self.origin, *arguments],
                                capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.transcript += [result.stdout, result.stderr]
        try:
            body = json.loads(result.stdout) if result.stdout.strip() else None
        except ValueError:
            body = None
        return result.returncode, body, result.stderr.strip()

    # Setup -----------------------------------------------------------------
    def prepare(self):
        from pykeepass import create_database
        vault = create_database(io.BytesIO(), password=MASTER)
        params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
        params['I'].value, params['M'].value = 1, 1024 * 1024
        for title, (username, password, url) in ENTRIES.items():
            entry = vault.add_entry(vault.root_group, title, username, password, url=url,
                                    notes='preserve ' + title)
            if title in ('Desktop TOTP', 'Browser Login'):
                entry.otp = f'otpauth://totp/Synthetic:{username}?secret={TOTP_SECRET}&issuer=Synthetic'
        buffer = io.BytesIO()
        vault.save(buffer)
        self.vault = self.root / 'synthetic.kdbx'
        self.security.write_new(self.vault, buffer.getvalue())
        certificate, key = loopback_certificate()
        self.certificate, self.key = self.root / 'cert.pem', self.root / 'key.pem'
        self.security.write_new(self.certificate, certificate)
        self.security.write_new(self.key, key)

    def start_broker(self):
        command = ([str(self.cli_path)] if self.cli_path else [sys.executable, '-m', 'akdbx.cli'])
        self.broker_log = self.root / 'broker.log'
        self.broker_log_handle = open(self.broker_log, 'w', encoding='utf-8')
        self.broker = subprocess.Popen(
            [*command, '--socket', self.pipe, '--unlock-origin', self.origin, 'serve', str(self.vault),
             '--tls-cert', str(self.certificate), '--tls-key', str(self.key)],
            stdin=subprocess.DEVNULL, stdout=self.broker_log_handle, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 20
        while True:
            code, status, _ = self.cli('status')
            if code == 0 and status:
                break
            if self.broker.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('broker did not start')
            time.sleep(0.1)
        self.check('1', 'installed CLI broker starts locked on the named pipe',
                   status.get('locked') is True and status.get('target_fill_delivery') == 'win32-char-v1',
                   f'cli={"akdbx.exe" if self.cli_path else "python -m akdbx.cli"}')
        context = ssl.create_default_context(cafile=str(self.certificate))
        parsed = urlsplit(status['unlock_url'])
        connection = HTTPSConnection('127.0.0.1', self.port, context=context, timeout=15)
        connection.request('GET', parsed.path + '?' + parsed.query)
        page = connection.getresponse()
        page_ok = page.status == 200 and b'<form' in page.read().lower()
        connection.close()
        self.check('1', 'one-time unlock page serves over verified loopback TLS', page_ok)
        status_code = self.https_post(status['unlock_url'], {'password': MASTER})
        code, status, _ = self.cli('status')
        self.check('1', 'HTTPS unlock with the synthetic master password',
                   status_code == 200 and status and status.get('locked') is False
                   and status.get('writes_available') is True, f'http={status_code}')

    def https_post(self, url: str, values: dict) -> int:
        context = ssl.create_default_context(cafile=str(self.certificate))
        parsed = urlsplit(url)
        connection = HTTPSConnection('127.0.0.1', self.port, context=context, timeout=15)
        try:
            connection.request('POST', parsed.path + '?' + parsed.query, urlencode(values),
                               {'Content-Type': 'application/x-www-form-urlencoded', 'Origin': self.origin})
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def select(self, title: str) -> dict:
        code, body, _ = self.cli('search', title)
        matches = [entry for entry in (body or {}).get('entries', []) if entry['title'] == title]
        if code != 0 or len(matches) != 1:
            raise RuntimeError(f'search for {title!r} failed')
        return matches[0]

    def pin(self, pid: int, hwnd: int) -> tuple[int, dict | None, str]:
        return self.cli('pin-target', '--pid', str(pid), '--window', str(hwnd))

    def fill_totp(self, title: str, pid: int, hwnd: int, target_url: str):
        """Fill a TOTP code, honouring one not-started near-expiry refusal."""
        for attempt in range(2):
            handle = self.select(title)['handle']
            code, pin, error = self.pin(pid, hwnd)
            if code != 0:
                return code, pin, 'pin: ' + error, time.time()
            started = time.time()
            code, body, error = self.cli('fill-totp', handle, '--target-url', target_url, '--target', pin['target'])
            body = body or {}
            if (attempt == 0 and code != 0 and isinstance(body.get('retry_after'), int)
                    and body.get('delivery', 'not-started') == 'not-started'):
                self.check('1', f'TOTP near-expiry refusal for {title} sent nothing and asked for a retry', True,
                           f'retry_after={body["retry_after"]}')
                time.sleep(body['retry_after'] + 1)
                continue
            return code, body, error or body.get('error', ''), started
        return code, body, error, started

    def fill(self, title: str, mode: str, pid: int, hwnd: int):
        handle = self.select(title)['handle']
        code, pin, error = self.pin(pid, hwnd)
        if code != 0:
            return code, pin, 'pin: ' + error
        return self.cli('fill', handle, '--mode', mode, '--target', pin['target'])

    # Native checks -----------------------------------------------------------
    def native_checks(self):
        a, b = NativeFixture('A', 120), NativeFixture('B', 640)
        try:
            self._native_fills(a)
            self._native_refusals(a, b)
            self._native_generated(a)
        finally:
            a.close()
            b.close()

    def _front(self, fixture: NativeFixture, field: int) -> bool:
        bring_to_front(fixture.hwnd)
        result = fixture.send(f'focus {field}')
        time.sleep(0.15)
        return result['foreground'] and result['focused'] and user32.GetForegroundWindow() == fixture.hwnd

    def _native_fills(self, a: NativeFixture):
        for title in ('Desktop ASCII', 'Desktop Unicode'):
            username, password, _url = ENTRIES[title]
            a.send('clear')
            if self.check('1', f'native {title} username: fixture has foreground and focus', self._front(a, 0)):
                code, body, error = self.fill(title, 'username', a.pid, a.hwnd)
                fields = a.report()
                self.check('1', f'native {title} username accepted by Win32 EDIT',
                           code == 0 and body.get('filled') == 'username' and fields[0]['sha256'] == digest(username),
                           f'code={code} units={fields[0]["units"]}/{len(username.encode("utf-16-le")) // 2} {error}')
            # Only verified Chromium DOM pins may receive passwords; an HWND pin
            # cannot tell a browser page from its address bar.
            if self.check('1', f'native {title} password: fixture has foreground and focus', self._front(a, 1)):
                code, body, error = self.fill(title, 'password', a.pid, a.hwnd)
                self.check('1', f'native {title} password fill to an HWND pin is refused before any character',
                           code != 0 and (body or {}).get('delivery', 'not-started') == 'not-started'
                           and a.report()[1]['sha256'] == digest(''), f'code={code}')
        # TOTP into the fourth field.
        a.send('clear')
        if self.check('1', 'native TOTP: fixture has foreground and focus', self._front(a, 3)):
            code, body, error, started = self.fill_totp('Desktop TOTP', a.pid, a.hwnd, 'https://totp.test/login')
            if user32.GetForegroundWindow() != a.hwnd:
                self._front(a, 3)
            codes = {digest(totp(TOTP_SECRET, started + delta)) for delta in (-30, 0, 30)}
            self.check('1', 'native TOTP code accepted and current', code == 0 and body.get('filled') == 'totp'
                       and a.report()[3]['sha256'] in codes, f'code={code} {error}')

    def _native_refusals(self, a: NativeFixture, b: NativeFixture):
        username = ENTRIES['Desktop ASCII'][0]
        empty = digest('')
        # Foreground switch between pin and dispatch.
        a.send('clear'); b.send('clear')
        if self._front(a, 0):
            handle = self.select('Desktop ASCII')['handle']
            code, pin, _ = self.pin(a.pid, a.hwnd)
            self._front(b, 0)
            code, body, error = self.cli('fill', handle, '--mode', 'username', '--target', pin['target'])
            self.check('2', 'foreground switch after pin is refused before any character',
                       code != 0 and (body or {}).get('delivery', 'not-started') == 'not-started'
                       and a.report()[0]['sha256'] == empty and b.report()[0]['sha256'] == empty,
                       f'code={code} delivery={(body or {}).get("delivery")}')
        # Pin while another window is foreground.
        self._front(b, 0)
        code, body, _ = self.pin(a.pid, a.hwnd)
        self.check('3', 'pin of a background window is refused', code != 0)
        # Wrong PID and wrong (child) HWND.
        self._front(a, 0)
        code, _, _ = self.pin(b.pid, a.hwnd)
        self.check('3', 'pin with the wrong PID is refused', code != 0)
        code, _, _ = self.pin(a.pid, a.edits[0])
        self.check('3', 'pin of a child HWND instead of the top-level window is refused', code != 0)
        # Focus moved to another field of the same window after pinning.
        a.send('clear')
        if self._front(a, 0):
            handle = self.select('Desktop ASCII')['handle']
            code, pin, _ = self.pin(a.pid, a.hwnd)
            a.send('focus 1')
            code, body, _ = self.cli('fill', handle, '--mode', 'username', '--target', pin['target'])
            fields = a.report()
            self.check('2', 'focus moved to another field after pin is refused',
                       code != 0 and fields[0]['sha256'] == empty and fields[1]['sha256'] == empty, f'code={code}')
        # Reused pin.
        a.send('clear')
        if self._front(a, 0):
            code, pin, _ = self.pin(a.pid, a.hwnd)
            first = self.cli('fill', self.select('Desktop ASCII')['handle'], '--mode', 'username', '--target', pin['target'])
            a.send('clear'); self._front(a, 0)
            second = self.cli('fill', self.select('Desktop ASCII')['handle'], '--mode', 'username', '--target', pin['target'])
            self.check('3', 'a pin is single-use', first[0] == 0 and second[0] != 0
                       and a.report()[0]['sha256'] == empty, f'first={first[0]} second={second[0]}')
        # Reused search handle.
        a.send('clear')
        if self._front(a, 0):
            handle = self.select('Desktop ASCII')['handle']
            _, pin, _ = self.pin(a.pid, a.hwnd)
            first = self.cli('fill', handle, '--mode', 'username', '--target', pin['target'])
            a.send('clear'); self._front(a, 0)
            _, pin, _ = self.pin(a.pid, a.hwnd)
            second = self.cli('fill', handle, '--mode', 'username', '--target', pin['target'])
            self.check('3', 'a search handle is single-use', first[0] == 0 and second[0] != 0
                       and a.report()[0]['sha256'] == empty, f'first={first[0]} second={second[0]}')
        # Expired pin.
        a.send('clear')
        if self._front(a, 0):
            handle = self.select('Desktop ASCII')['handle']
            _, pin, _ = self.pin(a.pid, a.hwnd)
            time.sleep(31)
            self._front(a, 0)
            code, body, _ = self.cli('fill', handle, '--mode', 'username', '--target', pin['target'])
            self.check('3', 'a pin expires after 30 seconds', code != 0 and a.report()[0]['sha256'] == empty,
                       f'code={code}')
        # Combined login fill is refused by the Windows CLI before sending.
        code, _, error = self.cli('fill', self.select('Desktop ASCII')['handle'], '--mode', 'login', '--target', '0' * 64)
        self.check('3', 'combined login fill is refused on Windows', code == 2 and 'only usernames' in error)
        # Hung target window: pinned, then its GUI thread stops pumping messages.
        a.send('clear')
        if self._front(a, 0):
            handle = self.select('Desktop ASCII')['handle']
            _, pin, _ = self.pin(a.pid, a.hwnd)
            a.send('hang 3')
            code, body, error = self.cli('fill', handle, '--mode', 'username', '--target', pin['target'])
            time.sleep(3.5)
            units = a.report()[0]['units']
            delivery = (body or {}).get('delivery')
            self.check('3', 'hung target fails without completing or retrying delivery',
                       code != 0 and units < len(username) and delivery in ('uncertain', 'not-started', None),
                       f'code={code} delivery={delivery} units_after_resume={units}')
        # Fixture process exits between pin and fill.
        c = NativeFixture('C', 380)
        try:
            if self._front(c, 0):
                handle = self.select('Desktop ASCII')['handle']
                _, pin, _ = self.pin(c.pid, c.hwnd)
                c.close()
                code, body, _ = self.cli('fill', handle, '--mode', 'username', '--target', pin['target'])
                self.check('3', 'target process exit after pin is refused', code != 0, f'code={code}')
        finally:
            if c.process.poll() is None:
                c.close()

    def _native_generated(self, a: NativeFixture):
        from pykeepass import PyKeePass
        title = 'Desktop Generated'
        username, _old, url = ENTRIES[title]
        selected = self.select(title)
        code, body, error = self.cli('generate-password', selected['handle'], '--title', title,
                                     '--username', username, '--url', url, '--group', selected['group'])
        if not self.check('4', 'generate-password stages a broker-generated password',
                          code == 0 and set(body.get('fill_handles', {})) == {'password', 'confirmation'}, error):
            return
        a.send('clear')
        refused = []
        for field, mode in ((1, 'password'), (2, 'confirmation')):
            if not self._front(a, field):
                break
            _, pin, _ = self.pin(a.pid, a.hwnd)
            result = self.cli('fill-generated', body['fill_handles'][mode], '--target-url', url + '/reset',
                              '--target', pin['target'])
            refused.append(result[0] != 0 and (result[1] or {}).get('delivery', 'not-started') == 'not-started')
        fields = a.report()
        self.check('4', 'generated password fills to HWND pins are refused before any character',
                   refused == [True, True] and fields[1]['sha256'] == fields[2]['sha256'] == digest(''))
        code, _commit, error = self.cli('commit-password', body['write_handle'], '--site-accepted')
        cancel = self.cli('cancel-write', body['write_handle'])[0]
        persisted = PyKeePass(str(self.vault), password=MASTER)
        entry = persisted.find_entries(title=title, first=True)
        self.check('4', 'unfilled generated password cannot be committed; vault unchanged',
                   code != 0 and cancel == 0 and entry.password == _old and entry.notes == 'preserve ' + title,
                   f'commit={code} cancel={cancel}')

    def import_check(self):
        from pykeepass import PyKeePass
        title = 'Desktop Import'
        username, old, url = ENTRIES[title]
        selected = self.select(title)
        code, body, error = self.cli('update-password', selected['handle'], '--title', title,
                                     '--username', username, '--url', url, '--group', selected['group'])
        if not self.check('4', 'update-password returns a private HTTPS page', code == 0 and 'private_url' in body, error):
            return
        status_code = self.https_post(body['private_url'], {'password': IMPORTED, 'confirmation': IMPORTED,
                                                            'confirmed': 'yes'})
        state = (self.cli('write-status', body['write_handle'])[1] or {}).get('state')
        persisted = PyKeePass(str(self.vault), password=MASTER)
        entry = persisted.find_entries(title=title, first=True)
        others = all(persisted.find_entries(title=name, first=True).password == ENTRIES[name][1]
                     for name in ENTRIES if name != title)
        self.check('4', 'private HTTPS password import saved; unrelated entries and history preserved',
                   status_code == 200 and state == 'saved' and entry.password == IMPORTED
                   and entry.notes == 'preserve ' + title and any(h.password == old for h in entry.history) and others,
                   f'http={status_code} state={state}')

    # Browser checks ----------------------------------------------------------
    def browser_checks(self, name: str, executable: Path):
        if not executable.exists():
            self.check('1', f'{name}: browser installed', False, str(executable))
            return
        fixture = BrowserFixture(f'AKDBX browser fixture {name} {uuid.uuid4().hex[:6]}')
        # Keep browser profiles out of the protected vault folder: Chromium's
        # sandbox rewrites cache ACLs, which would block later cleanup there.
        profile = self.browser_root / f'{name.lower()}-profile'
        process = subprocess.Popen([str(executable), f'--user-data-dir={profile}', '--no-first-run',
                                    '--no-default-browser-check', '--disable-sync', '--password-store=basic',
                                    '--disable-features=Translate,PasswordManagerOnboarding',
                                    '--window-size=720,520', '--window-position=260,140', f'--app={fixture.url}'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            hwnd = find_window(fixture.title)
            if not self.check('1', f'{name}: fixture window opened', hwnd is not None, file_version(executable)):
                return
            _thread, pid = window_owner(hwnd)
            username, _password, _url = ENTRIES['Browser Login']
            fixture.want = 'u'
            if self.check('1', f'{name} username: page field focused in foreground window',
                          self._browser_front(fixture, hwnd, 'u')):
                code, body, error = self.fill('Browser Login', 'username', pid, hwnd)
                accepted = self._browser_value(fixture, 'u', digest(username))
                self.check('1', f'{name} username accepted by the DOM field',
                           code == 0 and (body or {}).get('filled') == 'username' and accepted,
                           f'code={code} units={fixture.values.get("u", ("", 0))[1]}/'
                           f'{len(username.encode("utf-16-le")) // 2} {error or (body or {}).get("error", "")}')
            fixture.want = 'p'
            if self.check('1', f'{name} password: page field focused in foreground window',
                          self._browser_front(fixture, hwnd, 'p')):
                code, body, error = self.fill('Browser Login', 'password', pid, hwnd)
                time.sleep(1.0)  # let any stray input reach the page before checking
                self.check('1', f'{name} password fill to an HWND pin is refused before any character',
                           code != 0 and (body or {}).get('delivery', 'not-started') == 'not-started'
                           and 'p' not in fixture.values, f'code={code}')
            fixture.want = 't'
            if self.check('1', f'{name} TOTP: page field focused', self._browser_front(fixture, hwnd, 't')):
                code, body, error, started = self.fill_totp('Browser Login', pid, hwnd, 'https://browser.test/login')
                codes = [digest(totp(TOTP_SECRET, started + delta)) for delta in (-30, 0, 30)]
                accepted = any(self._browser_value(fixture, 't', value, timeout=1.5) for value in codes)
                self.check('1', f'{name} TOTP code accepted by the DOM field', code == 0 and accepted,
                           f'code={code} {error}')
        finally:
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True)
            fixture.close()

    def _browser_front(self, fixture: BrowserFixture, hwnd, field: str) -> bool:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if user32.GetForegroundWindow() != hwnd:
                bring_to_front(hwnd)
            time.sleep(0.3)
            if user32.GetForegroundWindow() == hwnd and fixture.focus == field and fixture.page_focus:
                return True
        return False

    @staticmethod
    def _browser_value(fixture: BrowserFixture, field: str, expected: str, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if fixture.values.get(field, ('',))[0] == expected:
                return True
            time.sleep(0.1)
        return False

    # Secrecy -----------------------------------------------------------------
    def secrecy_checks(self):
        self.broker.terminate()
        self.broker.wait(10)
        self.broker_log_handle.close()
        texts = self.transcript + [self.broker_log.read_text(encoding='utf-8', errors='replace')]
        leaked = [index for index, secret in enumerate(self.secrets) if any(secret in text for text in texts)]
        self.check('6', 'no synthetic secret in CLI output, receipts printed to console, or broker log',
                   not leaked, f'{len(texts)} streams scanned')
        unsafe = []
        for path in self.root.iterdir():
            if path.is_dir() or path.name.endswith('.kdbx') or '.akdbx-backup-' in path.name:
                continue
            data = path.read_bytes()
            if any(secret.encode(codec) in data for secret in self.secrets for codec in ('utf-8', 'utf-16-le')):
                unsafe.append(path.name)
        self.check('6', 'no synthetic secret in unencrypted broker files (receipts, lock, log)', not unsafe,
                   ', '.join(unsafe))


def loopback_certificate() -> tuple[bytes, bytes]:
    """A one-day self-signed 127.0.0.1 certificate trusted only by this check."""
    from datetime import datetime, timedelta, timezone
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                                  x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                   .sign(key, hashes.SHA256()))
    return (certificate.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--report', type=Path, required=False)
    parser.add_argument('--keep', action='store_true', help='keep the private test directory')
    parser.add_argument('--skip-browsers', action='store_true')
    parser.add_argument('--no-prompt', action='store_true', help='start without the desktop OK prompt')
    parser.add_argument('--native-fixture', help=argparse.SUPPRESS)
    parser.add_argument('--x', type=int, default=120, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.native_fixture:
        native_fixture(args.native_fixture, args.x)
        return 0
    if sys.platform != 'win32':
        print('Windows desktop required', file=sys.stderr)
        return 2
    sys.path.insert(0, str(HERE))
    from akdbx import windows_security as security
    from akdbx import __version__ as akdbx_version
    import win32file
    if not args.no_prompt:
        # Blocks until a person at the desktop clicks OK. That click is also the
        # input event Windows requires before this process may set the foreground.
        user32.MessageBoxW.argtypes = [W.HWND, W.LPCWSTR, W.LPCWSTR, W.UINT]
        answer = user32.MessageBoxW(None, 'AKDBX Windows desktop test (synthetic data only).\n\n'
                                    'Click OK, then do not type or click for about three minutes. '
                                    'Test windows will open, take focus and close.',
                                    'AKDBX desktop test', 0x1 | 0x40 | 0x10000 | 0x40000)
        if answer != 1:  # IDOK; MB_OKCANCEL | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST
            print('cancelled at the desktop prompt', file=sys.stderr)
            return 3
        user32.AllowSetForegroundWindow(-1)  # ASFW_ANY: fixtures and browsers may follow.
    root = Path(os.environ['LOCALAPPDATA']) / ('akdbx-desktop-' + uuid.uuid4().hex[:8])
    win32file.CreateDirectory(str(root), security.private_attributes())
    original_foreground = user32.GetForegroundWindow()
    harness = Harness(root)
    harness.browser_root.mkdir()
    started = time.time()
    try:
        harness.prepare()
        harness.start_broker()
        harness.native_checks()
        harness.import_check()
        if not args.skip_browsers:
            harness.browser_checks('Chrome', Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe'))
            harness.browser_checks('Edge', Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'))
        harness.secrecy_checks()
    except Exception as error:  # Report harness faults as a failed check.
        harness.check('harness', 'desktop check completed', False, type(error).__name__ + ': ' + str(error))
    finally:
        if getattr(harness, 'broker', None) is not None and harness.broker.poll() is None:
            harness.broker.kill()
        if original_foreground and user32.IsWindow(original_foreground):
            bring_to_front(original_foreground)
        if not args.keep:
            # Browser helper processes can hold profile files briefly after exit.
            for _attempt in range(20):
                for path in (root, harness.browser_root):
                    shutil.rmtree(path, ignore_errors=True)
                if not root.exists() and not harness.browser_root.exists():
                    break
                time.sleep(0.5)
            harness.check('cleanup', 'test vault and browser profile directories removed',
                          not root.exists() and not harness.browser_root.exists(), root.name)
    passed = all(check['ok'] for check in harness.checks)
    report = {
        'result': 'pass' if passed else 'fail',
        'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(started)),
        'duration_s': round(time.time() - started, 1),
        'environment': {
            'windows': platform.platform(), 'windows_build': platform.version(),
            'python': platform.python_version(), 'akdbx': akdbx_version,
            'chrome': file_version(Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe')),
            'edge': file_version(Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')),
            'cli': 'akdbx.exe' if harness.cli_path else 'python -m akdbx.cli',
        },
        'not_covered': [
            'held keys during dispatch (needs physical/global input; unit-tested)',
            'elevated or UAC targets (needs an administrator prompt)',
            'second standard Windows user (needs a second account)',
        ],
        'checks': harness.checks,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"{report['result'].upper()}: {sum(c['ok'] for c in harness.checks)}/{len(harness.checks)} checks")
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
