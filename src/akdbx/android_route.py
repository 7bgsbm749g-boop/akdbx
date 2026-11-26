"""Android route: fill one verified field on a configured Android device.

The broker speaks adb's host and shell protocols itself, on a loopback
connection to the operator's adb server whose owner it checks, and starts a
small helper on the device (``android_assets/akdbx-android-helper.dex``, built
from ``android/helper``) with ``app_process`` as the adb shell user. A value
travels only on that connection's standard input to the helper, or (Chrome
pages) over a DevTools connection proven to be Chrome's. It is never an adb or
shell argument, never on the clipboard, and never in a response, an exception
message or a log.

- App fields and Google account sign-in: the helper finds the exact field
  through the platform's accessibility API (UiAutomation), checks the app,
  its signing certificate, task and field again, empties the field, sets the
  value (ACTION_SET_TEXT) and confirms that the field holds it.
- Chrome tabs and Custom Tabs: Chrome's accessibility tree can be stale, so
  the broker reads the page through Chrome's DevTools socket (adb forwards it
  to a loopback port only until the broker connects). Any app could hold that
  socket's name, so before a value moves the field is emptied and focused,
  the helper types a random check string as key events that Android delivers
  only to windows of Chrome's app user (after it checks that Chrome is focused
  in the pinned task and its own address bar shows the pinned host), and the
  broker reads the pinned element's text and compares it with that string
  itself. The broker then sets the value on that element over the same, now
  proven, connection.

The site that a pin may receive a credential for is one of:

- the page in Chrome (com.android.chrome, signed by Google): the exact origin
  of the one visible, focused tab, whose host must match Chrome's address bar;
- Google's account sign-in in Google Play services: https://accounts.google.com,
  for an email pin and for the one-run google_sign_in (consumer accounts only);
- a native field of any other app, when the agent names a site (--app-site)
  whose Digital Asset Links share its credentials with that app's package and
  current signing certificate.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Callable

from .target import DeliveryError, TargetError

PROTOCOL = 1
DELIVERY = 'android-accessibility-set-text-v1'
# A value set on the exact Chrome page element over a DevTools connection that
# typed key events (which only Chrome's windows receive) proved to be Chrome's.
CHROME_DELIVERY = 'android-chrome-verified-dom-v1'
NONCE_ALPHABET = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
PIN_TTL = 30.0
MAX_PINS = 64
MODES = ('login', 'username', 'password', 'totp', 'sms', 'card', 'identity', 'read')
CHALLENGE_MODES = {'sms', 'card', 'identity', 'read'}
READ_DELIVERY = 'android-chrome-verified-read-v1'
CONFIG_ENV = 'AKDBX_ANDROID_DEVICES'
MAX_CONFIG = 64 * 1024
MAX_DEVICES = 16
DEVICE_NAME = re.compile(r'[a-z0-9][a-z0-9._-]{0,31}')
AVD_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._-]{0,249}')
SERIAL = re.compile(r'[A-Za-z0-9._:-]{1,64}')

HELPER_ASSET = 'akdbx-android-helper.dex'
# SHA-256 of the bundled helper; tests/test_android_route.py checks it.
HELPER_SHA256 = '0fae7b1b8efebbfa53abd6d8262845f8300b04c54d58be77f67a7e8cfd188fbd'
HELPER_CLASS = 'org.akdbx.android.Helper'
HELPER_PROTOCOL = 1
RESULT_PREFIX = 'AKDBX-ANDROID-RESULT '
DEVICE_DIR = '/data/local/tmp/akdbx'
HELPER_MISSING = 86
HELPER_TIMEOUT = 25.0
SIGN_IN_TIMEOUT = 140.0
DEVICE_PROBE_TIMEOUT = 15.0
DEVICE_LIST_BUDGET = 150.0
TAB_ATTACH_BUDGET = 30.0
TAB_CALL_TIMEOUT = 2.0
# A frozen background tab answers no DevTools call: all tabs are asked at once.
TAB_PROBE_TIMEOUT = 3.0
INSTALL_BUDGET = 100.0
MAX_HELPER_OUTPUT = 512 * 1024
MAX_TAB_LIST = 1024 * 1024
MAX_ASSET_LINKS = 256 * 1024

# Google's app signing key: Chrome and the Play Store use it, and Google Play
# services rotated from it (its signing lineage starts with this key).
GOOGLE_SIGNER = 'F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83'
CHROME_PACKAGE = 'com.android.chrome'
CHROME_ACTIVITIES = ('com.android.chrome/org.chromium.chrome.browser.ChromeTabbedActivity',
                     'com.android.chrome/org.chromium.chrome.browser.customtabs.CustomTabActivity')
GMS_PACKAGE = 'com.google.android.gms'
GMS_SIGN_IN_ACTIVITY = 'com.google.android.gms/.auth.uiflows.minutemaid.MinuteMaidActivity'
GOOGLE_SIGN_IN_ORIGIN = ('https', 'accounts.google.com', 443)
# Only the relation that shares sign-in credentials; App Links (handle_all_urls)
# let an app open a site's links, not receive its passwords.
ASSET_LINK_RELATIONS = ('delegate_permission/common.get_login_creds',)

GMAIL_ONLY = ('google-sign-in fills the password only for a @gmail.com or @googlemail.com account: '
              'another domain can send the sign-in to its own company page, whose site akdbx cannot read; '
              'no value sent')
SPEAK_PASSWORD_REFUSAL = ('device lets accessibility services read password text; on the device run '
                          '"settings put secure speak_password 0" (adb shell), then pin again')
GOOGLE_SECRETS_REFUSAL = ('Google sign-in takes the password and code only through '
                          '"akdbx android google-sign-in"; pin only the email here')
ORIGIN_MISMATCH = "autofill not started: the pinned Android app or page is not this entry's site; no value sent"


class AndroidError(TargetError):
    """A refusal whose message is fixed text or helper text with no secret."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class AndroidMismatch(TargetError):
    """The selected entry may not fill the pinned app or page."""


def capabilities(configured: bool) -> dict:
    return dict(android_fill_protocol=PROTOCOL, android_fill_delivery=DELIVERY,
                android_chrome_delivery=CHROME_DELIVERY,
                android_generated_password=True, android_pending_totp=True, android_read_delivery=READ_DELIVERY,
                android_fill_modes=list(MODES), android_devices_configured=configured)


def default_config_path() -> Path:
    if os.name == 'nt':
        return Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData' / 'Local') / 'akdbx' / 'android-devices.json'
    base = os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
    return Path(base) / 'akdbx' / 'android-devices.json'


def serialize_origin(origin) -> str:
    scheme, host, port = origin
    return f'{scheme}://' + (f'[{host}]' if ':' in host else host) + ('' if port == {'https': 443, 'http': 80}.get(scheme) else f':{port}')


def _clip(value, limit=200):
    return value[:limit] if isinstance(value, str) else None


# ----- operator configuration ---------------------------------------------

@dataclass(frozen=True)
class Device:
    name: str
    adb: str
    port: int
    serial: str
    managed: dict | None = None

    def reserved_ports(self):
        ports = {self.port}
        if self.managed:
            console = int(self.serial.removeprefix('emulator-'))
            ports.update((console, console + 1))
        return ports

    def conflicts_with(self, other):
        if not (self.managed or other.managed):
            return False
        return (bool(self.reserved_ports() & other.reserved_ports()) or self.serial == other.serial
                or (self.managed and other.managed and
                    (self.managed['avd_home'], self.managed['avd']) ==
                    (other.managed['avd_home'], other.managed['avd'])))


def _read_private_file(path: Path) -> bytes:
    """Read the bounded operator file only through a checked file handle."""
    if os.name == 'nt':
        import pywintypes
        from .windows_security import read_private_optional
        try:
            data = read_private_optional(path, limit=MAX_CONFIG)
        except (OSError, ValueError, pywintypes.error) as exc:
            raise AndroidError('Android device configuration is unsafe or unavailable') from exc
        if data is None:
            raise FileNotFoundError(path)
    else:
        directory = path.parent
        info = os.stat(directory)
        if info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
            raise AndroidError('Android device configuration folder is writable by other accounts')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise AndroidError('Android device configuration must be a regular file owned by the broker '
                                   'user and not writable by others')
            data = os.read(fd, MAX_CONFIG + 1)
        finally:
            os.close(fd)
    if len(data) > MAX_CONFIG:
        raise AndroidError('Android device configuration is too large')
    return data


def load_devices(path: Path | None) -> dict[str, Device]:
    """Parse {"version": 1, "devices": {NAME: {"adb", "adb_server_port", "serial"}}}."""
    if path is None:
        return {}
    try:
        data = _read_private_file(path)
    except FileNotFoundError:
        return {}
    except AndroidError:
        raise
    except OSError:
        raise AndroidError('Android device configuration unavailable') from None
    try:
        raw = json.loads(data.decode('utf-8'))
    except (UnicodeError, ValueError):
        raise AndroidError('Android device configuration is not valid JSON') from None
    if (not isinstance(raw, dict) or set(raw) != {'version', 'devices'} or raw['version'] != 1
            or not isinstance(raw['devices'], dict) or len(raw['devices']) > MAX_DEVICES):
        raise AndroidError('unsupported Android device configuration')
    devices = {}
    for name, value in raw['devices'].items():
        if (not isinstance(name, str) or not DEVICE_NAME.fullmatch(name) or not isinstance(value, dict)
                or set(value) not in ({'adb', 'adb_server_port', 'serial'}, {'adb', 'adb_server_port', 'serial', 'managed'})):
            raise AndroidError('invalid Android device entry')
        adb, port, serial = value['adb'], value['adb_server_port'], value['serial']
        if (not isinstance(adb, str) or not os.path.isabs(adb) or os.path.normpath(adb) != adb
                or type(port) is not int or not 1024 <= port <= 65535
                or not isinstance(serial, str) or not SERIAL.fullmatch(serial)):
            raise AndroidError('invalid Android device entry')
        managed = value.get('managed')
        if 'managed' in value:
            if (not isinstance(managed, dict) or set(managed) != {'avd', 'sdk', 'avd_home', 'idle_seconds'}
                    or not isinstance(managed['avd'], str) or not AVD_NAME.fullmatch(managed['avd'])
                    or any(not isinstance(managed[k], str) or not os.path.isabs(managed[k])
                           for k in ('sdk', 'avd_home'))
                    or type(managed['idle_seconds']) is not int or not 120 <= managed['idle_seconds'] <= 3600
                    or not re.fullmatch(r'emulator-[0-9]{4}', serial)):
                raise AndroidError('invalid managed Android device settings')
            console = int(serial[9:])
            if console % 2 or not 5554 <= console <= 5682 or port in (console, console + 1):
                raise AndroidError('invalid managed emulator ports')
        device = Device(name, adb, port, serial, managed)
        if any(device.conflicts_with(other) for other in devices.values()):
            raise AndroidError('another device uses this managed transport or AVD')
        devices[name] = device
    return devices


# ----- adb ------------------------------------------------------------------

def helper_path() -> Path:
    return Path(str(resources.files('akdbx').joinpath('android_assets', HELPER_ASSET)))


def helper_digest() -> str:
    return hashlib.sha256(helper_path().read_bytes()).hexdigest()


class Adb:
    """Runs adb for one configured device. No value to fill is ever an argument."""

    def __init__(self, device: Device):
        self.device = device

    def _environment(self):
        # Nothing from the caller's environment may redirect adb elsewhere.
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('ADB_', 'ANDROID_')) and key != 'ADBHOST'}
        if self.device.managed:
            from .android_lifecycle import runtime
            env['ADB_SERVER_SOCKET'] = 'localfilesystem:' + str(runtime(self.device)[1] / 'adb')
        else:
            env['ANDROID_ADB_SERVER_PORT'] = str(self.device.port)
        return env

    def server_running(self) -> bool:
        """True when this user's process listens on the configured adb port.

        Another OS account could listen on the port while the operator's adb
        server is down; the CDP route's peer check refuses that listener.
        """
        try:
            with self._connect(1):
                return True
        except OSError:
            return False

    def run(self, *args, stdin: bytes | None = None, timeout: float = 15.0) -> subprocess.CompletedProcess:
        if not os.path.isfile(self.device.adb) or not os.access(self.device.adb, os.X_OK):
            raise AndroidError('configured adb executable not found')
        if not self.server_running():
            # Starting a server here would make one the operator did not set up.
            raise AndroidError('adb server not running on the configured port')
        argv = [self.device.adb, '-s', self.device.serial, *args]
        return subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=self._environment(), timeout=timeout, check=False)

    def _helper_command(self) -> str:
        digest = HELPER_SHA256
        path = f'{DEVICE_DIR}/helper-{digest[:16]}.dex'
        return (f'p={path}; [ "$(sha256sum "$p" 2>/dev/null)" = "{digest}  {path}" ] || exit {HELPER_MISSING}; '
                f'CLASSPATH="$p" exec app_process /system/bin {HELPER_CLASS}')

    def install_helper(self) -> None:
        local = helper_path()
        if helper_digest() != HELPER_SHA256:
            raise AndroidError('bundled Android helper does not match this akdbx version')
        temporary = f'{DEVICE_DIR}/.helper-{secrets.token_hex(8)}.dex'
        path = f'{DEVICE_DIR}/helper-{HELPER_SHA256[:16]}.dex'
        prepared = self.run('shell', f'mkdir -p {DEVICE_DIR} && chmod 700 {DEVICE_DIR}')
        pushed = prepared.returncode == 0 and self.run('push', str(local), temporary, timeout=60).returncode == 0
        moved = pushed and self.run('shell', f'chmod 444 {temporary} && mv -f {temporary} {path}').returncode == 0
        if not moved:
            self.run('shell', f'rm -f {temporary}')
            raise AndroidError('could not copy the akdbx helper to the device')

    def _connect(self, timeout: float) -> socket.socket:
        """A connection to the adb server whose owner is this user (checked on this very socket)."""
        from .browser_password import verify_peer
        if self.device.managed:
            from .android_lifecycle import runtime
            from .cli import _peer_credentials
            connection = socket.socket(socket.AF_UNIX)
            try:
                connection.settimeout(min(timeout, 5.0))
                connection.connect(str(runtime(self.device)[1] / 'adb'))
                if _peer_credentials(connection)[1] != os.getuid():
                    raise AndroidError('the managed adb server belongs to another account')
                return connection
            except BaseException:
                connection.close()
                raise
        connection = socket.create_connection(('127.0.0.1', self.device.port), timeout=min(timeout, 5.0))
        try:
            verify_peer(connection)
        except TargetError:
            connection.close()
            raise AndroidError('the adb server port belongs to another account') from None
        except BaseException:
            connection.close()
            raise
        return connection

    @staticmethod
    def _request(connection, service: str) -> None:
        data = service.encode('utf-8')
        connection.sendall(b'%04x' % len(data) + data)
        status = _read_exact(connection, 4)
        if status != b'OKAY':
            raise AndroidError('adb refused the request; is the device connected?')

    def shell(self, command: str, stdin: bytes, *, timeout: float, answer=None) -> tuple[int, bytes]:
        """Run a device command over adb's shell protocol on a verified server connection.

        The bytes on stdin go through the same connection that passed the owner
        check, so another account cannot take over between check and use.
        answer(line) is called for each stdout line that starts with NEED_PREFIX
        and returns bytes to write to stdin (or None to close stdin).
        """
        deadline = time.monotonic() + timeout
        connection = self._connect(timeout)
        try:
            self._request(connection, 'host:transport:' + self.device.serial)
            self._request(connection, 'shell,v2,raw:' + command)
            if stdin:
                _send_packet(connection, SHELL_STDIN, stdin)
            if answer is None:
                _send_packet(connection, SHELL_CLOSE_STDIN, b'')
            output = bytearray()
            pending = b''
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                connection.settimeout(remaining)
                kind, data = _read_packet(connection)
                if kind == SHELL_EXIT:
                    return (data[0] if data else 255), bytes(output[-MAX_HELPER_OUTPUT:])
                if kind != SHELL_STDOUT:
                    continue
                output += data
                if len(output) > 4 * MAX_HELPER_OUTPUT:
                    del output[:-MAX_HELPER_OUTPUT]
                if answer is not None:
                    pending += data
                    while b'\n' in pending:
                        line, pending = pending.split(b'\n', 1)
                        if line.startswith(NEED_PREFIX.encode()):
                            reply = answer(line[len(NEED_PREFIX):].decode('utf-8', 'replace'))
                            if reply is None:
                                _send_packet(connection, SHELL_CLOSE_STDIN, b'')
                            else:
                                _send_packet(connection, SHELL_STDIN, reply)
                    pending = pending[-4096:]
        finally:
            connection.close()

    def helper(self, request: dict, *, install: bool, timeout: float = HELPER_TIMEOUT, answer=None) -> dict:
        """Run one helper request. Answers hold no value from the request."""
        data = (json.dumps(request, separators=(',', ':')) + '\n').encode('utf-8')
        if not os.path.isfile(self.device.adb):
            raise AndroidError('configured adb executable not found')
        for attempt in (0, 1):
            code, stdout = self.shell(self._helper_command(), data, timeout=timeout, answer=answer)
            if code == HELPER_MISSING and install and attempt == 0:
                self.install_helper()
                continue
            break
        data = None
        if code == HELPER_MISSING:
            raise AndroidError('akdbx helper missing on the device')
        output = stdout.decode('utf-8', 'replace')
        lines = [line for line in output.splitlines() if line.startswith(RESULT_PREFIX)]
        if len(lines) != 1:
            raise AndroidError('Android helper gave no answer')
        try:
            result = json.loads(lines[0][len(RESULT_PREFIX):])
        except ValueError:
            raise AndroidError('Android helper gave no answer') from None
        if not isinstance(result, dict) or result.get('protocol') != HELPER_PROTOCOL:
            raise AndroidError('Android helper protocol mismatch')
        return result

    def forward_devtools(self) -> int:
        """Forward Chrome's DevTools socket to a new loopback port; only adbd may reach it."""
        forwarded = self.run('forward', 'tcp:0', 'localabstract:chrome_devtools_remote')
        port = forwarded.stdout.decode('ascii', 'replace').strip()
        if forwarded.returncode != 0 or not port.isdigit() or not 0 < int(port) < 65536:
            raise AndroidError("Chrome's DevTools socket is unavailable; is Chrome running?")
        return int(port)

    def remove_forward(self, port: int) -> None:
        try:
            self.run('forward', '--remove', f'tcp:{port}')
        except Exception:
            pass


SHELL_STDIN, SHELL_STDOUT, SHELL_STDERR, SHELL_EXIT, SHELL_CLOSE_STDIN = 0, 1, 2, 3, 4
NEED_PREFIX = 'AKDBX-ANDROID-NEED '


def _read_exact(connection, size: int) -> bytes:
    data = b''
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise AndroidError('adb connection closed')
        data += chunk
    return data


def _send_packet(connection, kind: int, data: bytes) -> None:
    connection.sendall(bytes([kind]) + len(data).to_bytes(4, 'little') + data)


def _read_packet(connection) -> tuple[int, bytes]:
    header = _read_exact(connection, 5)
    size = int.from_bytes(header[1:], 'little')
    if size > MAX_HELPER_OUTPUT:
        raise AndroidError('adb packet too large')
    return header[0], _read_exact(connection, size)


class ChromeDevTools:
    """A browser 'profile' for the CDP route: Chrome on a configured device.

    The loopback port exists only from devtools_endpoint() until the CDP
    connection opens (release_endpoint); the open connection outlives it.
    """

    def __init__(self, adb: Adb):
        self.adb = adb
        self.port = None

    def devtools_endpoint(self) -> str:
        self.port = self.adb.forward_devtools()
        return f'ws://127.0.0.1:{self.port}/devtools/browser'

    def release_endpoint(self) -> None:
        if self.port is not None:
            self.adb.remove_forward(self.port)
            self.port = None


class ManagedChromeDevTools:
    """Upgrade a stream through the private adb socket without publishing a forward."""

    def __init__(self, adb: Adb):
        self.adb = adb

    def devtools_endpoint(self):
        # The WebSocket handshake needs a Host and path. No TCP connection is made.
        return 'ws://127.0.0.1/devtools/browser'

    def open_verified_socket(self):
        connection = self.adb._connect(2)
        try:
            self.adb._request(connection, 'host:transport:' + self.adb.device.serial)
            self.adb._request(connection, 'localabstract:chrome_devtools_remote')
            return connection
        except BaseException:
            connection.close()
            raise


# Run in a fresh isolated world of the main frame: page scripts cannot change them.
PAGE_STATE = r"""(function() {
  return {url: location.href, shown: document.visibilityState === 'visible' && document.hasFocus(),
          secure: isSecureContext};
})()"""
PAGE_FIELDS = r"""(function() {
  const type = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type').get;
  const attribute = Element.prototype.getAttribute;
  // A selector is usable only when its one match is the element it describes.
  let current = null;
  const only = (s, element) => { try { const a = document.querySelectorAll(s); return a.length === 1 && a[0] === element; } catch (e) { return false; } };
  const unique = s => only(s, current);
  const fields = [];
  for (const e of document.querySelectorAll('input')) {
    const t = type.call(e);
    if (!['text', 'email', 'password', 'tel', 'number', 'search', 'url'].includes(t)) continue;
    const r = e.getBoundingClientRect();
    if (!e.checkVisibility({checkOpacity: true, checkVisibilityCSS: true}) || r.width <= 0 || r.height <= 0) continue;
    current = e;
    const id = attribute.call(e, 'id'), name = attribute.call(e, 'name');
    let selector = null;
    const short = s => s.length <= 1000 && unique(s);
    if (id && short('#' + CSS.escape(id))) selector = '#' + CSS.escape(id);
    else if (name && short('input[name="' + CSS.escape(name) + '"]')) selector = 'input[name="' + CSS.escape(name) + '"]';
    else if (unique('input[type="' + t + '"]')) selector = 'input[type="' + t + '"]';
    else {
      // A structural path from the nearest ancestor with a unique id, or the root.
      const steps = [];
      for (let node = e; node && node.nodeType === 1 && node !== document.documentElement; node = node.parentElement) {
        const nodeId = attribute.call(node, 'id');
        if (node !== e && nodeId && only('#' + CSS.escape(nodeId), node)) { steps.unshift('#' + CSS.escape(nodeId)); break; }
        let index = 1;
        for (let sibling = node.previousElementSibling; sibling; sibling = sibling.previousElementSibling)
          if (sibling.localName === node.localName) index++;
        steps.unshift(node.localName + ':nth-of-type(' + index + ')');
      }
      const path = steps.join(' > ');
      if (path.length <= 1000 && unique(path)) selector = path;
    }
    const clip = v => typeof v === 'string' ? v.slice(0, 200) : null;
    const label = e.labels && e.labels.length ? e.labels[0].textContent.trim() : attribute.call(e, 'aria-label');
    fields.push({selector: selector, type: t, id: clip(id), name: clip(name),
                 autocomplete: clip(attribute.call(e, 'autocomplete')), placeholder: clip(attribute.call(e, 'placeholder')),
                 label: clip(label), focused: document.activeElement === e, has_value: e.value.length > 0,
                 disabled: e.disabled || e.readOnly});
    if (fields.length >= 40) break;
  }
  return fields;
})()"""
# A pinned page field, held in an isolated world. Before a value moves, the
# field is emptied and focused, the device helper types a random check string
# as key events that Android delivers only to Chrome's windows, and the broker
# compares the field's text with that string: only real Chrome can return it,
# and only if the pinned element had focus. The value is then set on it.
PAGE_FIELD = r"""(function(selector, url, kind) {
  if (!isSecureContext || location.href !== url || !document.hasFocus() || document.visibilityState !== 'visible') throw 0;
  const query = s => { const a = document.querySelectorAll(s); if (a.length !== 1) throw 0; return a[0]; };
  const field = query(selector);
  const created = performance.now();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const getter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').get;
  const type = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type').get;
  const kinds = {password: ['password'], username: ['text', 'email'], code: ['text', 'tel', 'number']};
  const valid = e => {
    if (!(e instanceof HTMLInputElement) || !e.isConnected || e.ownerDocument !== document || e.disabled || e.readOnly || e.closest('[inert]')) return false;
    const t = type.call(e), r = e.getBoundingClientRect(), s = getComputedStyle(e);
    return kinds[kind].includes(t) && e.checkVisibility({checkOpacity:true,checkVisibilityCSS:true}) && r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth && s.visibility === 'visible' && s.display !== 'none' && s.opacity !== '0';
  };
  let tainted = false;
  const dirty = () => { tainted = true; };
  if (!window.navigation) throw 0;
  window.navigation.addEventListener('navigate', dirty);
  document.addEventListener('visibilitychange', dirty, true);
  const observer = new MutationObserver(records => {
    for (const r of records) if (r.type === 'childList' && [...r.removedNodes].some(n => n === field || n.contains(field))) dirty();
  });
  observer.observe(document, {childList:true, subtree:true});
  const dispose = () => {
    window.navigation.removeEventListener('navigate', dirty);
    document.removeEventListener('visibilitychange', dirty, true);
    observer.disconnect();
  };
  const check = () => performance.now() - created < 60000 && !tainted && isSecureContext && location.href === url &&
    document.hasFocus() && document.visibilityState === 'visible' && valid(field) && query(selector) === field;
  if (!check()) { dispose(); throw 0; }
  return {kind, field, check, dispose, focused: document.activeElement === field,
    // Empty the field and focus it; the helper then types into the focused
    // element. Answers the field's maximum length (-1 for none), or false.
    prepare(deadline) {
      if (!this.check() || performance.now() >= deadline) return false;
      setter.call(field, '');
      field.dispatchEvent(new Event('input', {bubbles:true}));
      field.focus();
      return document.activeElement === field && getter.call(field) === '' && this.check() ? [field.maxLength, type.call(field)] : false;
    },
    // The field's text, for the broker to compare: the expected text never goes to this peer.
    read() { return this.check() && document.activeElement === field ? getter.call(field) : null; },
    // Set the value on this element only; report whether the field keeps it.
    set(value) {
      if (!this.check() || document.activeElement !== field) return false;
      setter.call(field, value);
      field.dispatchEvent(new Event('input', {bubbles:true}));
      field.dispatchEvent(new Event('change', {bubbles:true}));
      return getter.call(field) === value ? true : 'changed';
    }};
})"""


# For reads and structured fields the check must not clear a value, notify
# a form or submit a short code. Observe the random hardware key sequence on
# the retained focused node in Chrome's isolated world. No expected byte is
# supplied over CDP. Remove the listener even if the client disappears.
KEY_PROOF = r"""(function(guard, field, mode, url) {
  if (!guard || !field || !window.navigation || field !== document.activeElement) throw 0;
  let tainted = false;
  const dirty = () => { tainted = true; };
  const observer = new MutationObserver(records => {
    if (records.some(r => [...r.removedNodes].some(n => n === field || n.contains(field)))) dirty();
  });
  observer.observe(document, {childList:true, subtree:true});
  window.navigation.addEventListener('navigate', dirty);
  document.addEventListener('visibilitychange', dirty);
  field.addEventListener('blur', dirty);
  const valid = () => !tainted && location.href === url && isSecureContext && document.hasFocus() &&
    document.visibilityState === 'visible' && document.activeElement === field &&
    (mode === 'read' ? guard.check() : guard.geometry());
  let keys = '', timer;
  const observe = e => {
    if (e.isTrusted && /^[a-z0-9]$/.test(e.key)) {
      e.preventDefault();
      e.stopImmediatePropagation();
      if (e.type === 'keydown' && e.target === field && valid() && keys.length < 17) keys += e.key;
    }
  };
  const stop = () => {
    window.removeEventListener('keydown', observe, true);
    window.removeEventListener('keyup', observe, true);
    clearTimeout(timer);
  };
  return {focused: !!valid(), node: () => field, points() {
    if (!valid()) return [];
    if (mode !== 'read') return [guard.geometry()];
    // Match the read guard's visibility probes for every rendered text line.
    let rects;
    if (field instanceof HTMLInputElement) {
      rects = [field.getBoundingClientRect()];
    } else {
      const range = document.createRange();
      range.selectNodeContents(field);
      rects = Array.from(range.getClientRects());
    }
    if (rects.length > 16) return [];
    return rects.flatMap(r => [r.left + 1, r.left + r.width / 2, r.right - 1].map(x =>
      ({rootX: x + scrollX, rootY: r.top + r.height / 2 + scrollY})));
  }, prepare() {
    if (!valid()) return false;
    keys = '';
    window.addEventListener('keydown', observe, true);
    window.addEventListener('keyup', observe, true);
    timer = setTimeout(stop, 8000);
    return true;
  }, proof() { stop(); return valid() ? keys : null; },
  capture(deadline) { return mode === 'read' && performance.now() < deadline && valid() ? guard.value() : null; },
  write(value, notify, deadline) {
    if (performance.now() >= deadline || !valid()) return 'refused';
    const result = guard.fill(value, 30000, notify);
    return result === 'filled' && !valid() ? 'uncertain' : result;
  }, dispose() {
    stop();
    observer.disconnect();
    window.navigation.removeEventListener('navigate', dirty);
    document.removeEventListener('visibilitychange', dirty);
    field.removeEventListener('blur', dirty);
    if (guard.dispose) guard.dispose();
  }};
})"""


def _structured_page_field(mode, selector, url, purpose):
    from .browser_card import PIN_SCRIPT
    from .browser_code import BrowserCodes
    from .browser_password import MAX_READ_SELECTOR, READ_CAPTURE, READ_SELECTOR

    if mode == 'read':
        if len(selector) > MAX_READ_SELECTOR or not READ_SELECTOR.fullmatch(selector):
            raise AndroidError('unsupported read selector')
        script, args = READ_CAPTURE, [selector, url, serialize_origin(_origin_of(url))]
    elif mode == 'sms':
        script, args = BrowserCodes.pin_script, [selector, 'one-time-code', url, url, *BrowserCodes.pin_extra]
    else:
        script, args = PIN_SCRIPT, [selector, purpose, url, url, False, mode == 'identity']
    call = '(' + script + ')(' + ','.join(map(json.dumps, args)) + ')'
    return (KEY_PROOF + '(' + call + ',document.querySelector(' + json.dumps(selector) + '),'
            + json.dumps(mode) + ',' + json.dumps(url) + ')')


QUICK_STATE = "document.visibilityState === 'visible' && document.hasFocus()"


def _answering_shown(connection, sessions, timeout):
    """Sessions whose page says it is visible and focused, asked all at once."""
    socket_ = getattr(connection, 'socket', None)
    if socket_ is None or not hasattr(connection, 'counter'):
        shown = []
        for session in sessions:
            try:
                result = connection.call('Runtime.evaluate', {'expression': QUICK_STATE, 'returnByValue': True},
                                         session, timeout=timeout)
            except Exception:
                continue
            if result.get('result', {}).get('value') is True:
                shown.append(session)
        return shown
    waiting = {}
    for session in sessions:
        connection.counter += 1
        waiting[connection.counter] = session
        socket_.send(json.dumps({'id': connection.counter, 'method': 'Runtime.evaluate', 'sessionId': session,
                                 'params': {'expression': QUICK_STATE, 'returnByValue': True}}))
    shown = []
    deadline = time.monotonic() + timeout
    while waiting and time.monotonic() < deadline:
        try:
            socket_.settimeout(max(0.01, deadline - time.monotonic()))
            message = json.loads(socket_.recv())
        except Exception:
            break
        session = waiting.pop(message.get('id'), None) if isinstance(message, dict) else None
        if session is not None and message.get('result', {}).get('result', {}).get('value') is True:
            shown.append(session)
    return shown


def _check_string(mode, max_length, input_type):
    """A random string for the typed check that the field takes and that cannot pass as a code.

    In a code field it is five characters, fewer than any code, so a page that
    submits when a code is complete never submits it; it has a letter where
    the field takes one. A number field takes digits only.
    """
    if mode == 'totp':
        size, alphabet = 5, '0123456789' if input_type == 'number' else NONCE_ALPHABET
        if 0 <= max_length < 6:
            raise TargetError()
        text = ''.join(secrets.choice(alphabet) for _ in range(size))
        if alphabet is NONCE_ALPHABET and text.isdigit():
            text = secrets.choice('abcdefghijkmnpqrstuvwxyz') + text[1:]
        return text
    size = 16 if max_length < 0 else min(16, max_length)
    if size < 6:
        raise TargetError()
    return ''.join(secrets.choice(NONCE_ALPHABET) for _ in range(size))


def _origin_of(url):
    from .totp import https_origin
    try:
        return https_origin(url)
    except Exception:
        return None


def _authority_matches(authority, origin) -> bool:
    """Chrome's address bar shows the host, and the port when it is not the default.

    It hides a leading "www.". The DevTools origin stays the exact origin.
    """
    _, host, port = origin
    if ':' in host:
        host = f'[{host}]'  # Chrome shows an IPv6 address in brackets.
    hosts = {host, host[4:]} if host.startswith('www.') and len(host) > 4 else {host}
    # Chrome shows an internationalized host in Unicode; DevTools gives punycode.
    try:
        import idna
        hosts |= {idna.decode(h) for h in hosts if 'xn--' in h}
    except Exception:
        pass
    return authority in {h if port == 443 else f'{h}:{port}' for h in hosts} | {f'{h}:{port}' for h in hosts}


def asset_link_allows(site, package: str, signer: str, *, fetch=None) -> bool:
    """True when the site's Digital Asset Links file names this app and signer."""
    url = serialize_origin(site) + '/.well-known/assetlinks.json'
    try:
        statements = json.loads((fetch or _fetch_asset_links)(url))
    except Exception:
        return False
    if not isinstance(statements, list):
        return False
    wanted = signer.upper()
    for statement in statements[:256]:
        if not isinstance(statement, dict):
            continue
        relations = statement.get('relation')
        target = statement.get('target')
        if (not isinstance(relations, list) or not any(r in ASSET_LINK_RELATIONS for r in relations)
                or not isinstance(target, dict) or target.get('namespace') != 'android_app'
                or target.get('package_name') != package):
            continue
        prints = target.get('sha256_cert_fingerprints')
        if isinstance(prints, list) and any(isinstance(p, str) and p.replace(':', '').upper() == wanted for p in prints):
            return True
    return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _fetch_asset_links(url: str) -> bytes:
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(urllib.request.Request(url, headers={'Accept': 'application/json'}), timeout=8) as response:
        if response.status != 200:
            raise ValueError
        data = response.read(MAX_ASSET_LINKS + 1)
    if len(data) > MAX_ASSET_LINKS:
        raise ValueError
    return data


# ----- pins -----------------------------------------------------------------

@dataclass
class ChromeFields:
    """A Chrome pin's DevTools connection and its page-field objects, in fill order."""
    connection: object
    session: str
    page_id: str
    url: str
    objects: list
    frame_id: str | None = None
    backend_node: int | None = None

    def check_proof_listeners(self):
        # A window capture handler registered by the page can run before our
        # isolated-world listener. Check the page's main world after arming
        # our listener; any handler registered afterwards runs behind it.
        obj = self.connection.call('Runtime.evaluate', {'expression': 'this', 'silent': True},
                                   self.session)['result']['objectId']
        try:
            listeners = self.connection.call('DOMDebugger.getEventListeners', {'objectId': obj, 'depth': 1},
                                             self.session)['listeners']
            if any(event['useCapture'] and event['type'] in ('keydown', 'keyup') for event in listeners):
                raise AndroidError('the page handles proof keys before the focused field')
        finally:
            self.connection.call('Runtime.releaseObject', {'objectId': obj}, self.session)

    def check_exposed(self):
        from . import card_hit_test
        points = self.call(0, 'function() { return this.points(); }')
        if (not isinstance(points, list) or not 1 <= len(points) <= 48
                or not all(card_hit_test.hit(self.connection, self.session, point, self.backend_node, self.frame_id)
                           for point in points)):
            raise AndroidError('the pinned field is covered or no longer visible')

    def call(self, index, declaration, *args, timeout=3):
        result = self.connection.call('Runtime.callFunctionOn', {
            'objectId': self.objects[index], 'functionDeclaration': declaration,
            'arguments': [{'value': value} for value in args], 'returnByValue': True}, self.session, timeout=timeout)
        if 'exceptionDetails' in result:
            raise TargetError()
        return result.get('result', {}).get('value')

    def close(self):
        try:
            for index in range(len(self.objects)):
                self.call(index, 'function() { this.dispose(); }', timeout=0.2)
        except Exception:
            pass
        finally:
            self.connection.close()


@dataclass
class AndroidPin:
    token: str
    device: Device
    boot_id: str
    context: dict
    fields: list
    mode: str
    origin: tuple
    source: str
    expires_at: float
    # A Chrome page pin holds its DevTools fields (ChromeFields).
    purpose: str | None = None
    dom: object = None
    used: bool = field(default=False)

    def __getitem__(self, key):
        if key == 'field':
            return self.purpose
        raise KeyError(key)

    def close(self):
        self.used = True
        if self.dom is not None:
            dom, self.dom = self.dom, None
            dom.close()


FIELD_KEYS = {'window_id': int, 'node_id': str, 'class': str, 'view_id': (str, type(None)),
              'package': str, 'hint': (str, type(None)), 'label': (str, type(None)),
              'password': bool, 'editable': bool, 'enabled': bool, 'visible': bool, 'focused': bool,
              'has_text': bool, 'input_type': int, 'bounds': list, 'web': bool}
CONTEXT_KEYS = {'address_bar': (str, type(None)), 'boot_id': str, 'sdk': int, 'speak_password': bool,
                'window_id': int, 'window_title': (str, type(None)), 'package': str, 'activity': str,
                'task_id': int, 'user_id': int,
                'signers': list, 'signer_lineage': list, 'debuggable': bool, 'system_app': bool}
HEX64 = re.compile(r'[0-9A-F]{64}')
NODE_ID = re.compile(r'-?[0-9]{1,20}')


def _checked(value: dict, keys: dict, optional=()) -> dict:
    """Keep only expected keys of the expected types from a helper answer."""
    if not isinstance(value, dict):
        raise AndroidError('Android helper answer malformed')
    result = {}
    for key, kind in keys.items():
        if key not in value:
            raise AndroidError('Android helper answer malformed')
        item = value[key]
        if not isinstance(item, kind) or isinstance(item, bool) and kind is int:
            raise AndroidError('Android helper answer malformed')
        result[key] = _clip(item) if isinstance(item, str) else item
    for key in optional:
        if key in value:
            if not isinstance(value[key], bool):
                raise AndroidError('Android helper answer malformed')
            result[key] = value[key]
    return result


def _field(value) -> dict:
    result = _checked(value, FIELD_KEYS, optional=('in_frame',))
    if (not NODE_ID.fullmatch(result['node_id']) or len(result['bounds']) != 4
            or not all(type(n) is int for n in result['bounds'])):
        raise AndroidError('Android helper answer malformed')
    return result


def _context(value) -> dict:
    result = _checked(value, CONTEXT_KEYS)
    for key in ('signers', 'signer_lineage'):
        if not 1 <= len(result[key]) <= 16 or not all(isinstance(s, str) and HEX64.fullmatch(s) for s in result[key]):
            raise AndroidError('Android helper answer malformed')
    if len(result['signers']) != 1 or result['signers'][0] != result['signer_lineage'][-1]:
        raise AndroidError('Android helper answer malformed')
    return result


def _is_chrome(context) -> bool:
    return (context['package'] == CHROME_PACKAGE and context['signer_lineage'][0] == GOOGLE_SIGNER
            and context['activity'] in CHROME_ACTIVITIES)


class AndroidTargets:
    """Android pins and fills for the broker."""

    def __init__(self, config_path: Path | None, *, clock: Callable[[], float] = time.monotonic,
                 adb_factory=Adb, fetch=None, cdp_factory=None):
        self.config_path = config_path
        self.clock = clock
        self.adb_factory = adb_factory
        self.fetch = fetch
        self.cdp_factory = cdp_factory
        self._pins: dict[str, AndroidPin] = {}
        self._lock = threading.Lock()

    # Configuration is read per request: the operator can add a device
    # without restarting the broker (and locking the vault).
    def devices(self) -> dict[str, Device]:
        return load_devices(self.config_path)

    def configured(self) -> bool:
        try:
            return bool(self.devices())
        except AndroidError:
            return False

    def capabilities(self) -> dict:
        from .android_lifecycle import state, unit_name
        try:
            devices = self.devices()
        except AndroidError:
            devices = {}
        result = capabilities(bool(devices))
        managed = {d.name: {'state': state(d), 'unit': unit_name(d)} for d in devices.values() if d.managed}
        if managed:
            result['android_managed_devices'] = managed
        return result

    def _device(self, request) -> Device:
        name = request.get('device')
        devices = self.devices()
        if not isinstance(name, str) or name not in devices:
            raise AndroidError('unknown Android device; configured devices: ' + (', '.join(sorted(devices)) or 'none'))
        device = devices[name]
        if device.managed:
            from .android_lifecycle import state
            if state(device) != 'awake':
                raise AndroidError('managed Android device is asleep; use android wake on the broker host')
        return device

    def list_devices(self, request) -> dict:
        if set(request) - {'action', 'android_protocol'}:
            raise AndroidError('invalid Android device list request')
        result = []
        deadline = time.monotonic() + DEVICE_LIST_BUDGET
        for device in self.devices().values():
            adb = self.adb_factory(device)
            item = {'name': device.name, 'serial': device.serial, 'adb_server_port': device.port}
            if device.managed is not None:
                from .android_lifecycle import state
                item['power_state'] = state(device)
                if item['power_state'] != 'awake':
                    item.update(reachable=False, speak_password=None, sdk=None)
                    result.append(item)
                    continue
            if time.monotonic() >= deadline:
                item.update(reachable=None, speak_password=None, sdk=None)
                result.append(item)
                continue
            try:
                # Install the helper only while the list has time for a push and a second probe.
                install = deadline - time.monotonic() >= INSTALL_BUDGET
                probe = adb.helper({'op': 'probe'}, install=install, timeout=DEVICE_PROBE_TIMEOUT)
                item.update(reachable=probe.get('ok') is True,
                            speak_password=probe.get('speak_password') if isinstance(probe.get('speak_password'), bool) else None,
                            sdk=probe.get('sdk') if type(probe.get('sdk')) is int else None)
            except (AndroidError, OSError, subprocess.SubprocessError):
                item.update(reachable=False, speak_password=None, sdk=None)
            result.append(item)
        return {'ok': True, 'devices': result}

    # ----- Chrome pages ------------------------------------------------

    def _cdp(self, adb):
        if self.cdp_factory is not None:
            return self.cdp_factory(adb)
        from .browser_password import CDP
        profile = ManagedChromeDevTools(adb) if adb.device.managed else ChromeDevTools(adb)
        return CDP(profile)

    def _chrome_page(self, connection, context) -> dict:
        """The one visible, focused Chrome tab; its host must match the address bar."""
        pages = [t for t in connection.call('Target.getTargets')['targetInfos'] if t.get('type') == 'page']
        if context['address_bar'] is not None:
            # Only tabs with the host the address bar shows: Chrome freezes
            # background tabs, and a frozen tab answers no DevTools call.
            pages = [t for t in pages if isinstance(t.get('url'), str) and _origin_of(t['url']) is not None
                     and _authority_matches(context['address_bar'], _origin_of(t['url']))]
        sessions = {}
        attach_deadline = time.monotonic() + TAB_ATTACH_BUDGET
        too_many = AndroidError('too many tabs on this site to find the focused one; close some and try again')
        for page in pages:
            left = attach_deadline - time.monotonic()
            if left <= 0:
                raise too_many
            try:
                sessions[connection.call('Target.attachToTarget', {'targetId': page['targetId'], 'flatten': True},
                                         timeout=min(TAB_CALL_TIMEOUT, left))['sessionId']] = page
            except Exception:
                continue
        if time.monotonic() >= attach_deadline:
            raise too_many
        shown = []
        # Ask every tab at once: frozen background tabs never answer, so they cannot use up the search.
        for session in _answering_shown(connection, list(sessions), TAB_PROBE_TIMEOUT):
            page = sessions[session]
            try:
                frame = connection.call('Page.getFrameTree', session=session)['frameTree']['frame']
                world = connection.call('Page.createIsolatedWorld', {'frameId': frame['id'], 'worldName': 'akdbx-android-v1'},
                                        session)['executionContextId']
                # The page's own answer only picked candidates; this isolated world decides.
                state = connection.call('Runtime.evaluate', {'expression': PAGE_STATE, 'contextId': world,
                                                             'returnByValue': True}, session)['result'].get('value')
            except Exception:
                continue
            if isinstance(state, dict) and state.get('shown') is True and state.get('url') == page.get('url'):
                shown.append({'page_id': page['targetId'], 'url': page['url'], 'frame_id': frame['id'],
                              'session': session, 'world': world, 'secure': state.get('secure') is True})
        if len(shown) != 1:
            raise AndroidError('no single visible, focused Chrome tab; bring the page to the front and try again')
        page = shown[0]
        origin = _origin_of(page['url'])
        if origin is None or not page['secure']:
            raise AndroidError('page is not HTTPS')
        if context['address_bar'] is not None and not _authority_matches(context['address_bar'], origin):
            raise AndroidError("Chrome's address bar does not show the focused tab's site; try again")
        page['origin'] = origin
        return page

    def _chrome_inspect(self, adb, context) -> dict:
        connection = self._cdp(adb)
        try:
            page = self._chrome_page(connection, context)
            result = connection.call('Runtime.evaluate', {'expression': PAGE_FIELDS, 'contextId': page['world'],
                                                          'returnByValue': True}, page['session'])
            fields = result.get('result', {}).get('value')
        finally:
            connection.close()
        if not isinstance(fields, list):
            raise AndroidError('could not read the page fields')
        clean = []
        for item in fields[:40]:
            if not isinstance(item, dict):
                continue
            selector = item.get('selector')
            clean.append({'field': selector if isinstance(selector, str) and len(selector) <= 1000 else None, 'kind': 'page',
                          **{key: _clip(item.get(key)) for key in ('type', 'id', 'name', 'autocomplete', 'placeholder', 'label')},
                          **{key: item.get(key) is True for key in ('focused', 'has_value', 'disabled')}})
        return {'site': {'origin': serialize_origin(page['origin']), 'source': 'chrome'}, 'page_url': _clip(page['url'], 2048),
                'fields': clean}

    def _chrome_pin(self, request, mode, device, adb, context) -> dict:
        """Pin Chrome page fields: DevTools reads and focuses them; the helper types the values."""
        selectors = [request.get('username_field'), request.get('field')] if mode == 'login' else [request.get('field')]
        for value in selectors:
            if not isinstance(value, str) or not 0 < len(value) <= 4096:
                raise AndroidError('page fields are CSS selectors from android inspect')
        if request.get('app_site') is not None:
            raise AndroidError('--app-site is for apps; a Chrome page is verified by its own origin')
        if context['address_bar'] is None:
            raise AndroidError("Chrome's address bar is not shown; scroll up so it shows, then pin again")
        kinds = {'login': ('username', 'password'), 'username': ('username',), 'password': ('password',),
                 'totp': ('code',)}.get(mode, (mode,))
        connection = self._cdp(adb)
        fields = []
        try:
            page = self._chrome_page(connection, context)
            for selector, kind in zip(selectors, kinds):
                result = connection.call('Runtime.evaluate', {
                    'expression': (_structured_page_field(mode, selector, page['url'], request.get('purpose'))
                                   if mode in CHALLENGE_MODES else
                                   PAGE_FIELD + '(' + ','.join(map(json.dumps, (selector, page['url'], kind))) + ')'),
                    'contextId': page['world']}, page['session'])
                if 'exceptionDetails' in result or result['result'].get('type') != 'object' or 'objectId' not in result['result']:
                    raise AndroidError(f'page {kind} field refused: it must be unique for its selector, visible and '
                                       f'enabled, and a {"password" if kind == "password" else "text"} input')
                fields.append(result['result']['objectId'])
            # The caller tapped the first field: the pin is for the field the person sees in use.
            focused = connection.call('Runtime.callFunctionOn', {
                'objectId': fields[0], 'functionDeclaration': 'function() { return this.focused; }',
                'returnByValue': True}, page['session'])
            if focused.get('result', {}).get('value') is not True:
                raise AndroidError('tap the field first: the pinned field must be the focused one')
            dom = ChromeFields(connection, page['session'], page['page_id'], page['url'], fields)
            if mode in CHALLENGE_MODES:
                from . import card_hit_test
                dom.frame_id = page['frame_id']
                dom.backend_node = card_hit_test.retained_node(connection, page['session'], fields[0])
                dom.check_exposed()
        except Exception:
            connection.close()
            raise
        return self._store(device, context, [], mode, page['origin'], 'chrome', dom=dom, purpose=request.get('purpose'))

    # ----- apps ----------------------------------------------------------

    def _app_site(self, context: dict, fields: list, app_site):
        """Decide the one HTTPS origin these app fields may receive a credential for."""
        package, activity = context['package'], context['activity']
        google = context['signer_lineage'][0] == GOOGLE_SIGNER
        if any(f.get('in_frame') for f in fields):
            raise AndroidError('field is inside a frame; only fields of the top page are supported')
        if (app_site is None and package == GMS_PACKAGE and google and activity == GMS_SIGN_IN_ACTIVITY
                and all(f['web'] for f in fields)):
            return GOOGLE_SIGN_IN_ORIGIN, 'google-sign-in'
        if any(f['web'] for f in fields):
            # An app's web view shows no page URL to accessibility.
            raise AndroidError("a web field inside an app is refused: its page's site cannot be read")
        if app_site is None:
            raise AndroidError('app not verified for any site; give --app-site with the HTTPS site whose '
                               'Digital Asset Links name this app')
        from .password_frames import canonical_origin
        from .totp import https_origin
        try:
            site = https_origin(canonical_origin(app_site))
        except Exception:
            raise AndroidError('--app-site must be an exact HTTPS origin such as https://example.com') from None
        if not asset_link_allows(site, package, context['signers'][0], fetch=self.fetch):
            raise AndroidError("the site's Digital Asset Links do not name this app and signing certificate")
        return site, 'asset-links'

    def _helper_context(self, answer) -> dict:
        if answer.get('ok') is not True:
            raise AndroidError('device refused: ' + str(_clip(answer.get('error')) or 'unknown'))
        context = _context(answer.get('context'))
        if context['debuggable']:
            raise AndroidError('target app is debuggable; another process could read its memory')
        return context

    def inspect(self, request) -> dict:
        if set(request) - {'action', 'device', 'android_protocol'}:
            raise AndroidError('invalid Android inspect request')
        device = self._device(request)
        adb = self.adb_factory(device)
        answer = adb.helper({'op': 'inspect', 'wake': True}, install=True)
        if answer.get('ok') is not True:
            raise AndroidError('device refused: ' + str(_clip(answer.get('error')) or 'unknown'))
        context = _context(answer.get('context'))
        app = {key: context[key] for key in ('package', 'activity', 'window_title', 'debuggable', 'system_app')}
        app['signer_sha256'] = context['signers'][0]
        base = {'ok': True, 'device': device.name, 'app': app, 'speak_password': context['speak_password']}
        if _is_chrome(context):
            return {**base, **self._chrome_inspect(adb, context)}
        raw_fields = answer.get('fields')
        if not isinstance(raw_fields, list) or len(raw_fields) > 64:
            raise AndroidError('Android helper answer malformed')
        fields = [_field(f) for f in raw_fields]
        verified, note = None, None
        web = [f for f in fields if f['web']]
        try:
            if context['package'] == CHROME_PACKAGE:
                raise AndroidError('Chrome is not in a tab or Custom Tab, or is not signed by Google')
            if context['debuggable']:
                raise AndroidError('target app is debuggable')
            origin, source = self._app_site(context, web[:1] or fields[:1], None)
            verified = {'origin': serialize_origin(origin), 'source': source}
            if source == 'google-sign-in':
                note = 'pin only the email here; use "akdbx android google-sign-in" for the password and code'
        except AndroidError as exc:
            note = exc.message
        return {**base, 'site': verified, **({'site_note': note} if note else {}),
                'fields': [{'field': f['node_id'], 'kind': 'app',
                            **{key: f[key] for key in ('class', 'view_id', 'hint', 'label', 'password', 'editable',
                                                        'enabled', 'visible', 'focused', 'has_text', 'bounds', 'web')},
                            **({'in_frame': f['in_frame']} if 'in_frame' in f else {})}
                           for f in fields]}

    def pin(self, request) -> dict:
        allowed = {'action', 'device', 'mode', 'field', 'username_field', 'app_site', 'android_protocol', 'purpose'}
        if set(request) - allowed or request.get('android_protocol') != PROTOCOL:
            raise AndroidError('invalid Android pin request')
        mode = request.get('mode')
        if mode not in MODES:
            raise AndroidError('unsupported Android pin mode')
        from .cards import FILL_FIELDS as CARD_FIELDS
        from .identities import FILL_FIELDS as IDENTITY_FIELDS
        if mode in ('card', 'identity'):
            if request.get('purpose') not in (CARD_FIELDS if mode == 'card' else IDENTITY_FIELDS):
                raise AndroidError('select a supported field with --purpose')
        elif 'purpose' in request:
            raise AndroidError('--purpose requires card or identity mode')
        if (mode == 'login') != (request.get('username_field') is not None):
            raise AndroidError('--username-field is required in login mode and only there')
        app_site = request.get('app_site')
        if app_site is not None and not isinstance(app_site, str):
            raise AndroidError('invalid --app-site')
        device = self._device(request)
        adb = self.adb_factory(device)
        context = self._helper_context(adb.helper({'op': 'context'}, install=True))
        if _is_chrome(context):
            return self._chrome_pin(request, mode, device, adb, context)
        if context['package'] == CHROME_PACKAGE:
            raise AndroidError('Chrome is not in a tab or Custom Tab, or is not signed by Google')
        if (context['package'] == GMS_PACKAGE and context['activity'] == GMS_SIGN_IN_ACTIVITY
                and context['signer_lineage'][0] == GOOGLE_SIGNER and mode != 'username'):
            raise AndroidError(GOOGLE_SECRETS_REFUSAL)
        if mode == 'read':
            raise AndroidError('Android read pins require a focused Chrome page field')
        ids = [request.get('username_field'), request.get('field')] if mode == 'login' else [request.get('field')]
        if not all(isinstance(i, str) and NODE_ID.fullmatch(i) for i in ids) or len(set(ids)) != len(ids):
            raise AndroidError('app fields are the field values from android inspect')
        answer = adb.helper({'op': 'check', 'node_ids': ids, 'wake': True}, install=True)
        context = self._helper_context(answer)
        if _is_chrome(context) or context['package'] == CHROME_PACKAGE:
            raise AndroidError('the focused app changed; inspect again')
        raw = answer.get('fields')
        if not isinstance(raw, list) or len(raw) != len(ids):
            raise AndroidError('Android helper answer malformed')
        fields = [_field(f) for f in raw]
        if [f['node_id'] for f in fields] != ids:
            raise AndroidError('Android helper answer malformed')
        if context['speak_password']:
            raise AndroidError(SPEAK_PASSWORD_REFUSAL)
        for f in fields:
            if f['package'] != context['package'] or not f['enabled'] or not f['visible']:
                raise AndroidError('field is not an enabled, visible field of the focused app')
        roles = {'login': (False, True), 'username': (False,), 'password': (True,), 'totp': (None,), 'sms': (None,), 'card': (None,), 'identity': (False,)}[mode]
        for f, wants_password in zip(fields, roles):
            if wants_password is not None and f['password'] != wants_password:
                raise AndroidError('password value needs a password field' if wants_password
                                   else 'this mode needs a field that is not a password field')
        if len({f['web'] for f in fields}) != 1:
            raise AndroidError('login fields must both be web fields or both be app fields')
        origin, source = self._app_site(context, fields, app_site)
        if source == 'google-sign-in' and mode != 'username':
            # The sign-in web view shows no page URL: a work account can move
            # it to another site. Only the one-run sign-in may fill secrets.
            raise AndroidError(GOOGLE_SECRETS_REFUSAL)
        return self._store(device, context, fields, mode, origin, source, purpose=request.get('purpose'))

    def google_sign_in(self, request, values: dict, ready: Callable[[], bool], code=None) -> dict:
        """Fill the email, then the password (and a code) on the pages Google's flow shows next.

        Returns the receipt; raises DeliveryError(started) when the outcome is unknown.
        """
        device = self._device(request)
        adb = self.adb_factory(device)
        try:
            context = self._helper_context(adb.helper({'op': 'context'}, install=True))
        except AndroidError:
            raise DeliveryError(False) from None
        if context['speak_password']:
            raise AndroidError(SPEAK_PASSWORD_REFUSAL)
        if not ready():
            raise DeliveryError(False)
        request = {'op': 'google_sign_in', 'boot_id': context['boot_id'], **values}
        if code is not None:
            request['code'] = True

        def answer_need(need):
            if need != 'code' or code is None:
                return b'{}\n'
            return (json.dumps({'code': code()}) + '\n').encode()
        try:
            # The run opens a new sign-in, then each page may take the helper's 25-second wait.
            answer = adb.helper(request, install=False, timeout=SIGN_IN_TIMEOUT, answer=answer_need)
        except Exception:
            raise DeliveryError(True) from None
        finally:
            request = None
        if answer.get('ok') is not True:
            error = answer.get('error')
            raise DeliveryError(not isinstance(error, str) or error.startswith('helper failed'))
        steps = answer.get('steps')
        stopped = answer.get('stopped_at')
        allowed = set(values) | ({'code'} if code is not None else set())
        if (not isinstance(steps, list) or not all(step in allowed for step in steps)
                or stopped not in {None, 'email', 'password', 'code', 'submit'} or answer.get('uncertain') is True):
            raise DeliveryError(True)
        receipt = {'ok': True, 'filled': list(steps), 'target_delivery': DELIVERY}
        if stopped is not None:
            receipt['stopped_at'] = stopped
        return receipt

    def _store(self, device, context, fields, mode, origin, source, *, dom=None, purpose=None) -> dict:
        token = secrets.token_hex(32)
        pin = AndroidPin(token=token, device=device, boot_id=context['boot_id'], context=context, fields=fields,
                         mode=mode, origin=origin, source=source, expires_at=self.clock() + PIN_TTL, dom=dom, purpose=purpose)
        evicted = []
        with self._lock:
            now = self.clock()
            for key in [k for k, p in self._pins.items() if p.expires_at <= now or p.used]:
                evicted.append(self._pins.pop(key))
            if len(self._pins) >= MAX_PINS:
                evicted.append(self._pins.pop(next(iter(self._pins))))
            self._pins[token] = pin
        for old in evicted:
            old.close()
        return {'ok': True, 'target': token, 'expires_in': int(PIN_TTL),
                'android_delivery': CHROME_DELIVERY if dom is not None else DELIVERY,
                'mode': mode, 'origin': serialize_origin(origin), 'site_source': source,
                'package': context['package']}

    def clear(self):
        with self._lock:
            pins, self._pins = self._pins, {}
        for pin in pins.values():
            pin.close()

    def take(self, token) -> AndroidPin | None:
        if not isinstance(token, str):
            return None
        with self._lock:
            pin = self._pins.pop(token, None)
        if pin is None:
            return None
        if pin.used or pin.expires_at <= self.clock():
            pin.close()
            raise TargetError()
        return pin

    def check_entry(self, pin: AndroidPin, allowed_origins) -> None:
        if pin.origin not in allowed_origins:
            raise AndroidMismatch()

    def delivery(self, pin: AndroidPin) -> str:
        return CHROME_DELIVERY if pin.source == 'chrome' else DELIVERY

    def deliver(self, pin: AndroidPin, mode: str, values: list[str], ready: Callable[[], bool],
                start_deadline: float, connected: Callable[[], bool] = lambda: True,
                valid: Callable[[], bool] = lambda: True) -> None:
        """Fill the pinned fields; raise DeliveryError(started) on any failure."""
        if pin.used or pin.mode != mode or len(values) != (len(pin.dom.objects) if pin.dom is not None else len(pin.fields)):
            raise DeliveryError(False)
        if pin.dom is not None:
            return self._deliver_page(pin, values, ready, start_deadline, connected, valid)
        pin.used = True
        adb = self.adb_factory(pin.device)
        try:
            probe = adb.helper({'op': 'probe'}, install=False)
            if probe.get('ok') is not True or probe.get('boot_id') != pin.boot_id or probe.get('speak_password') is not False:
                raise DeliveryError(False)
        except DeliveryError:
            raise
        except Exception:
            raise DeliveryError(False) from None
        if self.clock() >= pin.expires_at or not ready():
            raise DeliveryError(False)
        request = {'op': 'fill', 'boot_id': pin.boot_id, 'context': pin.context,
                   'fields': [{'expect': f, 'value': v} for f, v in zip(pin.fields, values)]}
        try:
            answer = adb.helper(request, install=False)
        except Exception:
            # The value may have reached the device.
            raise DeliveryError(True) from None
        finally:
            request = None
        if answer.get('ok') is not True:
            # The helper checks everything before the first field; only an
            # unexpected error can come after a value was set.
            error = answer.get('error')
            raise DeliveryError(not isinstance(error, str) or error.startswith('helper failed'))
        results = answer.get('results')
        # Success needs every field to hold the value: a field may accept the
        # write and still truncate or clear it.
        if (not isinstance(results, list) or len(results) != len(values)
                or not all(isinstance(r, dict) and r.get('accepted') is True and r.get('confirmed') is True
                           for r in results)):
            raise DeliveryError(answer.get('delivered') is not False)

    def _verified_field(self, pin, ready, deadline):
        if pin.used or not ready() or self.clock() >= pin.expires_at:
            raise TargetError()
        pin.used = True
        adb = self.adb_factory(pin.device)
        dom = pin.dom
        dom.check_exposed()
        if dom.call(0, 'function() { return this.prepare(); }') is not True or not ready():
            raise TargetError()
        dom.check_proof_listeners()
        if not ready():
            raise TargetError()
        check = ''.join(secrets.choice('abcdefghijkmnpqrstuvwxyz23456789') for _ in range(16))
        answer = adb.helper({'op': 'type', 'boot_id': pin.boot_id, 'task_id': pin.context['task_id'],
                             'address_bar': pin.context['address_bar'], 'value': check}, install=False)
        if answer.get('ok') is not True or answer.get('complete') is not True:
            raise TargetError()
        shown = dom.call(0, 'function() { return this.proof(); }')
        if (not isinstance(shown, str) or not secrets.compare_digest(shown.encode(), check.encode())
                or self.clock() >= pin.expires_at):
            raise TargetError()
        dom.check_exposed()
        sample = dom.call(0, 'function() { return performance.now(); }')
        remaining = min(pin.expires_at, deadline) - self.clock()
        if type(sample) not in (int, float) or remaining <= 0 or not ready():
            raise TargetError()
        return dom, sample + remaining * 1000

    def read(self, pin, origins, ready, deadline):
        if pin.mode != 'read' or pin.origin not in origins or pin.dom is None:
            raise TargetError()
        dom, cutoff = self._verified_field(pin, ready, deadline)
        value = dom.call(0, 'function(deadline) { return this.capture(deadline); }', cutoff)
        if not isinstance(value, str) or not 0 < len(value) <= 4096:
            raise TargetError()
        return value

    def fill_element(self, pin, value, field, ready, deadline, *, notify_page=False):
        from .browser_card import failure
        if (pin.mode not in ('card', 'identity', 'sms') or field !=
                ('one-time-code' if pin.mode == 'sms' else pin.purpose)):
            return failure(kind=pin.mode)
        started = False
        try:
            if pin.dom is None:
                if notify_page:
                    raise TargetError()
                self.deliver(pin, pin.mode, [value], ready, deadline)
            else:
                dom, cutoff = self._verified_field(pin, ready, deadline)
                started = True
                result = dom.call(0, 'function(value, notify, deadline) { return this.write(value, notify, deadline); }',
                                  value, notify_page, cutoff)
                if result != 'filled':
                    raise DeliveryError(result != 'refused')
                dom.check_exposed()
            key = 'target_delivery' if pin.mode == 'sms' else pin.mode + '_delivery'
            return dict(ok=True, filled=field, **{key: self.delivery(pin)})
        except DeliveryError as exc:
            started = exc.started
        except Exception:
            pass
        if pin.mode == 'sms':
            from .target import failure as target_failure
            return target_failure(started)
        return failure(started, kind=pin.mode)

    def _deliver_page(self, pin, values, ready, start_deadline, connected, valid):
        """Prove the DevTools peer is Chrome and the pinned field has focus, then set each value on it."""
        dom = pin.dom
        adb = self.adb_factory(pin.device)
        started = False
        try:
            if self.clock() >= pin.expires_at:
                raise TargetError()
            probe = adb.helper({'op': 'probe'}, install=False)
            if probe.get('ok') is not True or probe.get('boot_id') != pin.boot_id or probe.get('speak_password') is not False:
                raise TargetError()
            for index, value in enumerate(values):
                # The start deadline bounds only the start; later fields need the caller and the pin.
                if not (ready() if index == 0 else connected()) or self.clock() >= pin.expires_at + PIN_TTL:
                    raise TargetError()
                sample = dom.connection.call('Runtime.evaluate', {'expression': 'performance.now()', 'returnByValue': True},
                                             dom.session)['result']['value']
                if type(sample) not in {int, float}:
                    raise TargetError()
                prepared = dom.call(index, 'function(deadline) { return this.prepare(deadline); }', sample + 10000)
                if (not isinstance(prepared, list) or len(prepared) != 2 or type(prepared[0]) is not int
                        or not isinstance(prepared[1], str)):
                    raise TargetError()
                check = _check_string(pin.mode, *prepared)
                # The first key event starts the fill: the start deadline bounds it.
                if not (ready() if index == 0 else connected()):
                    raise TargetError()
                answer = adb.helper({'op': 'type', 'boot_id': pin.boot_id, 'task_id': pin.context['task_id'],
                                     'address_bar': pin.context['address_bar'], 'value': check}, install=False)
                if answer.get('ok') is not True or answer.get('complete') is not True:
                    raise TargetError()
                # Only Chrome received the keys, and only the focused element shows them. The
                # broker compares: a peer that is not Chrome cannot know the string.
                shown = dom.call(index, 'function() { return this.read(); }')
                if not isinstance(shown, str) or not secrets.compare_digest(shown.encode(), check.encode()):
                    raise TargetError()
                # Right before each value: the caller is still there and a code is still valid.
                if not (connected() and valid()):
                    raise TargetError()
                started = True
                result = dom.call(index, 'function(value) { return this.set(value); }', value)
                if result is not True:
                    started = started if result == 'changed' or index > 0 else False
                    raise TargetError()
        except Exception:
            raise DeliveryError(started) from None
        finally:
            pin.close()
