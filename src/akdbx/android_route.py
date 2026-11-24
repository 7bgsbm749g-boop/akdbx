"""Android route: fill one verified field on a configured Android device.

The broker reaches the device through the operator's adb server, with one of
two deliveries:

- App fields, and Google's account sign-in in Google Play services: the
  broker copies a small helper (``android_assets/akdbx-android-helper.dex``,
  built from ``android/helper``) to the device and starts it with
  ``app_process`` as the adb shell user. The helper reads the screen through
  the platform's accessibility API (UiAutomation), checks the app, its
  signing certificate and the exact field, and puts the value into that
  field with ACTION_SET_TEXT. The value travels only on the helper's
  standard input.
- Pages in Chrome (tabs and Custom Tabs): Chrome's accessibility tree can be
  stale, so the broker reads and fills the page through Chrome's DevTools
  socket, which adb forwards to a loopback port only while the broker
  connects. Logins use the CDP route's own DOM pin and fill; authenticator
  codes use the same checks for a focused code field.

A value is never an adb or shell argument, never on the clipboard, never
typed as key events, and never in a response, an exception message or a log.

A pin binds the device (configured name, adb serial and boot id), the focused
app (package, current signer and activity) and the field. The site that a pin
may receive a credential for is one of:

- the page in Chrome (com.android.chrome, signed by Google): the exact origin
  of the one visible, focused tab, whose host must also match Chrome's own
  address bar when the bar is shown;
- Google's account sign-in in Google Play services (com.google.android.gms,
  Google signing lineage, its sign-in activity): https://accounts.google.com;
- any other app, when the agent names a site (--app-site) whose Digital
  Asset Links file names that app's package and current signing certificate.
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
# An authenticator code set in a Chrome page through Chrome's DevTools socket.
CHROME_CODE_DELIVERY = 'android-chrome-dom-code-v1'
PIN_TTL = 30.0
MAX_PINS = 64
MODES = ('login', 'username', 'password', 'totp')
CONFIG_ENV = 'AKDBX_ANDROID_DEVICES'
MAX_CONFIG = 64 * 1024
MAX_DEVICES = 16
DEVICE_NAME = re.compile(r'[a-z0-9][a-z0-9._-]{0,31}')
SERIAL = re.compile(r'[A-Za-z0-9._:-]{1,64}')

HELPER_ASSET = 'akdbx-android-helper.dex'
# SHA-256 of the bundled helper; tests/test_android_route.py checks it.
HELPER_SHA256 = 'ba5a063bf2603efaa93480fd19fcaeca7eef4e31c88e3b889a47a54bd3ffba27'
HELPER_CLASS = 'org.akdbx.android.Helper'
HELPER_PROTOCOL = 1
RESULT_PREFIX = 'AKDBX-ANDROID-RESULT '
DEVICE_DIR = '/data/local/tmp/akdbx'
HELPER_MISSING = 86
HELPER_TIMEOUT = 25.0
SIGN_IN_TIMEOUT = 100.0
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
                android_page_code_delivery=CHROME_CODE_DELIVERY,
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


def _read_private_file(path: Path) -> bytes:
    """Read the operator file; on POSIX only this user (or root) may change it."""
    if os.name == 'nt':
        data = path.read_bytes()
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
                or set(value) != {'adb', 'adb_server_port', 'serial'}):
            raise AndroidError('invalid Android device entry')
        adb, port, serial = value['adb'], value['adb_server_port'], value['serial']
        if (not isinstance(adb, str) or not os.path.isabs(adb) or os.path.normpath(adb) != adb
                or type(port) is not int or not 1024 <= port <= 65535
                or not isinstance(serial, str) or not SERIAL.fullmatch(serial)):
            raise AndroidError('invalid Android device entry')
        devices[name] = Device(name, adb, port, serial)
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
               if not key.startswith(('ADB_', 'ANDROID_')) and key not in {'ADB_SERVER_SOCKET'}}
        env['ANDROID_ADB_SERVER_PORT'] = str(self.device.port)
        return env

    def server_running(self) -> bool:
        """True when this user's process listens on the configured adb port.

        Another OS account could listen on the port while the operator's adb
        server is down; the CDP route's peer check refuses that listener.
        """
        from .browser_password import verify_peer
        try:
            with socket.create_connection(('127.0.0.1', self.device.port), timeout=1.0) as connection:
                verify_peer(connection)
                return True
        except TargetError:
            raise AndroidError('the adb server port belongs to another account') from None
        except OSError:
            return False

    def run(self, *args, stdin: bytes | None = None, timeout: float = 15.0) -> subprocess.CompletedProcess:
        if not os.path.isfile(self.device.adb) or not os.access(self.device.adb, os.X_OK):
            raise AndroidError('configured adb executable not found')
        if not self.server_running():
            # Starting a server here would make one the operator did not set up.
            raise AndroidError('adb server not running on the configured port')
        argv = [self.device.adb, '-P', str(self.device.port), '-s', self.device.serial, *args]
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

    def helper(self, request: dict, *, install: bool, timeout: float = HELPER_TIMEOUT) -> dict:
        """Run one helper request. Answers hold no value from the request."""
        data = (json.dumps(request, separators=(',', ':')) + '\n').encode('utf-8')
        for attempt in (0, 1):
            result = self.run('shell', '-T', self._helper_command(), stdin=data, timeout=timeout)
            if result.returncode == HELPER_MISSING and install and attempt == 0:
                self.install_helper()
                continue
            break
        if result.returncode == HELPER_MISSING:
            raise AndroidError('akdbx helper missing on the device')
        output = result.stdout[-MAX_HELPER_OUTPUT:].decode('utf-8', 'replace')
        lines = [line for line in output.splitlines() if line.startswith(RESULT_PREFIX)]
        if len(lines) != 1:
            raise AndroidError('Android helper gave no answer')
        try:
            answer = json.loads(lines[0][len(RESULT_PREFIX):])
        except ValueError:
            raise AndroidError('Android helper gave no answer') from None
        if not isinstance(answer, dict) or answer.get('protocol') != HELPER_PROTOCOL:
            raise AndroidError('Android helper protocol mismatch')
        return answer

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
    if (id && unique('#' + CSS.escape(id))) selector = '#' + CSS.escape(id);
    else if (name && unique('input[name="' + CSS.escape(name) + '"]')) selector = 'input[name="' + CSS.escape(name) + '"]';
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
# An authenticator-code field: the CDP route's capture checks for one focused
# text, tel or number input. The code is set with the native value setter.
OTP_CAPTURE = r"""(function(selector, url) {
  if (!isSecureContext || location.href !== url || !document.hasFocus() || document.visibilityState !== 'visible') throw 0;
  const query = s => { const a = document.querySelectorAll(s); if (a.length !== 1) throw 0; return a[0]; };
  const field = query(selector);
  const created = performance.now();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const type = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type').get;
  const valid = e => {
    if (!(e instanceof HTMLInputElement) || !e.isConnected || e.ownerDocument !== document || e.disabled || e.readOnly || e.closest('[inert]')) return false;
    const t = type.call(e), r = e.getBoundingClientRect(), s = getComputedStyle(e);
    return ['text', 'tel', 'number'].includes(t) && e.checkVisibility({checkOpacity:true,checkVisibilityCSS:true}) && r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth && s.visibility === 'visible' && s.display !== 'none' && s.opacity !== '0';
  };
  let tainted = false;
  const dirty = () => { tainted = true; };
  if (!window.navigation) throw 0;
  window.navigation.addEventListener('navigate', dirty);
  window.addEventListener('blur', dirty, true);
  document.addEventListener('visibilitychange', dirty, true);
  document.addEventListener('focusin', dirty, true);
  const observer = new MutationObserver(records => {
    for (const r of records) if (r.type === 'childList' && [...r.removedNodes].some(n => n === field || n.contains(field))) dirty();
  });
  observer.observe(document, {childList:true, subtree:true});
  const dispose = () => {
    window.navigation.removeEventListener('navigate', dirty);
    window.removeEventListener('blur', dirty, true);
    document.removeEventListener('visibilitychange', dirty, true);
    document.removeEventListener('focusin', dirty, true);
    observer.disconnect();
  };
  const originalFocus = document.activeElement;
  const check = () => performance.now() - created < 30000 && !tainted && isSecureContext && location.href === url && document.hasFocus() && document.visibilityState === 'visible' && document.activeElement === originalFocus && valid(field) && query(selector) === field;
  if (!check() || originalFocus !== field) { dispose(); throw 0; }
  return {mode: 'totp', field, setter, check, dispose};
})"""
OTP_FILL = r"""function(code, deadline) {
  if (this.mode !== 'totp' || !this.check() || performance.now() >= deadline) return false;
  this.setter.call(this.field, code);
  this.field.dispatchEvent(new Event('input', {bubbles:true}));
  this.field.dispatchEvent(new Event('change', {bubbles:true}));
  this.dispose();
  return true;
}"""


# Written into the chosen tab through the DevTools connection, then read back
# from Chrome's own UI by the helper (see Helper.markShown).
MARK_SET = r"""(function(mark, custom) {
  const old = {href: location.href, title: document.title};
  if (custom) document.title = mark;
  else history.replaceState(history.state, '', location.href.split('#')[0] + '#' + mark);
  return old;
})"""
MARK_RESTORE = r"""(function(old, custom) {
  if (custom) document.title = old.title;
  else history.replaceState(history.state, '', old.href);
  return location.href;
})"""


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
    hosts = {host, host[4:]} if host.startswith('www.') and len(host) > 4 else {host}
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
    # A Chrome code-field pin holds its DevTools pin (a browser_password.PasswordPin).
    dom: object = None
    used: bool = field(default=False)

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
                 passwords=None, adb_factory=Adb, fetch=None, cdp_factory=None):
        self.config_path = config_path
        self.clock = clock
        # The broker's CDP password pins: Chrome login pins live there.
        self.passwords = passwords
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
        return capabilities(self.configured())

    def _device(self, request) -> Device:
        name = request.get('device')
        devices = self.devices()
        if not isinstance(name, str) or name not in devices:
            raise AndroidError('unknown Android device; configured devices: ' + (', '.join(sorted(devices)) or 'none'))
        return devices[name]

    def list_devices(self, request) -> dict:
        if set(request) - {'action', 'android_protocol'}:
            raise AndroidError('invalid Android device list request')
        result = []
        for device in self.devices().values():
            adb = self.adb_factory(device)
            item = {'name': device.name, 'serial': device.serial, 'adb_server_port': device.port}
            try:
                probe = adb.helper({'op': 'probe'}, install=True)
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
        return CDP(ChromeDevTools(adb))

    def _chrome_page(self, connection, context) -> dict:
        """The one visible, focused Chrome tab; its host must match the address bar."""
        pages = [t for t in connection.call('Target.getTargets')['targetInfos'] if t.get('type') == 'page']
        if context['address_bar'] is not None:
            # Only tabs with the host the address bar shows: Chrome freezes
            # background tabs, and a frozen tab answers no DevTools call.
            pages = [t for t in pages if isinstance(t.get('url'), str) and _origin_of(t['url']) is not None
                     and _authority_matches(context['address_bar'], _origin_of(t['url']))]
        shown = []
        for page in pages[:16]:
            try:
                session = connection.call('Target.attachToTarget', {'targetId': page['targetId'], 'flatten': True},
                                          timeout=1.5)['sessionId']
                frame = connection.call('Page.getFrameTree', session=session, timeout=1.5)['frameTree']['frame']
                world = connection.call('Page.createIsolatedWorld', {'frameId': frame['id'], 'worldName': 'akdbx-android-v1'},
                                        session, timeout=1.5)['executionContextId']
                state = connection.call('Runtime.evaluate', {'expression': PAGE_STATE, 'contextId': world,
                                                             'returnByValue': True}, session, timeout=1.5)['result'].get('value')
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
            clean.append({'field': _clip(item.get('selector'), 300), 'kind': 'page',
                          **{key: _clip(item.get(key)) for key in ('type', 'id', 'name', 'autocomplete', 'placeholder', 'label')},
                          **{key: item.get(key) is True for key in ('focused', 'has_value', 'disabled')}})
        return {'site': {'origin': serialize_origin(page['origin']), 'source': 'chrome'}, 'page_url': _clip(page['url'], 2048),
                'fields': clean}

    def _bind_devtools(self, adb, connection, page, context) -> None:
        """Prove that the DevTools peer is the focused Chrome, before any value moves.

        Any app could hold the abstract socket name chrome_devtools_remote,
        and SELinux keeps the shell from reading its owner. Only Chrome draws
        its address bar and sets its task's description, so a mark written
        through this connection must show there.
        """
        mark = 'akdbx-' + secrets.token_hex(12)
        custom = context['activity'] == CHROME_ACTIVITIES[1]
        result = connection.call('Runtime.evaluate', {
            'expression': MARK_SET + '(' + json.dumps(mark) + ',' + json.dumps(custom) + ')',
            'contextId': page['world'], 'returnByValue': True}, page['session'])
        old = result.get('result', {}).get('value')
        if not isinstance(old, dict) or old.get('href') != page['url'] or not isinstance(old.get('title'), str):
            raise AndroidError('could not check that the page belongs to Chrome')
        try:
            seen = adb.helper({'op': 'context', 'mark': mark}, install=False)
        finally:
            restored = connection.call('Runtime.evaluate', {
                'expression': MARK_RESTORE + '(' + json.dumps(old) + ',' + json.dumps(custom) + ')',
                'contextId': page['world'], 'returnByValue': True}, page['session'])
        if seen.get('ok') is not True or seen.get('mark_seen') is not True:
            raise AndroidError("Chrome's DevTools socket is not the focused Chrome's; restart Chrome and try again")
        if restored.get('result', {}).get('value') != page['url']:
            raise AndroidError('the page changed while it was checked; try again')

    def _chrome_pin(self, request, mode, device, adb, context) -> dict:
        from .browser_password import PROTOCOL as PASSWORD_PROTOCOL, DELIVERY as PASSWORD_DELIVERY, PasswordPin
        selector = request.get('field')
        username_selector = request.get('username_field')
        for value in (selector, username_selector):
            if value is not None and (not isinstance(value, str) or not 0 < len(value) <= 4096):
                raise AndroidError('page fields are CSS selectors from android inspect')
        if request.get('app_site') is not None:
            raise AndroidError('--app-site is for apps; a Chrome page is verified by its own origin')
        connection = self._cdp(adb)
        try:
            page = self._chrome_page(connection, context)
            self._bind_devtools(adb, connection, page, context)
        except Exception:
            connection.close()
            raise
        if mode != 'totp':
            connection.close()
            if self.passwords is None:
                raise AndroidError('Chrome page fill unavailable')
            pin_request = {'action': 'pin-password-target', 'password_protocol': PASSWORD_PROTOCOL,
                           'page_id': page['page_id'], 'frame_id': page['frame_id'], 'top_url': page['url'],
                           'selector': selector, 'mode': mode}
            if mode == 'login':
                pin_request['username_selector'] = username_selector
            if request.get('password_purpose') is not None:
                pin_request['password_purpose'] = request['password_purpose']
            self.passwords.prune()
            try:
                pinned = self.passwords.pin_with(pin_request, ChromeDevTools(adb))
            except TargetError:
                raise AndroidError('page field refused: it must be the focused field, unique for its selector, '
                                   'visible, and marked username or current-password (or use --password-purpose)') from None
            return {'ok': True, 'target': pinned['target'], 'expires_in': int(PIN_TTL),
                    'android_delivery': PASSWORD_DELIVERY, 'mode': mode, 'origin': serialize_origin(page['origin']),
                    'site_source': 'chrome', 'package': context['package']}
        dom = None
        try:
            result = connection.call('Runtime.evaluate', {
                'expression': OTP_CAPTURE + '(' + json.dumps(selector) + ',' + json.dumps(page['url']) + ')',
                'contextId': page['world']}, page['session'])
            if 'exceptionDetails' in result or result['result'].get('type') != 'object' or 'objectId' not in result['result']:
                raise TargetError()
            dom = PasswordPin(connection, page['session'], result['result']['objectId'], page['page_id'],
                              page['frame_id'], page['url'], 'totp')
        except Exception:
            connection.close()
            raise AndroidError('code field refused: it must be the focused text field, unique for its selector, and visible') from None
        return self._store(device, context, [], 'totp', page['origin'], 'chrome', dom=dom)

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
        allowed = {'action', 'device', 'mode', 'field', 'username_field', 'app_site', 'password_purpose', 'android_protocol'}
        if set(request) - allowed or request.get('android_protocol') != PROTOCOL:
            raise AndroidError('invalid Android pin request')
        mode = request.get('mode')
        if mode not in MODES:
            raise AndroidError('mode must be login, username, password or totp')
        if (mode == 'login') != (request.get('username_field') is not None):
            raise AndroidError('--username-field is required in login mode and only there')
        purpose = request.get('password_purpose')
        if purpose is not None and (mode != 'password' or purpose not in {'current-password', 'new-password'}):
            raise AndroidError('--password-purpose is current-password or new-password, in password mode on a page')
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
        if purpose is not None:
            raise AndroidError('--password-purpose is only for Chrome pages')
        if (context['package'] == GMS_PACKAGE and context['activity'] == GMS_SIGN_IN_ACTIVITY
                and context['signer_lineage'][0] == GOOGLE_SIGNER and mode != 'username'):
            raise AndroidError(GOOGLE_SECRETS_REFUSAL)
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
        roles = {'login': (False, True), 'username': (False,), 'password': (True,), 'totp': (None,)}[mode]
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
        return self._store(device, context, fields, mode, origin, source)

    def google_sign_in(self, request, values: dict, ready: Callable[[], bool]) -> dict:
        """Fill the email, then the password (and a code) on the pages Google's flow shows next.

        Returns the receipt; raises DeliveryError(started) when the outcome is unknown.
        """
        device = self._device(request)
        adb = self.adb_factory(device)
        try:
            context = self._helper_context(adb.helper({'op': 'context'}, install=True))
        except AndroidError:
            raise DeliveryError(False) from None
        if not (context['package'] == GMS_PACKAGE and context['activity'] == GMS_SIGN_IN_ACTIVITY
                and context['signer_lineage'][0] == GOOGLE_SIGNER):
            raise AndroidError('the focused screen is not Google account sign-in')
        if context['speak_password']:
            raise AndroidError(SPEAK_PASSWORD_REFUSAL)
        if not ready():
            raise DeliveryError(False)
        request = {'op': 'google_sign_in', 'boot_id': context['boot_id'], **values}
        try:
            # Each later page may take the helper's 25-second wait.
            answer = adb.helper(request, install=False, timeout=SIGN_IN_TIMEOUT)
        except Exception:
            raise DeliveryError(True) from None
        finally:
            request = None
        if answer.get('ok') is not True:
            error = answer.get('error')
            raise DeliveryError(not isinstance(error, str) or error.startswith('helper failed'))
        steps = answer.get('steps')
        stopped = answer.get('stopped_at')
        if (not isinstance(steps, list) or not all(step in values for step in steps)
                or stopped not in {None, 'email', 'password', 'code', 'submit'} or answer.get('uncertain') is True):
            raise DeliveryError(True)
        receipt = {'ok': True, 'filled': list(steps), 'target_delivery': DELIVERY}
        if stopped is not None:
            receipt['stopped_at'] = stopped
        return receipt

    def _store(self, device, context, fields, mode, origin, source, *, dom=None) -> dict:
        token = secrets.token_hex(32)
        pin = AndroidPin(token=token, device=device, boot_id=context['boot_id'], context=context, fields=fields,
                         mode=mode, origin=origin, source=source, expires_at=self.clock() + PIN_TTL, dom=dom)
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
                'android_delivery': CHROME_CODE_DELIVERY if dom is not None else DELIVERY,
                'mode': mode, 'origin': serialize_origin(origin), 'site_source': source,
                'package': context['package']}

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
        return CHROME_CODE_DELIVERY if pin.source == 'chrome' else DELIVERY

    def deliver(self, pin: AndroidPin, mode: str, values: list[str], ready: Callable[[], bool],
                start_deadline: float) -> None:
        """Fill the pinned fields; raise DeliveryError(started) on any failure."""
        if pin.used or pin.mode != mode or (pin.dom is None and len(values) != len(pin.fields)):
            raise DeliveryError(False)
        if pin.dom is not None:
            return self._deliver_page_code(pin, values, ready, start_deadline)
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

    def _deliver_page_code(self, pin, values, ready, start_deadline):
        from .browser_password import BrowserPasswords
        started = False
        dom = pin.dom
        try:
            if len(values) != 1 or self.clock() >= pin.expires_at:
                raise TargetError()
            # The same page, frame and renderer clock checks as the CDP route.
            checker = self.passwords if self.passwords is not None else BrowserPasswords(clock=self.clock)
            renderer_deadline = checker._recheck(dom, {pin.origin}, ready, start_deadline)
            started = True
            result = dom.connection.call('Runtime.callFunctionOn', {
                'objectId': dom.object_id, 'functionDeclaration': OTP_FILL,
                'arguments': [{'value': values[0]}, {'value': renderer_deadline}], 'returnByValue': True,
            }, dom.session)
            if 'exceptionDetails' in result:
                raise TargetError()
            if result['result'].get('value') is not True:
                started = False
                raise TargetError()
        except Exception:
            raise DeliveryError(started) from None
        finally:
            pin.close()
