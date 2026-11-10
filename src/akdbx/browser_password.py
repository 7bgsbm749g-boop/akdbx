"""Opt-in Chromium password delivery to retained DOM nodes; never keyboard input.

CDP is a privileged local interface. The operator selects the profile at broker
startup, never through RPC. Hostile pages/OS and other local debugging clients
are outside this boundary. Unsupported frames/controls fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import sys
import time
import threading
from urllib.parse import urlsplit

from .target import TargetError, DeliveryError
from .totp import https_origin

DELIVERY = 'chromium-password-dom-v1'
PROTOCOL = 1
TTL = 30
MAX_PINS = 16
MAX_MESSAGE = 256 * 1024


def frame_url(frame):
    """Reconstruct CDP's exact frame URL, without stripping or decoding anything."""
    url, fragment = frame['url'], frame.get('urlFragment', '')
    # Page.Frame.url excludes the fragment; urlFragment includes its leading #.
    if not isinstance(url, str) or not isinstance(fragment, str) or '#' in url or fragment and not fragment.startswith('#'):
        raise TargetError()
    return url + fragment


def endpoint(profile):
    if profile is None:
        raise TargetError()
    path = Path(os.path.abspath(os.fspath(profile)))
    # Do not follow a substituted profile or ancestor symlink.
    for item in [*reversed(path.parents), path]:
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise TargetError()
    info = path.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise TargetError()
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open('DevToolsActivePort', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or info.st_size > 256:
                raise TargetError()
            data = os.read(fd, 257).decode('ascii')
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    match = re.fullmatch(r'([1-9][0-9]{0,4})\n(/devtools/browser/[a-zA-Z0-9-]{1,80})\n?', data)
    if match is None or int(match[1]) > 65535:
        raise TargetError()
    return 'ws://127.0.0.1:' + match[1] + match[2]


def verify_peer(connection):
    """Require our UID on the server side of this connected Linux TCP socket.

    Checking a listener before connect permits port reuse between the check and
    connect. The reciprocal ESTABLISHED tuple identifies this actual peer. Keep
    this socket for the WebSocket handshake; never reconnect or follow redirects.
    Missing, ambiguous or oversized kernel tables refuse before sending data.
    """
    local, remote = connection.getsockname(), connection.getpeername()
    if connection.family != socket.AF_INET or local[0] != '127.0.0.1' or remote[0] != '127.0.0.1':
        raise TargetError()
    def address(value):
        return f'{int.from_bytes(socket.inet_aton(value[0]), sys.byteorder):08X}:{value[1]:04X}'.encode('ascii')
    server, client = address(remote), address(local)
    owners = []
    with open('/proc/self/net/tcp', 'rb') as table:
        for _ in range(16384):
            line = table.readline(1025)
            if not line:
                break
            if len(line) > 1024:
                raise TargetError()
            fields = line.split()
            if len(fields) >= 4 and fields[1:4] == [server, client, b'01']:
                if len(fields) < 8:
                    raise TargetError()
                owners.append(int(fields[7]))
        else:
            raise TargetError()
    if owners != [os.getuid()]:
        raise TargetError()


class CDP:
    def __init__(self, profile):
        import websocket
        url = endpoint(profile)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection = None
        try:
            raw.settimeout(2)
            raw.connect(('127.0.0.1', urlsplit(url).port))
            verify_peer(raw)
            connection = websocket.create_connection(url, socket=raw, redirect_limit=0, timeout=2,
                                                      suppress_origin=True, http_no_proxy=['127.0.0.1'])
            if connection.sock is not raw or connection.getstatus() != 101:
                raise TargetError()
        except BaseException:
            try:
                if connection is not None:
                    connection.close(timeout=0.2)
            finally:
                raw.close()
            raise
        self.socket = connection
        self.counter = 0

    def close(self):
        try:
            self.socket.close(timeout=0.2)
        except Exception:
            pass

    def call(self, method, params=None, session=None, *, timeout=3):
        self.counter += 1
        request = dict(id=self.counter, method=method, params=params or {})
        if session is not None:
            request['sessionId'] = session
        deadline = time.monotonic() + timeout
        self.socket.send(json.dumps(request))
        for _ in range(256):
            self.socket.settimeout(max(.001, deadline - time.monotonic()))
            raw = self.socket.recv()
            if time.monotonic() >= deadline or len(raw) > MAX_MESSAGE:
                raise TargetError()
            response = json.loads(raw)
            if response.get('id') == self.counter:
                if 'error' in response:
                    raise TargetError()
                return response['result']
        raise TargetError()


# Both scripts run in a fresh isolated world. Retain the actual elements, native
# setter/getters and document, never resolve a replacement by selector on fill.
CAPTURE = r'''(function(selector, usernameSelector, mode, url) {
  if (!isSecureContext || location.href !== url || !document.hasFocus() || document.visibilityState !== 'visible') throw 0;
  const query = s => { const a = document.querySelectorAll(s); if (a.length !== 1) throw 0; return a[0]; };
  const password = mode === 'username' ? null : query(selector);
  const username = mode === 'password' ? null : query(mode === 'username' ? selector : usernameSelector);
  const created = performance.now();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const type = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type').get;
  const attribute = Element.prototype.getAttribute;
  const hasAutocomplete = (e, secret) => {
    // The autocomplete IDL getter can deduplicate malformed raw token lists.
    const value = attribute.call(e, 'autocomplete') || '';
    if (value.length > 4096) return false;
    const tokens = value.split(/[\t\n\f\r ]+/).filter(Boolean).map(t => t.replace(/[A-Z]/g, c => c.toLowerCase()));
    if (tokens[0]?.startsWith('section-')) tokens.shift();
    if (['shipping','billing'].includes(tokens[0])) tokens.shift();
    if (tokens[tokens.length - 1] === 'webauthn') tokens.pop();
    return tokens.length === 1 && (secret ? ['current-password','new-password'] : ['username']).includes(tokens[0]);
  };
  const valid = (e, secret) => {
    if (!(e instanceof HTMLInputElement) || !e.isConnected || e.ownerDocument !== document || e.disabled || e.readOnly || e.closest('[inert]')) return false;
    const t = type.call(e), r = e.getBoundingClientRect(), s = getComputedStyle(e);
    return (secret ? t === 'password' : ['text','email'].includes(t)) && hasAutocomplete(e, secret) && e.checkVisibility({checkOpacity:true,checkVisibilityCSS:true}) && r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth && s.visibility === 'visible' && s.display !== 'none' && s.opacity !== '0';
  };
  let tainted = false;
  const dirty = () => { tainted = true; };
  if (!window.navigation) throw 0;
  window.navigation.addEventListener('navigate', dirty);
  window.addEventListener('blur', dirty, true);
  document.addEventListener('visibilitychange', dirty, true);
  document.addEventListener('focusin', dirty, true);
  const observer = new MutationObserver(records => {
    for (const r of records) if (r.type === 'childList' && [...r.removedNodes].some(n => n === password || n === username || n.contains(password) || n.contains(username))) dirty();
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
  const check = () => performance.now() - created < 30000 && !tainted && isSecureContext && location.href === url && document.hasFocus() && document.visibilityState === 'visible' && document.activeElement === originalFocus &&
    (!password || valid(password, true) && query(selector) === password) &&
    (!username || valid(username, false) && query(mode === 'username' ? selector : usernameSelector) === username) &&
    (!password || !username || password !== username && password.form === username.form);
  if (!check() || originalFocus !== (username || password)) { dispose(); throw 0; }
  return {password, username, setter, check, mode, url, dispose};
})'''
FILL = r'''function(mode, username, password, deadline) {
  if (mode !== this.mode || !this.check() || performance.now() >= deadline) return false;
  // Native setters do not dispatch page handlers. No key, Tab, focus change,
  // await, or re-selection occurs between validation and assignment.
  if (this.username) this.setter.call(this.username, username);
  if (this.password) this.setter.call(this.password, password);
  // Send compatibility notifications only after all assignments are complete.
  for (const e of [this.username, this.password]) if (e) {
    e.dispatchEvent(new Event('input', {bubbles:true}));
    e.dispatchEvent(new Event('change', {bubbles:true}));
  }
  return true;
}'''


@dataclass
class PasswordPin:
    connection: CDP
    session: str
    object_id: str
    page_id: str
    frame_id: str
    url: str
    mode: str

    def close(self):
        try:
            self.connection.call('Runtime.callFunctionOn', {'objectId': self.object_id,
                                 'functionDeclaration': 'function() { this.dispose(); }'}, self.session, timeout=0.2)
            self.connection.call('Runtime.releaseObject', {'objectId': self.object_id}, self.session, timeout=0.2)
        except Exception:
            pass
        finally:
            self.connection.close()


class BrowserPasswords:
    """Own bounded browser pins with map synchronization separate from the vault."""
    def __init__(self, profile=None, *, clock=time.monotonic):
        self.profile, self.clock = profile, clock
        self.pins = {}
        self._lock = threading.Lock()
        self._creating = 0
        self._closed = False

    def prune(self):
        """Remove expired pins atomically; perform their CDP cleanup outside locks."""
        now = self.clock()
        with self._lock:
            expired = [self.pins.pop(token)[1] for token, (expiry, _) in list(self.pins.items()) if expiry <= now]
        for pin in expired:
            pin.close()

    def close(self):
        """Refuse new pins and close retained pins without holding the map lock."""
        with self._lock:
            self._closed = True
            pins, self.pins = self.pins, {}
        for _, pin in pins.values():
            pin.close()

    def pin(self, request):
        """Reserve capacity atomically and capture the DOM target outside locks."""
        self.prune()
        required = {'action', 'password_protocol', 'page_id', 'frame_id', 'top_url', 'selector', 'mode'}
        if (set(request) != required | ({'username_selector'} if request.get('mode') == 'login' else set())
                or type(request.get('password_protocol')) is not int or request['password_protocol'] != PROTOCOL
                or request.get('mode') not in {'username', 'password', 'login'}):
            raise TargetError()
        for key in required - {'action', 'password_protocol'} | ({'username_selector'} if request['mode'] == 'login' else set()):
            if not isinstance(request[key], str) or not 0 < len(request[key]) <= 4096:
                raise TargetError()
        https_origin(request['top_url'])
        with self._lock:
            if self._closed or len(self.pins) + self._creating >= MAX_PINS:
                raise TargetError()
            self._creating += 1
        try:
            return self._capture(request)
        finally:
            with self._lock:
                self._creating -= 1

    def _capture(self, request):
        """Do browser I/O outside the vault/map locks, then publish one pin."""
        connection = CDP(self.profile)
        pin = None
        try:
            page = connection.call('Target.getTargetInfo', {'targetId': request['page_id']})['targetInfo']
            if page['type'] != 'page' or page['url'] != request['top_url']:
                raise TargetError()
            session = connection.call('Target.attachToTarget', {'targetId': request['page_id'], 'flatten': True})['sessionId']
            frame = connection.call('Page.getFrameTree', session=session)['frameTree']['frame']
            if frame['id'] != request['frame_id'] or frame_url(frame) != request['top_url']:
                raise TargetError()  # Child frames and shadow DOM are deliberately unsupported.
            world = connection.call('Page.createIsolatedWorld', {'frameId': frame['id'], 'worldName': 'akdbx-password-v1'}, session)['executionContextId']
            args = [request['selector'], request.get('username_selector'), request['mode'], request['top_url']]
            result = connection.call('Runtime.evaluate', {'expression': CAPTURE + '(' + ','.join(json.dumps(v) for v in args) + ')', 'contextId': world}, session)
            if 'exceptionDetails' in result or result['result'].get('type') != 'object' or 'objectId' not in result['result']:
                raise TargetError()
            pin = PasswordPin(connection, session, result['result']['objectId'], page['targetId'], frame['id'], request['top_url'], request['mode'])
            token = secrets.token_hex(32)
            with self._lock:
                if self._closed:
                    raise TargetError()
                self.pins[token] = self.clock() + TTL, pin
            return dict(ok=True, target=token, expires_in=TTL, target_delivery=DELIVERY)
        except Exception:
            if pin is not None:
                pin.close()
            else:
                connection.close()
            raise TargetError() from None

    def consume(self, token):
        """Atomically take one token; never sweep other pins during a fill."""
        with self._lock:
            found = self.pins.pop(token, None)
        if found is None:
            raise TargetError()
        if found[0] <= self.clock():
            found[1].close()
            raise TargetError()
        return found[1]

    def deliver(self, pin, mode, username, password, site_url, ready, start_deadline):
        started = False
        try:
            if mode != pin.mode or https_origin(site_url) != https_origin(pin.url):
                raise TargetError()
            page = pin.connection.call('Target.getTargetInfo', {'targetId': pin.page_id})['targetInfo']
            frame = pin.connection.call('Page.getFrameTree', session=pin.session)['frameTree']['frame']
            if page['url'] != pin.url or frame_url(frame) != pin.url or frame['id'] != pin.frame_id or not ready():
                raise TargetError()
            # Sample renderer time without secrets. Using this older sample
            # plus the remaining host budget gives a conservative renderer
            # deadline, even if the subsequent fill command sits in its queue.
            sample = pin.connection.call('Runtime.callFunctionOn', {
                'objectId': pin.object_id, 'functionDeclaration': 'function() { return performance.now(); }',
                'returnByValue': True,
            }, pin.session)
            timestamp = sample['result']['value']
            remaining = min(start_deadline - self.clock(), TTL)
            if type(timestamp) not in {int, float} or remaining <= 0 or not ready():
                raise TargetError()
            renderer_deadline = timestamp + remaining * 1000
            started = True
            result = pin.connection.call('Runtime.callFunctionOn', {
                'objectId': pin.object_id, 'functionDeclaration': FILL,
                'arguments': [{'value': v} for v in (mode, username, password, renderer_deadline)], 'returnByValue': True,
            }, pin.session)
            if 'exceptionDetails' in result:
                raise TargetError()
            if result['result'].get('value') is not True:
                started = False
                raise TargetError()
        except Exception:
            raise DeliveryError(started) from None
