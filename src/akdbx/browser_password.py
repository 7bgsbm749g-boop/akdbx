"""Opt-in Chromium password delivery to retained DOM nodes; never keyboard input.

CDP is a privileged local interface. The operator selects the profile at broker
startup, never through RPC. Hostile pages/OS and other local debugging clients
are outside this boundary. Unsupported frames/controls fail closed. Child frames
need the explicit same-site route proof in `password_frames`. Linux and Windows
share the DOM contract; only the profile and peer checks are per platform.
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
from . import password_frames

DELIVERY = 'chromium-password-dom-v1'
PROTOCOL = 1
CAPTURE_PROTOCOL = 1
# Read-pin selectors: type, #id, .class and :nth-of-type(n)/:nth-child(n)
# compounds joined by descendant or child combinators. Attribute selectors
# and other pseudo-classes could test the secret (for example
# input[value^="a"]) and turn pin success into an oracle.
# Every compound is non-empty and starts with a non-space character, so the
# combinators cannot overlap and matching stays linear (no backtracking blow-up).
_SUFFIX = r'(?:[#.][A-Za-z_-][A-Za-z0-9_-]*|:nth-(?:of-type|child)\([1-9][0-9]{0,3}\))'
_COMPOUND = r'(?:(?:[A-Za-z][A-Za-z0-9-]*|\*)' + _SUFFIX + r'*|' + _SUFFIX + r'+)'
READ_SELECTOR = re.compile(_COMPOUND + r'(?:(?:[ ]*>[ ]*|[ ]+)' + _COMPOUND + r')*')
MAX_READ_SELECTOR = 512
TTL = 30
MAX_PINS = 16
MAX_MESSAGE = 256 * 1024
MAX_TCP_TABLE_BYTES = 64 * 1024 * 1024
PEER_SCAN_TIMEOUT = 1.0


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
    if os.name == 'nt':
        from . import windows_browser
        try:
            return windows_browser.endpoint(profile)
        except Exception:
            raise TargetError() from None
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
    Missing, ambiguous, oversized or slow tables refuse before sending data.
    Windows proves the same fact with the kernel's TCP owner table and the
    owning process's user and desktop session.
    """
    if os.name == 'nt':
        from . import windows_browser
        try:
            return windows_browser.verify_peer(connection)
        except Exception:
            raise TargetError() from None
    local, remote = connection.getsockname(), connection.getpeername()
    if connection.family != socket.AF_INET or local[0] != '127.0.0.1' or remote[0] != '127.0.0.1':
        raise TargetError()
    def address(value):
        return f'{int.from_bytes(socket.inet_aton(value[0]), sys.byteorder):08X}:{value[1]:04X}'.encode('ascii')
    server, client = address(remote), address(local)
    owners = []
    consumed = 0
    deadline = time.monotonic() + PEER_SCAN_TIMEOUT
    with open('/proc/self/net/tcp', 'rb') as table:
        while True:
            line = table.readline(1025)
            consumed += len(line)
            if len(line) > 1024 or consumed > MAX_TCP_TABLE_BYTES or time.monotonic() >= deadline:
                raise TargetError()
            if not line:
                break
            fields = line.split()
            if len(fields) >= 4 and fields[1:4] == [server, client, b'01']:
                if len(fields) < 8:
                    raise TargetError()
                owners.append(int(fields[7]))
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
CAPTURE = r'''(function(selector, usernameSelector, mode, url, passwordPurpose, allowAutocompleteOff, frameOrigin) {
  // A child frame must keep its exact non-opaque origin (sandboxing makes it "null").
  const sameOrigin = () => frameOrigin === null || (location.origin === frameOrigin && self.origin === frameOrigin);
  if (!isSecureContext || location.href !== url || !sameOrigin() || !document.hasFocus() || document.visibilityState !== 'visible') throw 0;
  const query = s => { const a = document.querySelectorAll(s); if (a.length !== 1) throw 0; return a[0]; };
  const password = mode === 'username' ? null : query(selector);
  const username = mode === 'password' ? null : query(mode === 'username' ? selector : usernameSelector);
  const created = performance.now();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const type = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type').get;
  const attribute = Element.prototype.getAttribute;
  const originalPasswordAutocomplete = password ? attribute.call(password, 'autocomplete') : null;
  const hasAutocomplete = (e, secret) => {
    // The autocomplete IDL getter can deduplicate malformed raw token lists.
    const value = attribute.call(e, 'autocomplete') || '';
    if (value.length > 4096) return false;
    const tokens = value.split(/[\t\n\f\r ]+/).filter(Boolean).map(t => t.replace(/[A-Z]/g, c => c.toLowerCase()));
    // A caller may explicitly attest a password-only field's purpose when the
    // site supplies no semantic hint. Never infer it from a name or rewrite DOM.
    if (secret && passwordPurpose) {
      if (attribute.call(e, 'autocomplete') !== originalPasswordAutocomplete) return false;
      if (tokens.length === 0 || tokens.length === 1 && tokens[0] === 'on') return true;
      if (allowAutocompleteOff && tokens.length === 1 && tokens[0] === 'off') return true;
    }
    if (tokens[0]?.startsWith('section-')) tokens.shift();
    if (['shipping','billing'].includes(tokens[0])) tokens.shift();
    if (tokens[tokens.length - 1] === 'webauthn') tokens.pop();
    return tokens.length === 1 && (secret ? ['current-password','new-password'] : ['username']).includes(tokens[0]) &&
      (!secret || !passwordPurpose || tokens[0] === passwordPurpose);
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
    for (const r of records) {
      if (r.type === 'childList' && [...r.removedNodes].some(n => n === password || n === username || n.contains(password) || n.contains(username))) dirty();
      if (passwordPurpose && r.type === 'attributes' && r.target === password) dirty();
    }
  });
  observer.observe(document, {childList:true, subtree:true, ...(passwordPurpose ? {attributes:true, attributeFilter:['autocomplete','type']} : {})});
  const dispose = () => {
    window.navigation.removeEventListener('navigate', dirty);
    window.removeEventListener('blur', dirty, true);
    document.removeEventListener('visibilitychange', dirty, true);
    document.removeEventListener('focusin', dirty, true);
    observer.disconnect();
  };
  const originalFocus = document.activeElement;
  const check = () => performance.now() - created < 30000 && !tainted && isSecureContext && location.href === url && sameOrigin() && document.hasFocus() && document.visibilityState === 'visible' && document.activeElement === originalFocus &&
    (!password || valid(password, true) && query(selector) === password) &&
    (!username || valid(username, false) && query(mode === 'username' ? selector : usernameSelector) === username) &&
    (!password || !username || password !== username && password.form === username.form);
  if (!check() || originalFocus !== (username || password)) { dispose(); throw 0; }
  return {password, username, setter, check, mode, url, dispose};
})'''
# Read pins (`mode: "read"`) retain one element that shows a secret. The caller
# must focus it. Text selection is not accepted: on X11, Chromium publishes any
# selected text to the PRIMARY selection, outside the broker. Pin and read both require the exact
# URL/origin, page focus, visibility, a unique selector match and one
# unchanged single-line value. Any mutation of the element, navigation, blur,
# focus change or value change taints the pin. The value stays in the
# renderer until the broker's own read call; the pin receipt never holds it.
READ_CAPTURE = r'''(function(selector, url, frameOrigin) {
  const sameOrigin = () => frameOrigin === null || (location.origin === frameOrigin && self.origin === frameOrigin);
  if (!isSecureContext || location.href !== url || !sameOrigin() || !document.hasFocus() || document.visibilityState !== 'visible') throw 0;
  const query = s => { const a = document.querySelectorAll(s); if (a.length !== 1) throw 0; return a[0]; };
  const element = query(selector);
  const created = performance.now();
  const inputValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').get;
  const inputType = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'type').get;
  const inputReadOnly = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'readOnly').get;
  const innerText = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'innerText').get;
  const isInput = element instanceof HTMLInputElement;
  // A read-only text input, or a leaf element that holds only text: the
  // element's own visibility check then covers every character that is read.
  const leaf = () => !element.isContentEditable && (isInput ? inputReadOnly.call(element) : element.childElementCount === 0);
  if (!(element instanceof HTMLElement) || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement ||
      isInput && inputType.call(element) !== 'text' || element.isContentEditable || !leaf()) throw 0;
  const text = () => isInput ? inputValue.call(element) : innerText.call(element);
  const clean = raw => {
    if (typeof raw !== 'string') return null;
    const value = raw.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '');
    if (!value || value.length > 4096 || /[\s\p{C}\p{Z}]/u.test(value)) return null;
    return value;
  };
  const visible = () => {
    if (!element.isConnected || element.ownerDocument !== document || element.closest('[inert]')) return false;
    const r = element.getBoundingClientRect(), s = getComputedStyle(element);
    return element.checkVisibility({checkOpacity:true,checkVisibilityCSS:true}) && r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0 &&
      r.top < innerHeight && r.left < innerWidth && s.visibility === 'visible' && s.display !== 'none' && s.opacity !== '0' &&
      shown(r);
  };
  // The text itself must be on screen and hit-test to the element at its
  // start, centre and end, in an opaque colour: clipping, covers, indents
  // and pointer-transparent tricks then refuse rather than read unseen text.
  // A Range is measured only; the document selection is never changed.
  const hit = (x, y) => {
    const found = document.elementFromPoint(x, y);
    return found === element || !isInput && element.contains(found);
  };
  const opaque = value => !/^(?:transparent|rgba\([^)]*,\s*0(?:\.0*)?\))$/.test(value.trim());
  const shown = r => {
    const s = getComputedStyle(element);
    if (!opaque(s.color) || !opaque(s.webkitTextFillColor || s.color) || parseFloat(s.fontSize) < 4) return false;
    let rects = [r];
    if (!isInput) {
      const range = document.createRange();
      range.selectNodeContents(element);
      rects = [...range.getClientRects()];
    }
    return rects.length > 0 && rects.every(t => t.width > 0 && t.height > 0 && t.left >= 0 && t.top >= 0 &&
      t.right <= innerWidth && t.bottom <= innerHeight && t.left >= r.left - 1 && t.right <= r.right + 1 &&
      t.top >= r.top - 1 && t.bottom <= r.bottom + 1 &&
      [t.left + 1, t.left + t.width / 2, t.right - 1].every(x => hit(x, t.top + t.height / 2)));
  };
  // Focus only, with no active selection anywhere: on X11 a selection is
  // published to PRIMARY.
  const selectionStart = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'selectionStart').get;
  const selectionEnd = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'selectionEnd').get;
  const pointed = () => {
    const selection = getSelection();
    return document.activeElement === element && (!selection || selection.isCollapsed) &&
      (!isInput || selectionStart.call(element) === selectionEnd.call(element));
  };
  const raw = text();
  const initial = clean(raw);
  let tainted = false;
  const dirty = () => { tainted = true; };
  if (!window.navigation || initial === null) throw 0;
  window.navigation.addEventListener('navigate', dirty);
  window.addEventListener('blur', dirty, true);
  document.addEventListener('visibilitychange', dirty, true);
  document.addEventListener('focusin', dirty, true);
  element.addEventListener('input', dirty, true);
  const observer = new MutationObserver(records => {
    for (const r of records) {
      if (r.target === element || element.contains(r.target)) dirty();
      if (r.type === 'childList' && [...r.removedNodes].some(n => n === element || n.contains(element))) dirty();
    }
  });
  observer.observe(document, {childList:true, subtree:true, characterData:true, attributes:true});
  const dispose = () => {
    window.navigation.removeEventListener('navigate', dirty);
    window.removeEventListener('blur', dirty, true);
    document.removeEventListener('visibilitychange', dirty, true);
    document.removeEventListener('focusin', dirty, true);
    element.removeEventListener('input', dirty, true);
    observer.disconnect();
  };
  const originalFocus = document.activeElement;
  const check = () => performance.now() - created < 30000 && !tainted && isSecureContext && location.href === url && sameOrigin() &&
    document.hasFocus() && document.visibilityState === 'visible' && document.activeElement === originalFocus &&
    visible() && leaf() && query(selector) === element && pointed() && text() === raw;
  if (!check()) { dispose(); throw 0; }
  return {mode: 'read', check, dispose, value: () => clean(text())};
})'''
READ = r'''function(deadline) {
  if (this.mode !== 'read' || !this.check() || performance.now() >= deadline) return null;
  const value = this.value();
  this.dispose();
  return value;
}'''
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
    # Child-frame pins only: the exact top URL, verified route and owner guards.
    top_url: str | None = None
    frame_origin: str | None = None
    route: dict | None = None
    guards: tuple = ()

    def close(self):
        try:
            password_frames.release_guards(self.connection, self.guards)
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
        optional = set(request) & {'password_purpose', 'allow_autocomplete_off', 'frame_protocol', 'frame_origin', 'capture_protocol'}
        reading = request.get('mode') == 'read'
        if (set(request) != required | optional | ({'username_selector'} if request.get('mode') == 'login' else set())
                or type(request.get('password_protocol')) is not int or request['password_protocol'] != PROTOCOL
                or request.get('mode') not in {'username', 'password', 'login', 'read'}
                # Read pins need the explicit capture protocol; fill pins never carry it.
                or reading != ('capture_protocol' in request)
                or reading and (type(request['capture_protocol']) is not int or request['capture_protocol'] != CAPTURE_PROTOCOL)
                or ('password_purpose' in request and (request['mode'] != 'password' or not isinstance(request['password_purpose'], str)
                                  or request['password_purpose'] not in {'current-password', 'new-password'}))
                or ('allow_autocomplete_off' in request and (request['allow_autocomplete_off'] is not True
                        or request['mode'] != 'password' or 'password_purpose' not in request))
                # Child-frame routing is explicit: both fields or neither.
                or ('frame_protocol' in request) != ('frame_origin' in request)
                or ('frame_protocol' in request and (type(request['frame_protocol']) is not int
                        or request['frame_protocol'] != password_frames.PROTOCOL))):
            raise TargetError()
        if 'frame_origin' in request:
            password_frames.canonical_origin(request['frame_origin'])
        for key in required - {'action', 'password_protocol'} | ({'username_selector'} if request['mode'] == 'login' else set()):
            if not isinstance(request[key], str) or not 0 < len(request[key]) <= 4096:
                raise TargetError()
        https_origin(request['top_url'])
        if reading and (len(request['selector']) > MAX_READ_SELECTOR or not READ_SELECTOR.fullmatch(request['selector'])):
            raise TargetError()  # No attribute or functional selectors: pin success must not test the secret.
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
        pin, retained = None, []
        try:
            page = connection.call('Target.getTargetInfo', {'targetId': request['page_id']})['targetInfo']
            if page['type'] != 'page' or page['url'] != request['top_url']:
                raise TargetError()
            session = connection.call('Target.attachToTarget', {'targetId': request['page_id'], 'flatten': True})['sessionId']
            route, guards, origin = None, (), request.get('frame_origin')
            if origin is None:
                frame = connection.call('Page.getFrameTree', session=session)['frameTree']['frame']
                if frame['id'] != request['frame_id'] or frame_url(frame) != request['top_url']:
                    raise TargetError()  # Child frames need the explicit frame route below.
                url, field_session = request['top_url'], session
            else:
                route = password_frames.resolve(connection, session, request['page_id'], request['top_url'],
                                                request['frame_id'], origin)
                guards = tuple(password_frames.owner_guards(connection, route['path'], guards=retained))
                frame = route['path'][-1]['frame']
                url, field_session = frame_url(frame), route['field_session']
            world = connection.call('Page.createIsolatedWorld', {'frameId': frame['id'], 'worldName': 'akdbx-password-v1'}, field_session)['executionContextId']
            if request['mode'] == 'read':
                script, args = READ_CAPTURE, [request['selector'], url, origin]
            else:
                script = CAPTURE
                args = [request['selector'], request.get('username_selector'), request['mode'], url, request.get('password_purpose'),
                        request.get('allow_autocomplete_off', False), origin]
            result = connection.call('Runtime.evaluate', {'expression': script + '(' + ','.join(json.dumps(v) for v in args) + ')', 'contextId': world}, field_session)
            if 'exceptionDetails' in result or result['result'].get('type') != 'object' or 'objectId' not in result['result']:
                raise TargetError()
            pin = PasswordPin(connection, field_session, result['result']['objectId'], page['targetId'], frame['id'], url, request['mode'],
                              request['top_url'] if route else None, origin, route, guards)
            if route is not None and not password_frames.verify(connection, route, request['top_url'], origin, guards):
                raise TargetError()
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
                # Remove owner-tracking listeners from a failed child-frame pin.
                password_frames.release_guards(connection, retained)
                connection.close()
            raise TargetError() from None

    def frames(self, request):
        """Read-only frame discovery for one exact top-level page; no pin or value.

        The page id is optional: without it exactly one page target must have
        the exact top URL. Only origins, ids and visible field counts return.
        """
        allowed = {'action', 'password_protocol', 'frame_protocol', 'top_url'}
        if (set(request) - {'page_id'} != allowed or type(request.get('password_protocol')) is not int
                or request['password_protocol'] != PROTOCOL or type(request.get('frame_protocol')) is not int
                or request['frame_protocol'] != password_frames.PROTOCOL or not isinstance(request.get('top_url'), str)
                or not 0 < len(request['top_url']) <= 4096
                or 'page_id' in request and (not isinstance(request['page_id'], str) or not 0 < len(request['page_id']) <= 128)):
            raise TargetError()
        https_origin(request['top_url'])
        with self._lock:
            if self._closed or len(self.pins) + self._creating >= MAX_PINS:
                raise TargetError()
            self._creating += 1
        try:
            connection = CDP(self.profile)
            try:
                if 'page_id' in request:
                    page = connection.call('Target.getTargetInfo', {'targetId': request['page_id']})['targetInfo']
                    if page['type'] != 'page' or page['url'] != request['top_url']:
                        raise TargetError()
                    page_id = page['targetId']
                else:
                    pages = [t for t in connection.call('Target.getTargets')['targetInfos']
                             if t.get('type') == 'page' and t.get('url') == request['top_url']]
                    if len(pages) != 1:
                        raise TargetError()  # Missing or ambiguous: pass --page-id.
                    page_id = pages[0]['targetId']
                session = connection.call('Target.attachToTarget', {'targetId': page_id, 'flatten': True})['sessionId']
                return password_frames.listing(connection, session, page_id, request['top_url'])
            finally:
                connection.close()
        except Exception:
            raise TargetError() from None
        finally:
            with self._lock:
                self._creating -= 1

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

    def _recheck(self, pin, site_origins, ready, start_deadline):
        """Re-verify page, frame route and origin; return a renderer-clock deadline."""
        # The field document's origin must exactly equal the main URL's
        # origin or one KP2A_URL* origin; no suffix, site or port widening.
        if https_origin(pin.url) not in site_origins:
            raise TargetError()
        page = pin.connection.call('Target.getTargetInfo', {'targetId': pin.page_id})['targetInfo']
        if pin.route is None:
            frame = pin.connection.call('Page.getFrameTree', session=pin.session)['frameTree']['frame']
            if page['url'] != pin.url or frame_url(frame) != pin.url or frame['id'] != pin.frame_id or not ready():
                raise TargetError()
        elif (page['url'] != pin.top_url or not ready()
                or not password_frames.verify(pin.connection, pin.route, pin.top_url, pin.frame_origin, pin.guards)):
            raise TargetError()  # Any frame, owner or parent change refuses.
        # Sample renderer time without secrets. Using this older sample
        # plus the remaining host budget gives a conservative renderer
        # deadline, even if the subsequent call sits in its queue.
        sample = pin.connection.call('Runtime.callFunctionOn', {
            'objectId': pin.object_id, 'functionDeclaration': 'function() { return performance.now(); }',
            'returnByValue': True,
        }, pin.session)
        timestamp = sample['result']['value']
        remaining = min(start_deadline - self.clock(), TTL)
        if type(timestamp) not in {int, float} or remaining <= 0 or not ready():
            raise TargetError()
        return timestamp + remaining * 1000

    def read(self, pin, site_origins, ready, start_deadline):
        """Return the pinned element's checked value; the caller never returns it over RPC."""
        if pin.mode != 'read':
            raise TargetError()
        renderer_deadline = self._recheck(pin, site_origins, ready, start_deadline)
        result = pin.connection.call('Runtime.callFunctionOn', {
            'objectId': pin.object_id, 'functionDeclaration': READ,
            'arguments': [{'value': renderer_deadline}], 'returnByValue': True,
        }, pin.session)
        value = result.get('result', {}).get('value') if 'exceptionDetails' not in result else None
        if not isinstance(value, str):
            raise TargetError()
        return value

    def deliver(self, pin, mode, username, password, site_origins, ready, start_deadline):
        """site_origins: the credential's exact (scheme, host, port) origins."""
        started = False
        try:
            if mode != pin.mode or pin.mode == 'read':
                raise TargetError()
            renderer_deadline = self._recheck(pin, site_origins, ready, start_deadline)
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
