"""Single-use native field pins. No global keys, Tab, clipboard or value RPC.

An application has no browser origin. `service_url` is the caller's assertion
of the service this independently verified application is being used for; it
must match the selected login's origin. It is never presented as URL proof.
Native fields deliberately cannot authorize browser or embedded web content.
"""
from dataclasses import dataclass
import secrets
import sys
import threading
import time
import unicodedata

from .target import TargetError, DeliveryError
from .totp import https_origin

PROTOCOL = 1
DELIVERY = 'native-field-v1'
READ_DELIVERY = 'native-field-read-v1'
TTL = 30
MAX_PINS = 16
MAX_TEXT = 65536
MODES = ('username', 'password', 'login', 'totp', 'card', 'identity', 'read')


ACCESSIBILITY_ERROR = 'macOS Accessibility permission required for the broker'


class AccessibilityRequired(TargetError):
    pass


def available_modes():
    if sys.platform == 'darwin':
        return ('username', 'totp', 'card', 'identity', 'read')
    return MODES if supported() else ()


def supported():
    return sys.platform.startswith('linux') or sys.platform in {'win32', 'darwin'}


def backend():
    if sys.platform.startswith('linux'):
        from .linux_fields import scan
    elif sys.platform == 'win32':
        from .windows_fields import scan
    elif sys.platform == 'darwin':
        from .macos_fields import scan
    else:
        raise TargetError()
    return scan


def text(value, multiline=False, identity=False):
    return (isinstance(value, str) and len(value) <= MAX_TEXT
            and not any(unicodedata.category(c).startswith('C')
                        and not (multiline and c == '\n' or identity and c in '\u200c\u200d') for c in value))


@dataclass
class NativePin:
    session: object
    mode: str
    kind: str
    indices: tuple
    facts: tuple
    focus: int
    origin: tuple
    field: str | None
    expires: float
    closed: bool = False

    def __getitem__(self, name):
        # IdentityManager uses the shared DOM/extension pin's field contract.
        if name == 'field':
            return self.field
        raise KeyError(name)

    def close(self):
        if not self.closed:
            self.closed = True
            self.session.close()


class NativeFields:
    def __init__(self, *, scan=None, clock=time.monotonic):
        self.scan, self.clock = scan, clock
        self.views, self.pins = {}, {}
        self.lock = threading.RLock()

    def capabilities(self):
        status = {}
        if sys.platform == 'darwin':
            from HIServices import AXIsProcessTrusted
            status['native_field_accessibility_granted'] = bool(AXIsProcessTrusted())
        return dict(**status, native_field_protocol=PROTOCOL, native_field_supported=supported(),
                    native_field_delivery=DELIVERY, native_field_read_delivery=READ_DELIVERY,
                    native_field_modes=list(available_modes()))

    def prune(self):
        with self.lock:
            for token, (expiry, session, _) in list(self.views.items()):
                if expiry <= self.clock():
                    self.views.pop(token)
                    session.close()
            for token, pin in list(self.pins.items()):
                if pin.expires <= self.clock():
                    self.pins.pop(token)
                    pin.close()

    def close(self):
        with self.lock:
            sessions = [s for _, s, _ in self.views.values()]
            pins = list(self.pins.values())
            self.views.clear()
            self.pins.clear()
        for session in sessions:
            session.close()
        for pin in pins:
            pin.close()

    def discover(self, request):
        if (set(request) != {'action', 'native_protocol', 'pid'}
                or type(request.get('native_protocol')) is not int or request['native_protocol'] != PROTOCOL
                or type(request.get('pid')) is not int or request['pid'] <= 0):
            raise TargetError()
        self.prune()
        sessions = (self.scan or backend())(request['pid'])
        result = []
        try:
            with self.lock:
                if not 0 < len(sessions) <= 8 or len(self.views) + len(self.pins) + len(sessions) > MAX_PINS:
                    raise TargetError()
                for session in sessions:
                    fields = []
                    if not 0 < len(session.controls) <= 128:
                        raise TargetError()
                    focused = session.focus(range(len(session.controls)))
                    for index in range(len(session.controls)):
                        facts = session.describe(index)
                        # No names, labels, titles, selected text or field values.
                        fields.append(dict(control=index, password=facts[0], readonly=facts[1], focused=index == focused))
                    token = secrets.token_hex(32)
                    self.views[token] = (self.clock() + TTL, session, focused)
                    result.append(dict(window=token, controls=fields))
            return dict(ok=True, pid=request['pid'], windows=result, expires_in=TTL)
        except BaseException:
            with self.lock:
                for item in result:
                    self.views.pop(item['window'], None)
            for session in sessions:
                session.close()
            raise

    def pin(self, request):
        from .cards import FILL_FIELDS as CARD_FIELDS
        from .identities import FILL_FIELDS as IDENTITY_FIELDS
        self.prune()
        token = request.get('window')
        with self.lock:
            found = self.views.pop(token, None) if isinstance(token, str) else None
        if found is None:
            raise TargetError()
        expiry, session, discovery_focus = found
        try:
            required = {'action', 'native_protocol', 'window', 'control', 'mode', 'service_url'}
            mode = request.get('mode')
            extra = {'username_control'} if mode == 'login' else {'field'} if mode in {'card', 'identity'} else set()
            if (set(request) != required | extra or type(request.get('native_protocol')) is not int
                    or request['native_protocol'] != PROTOCOL or mode not in available_modes() or expiry <= self.clock()):
                raise TargetError()
            origin = https_origin(request['service_url'])
            indices = (request['control'],)
            if mode == 'login':
                indices = (request['username_control'], request['control'])
            if (any(type(i) is not int or not 0 <= i < len(session.controls) for i in indices)
                    or len(set(indices)) != len(indices) or indices[0] != discovery_focus):
                raise TargetError()
            field = request.get('field')
            if mode == 'card' and field not in CARD_FIELDS or mode == 'identity' and field not in IDENTITY_FIELDS:
                raise TargetError()
            facts = tuple(session.describe(i) for i in indices)
            for n, fact in enumerate(facts):
                masked, readonly = fact[:2]
                password = mode == 'password' or mode == 'login' and n == 1
                if mode == 'read':
                    if masked or not readonly:
                        raise TargetError()
                elif readonly or password and not masked or not password and mode not in {'card'} and masked:
                    raise TargetError()
            focus = session.focus(indices)
            if focus != request['control']:
                raise TargetError()
            kind = 'password' if mode in {'username', 'password', 'login'} else mode
            pin = NativePin(session, mode, kind, indices, facts, focus, origin, field, self.clock() + TTL)
            self.check(pin, lambda: True, pin.expires)
            with self.lock:
                if len(self.views) + len(self.pins) >= MAX_PINS:
                    raise TargetError()
                target = secrets.token_hex(32)
                self.pins[target] = pin
            return dict(ok=True, target=target, expires_in=TTL, target_delivery=DELIVERY)
        except BaseException:
            session.close()
            raise

    def take(self, token, kind=None):
        self.prune()
        with self.lock:
            pin = self.pins.pop(token, None) if isinstance(token, str) else None
        if pin is not None and (kind is not None and pin.kind != kind or pin.expires <= self.clock()):
            pin.close()
            raise TargetError()
        return pin

    def check(self, pin, ready, deadline):
        if pin.closed or self.clock() >= min(pin.expires, deadline) or not ready():
            raise TargetError()
        pin.session.check(pin.indices, pin.facts, pin.focus)
        if self.clock() >= min(pin.expires, deadline) or not ready():
            raise TargetError()

    def _write(self, pin, values, ready, deadline):
        started = False
        try:
            if len(values) != len(pin.indices) or any(not text(v, pin.kind == 'identity' and pin.field == 'street-address' and bool(f[2]),
                                                            pin.kind == 'identity')
                                                       for v, f in zip(values, pin.facts)):
                raise TargetError()
            self.check(pin, ready, deadline)
            # Preflight the whole login before setting either field.
            for index, value in zip(pin.indices, values):
                pin.session.prepare(index, value)
            def before_write():
                nonlocal started
                self.check(pin, ready, deadline)
                started = True
            for index, value in zip(pin.indices, values):
                pin.session.write(index, value, before_write)
                self.check(pin, ready, deadline)
        except Exception:
            raise DeliveryError(started) from None

    def deliver_password(self, pin, mode, username, password, origins, ready, deadline):
        if pin.mode != mode or pin.origin not in origins:
            raise DeliveryError(False)
        values = (username, password) if mode == 'login' else (password if mode == 'password' else username,)
        self._write(pin, values, ready, deadline)

    def fill(self, pin, value, field, ready, deadline=None, *, notify_page=False):
        from .browser_card import failure
        try:
            if pin.kind not in {'card', 'identity'} or pin.field != field or notify_page:
                raise DeliveryError(False)
            self._write(pin, (value,), ready, self.clock() + 4 if deadline is None else deadline)
            return dict(ok=True, filled=field, **{pin.kind + '_delivery': DELIVERY})
        except DeliveryError as exc:
            return failure(exc.started, kind=pin.kind)
        except Exception:
            return failure(kind=pin.kind)

    def read(self, pin, origins, ready, deadline):
        if pin.mode != 'read' or pin.origin not in origins:
            raise TargetError()
        self.check(pin, ready, deadline)
        value = pin.session.read(pin.indices[0])
        self.check(pin, ready, deadline)
        if not isinstance(value, str) or len(value) > MAX_TEXT:
            raise TargetError()
        return value
