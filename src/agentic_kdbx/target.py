"""Target-pinned X11 delivery. No global input, clipboard, grabs or keymap writes."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import socket
import time

DELIVERY = 'x11-send-event-v1'
PIN_TTL = 30.0
MAX_PINS = 128
DELIVERY_TIMEOUT = 3.0


def capabilities():
    return dict(target_fill_required=True, target_fill_protocol=1, target_fill_delivery=DELIVERY)


class TargetError(Exception):
    """Internal only: callers must return fixed, secret-free error text."""


class DeliveryError(TargetError):
    def __init__(self, started):
        self.started = started


def failure(started=False):
    return {'ok': False, 'error': ('autofill outcome uncertain: target delivery interrupted; do not retry automatically'
                                  if started else 'autofill not started: target unavailable, changed or unsupported; pin again'),
            'delivery': 'uncertain' if started else 'not-started'}


class TargetPins:
    def __init__(self, typer, clock):
        self.typer, self.clock = typer, clock
        self.pins = {}

    def pin(self, request):
        if set(request) != {'action', 'pid', 'window', 'target_protocol'} or type(request.get('target_protocol')) is not int or request['target_protocol'] != 1:
            raise TargetError()
        pid, window = request.get('pid'), request.get('window')
        if type(pid) is not int or pid <= 0 or type(window) is not int or not 1 < window <= 0xffffffff:
            raise TargetError()
        self.pins = {key: value for key, value in self.pins.items() if value[0] > self.clock()}
        if len(self.pins) >= MAX_PINS:
            raise TargetError()
        identity = self.typer.capture(pid, window)
        token = secrets.token_hex(32)
        self.pins[token] = (self.clock() + PIN_TTL, identity)
        return {'ok': True, 'target': token, 'pid': pid, 'window': window,
                'expires_in': int(PIN_TTL), 'target_delivery': DELIVERY}

    def consume(self, request):
        token = request.get('target')
        pin = self.pins.pop(token, None) if isinstance(token, str) else None
        if (pin is None or pin[0] <= self.clock() or type(request.get('target_protocol')) is not int
                or request['target_protocol'] != 1):
            raise TargetError()
        return pin[1]


@dataclass(frozen=True)
class Identity:
    pid: int
    window: int
    focus: int
    root: int
    process: tuple
    wm_class: tuple
    machine: str


def process_identity(pid):
    path = Path('/proc') / str(pid)
    if path.stat().st_uid != os.getuid():
        raise TargetError()
    # stat's comm can contain spaces and parentheses. Field 22 is starttime.
    fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
    exe = (path / 'exe').stat()
    return fields[19], exe.st_dev, exe.st_ino


class X11Session:
    """One private connection per capture/delivery; explicit SendEvent destination.

    A focus change after the last check cannot redirect an event to the new app.
    Applications may ignore synthetic events, or change an internal field/tab;
    this is dispatch assurance, never proof of field receipt/authentication.
    """
    def __init__(self, pid, window):
        from Xlib import X, Xatom, display
        self.X, self.Xatom = X, Xatom
        self.display = display.Display()
        self.display.set_error_handler(self._error)
        self.bad = False
        self.pid, self.window = pid, window
        self.root = self.display.screen().root
        self.top = self.display.create_resource_object('window', window)
        self.active_atom = self.display.intern_atom('_NET_ACTIVE_WINDOW')
        self.pid_atom = self.display.intern_atom('_NET_WM_PID')
        self.machine_atom = self.display.intern_atom('WM_CLIENT_MACHINE')
        self.class_atom = self.display.intern_atom('WM_CLASS')
        try:
            if not self.display.has_extension('X-Resource'):
                raise TargetError()
            version = self.display.res_query_version(1, 2)
            if (version.server_major, version.server_minor) < (1, 2):
                raise TargetError()
            self.root.change_attributes(event_mask=X.PropertyChangeMask)
            self.top.change_attributes(event_mask=X.PropertyChangeMask | X.StructureNotifyMask)
            self.identity = self.snapshot()
            self.focus = self.display.create_resource_object('window', self.identity.focus)
            self.focus.change_attributes(event_mask=X.FocusChangeMask | X.StructureNotifyMask |
                                         (X.PropertyChangeMask if window == self.identity.focus else 0))
            self.check()
        except BaseException:
            self.close()
            raise

    def _error(self, *_):
        # Do not let python-xlib print native errors or credential-bearing data.
        self.bad = True

    def close(self):
        self.display.close()

    def _one(self, window, atom, kind):
        value = window.get_full_property(atom, kind)
        if value is None or value.format != 32 or len(value.value) != 1:
            raise TargetError()
        return int(value.value[0])

    def owner_pid(self, window):
        from Xlib.ext import res
        values = self.display.res_query_client_ids([
            {'client': window.id, 'mask': res.LocalClientPIDMask}]).ids
        if len(values) != 1 or values[0].spec.mask != res.LocalClientPIDMask or len(values[0].value) != 1:
            raise TargetError()
        return int(values[0].value[0])

    def snapshot(self):
        X = self.X
        if self._one(self.root, self.active_atom, self.Xatom.WINDOW) != self.window:
            raise TargetError()
        if self._one(self.top, self.pid_atom, self.Xatom.CARDINAL) != self.pid:
            raise TargetError()
        if self.top.get_attributes().map_state != X.IsViewable:
            raise TargetError()
        wm_class, machine = self.top.get_wm_class(), self.top.get_wm_client_machine()
        if not wm_class or len(wm_class) != 2 or not all(wm_class):
            raise TargetError()
        if machine not in {socket.gethostname(), os.uname().nodename}:
            raise TargetError()
        focus = self.display.get_input_focus().focus
        if not hasattr(focus, 'id') or focus.id in {0, 1, self.root.id}:
            raise TargetError()
        if self.owner_pid(self.top) != self.pid or self.owner_pid(focus) != self.pid:
            raise TargetError()
        node = focus
        for _ in range(64):
            if node.id == self.window:
                break
            tree = node.query_tree()
            if tree.root.id != self.root.id or tree.parent.id == self.root.id:
                raise TargetError()
            node = tree.parent
        else:
            raise TargetError()
        # Held keys/buttons can activate shortcuts or corrupt a fill. Never
        # release another client's keys or adjust global keyboard state.
        if any(self.display.query_keymap()) or self.root.query_pointer().mask:
            raise TargetError()
        return Identity(self.pid, self.window, focus.id, self.root.id,
                        process_identity(self.pid), tuple(wm_class), machine)

    def check(self):
        if self.snapshot() != self.identity:
            raise TargetError()
        self.display.sync()
        while self.display.pending_events():
            event = self.display.next_event()
            if (event.type in {self.X.FocusOut, self.X.DestroyNotify, self.X.UnmapNotify,
                               self.X.ReparentNotify, self.X.MappingNotify}
                    or event.type == self.X.PropertyNotify and event.atom in {
                        self.active_atom, self.pid_atom, self.machine_atom, self.class_atom}):
                raise TargetError()
        if self.bad:
            raise TargetError()

    def prepare(self, steps):
        # Use the first core layout group and explicit shift state. Refuse
        # unmapped characters before any key; never borrow/change keycodes.
        d = self.display
        first = d.display.info.min_keycode
        mapping = d.get_keyboard_mapping(first, d.display.info.max_keycode - first + 1)
        codes = {}
        for index, row in enumerate(mapping):
            for shift, sym in enumerate(row[:2]):
                if sym and sym not in codes:
                    codes[sym] = (first + index, self.X.ShiftMask if shift else 0)
        result = []
        for text in steps:
            symbols = [0xff09] if text is None else [ord(c) if ord(c) < 256 else 0x01000000 | ord(c) for c in text]
            for sym in symbols:
                if sym not in codes:
                    raise TargetError()
                result.append(codes[sym])
        return result

    def send_pair(self, code):
        from Xlib.protocol import event
        keycode, state = code
        # A fixed XID, propagate=False, event_mask=0 delivers only to its owner.
        # Neither InputFocus nor PointerWindow is used. Even a switch between
        # check and send cannot redirect the pair to a new foreground window.
        for kind in (event.KeyPress, event.KeyRelease):
            self.focus.send_event(kind(detail=keycode, state=state, time=self.X.CurrentTime,
                                       root=self.root, window=self.focus, same_screen=1,
                                       child=self.X.NONE, root_x=0, root_y=0, event_x=0, event_y=0),
                                  event_mask=0, propagate=False)
        self.display.sync()
        if self.bad:
            raise TargetError()


class X11Typer:
    def __init__(self, session_factory=X11Session):
        # Lazy: status, locked vaults and synthetic tests need no desktop.
        self.session_factory = session_factory

    def capture(self, pid, window):
        session = self.session_factory(pid, window)
        try:
            session.check()
            return session.identity
        finally:
            session.close()

    def deliver(self, identity, steps, ready):
        started = False
        session = None
        try:
            session = self.session_factory(identity.pid, identity.window)
            if session.identity != identity:
                raise TargetError()
            codes = session.prepare(steps)
            session.check()
            if not ready():
                raise TargetError()
            deadline = time.monotonic() + DELIVERY_TIMEOUT
            for code in codes:
                if time.monotonic() >= deadline:
                    raise TargetError()
                session.check()
                # Target validation can itself take time. Recheck the start
                # deadline/caller after the final preflight, before any key.
                if time.monotonic() >= deadline or not started and not ready():
                    raise TargetError()
                # Conservatively uncertain even if native send raises before
                # it can confirm whether the first pair reached the server.
                started = True
                session.send_pair(code)
                session.check()
            session.check()
        except Exception:
            raise DeliveryError(started) from None
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    raise DeliveryError(started) from None
