"""Retained AT-SPI native text controls; works without X11 input injection.

The registry is used only for discovery. The application's unique accessibility
connection supplies process ownership, and retained objects supply window and
control identity. No accessibility names or text are returned during discovery.
"""
import ctypes as C
import ctypes.util
import threading
import time
from pathlib import Path

from .target import TargetError, process_identity

LOCK = threading.RLock()
_API = None
_INIT_FAILED = False
# Stable AT-SPI StateType enum values.
ACTIVE, DEFUNCT, EDITABLE, ENABLED = 1, 6, 7, 8
FOCUSED, MULTILINE, SENSITIVE, SHOWING, VISIBLE = 12, 17, 24, 25, 30
TEXT_ROLES = {'text', 'entry', 'password text'}
WINDOW_ROLES = {'frame', 'dialog', 'window'}
WEB_ROLES = {'document web', 'document frame', 'embedded', 'html container'}
BROWSERS = {'chrome', 'chromium', 'chromium-browser', 'firefox', 'firefox-bin',
            'msedge', 'helium', 'brave', 'brave-browser', 'opera'}


class API:
    def __init__(self):
        self.lib = C.CDLL(ctypes.util.find_library('atspi') or 'libatspi.so.0')
        self.glib = C.CDLL(ctypes.util.find_library('glib-2.0'))
        self.obj = C.CDLL(ctypes.util.find_library('gobject-2.0'))
        self.glib.g_free.argtypes = [C.c_void_p]
        self.glib.g_error_free.argtypes = [C.c_void_p]
        self.obj.g_object_unref.argtypes = [C.c_void_p]
        self.obj.g_object_ref.argtypes = [C.c_void_p]
        self.obj.g_object_ref.restype = C.c_void_p
        signatures = {
            'init': (C.c_int, []), 'set_timeout': (None, [C.c_int, C.c_int]),
            'get_desktop': (C.c_void_p, [C.c_int]),
            'accessible_clear_cache': (None, [C.c_void_p]),
            'accessible_get_child_count': (C.c_int, [C.c_void_p, C.c_void_p]),
            'accessible_get_child_at_index': (C.c_void_p, [C.c_void_p, C.c_int, C.c_void_p]),
            'accessible_get_parent': (C.c_void_p, [C.c_void_p, C.c_void_p]),
            'accessible_get_process_id': (C.c_uint, [C.c_void_p, C.c_void_p]),
            'accessible_get_role_name': (C.c_void_p, [C.c_void_p, C.c_void_p]),
            'accessible_get_state_set': (C.c_void_p, [C.c_void_p]),
            'state_set_contains': (C.c_int, [C.c_void_p, C.c_int]),
            'accessible_get_text_iface': (C.c_void_p, [C.c_void_p]),
            'accessible_get_editable_text_iface': (C.c_void_p, [C.c_void_p]),
            'text_get_character_count': (C.c_int, [C.c_void_p, C.c_void_p]),
            'text_get_text': (C.c_void_p, [C.c_void_p, C.c_int, C.c_int, C.c_void_p]),
            'editable_text_set_text_contents': (C.c_int, [C.c_void_p, C.c_char_p, C.c_void_p]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.lib, 'atspi_' + name)
            function.restype, function.argtypes = result, args
            setattr(self, name, function)
        self.set_timeout(400, 400)
        if self.init() not in {0, 1}:
            raise TargetError()

    def call(self, name, *args):
        error = C.c_void_p()
        value = getattr(self, name)(*args, C.byref(error))
        if error.value:
            self.glib.g_error_free(error)
            raise TargetError()
        return value

    def string(self, name, *args):
        pointer = self.call(name, *args)
        if not pointer:
            raise TargetError()
        try:
            return C.string_at(pointer).decode('utf-8')
        finally:
            self.glib.g_free(pointer)

    def role(self, node):
        self.accessible_clear_cache(node)
        return self.string('accessible_get_role_name', node)

    def states(self, node):
        self.accessible_clear_cache(node)
        states = self.accessible_get_state_set(node)
        if not states:
            raise TargetError()
        try:
            return {value for value in (ACTIVE, DEFUNCT, EDITABLE, ENABLED, FOCUSED, MULTILINE, SENSITIVE, SHOWING, VISIBLE)
                    if self.state_set_contains(states, value)}
        finally:
            self.obj.g_object_unref(states)

    def children(self, node):
        count = self.call('accessible_get_child_count', node)
        if not 0 <= count <= 256:
            raise TargetError()
        return count


def api():
    global _API, _INIT_FAILED
    # libatspi can report "already initialized" after a failed initialization,
    # then abort in get_desktop. Never reuse that failed process-global state.
    if _INIT_FAILED:
        raise TargetError()
    if _API is None:
        try:
            _API = API()
        except Exception:
            _INIT_FAILED = True
            raise TargetError() from None
    return _API


class LinuxFields:
    def __init__(self, native, pid, identity, window, controls):
        self.api, self.pid, self.identity = native, pid, identity
        self.window, self.controls = window, controls
        self.closed = False

    def close(self):
        with LOCK:
            if not self.closed:
                self.closed = True
                for node in [self.window, *self.controls]:
                    self.api.obj.g_object_unref(node)

    def _base(self):
        if self.closed or process_identity(self.pid) != self.identity:
            raise TargetError()
        states = self.api.states(self.window)
        if (DEFUNCT in states or ACTIVE not in states or SHOWING not in states
                or self.api.role(self.window) not in WINDOW_ROLES
                or self.api.call('accessible_get_process_id', self.window) != self.pid):
            raise TargetError()

    def describe(self, index):
        with LOCK:
            self._base()
            node = self.controls[index]
            role, states = self.api.role(node), self.api.states(node)
            if (role not in TEXT_ROLES or DEFUNCT in states
                    or not {ENABLED, SENSITIVE, SHOWING, VISIBLE} <= states
                    or self.api.call('accessible_get_process_id', node) != self.pid):
                raise TargetError()
            current = self.api.obj.g_object_ref(node)
            try:
                for _ in range(32):
                    if current == self.window:
                        break
                    if self.api.role(current) in WEB_ROLES:
                        raise TargetError()
                    parent = self.api.call('accessible_get_parent', current)
                    self.api.obj.g_object_unref(current)
                    current = parent
                    if not current:
                        raise TargetError()
                else:
                    raise TargetError()
            finally:
                if current:
                    self.api.obj.g_object_unref(current)
            return role == 'password text', EDITABLE not in states, MULTILINE in states, role

    def focus(self, indices):
        with LOCK:
            found = [i for i in indices if FOCUSED in self.api.states(self.controls[i])]
            if len(found) != 1:
                raise TargetError()
            return found[0]

    def check(self, indices, facts, focus):
        with LOCK:
            if tuple(self.describe(i) for i in indices) != facts or self.focus(indices) != focus:
                raise TargetError()

    def prepare(self, index, value):
        if len(value.encode('utf-8')) > 65536:
            raise TargetError()
        with LOCK:
            for name in ('accessible_get_editable_text_iface', 'accessible_get_text_iface'):
                iface = getattr(self.api, name)(self.controls[index])
                if not iface:
                    raise TargetError()
                self.api.obj.g_object_unref(iface)

    def write(self, index, value, before_write):
        with LOCK:
            node = self.controls[index]
            iface = self.api.accessible_get_editable_text_iface(node)
            if not iface:
                raise TargetError()
            try:
                before_write()
                if not self.api.call('editable_text_set_text_contents', iface, value.encode('utf-8')):
                    raise TargetError()
            finally:
                self.api.obj.g_object_unref(iface)
            # Confirm length without reading a password or returning its length.
            iface = self.api.accessible_get_text_iface(node)
            if not iface:
                raise TargetError()
            try:
                if self.api.call('text_get_character_count', iface) != len(value):
                    raise TargetError()
            finally:
                self.api.obj.g_object_unref(iface)

    def read(self, index):
        with LOCK:
            if self.describe(index)[:2] != (False, True):
                raise TargetError()
            iface = self.api.accessible_get_text_iface(self.controls[index])
            if not iface:
                raise TargetError()
            try:
                count = self.api.call('text_get_character_count', iface)
                if not 0 < count <= 65536:
                    raise TargetError()
                # Qt rejects an end beyond the document. The reported end is
                # bounded above; a growing field is refused by the second count.
                value = self.api.string('text_get_text', iface, 0, count)
                after = self.api.call('text_get_character_count', iface)
                # GTK counts code points; Qt text cursors count UTF-16 units.
                if after != count or count not in {len(value), len(value.encode('utf-16-le')) // 2}:
                    raise TargetError()
                return value
            finally:
                self.api.obj.g_object_unref(iface)


def scan(pid):
    with LOCK:
        identity = process_identity(pid)
        if Path('/proc', str(pid), 'exe').resolve().name.lower() in BROWSERS:
            raise TargetError()
        native = api()
        desktop = native.get_desktop(0)
        if not desktop:
            raise TargetError()
        sessions = []
        deadline, budget = time.monotonic() + 3, [512]

        def walk(node, controls):
            budget[0] -= 1
            if budget[0] < 0 or time.monotonic() >= deadline:
                raise TargetError()
            role = native.role(node)
            if role in WEB_ROLES:
                raise TargetError()
            if role in TEXT_ROLES:
                states = native.states(node)
                if {ENABLED, SENSITIVE, SHOWING, VISIBLE} <= states and DEFUNCT not in states:
                    controls.append(native.obj.g_object_ref(node))
            for i in range(native.children(node)):
                child = native.call('accessible_get_child_at_index', node, i)
                if not child:
                    raise TargetError()
                try:
                    walk(child, controls)
                finally:
                    native.obj.g_object_unref(child)

        try:
            for i in range(native.children(desktop)):
                app = native.call('accessible_get_child_at_index', desktop, i)
                if not app:
                    continue
                try:
                    if native.call('accessible_get_process_id', app) != pid:
                        continue
                    for j in range(native.children(app)):
                        window = native.call('accessible_get_child_at_index', app, j)
                        controls = []
                        keep = False
                        try:
                            if (window and native.role(window) in WINDOW_ROLES
                                    and ACTIVE in native.states(window)):
                                walk(window, controls)
                                if controls:
                                    sessions.append(LinuxFields(native, pid, identity, window, controls))
                                    keep = True
                        finally:
                            if not keep:
                                for node in controls:
                                    native.obj.g_object_unref(node)
                                if window:
                                    native.obj.g_object_unref(window)
                finally:
                    native.obj.g_object_unref(app)
            return sessions
        except BaseException:
            for session in sessions:
                session.close()
            raise
        finally:
            native.obj.g_object_unref(desktop)
