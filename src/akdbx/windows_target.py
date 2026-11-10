"""Directed Unicode window messages. No SendInput, clipboard, or readback."""
from dataclasses import dataclass
import ctypes
from ctypes import wintypes as W

from .target import X11Typer, TargetError


@dataclass(frozen=True)
class WindowsIdentity:
    pid: int
    window: int
    focus: int
    thread: int
    process: tuple
    window_class: str
    focus_class: str


class GUIThreadInfo(ctypes.Structure):
    _fields_ = [('cbSize', W.DWORD), ('flags', W.DWORD), ('hwndActive', W.HWND),
                ('hwndFocus', W.HWND), ('hwndCapture', W.HWND), ('hwndMenuOwner', W.HWND),
                ('hwndMoveSize', W.HWND), ('hwndCaret', W.HWND), ('rcCaret', W.RECT)]


class NativeWindows:
    def __init__(self, pid):
        from .windows_security import verify_process
        self.process_handle, self.process = verify_process(pid)
        try:
            self.api = ctypes.WinDLL('user32', use_last_error=True)
            signatures = {
                'GetForegroundWindow': (W.HWND, []),
                'GetWindowThreadProcessId': (W.DWORD, [W.HWND, ctypes.POINTER(W.DWORD)]),
                'GetGUIThreadInfo': (W.BOOL, [W.DWORD, ctypes.POINTER(GUIThreadInfo)]),
                'GetAncestor': (W.HWND, [W.HWND, W.UINT]),
                'IsWindowVisible': (W.BOOL, [W.HWND]),
                'IsWindowEnabled': (W.BOOL, [W.HWND]),
                'IsWindowUnicode': (W.BOOL, [W.HWND]),
                'GetAsyncKeyState': (ctypes.c_short, [ctypes.c_int]),
                'GetClassNameW': (ctypes.c_int, [W.HWND, W.LPWSTR, ctypes.c_int]),
                'SendMessageTimeoutW': (ctypes.c_ssize_t, [W.HWND, W.UINT, W.WPARAM, W.LPARAM,
                                                       W.UINT, W.UINT, ctypes.POINTER(ctypes.c_size_t)]),
            }
            for name, (result, arguments) in signatures.items():
                function = getattr(self.api, name)
                function.restype, function.argtypes = result, arguments
        except BaseException:
            self.close()
            raise

    def owner(self, window):
        pid = W.DWORD()
        thread = self.api.GetWindowThreadProcessId(window, ctypes.byref(pid))
        if not thread or not pid.value:
            raise TargetError()
        return thread, pid.value

    def class_name(self, window):
        result = ctypes.create_unicode_buffer(256)
        if not self.api.GetClassNameW(window, result, len(result)):
            raise TargetError()
        return result.value

    def snapshot(self, pid, window):
        import win32event
        if win32event.WaitForSingleObject(self.process_handle, 0) != win32event.WAIT_TIMEOUT:
            raise TargetError()
        a = self.api
        thread, owner = self.owner(window)
        if (owner != pid or a.GetForegroundWindow() != window or a.GetAncestor(window, 2) != window
                or not a.IsWindowVisible(window) or not a.IsWindowEnabled(window)):
            raise TargetError()
        info = GUIThreadInfo(cbSize=ctypes.sizeof(GUIThreadInfo))
        if (not a.GetGUIThreadInfo(thread, ctypes.byref(info)) or info.flags & ~1
                or info.hwndActive != window or not info.hwndFocus):
            raise TargetError()
        focus = info.hwndFocus
        if (self.owner(focus) != (thread, pid) or a.GetAncestor(focus, 2) != window
                or not a.IsWindowUnicode(focus) or not a.IsWindowVisible(focus)
                or not a.IsWindowEnabled(focus) or info.hwndCapture):
            raise TargetError()
        if any(a.GetAsyncKeyState(key) & 0x8000 for key in range(1, 256)):
            raise TargetError()
        return WindowsIdentity(pid, window, focus, thread, self.process,
                               self.class_name(window), self.class_name(focus))

    def send_char(self, focus, value):
        result = ctypes.c_size_t()
        # Fixed HWND; switching foreground windows cannot redirect the message.
        # BLOCK | ABORTIFHUNG | ERRORONEXIT, with a finite timeout per message.
        if not self.api.SendMessageTimeoutW(focus, 0x0102, value, 1, 0x23, 100,
                                           ctypes.byref(result)):
            raise TargetError()

    def close(self):
        self.process_handle.Close()


class WindowsSession:
    def __init__(self, pid, window, native_factory=NativeWindows):
        self.native = native_factory(pid)
        self.pid, self.window = pid, window
        try:
            self.identity = self.native.snapshot(pid, window)
        except BaseException:
            self.close()
            raise

    def check(self):
        if self.native.snapshot(self.pid, self.window) != self.identity:
            raise TargetError()

    def prepare(self, steps):
        # Never emulate Tab with global keyboard input or guess the next field.
        # Separate username/password pins are required on Windows.
        if any(step is None for step in steps):
            raise TargetError()
        encoded = ''.join(steps).encode('utf-16-le', errors='strict')
        return [int.from_bytes(encoded[i:i + 2], 'little') for i in range(0, len(encoded), 2)]

    def send_pair(self, value):
        self.native.send_char(self.identity.focus, value)

    def close(self):
        self.native.close()


class WindowsTyper(X11Typer):
    def __init__(self, session_factory=WindowsSession):
        super().__init__(session_factory)
