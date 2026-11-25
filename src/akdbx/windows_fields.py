"""Exact Win32 Unicode Edit controls. No global input, Tab or clipboard.

Custom controls and browser processes are intentionally unsupported. Passwords
require an Edit control whose password style and mask remain set. Read capture
requires an unmasked, read-only Edit control.
"""
import ctypes as C
from dataclasses import replace
from ctypes import wintypes as W
from pathlib import PureWindowsPath

from .target import TargetError
from .windows_target import NativeWindows

BROWSERS = {'chrome.exe', 'chromium.exe', 'firefox.exe', 'msedge.exe', 'helium.exe',
            'brave.exe', 'opera.exe'}
READONLY, PASSWORD = 0x800, 0x20
CONVERTING = 0x8 | 0x10 | 0x400  # ES_UPPERCASE, ES_LOWERCASE, ES_OEMCONVERT


class WindowsFields:
    def __init__(self, pid, window, native):
        import win32gui
        self.gui, self.pid, self.window, self.native = win32gui, pid, window, native
        self.closed = False
        self.controls = []
        self.identity = self.native.snapshot(pid, window)
        self.gui.EnumChildWindows(window, lambda hwnd, _: self._add(hwnd), None)
        if not self.controls:
            raise TargetError()

    def _add(self, hwnd):
        if len(self.controls) >= 128:
            raise TargetError()
        if (self.gui.GetClassName(hwnd) == 'Edit' and self.native.api.IsWindowUnicode(hwnd)
                and self.gui.IsWindowVisible(hwnd) and self.gui.IsWindowEnabled(hwnd)):
            self.controls.append(hwnd)
        return True

    def _base(self):
        if self.closed:
            raise TargetError()
        current = self.native.snapshot(self.pid, self.window)
        # Discovery binds the username by focus, then login pinning binds the
        # password by focus. Delivery's check() locks that final focus.
        if replace(current, focus=self.identity.focus, focus_class=self.identity.focus_class) != self.identity:
            raise TargetError()
        return current

    def describe(self, index):
        self._base()
        hwnd = self.controls[index]
        if (self.native.owner(hwnd) != (self.identity.thread, self.pid)
                or self.native.api.GetAncestor(hwnd, 2) != self.window
                or self.gui.GetClassName(hwnd) != 'Edit' or not self.native.api.IsWindowUnicode(hwnd)
                or not self.gui.IsWindowVisible(hwnd) or not self.gui.IsWindowEnabled(hwnd)):
            raise TargetError()
        style = self.gui.GetWindowLong(hwnd, -16)
        mask = self.message(hwnd, 0xD2)  # EM_GETPASSWORDCHAR
        if bool(mask) != bool(style & PASSWORD):
            raise TargetError()
        return bool(style & PASSWORD), bool(style & READONLY), bool(style & 4), style, self.gui.GetParent(hwnd), self.gui.GetDlgCtrlID(hwnd)

    def focus(self, indices):
        current = self._base()
        found = [i for i in indices if self.controls[i] == current.focus]
        if len(found) != 1:
            raise TargetError()
        return found[0]

    def check(self, indices, facts, focus):
        if tuple(self.describe(i) for i in indices) != facts or self.focus(indices) != focus:
            raise TargetError()

    def message(self, hwnd, message, wparam=0, lparam=0):
        value = C.c_size_t()
        if not self.native.api.SendMessageTimeoutW(hwnd, message, wparam, lparam, 0x23, 100, C.byref(value)):
            raise TargetError()
        return value.value

    def prepare(self, index, value):
        count = len(value.encode('utf-16-le', errors='strict')) // 2
        if self.describe(index)[3] & CONVERTING or count > self.message(self.controls[index], 0xD5):  # EM_GETLIMITTEXT
            raise TargetError()

    def write(self, index, value, before_write):
        buffer = C.create_unicode_buffer(value)
        before_write()
        if not self.message(self.controls[index], 0x000C, 0, C.addressof(buffer)):  # WM_SETTEXT
            raise TargetError()
        if self.message(self.controls[index], 0x000E) != len(value.encode('utf-16-le')) // 2:
            raise TargetError()

    def read(self, index):
        if self.describe(index)[:2] != (False, True):
            raise TargetError()
        hwnd = self.controls[index]
        size = self.message(hwnd, 0x000E)  # WM_GETTEXTLENGTH
        if not 0 < size <= 65536:
            raise TargetError()
        buffer = C.create_unicode_buffer(65538)
        count = self.message(hwnd, 0x000D, len(buffer), C.addressof(buffer))  # WM_GETTEXT
        if count != size or self.message(hwnd, 0x000E) != size:
            raise TargetError()
        return buffer.value

    def close(self):
        if not self.closed:
            self.closed = True
            self.native.close()


def scan(pid):
    native = NativeWindows(pid)
    try:
        kernel = C.WinDLL('kernel32', use_last_error=True)
        query = kernel.QueryFullProcessImageNameW
        query.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
        query.restype = W.BOOL
        path, size = C.create_unicode_buffer(32768), W.DWORD(32768)
        if not query(int(native.process_handle), 0, path, C.byref(size)):
            raise TargetError()
        if PureWindowsPath(path.value).name.lower() in BROWSERS:
            raise TargetError()
        window = native.api.GetForegroundWindow()
        if not window or native.owner(window)[1] != pid:
            raise TargetError()
        session = WindowsFields(pid, window, native)
        for index in range(len(session.controls)):
            session.describe(index)
        return [session]
    except BaseException:
        native.close()
        raise
