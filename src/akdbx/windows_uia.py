"""Retained WPF UI Automation elements. Only the dedicated MTA uses COM pointers.

Every failure leaves this module as a bare TargetError. A COMError can carry
text from the target app's provider, so it is never kept, chained or returned.
"""
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from pathlib import Path
import threading

# Import on the caller before starting the MTA. comtypes initializes its first
# importing thread as an STA by default.
import comtypes
import comtypes.client
import win32api
import win32gui

from .native_fields import MAX_TEXT
from .target import TargetError
from .windows_fields import WindowsFields

_thread = threading.local()
# WPF builds its UI Automation provider when the first request arrives, so a
# starting or busy app can answer that request slowly. Only the first
# connection waits up to the Windows default; later requests keep the short
# limit, so a hung app fails as fast as before.
FIRST_CONNECTION_MS = 2000
REQUEST_MS = 500
# The first connection and the walk share one bound, inside the 5 s CLI budget
# of list-native-fields.
COLLECT_SECONDS = 4


def _initialize():
    comtypes.CoInitializeEx(comtypes.COINIT_MULTITHREADED)
    _thread.active = True


_worker = ThreadPoolExecutor(max_workers=1, initializer=_initialize, thread_name_prefix='akdbx-uia')


def in_apartment(method):
    @wraps(method)
    def call(*args):
        try:
            if getattr(_thread, 'active', False):
                return method(*args)
            return _worker.submit(method, *args).result()
        except TargetError as exc:
            exc.__cause__ = exc.__context__ = None
            raise
        except Exception:
            pass
        # Raised outside the handler, so no COM error or text is chained.
        # On the write path, the caller reports whether the write started.
        raise TargetError()
    return call


class WpfSession(WindowsFields):
    @in_apartment
    def __init__(self, pid, window, native):
        self.closed = False
        self.pid, self.window, self.native, self.gui = pid, window, native, win32gui
        self.identity = native.snapshot(pid, window)
        self.types = comtypes.client.GetModule(str(Path(win32api.GetSystemDirectory()) / 'UIAutomationCore.dll'))
        self.uia = comtypes.client.CreateObject(self.types.CUIAutomation8, interface=self.types.IUIAutomation2)
        self.uia.AutoSetFocus = False
        self.uia.TransactionTimeout = REQUEST_MS
        self.uia.ConnectionTimeout = FIRST_CONNECTION_MS
        deadline = self.clock() + COLLECT_SECONDS
        self.root = self.uia.ElementFromHandle(window)
        self.uia.ConnectionTimeout = REQUEST_MS
        self.walker = self.uia.RawViewWalker
        self.controls = []
        self.ids = []
        self._collect(deadline)

    def _collect(self, deadline):
        remaining = 512

        def walk(node, depth):
            nonlocal remaining
            remaining -= 1
            if remaining < 0 or depth > 48 or self.clock() >= deadline:
                raise TargetError()
            # Never descend into a hosted web document or another framework.
            if (node.CurrentProcessId != self.pid or node.CurrentFrameworkId != 'WPF'
                    or node.CurrentControlType == self.types.UIA_DocumentControlTypeId):
                return
            if node.CurrentControlType == self.types.UIA_EditControlTypeId:
                if (node.CurrentClassName in ('TextBox', 'PasswordBox') and node.CurrentIsEnabled
                        and not node.CurrentIsOffscreen and node.CurrentIsKeyboardFocusable):
                    identity = tuple(node.GetRuntimeId())
                    if not identity or identity in self.ids or len(self.controls) >= 128:
                        raise TargetError()
                    self.controls.append(node)
                    self.ids.append(identity)
                return
            child = self.walker.GetFirstChildElement(node)
            while child:
                walk(child, depth + 1)
                child = self.walker.GetNextSiblingElement(child)

        walk(self.root, 0)
        if not self.controls:
            raise TargetError()

    def _pattern(self, element, name):
        pattern = element.GetCurrentPattern(getattr(self.types, 'UIA_' + name + 'PatternId'))
        if not pattern:
            raise TargetError()
        return pattern.QueryInterface(getattr(self.types, 'IUIAutomation' + name + 'Pattern'))

    @in_apartment
    def describe(self, index):
        current = self._base()
        element = self.controls[index]
        if (current.focus != self.window or tuple(element.GetRuntimeId()) != self.ids[index]
                or element.CurrentControlType != self.types.UIA_EditControlTypeId
                or not element.CurrentIsEnabled or element.CurrentIsOffscreen
                or not element.CurrentIsKeyboardFocusable):
            raise TargetError()
        node = element
        for _ in range(49):
            if (not node or node.CurrentProcessId != self.pid or node.CurrentFrameworkId != 'WPF'
                    or node.CurrentControlType == self.types.UIA_DocumentControlTypeId):
                raise TargetError()
            if self.uia.CompareElements(node, self.root):
                break
            node = self.walker.GetParentElement(node)
        else:
            raise TargetError()
        if not self.uia.CompareElements(self.root, self.uia.ElementFromHandle(self.window)):
            raise TargetError()
        # Ignore default values. Unsupported IsPassword cannot authorize a read.
        masked = element.GetCurrentPropertyValueEx(self.types.UIA_IsPasswordPropertyId, True)
        expected = {'PasswordBox': True, 'TextBox': False}.get(element.CurrentClassName)
        if type(masked) is not bool or masked is not expected:
            raise TargetError()
        readonly = bool(self._pattern(element, 'Value').CurrentIsReadOnly)
        self._pattern(element, 'Text')
        # WPF exposes no AcceptsReturn property through UIA.
        return masked, readonly, False, self.ids[index]

    @in_apartment
    def focus(self, indices):
        self._base()
        focused = self.uia.GetFocusedElement()
        if not focused or focused.CurrentProcessId != self.pid or not focused.CurrentHasKeyboardFocus:
            raise TargetError()
        found = [i for i in indices if self.uia.CompareElements(self.controls[i], focused)
                 and self.ids[i] == tuple(focused.GetRuntimeId())]
        if len(found) != 1:
            raise TargetError()
        return found[0]

    @in_apartment
    def prepare(self, index, value):
        if self.describe(index)[1]:
            raise TargetError()
        self._pattern(self.controls[index], 'Text').DocumentRange

    @in_apartment
    def write(self, index, value, before_write):
        element = self.controls[index]
        pattern = self._pattern(element, 'Value')
        masked = self.describe(index)[0]
        before_write()
        pattern.SetValue(value)
        if not masked:
            # UIA string conditions and FindText compare linguistically: they
            # match canonically equivalent text and skip ignorable characters.
            # Compare the unmasked value ordinally here and never return it.
            if (pattern.CurrentValue or '') != value:
                raise TargetError()
            return
        # A WPF PasswordBox presents one mask character per UTF-16 unit.
        span = self._pattern(element, 'Text').DocumentRange
        end = span.Clone()
        span.MoveEndpointByRange(1, span, 0)
        length = len(value.encode('utf-16-le')) // 2
        if (span.MoveEndpointByUnit(1, self.types.TextUnit_Character, length + 1) != length
                or span.CompareEndpoints(1, end, 1) != 0):
            raise TargetError()

    @in_apartment
    def read(self, index):
        if self.describe(index)[:2] != (False, True):
            raise TargetError()
        result = self._pattern(self.controls[index], 'Text').DocumentRange.GetText(MAX_TEXT + 1)
        if not result or len(result.encode('utf-16-le')) // 2 > MAX_TEXT:
            raise TargetError()
        return result

    @in_apartment
    def close(self):
        self.controls.clear()
        self.root = self.walker = self.uia = None
        super().close()
