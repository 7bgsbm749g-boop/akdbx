"""Retained Accessibility controls in the frontmost native macOS application."""
import ctypes as C
import os
import time
from pathlib import Path

import HIServices as AX
from CoreFoundation import CFEqual

from .native_fields import AccessibilityRequired, MAX_TEXT
from .target import TargetError

SYSTEM = AX.AXUIElementCreateSystemWide()
TEXT = {'AXTextField', 'AXTextArea'}
WEB = {'AXWebArea', 'AXHTMLContent'}
BROWSERS = {'safari', 'safari technology preview', 'google chrome', 'chromium', 'microsoft edge',
            'firefox', 'firefox developer edition', 'brave browser', 'opera', 'helium', 'arc',
            'vivaldi', 'orion', 'zen', 'waterfox', 'tor browser', 'duckduckgo'}

# Darwin's libproc supplies the owner, executable and process start time. A
# retained AX application plus this identity prevents rebinding on PID reuse.
class BSDInfo(C.Structure):
    _fields_ = [(key, C.c_uint32) for key in (
        'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid', 'ruid', 'rgid', 'svuid', 'svgid', 'reserved'
    )] + [('comm', C.c_char * 16), ('name', C.c_char * 32),
          ('group_and_tty', C.c_uint32 * 6), ('start_sec', C.c_uint64), ('start_usec', C.c_uint64)]


_lib = C.CDLL('/usr/lib/libproc.dylib')
_lib.proc_pidinfo.argtypes = [C.c_int, C.c_int, C.c_uint64, C.c_void_p, C.c_int]
_lib.proc_pidpath.argtypes = [C.c_int, C.c_void_p, C.c_uint32]


def identity(pid):
    info, path = BSDInfo(), C.create_string_buffer(4096)
    if (not 0 < pid <= 0x7fffffff or _lib.proc_pidinfo(pid, 3, 0, C.byref(info), C.sizeof(info)) != C.sizeof(info)
            or info.pid != pid or {info.uid, info.ruid, info.svuid} != {os.getuid()}
            or _lib.proc_pidpath(pid, path, len(path)) <= 0):
        raise TargetError()
    executable = Path(os.fsdecode(path.value))
    names = [executable.name] + [p.stem for p in executable.parents if p.suffix.lower() == '.app']
    if any(n.lower() == browser or n.lower().startswith(browser + ' ')
           for browser in BROWSERS for n in names):
        raise TargetError()
    return executable, info.start_sec, info.start_usec


class MissingAttribute(TargetError):
    """An optional discovery candidate cannot supply a required field fact."""


def result(pair):
    error, value = pair
    if error in (AX.kAXErrorAttributeUnsupported, AX.kAXErrorNoValue):
        raise MissingAttribute()
    if error == AX.kAXErrorAPIDisabled:
        raise AccessibilityRequired()
    if error != AX.kAXErrorSuccess or value is None:
        raise TargetError()
    return value


def attr(node, name):
    return result(AX.AXUIElementCopyAttributeValue(node, name, None))


def optional(node, name):
    pair = AX.AXUIElementCopyAttributeValue(node, name, None)
    return None if pair[0] in (AX.kAXErrorAttributeUnsupported, AX.kAXErrorNoValue) else result(pair)


def visible(node):
    # Hit-test the center against the whole desktop. This excludes clipped,
    # hidden, covered and off-screen controls.
    position = AX.AXValueGetValue(attr(node, 'AXPosition'), AX.kAXValueCGPointType, None)
    size = AX.AXValueGetValue(attr(node, 'AXSize'), AX.kAXValueCGSizeType, None)
    if not position[0] or not size[0]:
        return False
    (x, y), (width, height) = position[1], size[1]
    if width <= 0 or height <= 0:
        return False
    hit = AX.AXUIElementCopyElementAtPosition(SYSTEM, x + width / 2, y + height / 2, None)
    if hit[0] in (AX.kAXErrorNoValue, AX.kAXErrorFailure):
        return False
    return CFEqual(result(hit), node)


def enabled(node, role):
    state = optional(node, 'AXEnabled')
    # Stock NSTextView has no AXEnabled attribute. Its editability and
    # selectability are independent; focus and hit-testing are checked too.
    return role == 'AXTextArea' if state is None else bool(state)


def field_facts(node, role):
    subrole = optional(node, 'AXSubrole')
    masked = role == 'AXTextField' and subrole == 'AXSecureTextField'
    if not masked and optional(node, 'AXProtectedContent'):
        return None
    if subrole not in (None, 'AXSecureTextField', 'AXSearchField'):
        return None
    writable = result(AX.AXUIElementIsAttributeSettable(node, 'AXValue', None))
    if not writable and (role != 'AXTextArea' or
            result(AX.AXUIElementIsAttributeSettable(node, 'AXSelectedText', None))):
        return None
    return masked, not writable, role == 'AXTextArea'


def count(node):
    size = attr(node, 'AXNumberOfCharacters')
    if not isinstance(size, int) or not 0 <= size <= MAX_TEXT:
        raise TargetError()
    return size


class MacFields:
    def __init__(self, pid):
        self.pid = pid
        self.identity = identity(pid)
        self.app = AX.AXUIElementCreateApplication(pid)
        self.window = attr(self.app, 'AXFocusedWindow')
        self.controls = []
        self.base()
        for node, role in self.walk():
            if role not in TEXT:
                continue
            try:
                eligible = enabled(node, role) and visible(node) and field_facts(node, role) is not None
            except MissingAttribute:
                continue
            if eligible:
                self.controls.append(node)
                if len(self.controls) > 128:
                    raise TargetError()

    def walk(self):
        pending, budget, deadline = [self.window], 512, time.monotonic() + 3
        while pending:
            if budget <= 0 or time.monotonic() >= deadline:
                raise TargetError()
            node = pending.pop()
            budget -= 1
            self.owner(node)
            role = attr(node, 'AXRole')
            if role in WEB:
                raise TargetError()
            yield node, role
            pair = AX.AXUIElementGetAttributeValueCount(node, 'AXChildren', None)
            if pair[0] == AX.kAXErrorAttributeUnsupported:
                continue
            length = result(pair)
            if not 0 <= length <= budget - len(pending):
                raise TargetError()
            if length:
                children = result(AX.AXUIElementCopyAttributeValues(node, 'AXChildren', 0, length, None))
                if len(children) != length:
                    raise TargetError()
                pending.extend(reversed(children))

    def close(self):
        self.controls.clear()
        self.app = self.window = None

    def owner(self, node):
        if result(AX.AXUIElementGetPid(node, None)) != self.pid:
            raise TargetError()

    def base(self):
        if not AX.AXIsProcessTrusted():
            raise AccessibilityRequired()
        if (self.app is None or identity(self.pid) != self.identity
                or not attr(self.app, 'AXFrontmost')
                or not CFEqual(attr(self.app, 'AXFocusedWindow'), self.window)
                or attr(self.window, 'AXRole') != 'AXWindow' or attr(self.window, 'AXMinimized')):
            raise TargetError()

    def describe(self, index):
        self.base()
        node = self.controls[index]
        current = node
        for _ in range(32):
            self.owner(current)
            if CFEqual(current, self.window):
                break
            if attr(current, 'AXRole') in WEB:
                raise TargetError()
            current = attr(current, 'AXParent')
        else:
            raise TargetError()
        role = attr(node, 'AXRole')
        if role not in TEXT or not enabled(node, role) or not visible(node):
            raise TargetError()
        facts = field_facts(node, role)
        if facts is None:
            raise TargetError()
        return facts

    def focus(self, indices):
        self.base()
        focused = attr(self.app, 'AXFocusedUIElement')
        matches = [i for i in indices if CFEqual(focused, self.controls[i])]
        if len(matches) != 1:
            raise TargetError()
        return matches[0]

    def check(self, indices, facts, focus):
        # The window must still be wholly native. Scanning also catches a
        # replacement whose stale AX object still reports its former parent.
        self.base()
        remaining = set(indices)
        for node, _ in self.walk():
            remaining.difference_update([i for i in remaining if CFEqual(node, self.controls[i])])
        if (remaining or any(fact[0] for fact in facts)
                or tuple(self.describe(i) for i in indices) != facts or self.focus(indices) != focus):
            raise TargetError()

    def prepare(self, index, value):
        if self.describe(index)[:2] != (False, False) or len(value.encode('utf-16-le')) // 2 > MAX_TEXT:
            raise TargetError()
        count(self.controls[index])

    def write(self, index, value, before_write):
        node = self.controls[index]
        before_write()
        if AX.AXUIElementSetAttributeValue(node, 'AXValue', value) != AX.kAXErrorSuccess:
            raise TargetError()
        if count(node) != len(value.encode('utf-16-le')) // 2:
            raise TargetError()

    def read(self, index):
        if self.describe(index)[:2] != (False, True):
            raise TargetError()
        node = self.controls[index]
        size = count(node)
        # Copy a bounded character range, even if the document grows.
        span = AX.AXValueCreate(AX.kAXValueCFRangeType, (0, size))
        value = result(AX.AXUIElementCopyParameterizedAttributeValue(node, 'AXStringForRange', span, None))
        if not isinstance(value, str) or len(value.encode('utf-16-le')) // 2 != size or count(node) != size:
            raise TargetError()
        return value


def scan(pid):
    if not AX.AXIsProcessTrusted():
        raise AccessibilityRequired()
    if AX.AXUIElementSetMessagingTimeout(SYSTEM, 0.4) != AX.kAXErrorSuccess:
        raise TargetError()
    return [MacFields(pid)]
