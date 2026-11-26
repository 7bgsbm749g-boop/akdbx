"""Hardware key challenge-response, written in-house over the OS's own libraries.

A KeePass vault protected by a hardware key uses HMAC-SHA1 challenge-response:
the key holds a secret in one of its two slots, and answers a 64-byte
challenge with a 20-byte response. The same protocol runs on two transports:

- USB HID feature reports (YubiKey, OnlyKey). Linux uses ``hidraw`` ioctls,
  Windows ``hid.dll`` and ``setupapi.dll``, macOS ``IOKit``.
- Smart card APDUs over PC/SC (USB smart card interface or an NFC reader):
  YubiKey, Nitrokey 3, Fidesmo, VivoKey Apex, Dangerous Things FlexSecure.
  Windows uses ``winscard.dll``, macOS ``PCSC.framework``, Linux
  ``libpcsclite``.

Only ``ctypes``, ``fcntl`` and the standard library are used. A key that
requires a touch waits for it; the caller sees ``on_touch`` once. Errors
carry fixed text only, never device data.
"""
from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

CHALLENGE_BYTES = 64
RESPONSE_BYTES = 20
# The key's own touch timeout is 15 s; allow for the transfer around it.
TOUCH_TIMEOUT = 20.0
# HMAC-SHA1 challenge commands, slot 2 first: slot 1 usually holds an OTP.
SLOT_COMMANDS = ((2, 0x38), (1, 0x30))
# USB vendors and products that speak the challenge-response protocol.
YUBICO_VID = 0x1050
ONLYKEY = (0x1D50, 0x60FC)
# Smart card applets that answer the same command (as an APDU).
APPLETS = (
    bytes.fromhex('A0000005272001'),  # YubiKey OTP
    bytes.fromhex('A0000005272101'),  # YubiKey OATH / Nitrokey 3 Secrets app
    bytes.fromhex('A0000006170007534EAF01'),  # Fidesmo
)

_LOCK = threading.Lock()


class HardwareKeyError(Exception):
    """A fixed, secret-free reason why no response came."""


class NoHardwareKey(HardwareKeyError):
    def __init__(self):
        super().__init__('no hardware key found')


class TouchTimeout(HardwareKeyError):
    def __init__(self):
        super().__init__('the hardware key was not touched in time')


class _Rejected(Exception):
    """The slot is not set up for challenge-response."""


def padded(challenge: bytes) -> bytes:
    """The 64 bytes sent to the key: the challenge with PKCS #7 padding."""
    if not 0 < len(challenge) <= CHALLENGE_BYTES:
        raise ValueError('invalid challenge')
    pad = CHALLENGE_BYTES - len(challenge)
    return challenge + bytes([pad]) * pad


# ----- the USB HID frame protocol ------------------------------------------------
FEATURE_SIZE = 8
DATA_SIZE = 7
RESP_PENDING = 0x40
SLOT_WRITE = 0x80
RESP_TIMEOUT_WAIT = 0x20
SEQUENCE_MASK = 0x1F
CRC_RESIDUAL = 0xF0B8


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            carry = crc & 1
            crc >>= 1
            if carry:
                crc ^= 0x8408
    return crc


def hid_hmac(transport, command: int, challenge: bytes, deadline: float,
             on_touch: Callable[[], None] | None = None) -> bytes:
    """Send one challenge over HID feature reports and read the response.

    ``transport.get()`` reads an 8-byte feature report and ``transport.set(data)``
    writes one. Raise ``_Rejected`` when the slot gives no response.
    """
    def receive():
        report = bytes(transport.get())
        if len(report) != FEATURE_SIZE:
            raise HardwareKeyError('the hardware key gave an invalid answer')
        return report

    def ready():
        for _ in range(40):
            if not receive()[DATA_SIZE] & SLOT_WRITE:
                return
            time.sleep(0.025)
        raise HardwareKeyError('the hardware key is busy')

    def reset():
        transport.set(bytes(DATA_SIZE) + b'\xff')

    payload = padded(challenge) if len(challenge) < CHALLENGE_BYTES else challenge
    frame = payload + bytes([command]) + crc16(payload).to_bytes(2, 'little') + bytes(3)
    sequence = receive()[4]
    for index in range(len(frame) // DATA_SIZE):
        packet = frame[index * DATA_SIZE:(index + 1) * DATA_SIZE]
        # Empty packets are skipped, except the first and the last.
        if index in (0, 9) or any(packet):
            ready()
            transport.set(packet + bytes([0x80 | index]))
    response, expected, touched = b'', 0, False
    while True:
        if time.monotonic() > deadline:
            reset()
            raise TouchTimeout()
        report = receive()
        status = report[DATA_SIZE]
        if status & RESP_PENDING:
            if status & SEQUENCE_MASK == expected:
                response += report[:DATA_SIZE]
                expected += 1
            elif status & SEQUENCE_MASK == 0:
                reset()
                break
        elif status == 0:
            if response:
                raise HardwareKeyError('the hardware key gave an incomplete answer')
            if touched:
                raise TouchTimeout()
            raise _Rejected()
        else:
            if status & RESP_TIMEOUT_WAIT and not touched:
                touched = True
                if on_touch is not None:
                    on_touch()
            time.sleep(0.1 if status & RESP_TIMEOUT_WAIT else 0.02)
        del report
    if len(response) < RESPONSE_BYTES + 2 or crc16(response[:RESPONSE_BYTES + 2]) != CRC_RESIDUAL:
        raise HardwareKeyError('the hardware key gave an invalid answer')
    return response[:RESPONSE_BYTES]


def _allowed(vendor: int, product: int) -> bool:
    return vendor == YUBICO_VID or (vendor, product) == ONLYKEY


def top_usage(descriptor: bytes) -> tuple[int, int] | None:
    """The usage page and usage of a HID report descriptor's first collection."""
    page = usage = None
    index = 0
    while index < len(descriptor):
        prefix = descriptor[index]
        if prefix == 0xFE:  # A long item: skip it.
            if index + 1 >= len(descriptor):
                return None
            index += 3 + descriptor[index + 1]
            continue
        size = (0, 1, 2, 4)[prefix & 3]
        value = int.from_bytes(descriptor[index + 1:index + 1 + size], 'little')
        kind, tag = (prefix >> 2) & 3, prefix >> 4
        if kind == 1 and tag == 0:
            page = value
        elif kind == 2 and tag == 0 and usage is None:
            usage = value
        elif kind == 0 and tag == 0xA:
            return (page, usage) if page is not None and usage is not None else None
        index += 1 + size
    return None


# A keyboard top-level collection: the interface that carries the protocol.
OTP_USAGE = (0x01, 0x06)


@dataclass(frozen=True)
class Device:
    transport: str
    path: str


# ----- Linux hidraw ----------------------------------------------------------------
HIDIOCSFEATURE_9 = 0xC0094806
HIDIOCGFEATURE_9 = 0xC0094807
SYSFS_HIDRAW = Path('/sys/class/hidraw')


def _linux_devices():
    try:
        entries = sorted(SYSFS_HIDRAW.iterdir())
    except OSError:
        return []
    found = []
    for entry in entries:
        try:
            fields = dict(line.split('=', 1) for line in (entry / 'device' / 'uevent').read_text().splitlines()
                          if '=' in line)
            _, vendor, product = fields['HID_ID'].split(':')
            if not _allowed(int(vendor, 16), int(product, 16)):
                continue
            if top_usage((entry / 'device' / 'report_descriptor').read_bytes()) != OTP_USAGE:
                continue
        except (OSError, KeyError, ValueError):
            continue
        found.append(Device('hidraw', '/dev/' + entry.name))
    return found


class _Hidraw:
    def __init__(self, path):
        try:
            self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        except PermissionError:
            raise HardwareKeyError('this user may not use the hardware key; allow it with a udev rule') from None

    def get(self):
        import fcntl
        buffer = bytearray(FEATURE_SIZE + 1)
        fcntl.ioctl(self.fd, HIDIOCGFEATURE_9, buffer, True)
        return bytes(buffer[1:])

    def set(self, data):
        import fcntl
        fcntl.ioctl(self.fd, HIDIOCSFEATURE_9, bytearray(b'\0' + data))

    def close(self):
        os.close(self.fd)


# ----- Windows hid.dll -------------------------------------------------------------
if sys.platform == 'win32':
    from ctypes import wintypes

    class _GUID(ctypes.Structure):
        _fields_ = [('Data1', wintypes.DWORD), ('Data2', wintypes.WORD), ('Data3', wintypes.WORD),
                    ('Data4', ctypes.c_ubyte * 8)]

    class _InterfaceData(ctypes.Structure):
        _fields_ = [('cbSize', wintypes.DWORD), ('InterfaceClassGuid', _GUID), ('Flags', wintypes.DWORD),
                    ('Reserved', ctypes.c_size_t)]

    class _Attributes(ctypes.Structure):
        _fields_ = [('Size', wintypes.ULONG), ('VendorID', wintypes.USHORT), ('ProductID', wintypes.USHORT),
                    ('VersionNumber', wintypes.USHORT)]

    class _Caps(ctypes.Structure):
        _fields_ = [('Usage', wintypes.USHORT), ('UsagePage', wintypes.USHORT),
                    ('Lengths', wintypes.USHORT * 3), ('Reserved', wintypes.USHORT * 17),
                    ('Counts', wintypes.USHORT * 10)]


def _windows_api():
    setupapi = ctypes.WinDLL('setupapi', use_last_error=True)
    hid = ctypes.WinDLL('hid', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE
    setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(_GUID), wintypes.LPCWSTR, wintypes.HWND,
                                              wintypes.DWORD]
    setupapi.SetupDiEnumDeviceInterfaces.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(_GUID),
                                                     wintypes.DWORD, ctypes.POINTER(_InterfaceData)]
    setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_InterfaceData),
                                                          ctypes.c_void_p, wintypes.DWORD,
                                                          ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
    hid.HidD_GetHidGuid.argtypes = [ctypes.POINTER(_GUID)]
    hid.HidD_GetAttributes.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Attributes)]
    hid.HidD_GetPreparsedData.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
    hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
    hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Caps)]
    hid.HidP_GetCaps.restype = ctypes.c_long
    hid.HidD_SetFeature.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.ULONG]
    hid.HidD_GetFeature.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.ULONG]
    return setupapi, hid, kernel32


_INVALID_HANDLE = ctypes.c_void_p(-1).value
_HIDP_STATUS_SUCCESS = 0x00110000


def _windows_open(kernel32, path):
    # Windows keeps keyboards for itself; feature reports work with no access rights.
    for access in (0xC0000000, 0):
        handle = kernel32.CreateFileW(path, access, 3, None, 3, 0, None)
        if handle not in (None, _INVALID_HANDLE):
            return handle
    return None


def _windows_devices():
    setupapi, hid, kernel32 = _windows_api()
    guid = _GUID()
    hid.HidD_GetHidGuid(ctypes.byref(guid))
    info = setupapi.SetupDiGetClassDevsW(ctypes.byref(guid), None, None, 0x12)  # PRESENT | DEVICEINTERFACE
    if info in (None, _INVALID_HANDLE):
        return []
    found = []
    try:
        index = 0
        while True:
            data = _InterfaceData(cbSize=ctypes.sizeof(_InterfaceData))
            if not setupapi.SetupDiEnumDeviceInterfaces(info, None, ctypes.byref(guid), index, ctypes.byref(data)):
                break
            index += 1
            size = wintypes.DWORD()
            setupapi.SetupDiGetDeviceInterfaceDetailW(info, ctypes.byref(data), None, 0, ctypes.byref(size), None)
            if not 6 <= size.value <= 4096:
                continue
            detail = ctypes.create_string_buffer(size.value)
            ctypes.c_uint32.from_buffer(detail).value = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(info, ctypes.byref(data), detail, size,
                                                             None, None):
                continue
            path = ctypes.wstring_at(ctypes.addressof(detail) + 4)
            handle = _windows_open(kernel32, path)
            if handle is None:
                continue
            try:
                attributes = _Attributes(Size=ctypes.sizeof(_Attributes))
                if not hid.HidD_GetAttributes(handle, ctypes.byref(attributes)) or not _allowed(
                        attributes.VendorID, attributes.ProductID):
                    continue
                parsed = ctypes.c_void_p()
                if not hid.HidD_GetPreparsedData(handle, ctypes.byref(parsed)):
                    continue
                try:
                    caps = _Caps()
                    if hid.HidP_GetCaps(parsed, ctypes.byref(caps)) != _HIDP_STATUS_SUCCESS:
                        continue
                finally:
                    hid.HidD_FreePreparsedData(parsed)
                if (caps.UsagePage, caps.Usage) == OTP_USAGE:
                    found.append(Device('winhid', path))
            finally:
                kernel32.CloseHandle(handle)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(info)
    return found


class _WinHid:
    def __init__(self, path):
        _, self.hid, self.kernel32 = _windows_api()
        self.handle = _windows_open(self.kernel32, path)
        if self.handle is None:
            raise HardwareKeyError('the hardware key could not be opened')

    def get(self):
        buffer = (ctypes.c_ubyte * (FEATURE_SIZE + 1))()
        if not self.hid.HidD_GetFeature(self.handle, buffer, len(buffer)):
            raise HardwareKeyError('the hardware key could not be read')
        return bytes(buffer)[1:]

    def set(self, data):
        buffer = (ctypes.c_ubyte * (FEATURE_SIZE + 1))(0, *data)
        if not self.hid.HidD_SetFeature(self.handle, buffer, len(buffer)):
            raise HardwareKeyError('the hardware key could not be written')

    def close(self):
        self.kernel32.CloseHandle(self.handle)


# ----- macOS IOKit -----------------------------------------------------------------
_REPORT_FEATURE = 2
_UTF8 = 0x08000100


def _mac_api():
    iokit = ctypes.cdll.LoadLibrary('/System/Library/Frameworks/IOKit.framework/IOKit')
    cf = ctypes.cdll.LoadLibrary('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    void = ctypes.c_void_p
    cf.CFStringCreateWithCString.restype = void
    cf.CFStringCreateWithCString.argtypes = [void, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFRelease.argtypes = [void]
    cf.CFSetGetCount.restype = ctypes.c_long
    cf.CFSetGetCount.argtypes = [void]
    cf.CFSetGetValues.argtypes = [void, ctypes.POINTER(void)]
    cf.CFNumberGetValue.restype = ctypes.c_bool
    cf.CFNumberGetValue.argtypes = [void, ctypes.c_long, void]
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFGetTypeID.argtypes = [void]
    cf.CFNumberGetTypeID.restype = ctypes.c_ulong
    iokit.IOHIDManagerCreate.restype = void
    iokit.IOHIDManagerCreate.argtypes = [void, ctypes.c_uint32]
    iokit.IOHIDManagerSetDeviceMatching.argtypes = [void, void]
    iokit.IOHIDManagerCopyDevices.restype = void
    iokit.IOHIDManagerCopyDevices.argtypes = [void]
    iokit.IOHIDDeviceGetProperty.restype = void
    iokit.IOHIDDeviceGetProperty.argtypes = [void, void]
    iokit.IOHIDDeviceOpen.restype = ctypes.c_int32
    iokit.IOHIDDeviceOpen.argtypes = [void, ctypes.c_uint32]
    iokit.IOHIDDeviceClose.argtypes = [void, ctypes.c_uint32]
    iokit.IOHIDDeviceSetReport.restype = ctypes.c_int32
    iokit.IOHIDDeviceSetReport.argtypes = [void, ctypes.c_int, ctypes.c_long, void, ctypes.c_long]
    iokit.IOHIDDeviceGetReport.restype = ctypes.c_int32
    iokit.IOHIDDeviceGetReport.argtypes = [void, ctypes.c_int, ctypes.c_long, void, ctypes.POINTER(ctypes.c_long)]
    return iokit, cf


def _mac_number(iokit, cf, device, name):
    key = cf.CFStringCreateWithCString(None, name, _UTF8)
    try:
        value = iokit.IOHIDDeviceGetProperty(device, key)
    finally:
        cf.CFRelease(key)
    if not value or cf.CFGetTypeID(value) != cf.CFNumberGetTypeID():
        return None
    number = ctypes.c_int32()
    return number.value if cf.CFNumberGetValue(value, 3, ctypes.byref(number)) else None  # kCFNumberSInt32Type


class _MacSession:
    """One IOHIDManager and its matching devices; keeps device references alive."""

    def __init__(self):
        self.iokit, self.cf = _mac_api()
        self.manager = self.iokit.IOHIDManagerCreate(None, 0)
        self.iokit.IOHIDManagerSetDeviceMatching(self.manager, None)
        self.devices = []
        found = self.iokit.IOHIDManagerCopyDevices(self.manager)
        if not found:
            return
        try:
            count = self.cf.CFSetGetCount(found)
            values = (ctypes.c_void_p * count)()
            self.cf.CFSetGetValues(found, values)
            for device in values:
                number = lambda name: _mac_number(self.iokit, self.cf, device, name)  # noqa: E731
                if (_allowed(number(b'VendorID') or 0, number(b'ProductID') or 0)
                        and (number(b'PrimaryUsagePage'), number(b'PrimaryUsage')) == OTP_USAGE):
                    self.devices.append(device)
        finally:
            self.cf.CFRelease(found)

    def close(self):
        self.cf.CFRelease(self.manager)


class _MacHid:
    def __init__(self, session, device):
        self.iokit, self.device = session.iokit, device
        if self.iokit.IOHIDDeviceOpen(device, 0) != 0:
            raise HardwareKeyError('this user may not use the hardware key; allow Input Monitoring for akdbx')

    def get(self):
        buffer = (ctypes.c_ubyte * FEATURE_SIZE)()
        length = ctypes.c_long(FEATURE_SIZE)
        if self.iokit.IOHIDDeviceGetReport(self.device, _REPORT_FEATURE, 0, buffer, ctypes.byref(length)) != 0:
            raise HardwareKeyError('the hardware key could not be read')
        return bytes(buffer)[:length.value]

    def set(self, data):
        buffer = (ctypes.c_ubyte * FEATURE_SIZE)(*data)
        if self.iokit.IOHIDDeviceSetReport(self.device, _REPORT_FEATURE, 0, buffer, FEATURE_SIZE) != 0:
            raise HardwareKeyError('the hardware key could not be written')

    def close(self):
        self.iokit.IOHIDDeviceClose(self.device, 0)


# ----- PC/SC (smart card interface and NFC readers) ------------------------------
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOLS = 3  # T=0 | T=1
SCARD_LEAVE_CARD = 0


def _pcsc_api():
    if sys.platform == 'win32':
        lib = ctypes.WinDLL('winscard')
        context, dword, long_ = ctypes.c_size_t, ctypes.c_uint32, ctypes.c_long
        names = dict(list='SCardListReadersA', connect='SCardConnectA')
    elif sys.platform == 'darwin':
        lib = ctypes.cdll.LoadLibrary('/System/Library/Frameworks/PCSC.framework/PCSC')
        context, dword, long_ = ctypes.c_int32, ctypes.c_uint32, ctypes.c_int32
        names = dict(list='SCardListReaders', connect='SCardConnect')
    else:
        from ctypes.util import find_library
        name = find_library('pcsclite') or 'libpcsclite.so.1'
        lib = ctypes.cdll.LoadLibrary(name)
        context, dword, long_ = ctypes.c_long, ctypes.c_ulong, ctypes.c_long
        names = dict(list='SCardListReaders', connect='SCardConnect')

    class IoRequest(ctypes.Structure):
        _fields_ = [('dwProtocol', dword), ('cbPciLength', dword)]

    api = dict(lib=lib, context=context, dword=dword, IoRequest=IoRequest)
    lib.SCardEstablishContext.restype = long_
    lib.SCardEstablishContext.argtypes = [dword, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(context)]
    lib.SCardReleaseContext.restype = long_
    lib.SCardReleaseContext.argtypes = [context]
    api['list'] = getattr(lib, names['list'])
    api['list'].restype = long_
    api['list'].argtypes = [context, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(dword)]
    api['connect'] = getattr(lib, names['connect'])
    api['connect'].restype = long_
    api['connect'].argtypes = [context, ctypes.c_char_p, dword, dword, ctypes.POINTER(context),
                               ctypes.POINTER(dword)]
    lib.SCardTransmit.restype = long_
    lib.SCardTransmit.argtypes = [context, ctypes.POINTER(IoRequest), ctypes.c_char_p, dword, ctypes.c_void_p,
                                  ctypes.c_char_p, ctypes.POINTER(dword)]
    lib.SCardDisconnect.restype = long_
    lib.SCardDisconnect.argtypes = [context, dword]
    return api


class _Pcsc:
    def __init__(self):
        self.api = _pcsc_api()
        self.context = self.api['context']()
        if self.api['lib'].SCardEstablishContext(2, None, None, ctypes.byref(self.context)) != 0:  # SYSTEM
            raise OSError('no PC/SC service')

    def readers(self):
        size = self.api['dword']()
        if self.api['list'](self.context, None, None, ctypes.byref(size)) != 0 or not 0 < size.value <= 65536:
            return []
        buffer = ctypes.create_string_buffer(size.value)
        if self.api['list'](self.context, None, buffer, ctypes.byref(size)) != 0:
            return []
        return [name for name in buffer.raw[:size.value].split(b'\0') if name]

    def connect(self, reader):
        card, protocol = self.api['context'](), self.api['dword']()
        if self.api['connect'](self.context, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOLS,
                               ctypes.byref(card), ctypes.byref(protocol)) != 0:
            return None
        return card, protocol.value

    def _exchange(self, card, apdu):
        handle, protocol = card
        request = self.api['IoRequest'](protocol, ctypes.sizeof(self.api['IoRequest']))
        response = ctypes.create_string_buffer(258)
        length = self.api['dword'](len(response))
        if self.api['lib'].SCardTransmit(handle, ctypes.byref(request), apdu, len(apdu), None, response,
                                         ctypes.byref(length)) != 0 or not 2 <= length.value <= len(response):
            raise HardwareKeyError('the hardware key could not be read')
        data = response.raw[:length.value]
        return data[:-2], int.from_bytes(data[-2:], 'big')

    def transmit(self, card, apdu):
        return with_continuation(lambda command: self._exchange(card, command), apdu)

    def disconnect(self, card):
        self.api['lib'].SCardDisconnect(card[0], SCARD_LEAVE_CARD)

    def close(self):
        self.api['lib'].SCardReleaseContext(self.context)


def with_continuation(exchange, apdu):
    """Send ``apdu``; while the card answers 61xx, fetch the rest with GET RESPONSE."""
    data, status = exchange(apdu)
    for _ in range(8):
        if status >> 8 != 0x61:
            break
        more, status = exchange(bytes([0x00, 0xC0, 0x00, 0x00, status & 0xFF]))
        data += more
    return data, status


def card_hmac(transmit, command: int, challenge: bytes) -> bytes:
    """Select a challenge-response applet and send the challenge as an APDU."""
    for applet in APPLETS:
        _, status = transmit(bytes([0x00, 0xA4, 0x04, 0x00, len(applet)]) + applet)
        if status != 0x9000:
            continue
        data, status = transmit(bytes([0x00, 0x01, command, 0x00, CHALLENGE_BYTES]) + padded(challenge))
        if status == 0x9000 and len(data) == RESPONSE_BYTES:
            return data
        raise _Rejected()
    raise _Rejected()


# ----- discovery and the public API ------------------------------------------------
def _hid_sessions():
    """Yield (open, close) pairs for each matching HID interface on this computer."""
    if sys.platform == 'win32':
        for device in _windows_devices():
            yield lambda path=device.path: _WinHid(path)
    elif sys.platform == 'darwin':
        session = _MacSession()
        try:
            for device in session.devices:
                yield lambda device=device: _MacHid(session, device)
        finally:
            session.close()
    else:
        for device in _linux_devices():
            yield lambda path=device.path: _Hidraw(path)


def _safe(generator):
    try:
        yield from generator
    except HardwareKeyError:
        raise
    except Exception:
        return


def selects_applet(transmit) -> bool:
    """True when the card has one of the challenge-response applets (no challenge is sent)."""
    for applet in APPLETS:
        if transmit(bytes([0x00, 0xA4, 0x04, 0x00, len(applet)]) + applet)[1] == 0x9000:
            return True
    return False


def available() -> bool:
    """True when this computer has a hardware key that may answer a challenge.

    It looks at USB descriptors, and at PC/SC cards that have a
    challenge-response applet; it never sends a challenge, so no key flashes.
    """
    for _ in _safe(_hid_sessions()):
        return True
    try:
        pcsc = _Pcsc()
    except Exception:
        return False
    try:
        for reader in pcsc.readers():
            card = pcsc.connect(reader)
            if card is None:
                continue
            try:
                if selects_applet(lambda apdu: pcsc.transmit(card, apdu)):
                    return True
            finally:
                pcsc.disconnect(card)
    except Exception:
        return False
    finally:
        pcsc.close()
    return False


def responses(challenge: bytes, *, timeout: float = TOUCH_TIMEOUT,
              on_touch: Callable[[], None] | None = None) -> list[bytes]:
    """Every response that this computer's hardware keys give to ``challenge``.

    Each key is asked on slot 2, then slot 1; a slot that is not set up for
    challenge-response is skipped. Raise NoHardwareKey when no key is found,
    and HardwareKeyError when keys are found but none answers.
    """
    deadline = time.monotonic() + timeout
    found, answers, failure = False, [], None
    with _LOCK:
        for opener in _safe(_hid_sessions()):
            found = True
            try:
                transport = opener()
            except HardwareKeyError as exc:
                failure = exc
                continue
            try:
                for _, command in SLOT_COMMANDS:
                    try:
                        answers.append(hid_hmac(transport, command, challenge, deadline, on_touch))
                    except _Rejected:
                        continue
                    except HardwareKeyError as exc:
                        failure = exc
                        break
            except OSError:
                failure = HardwareKeyError('the hardware key could not be read')
            finally:
                transport.close()
        # A USB key that answered over HID is also a smart card reader: never ask it twice.
        try:
            pcsc = None if answers or isinstance(failure, TouchTimeout) else _Pcsc()
        except Exception:
            pcsc = None
        if pcsc is not None:
            try:
                for reader in pcsc.readers():
                    if time.monotonic() > deadline:
                        failure = failure or TouchTimeout()
                        break
                    card = pcsc.connect(reader)
                    if card is None:
                        continue
                    found = True
                    try:
                        for _, command in SLOT_COMMANDS:
                            try:
                                answers.append(card_hmac(lambda apdu: pcsc.transmit(card, apdu), command, challenge))
                            except _Rejected:
                                continue
                            except HardwareKeyError as exc:
                                failure = exc
                                break
                    finally:
                        pcsc.disconnect(card)
            finally:
                pcsc.close()
    unique = list(dict.fromkeys(answers))
    if unique:
        return unique
    if not found:
        raise NoHardwareKey()
    raise failure or HardwareKeyError('the hardware key has no challenge-response slot set up')
