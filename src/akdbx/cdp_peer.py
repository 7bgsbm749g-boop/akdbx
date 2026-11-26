"""Authenticate the reciprocal ESTABLISHED loopback connection before writing any bytes."""
import ctypes
from ctypes import wintypes as W
import os
import socket
import struct
import sys
import time

MAX_TCP_TABLE_BYTES = 64 * 1024 * 1024
PEER_SCAN_TIMEOUT = 1.0
TCP_TABLE_OWNER_PID_CONNECTIONS = 4
MIB_TCP_STATE_ESTAB = 5
ERROR_INSUFFICIENT_BUFFER = 122


class PeerError(Exception):
    """Missing, ambiguous, foreign or over-budget kernel proof."""


def _linux_peer(local, remote, deadline):
    def address(value):
        return f'{int.from_bytes(socket.inet_aton(value[0]), sys.byteorder):08X}:{value[1]:04X}'.encode('ascii')
    server, client = address(remote), address(local)
    found = False
    consumed = 0
    with open('/proc/self/net/tcp', 'rb') as table:
        while True:
            line = table.readline(1025)
            consumed += len(line)
            if len(line) > 1024 or consumed > MAX_TCP_TABLE_BYTES or time.monotonic() >= deadline:
                raise PeerError()
            if not line:
                break
            fields = line.split()
            if len(fields) >= 4 and fields[1:4] == [server, client, b'01']:
                if found or len(fields) < 8 or int(fields[7]) != os.getuid():
                    raise PeerError()
                found = True
    if not found:
        raise PeerError()


class _Row(ctypes.Structure):
    _fields_ = [('state', W.DWORD), ('local_address', W.DWORD), ('local_port', W.DWORD),
                ('remote_address', W.DWORD), ('remote_port', W.DWORD), ('pid', W.DWORD)]


def tcp_rows(deadline):
    """Read the kernel's IPv4 connection table with a bounded size and time."""
    api = ctypes.WinDLL('iphlpapi', use_last_error=True)
    function = api.GetExtendedTcpTable
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(W.DWORD), W.BOOL, W.ULONG, ctypes.c_int, W.ULONG]
    function.restype = W.DWORD
    size = W.DWORD(0)
    # The table can grow between the size query and the read: retry, bounded.
    for _ in range(8):
        if size.value > MAX_TCP_TABLE_BYTES or time.monotonic() >= deadline:
            raise PeerError()
        buffer = ctypes.create_string_buffer(max(size.value, ctypes.sizeof(W.DWORD)))
        size = W.DWORD(len(buffer))
        status = function(buffer, ctypes.byref(size), False, socket.AF_INET,
                          TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
        if status == 0:
            count = W.DWORD.from_buffer(buffer).value
            if ctypes.sizeof(W.DWORD) + count * ctypes.sizeof(_Row) > len(buffer):
                raise PeerError()
            return (_Row * count).from_buffer(buffer, ctypes.sizeof(W.DWORD))
        if status != ERROR_INSUFFICIENT_BUFFER:
            raise PeerError()
    raise PeerError()


def server_pid(server_port, client_port, rows, deadline):
    """Find the one process that owns the server side of this exact connection."""
    loopback = int.from_bytes(socket.inet_aton('127.0.0.1'), 'little')
    # The table stores each port in network byte order in the low 16 bits.
    server, client = socket.htons(server_port), socket.htons(client_port)
    owner = None
    for index, row in enumerate(rows):
        if index % 1024 == 0 and time.monotonic() >= deadline:
            raise PeerError()
        if (row.state == MIB_TCP_STATE_ESTAB and row.local_address == loopback and row.remote_address == loopback
                and row.local_port & 0xffff == server and row.remote_port & 0xffff == client):
            if owner is not None or row.pid <= 4:
                raise PeerError()
            owner = row.pid
    if owner is None:
        raise PeerError()
    return owner


def _windows_peer(local, remote, deadline):
    from . import windows_security
    pid = server_pid(remote[1], local[1], tcp_rows(deadline), deadline)
    handle, _ = windows_security.verify_process(pid)
    try:
        windows_security.require_same_integrity(handle)
        # Hold the process object across the second table read to exclude PID reuse.
        if server_pid(remote[1], local[1], tcp_rows(deadline), deadline) != pid:
            raise PeerError()
    finally:
        handle.Close()


def _darwin_peer(local, remote, deadline):
    # XNU tcp_pcblist64 takes the socket lock while copying both the tuple and
    # xsocket64.so_uid (the socket credential). No PID lookup or accept is needed.
    sysctl = ctypes.CDLL(None, use_errno=True).sysctlbyname
    sysctl.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                       ctypes.c_void_p, ctypes.c_size_t]
    sysctl.restype = ctypes.c_int
    name = b'net.inet.tcp.pcblist64'
    size = ctypes.c_size_t()
    if sysctl(name, None, ctypes.byref(size), None, 0) or not 48 <= size.value <= MAX_TCP_TABLE_BYTES:
        raise PeerError()
    data = ctypes.create_string_buffer(size.value)
    if (time.monotonic() >= deadline or sysctl(name, data, ctypes.byref(size), None, 0)
            or not 48 <= size.value <= len(data)):
        raise PeerError()
    _darwin_rows(memoryview(data).cast('B')[:size.value], local, remote, deadline)


def _darwin_rows(data, local, remote, deadline):
    # XNU bsd/netinet/{in_pcb,tcp_var}.h and bsd/sys/socketvar.h, pack(4).
    # This frozen sysctl ABI brackets fixed xtcpcb64 records with two xinpgen
    # records. Refuse a different layout before interpreting any owner field.
    generation_size, record_size = 24, 472
    end = len(data) - generation_size
    if (end < generation_size or (end - generation_size) % record_size
            or struct.unpack_from('=I', data)[0] != generation_size
            or struct.unpack_from('=I', data, end)[0] != generation_size):
        raise PeerError()
    expected_ports = struct.pack('!HH', local[1], remote[1])  # foreign, local
    loopback = socket.inet_aton('127.0.0.1')
    matches = 0
    for offset in range(generation_size, end, record_size):
        row = data[offset:offset + record_size]
        if time.monotonic() >= deadline or struct.unpack_from('=I', row)[0] != record_size:
            raise PeerError()
        if (row[20:24] != expected_ports or not row[96] & 1  # INP_IPV4
                or row[112:116] != loopback or row[128:132] != loopback
                or struct.unpack_from('=i', row, 292)[0] != 4):  # TCPS_ESTABLISHED
            continue
        # xsocket64 starts at byte 148. Verify its length, type, protocol and
        # family before consuming so_uid, the final member of that structure.
        if (struct.unpack_from('=I', row, 148)[0] != 108
                or struct.unpack_from('=h', row, 160)[0] != socket.SOCK_STREAM
                or struct.unpack_from('=ii', row, 176) != (socket.IPPROTO_TCP, socket.AF_INET)
                or struct.unpack_from('=I', row, 252)[0] != os.getuid()):
            raise PeerError()
        matches += 1
    if matches != 1:
        raise PeerError()


def verify_peer(connection):
    """Check this open socket. The caller retains it for the handshake."""
    local, remote = connection.getsockname(), connection.getpeername()
    if connection.family != socket.AF_INET or local[0] != '127.0.0.1' or remote[0] != '127.0.0.1':
        raise PeerError()
    deadline = time.monotonic() + PEER_SCAN_TIMEOUT
    if sys.platform == 'win32':
        _windows_peer(local, remote, deadline)
    elif sys.platform == 'darwin':
        _darwin_peer(local, remote, deadline)
    elif sys.platform.startswith('linux'):
        _linux_peer(local, remote, deadline)
    else:
        raise PeerError()
    if time.monotonic() >= deadline:
        raise PeerError()
