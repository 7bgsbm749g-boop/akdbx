"""Windows checks for the Chromium DOM routes: profile, endpoint file and peer.

The Linux routes prove that the debugging endpoint belongs to the broker's
user with file modes and `/proc/self/net/tcp`. Windows uses the same three
facts through DACLs, checked handles and the kernel TCP owner table. Nothing
here sends a byte to the browser, and no caller supplies the profile by RPC.
"""
import ctypes
from ctypes import wintypes as W
import os
from pathlib import Path
import re
import socket
import time

from . import windows_security as security

MAX_TCP_TABLE_BYTES = 64 * 1024 * 1024
PEER_SCAN_TIMEOUT = 1.0
TCP_TABLE_OWNER_PID_CONNECTIONS = 4
MIB_TCP_STATE_ESTAB = 5
ERROR_INSUFFICIENT_BUFFER = 122


class BrowserEndpointError(Exception):
    """Internal only: callers return their own fixed, secret-free refusal."""


class _Row(ctypes.Structure):
    _fields_ = [('state', W.DWORD), ('local_address', W.DWORD), ('local_port', W.DWORD),
                ('remote_address', W.DWORD), ('remote_port', W.DWORD), ('pid', W.DWORD)]


def endpoint(profile):
    """Return the local DevTools URL of one private, operator-selected profile.

    Every ancestor must resist replacement by another user. The profile itself
    and its port file must grant no access outside this user, SYSTEM and
    administrators. Junctions, symlinks, hard links, UNC paths and alternate
    data streams are refused by the shared handle checks.
    """
    if profile is None:
        raise BrowserEndpointError()
    try:
        path = Path(os.path.abspath(os.fspath(profile)))
        with security.trusted_directory(path.parent):
            with security.checked_handle(path, directory=True):
                data, _ = security.read_private(path / 'DevToolsActivePort', limit=256)
        match = re.fullmatch(r'([1-9][0-9]{0,4})\n(/devtools/browser/[a-zA-Z0-9-]{1,80})\n?',
                             data.decode('ascii'))
    except Exception:
        raise BrowserEndpointError() from None
    if match is None or int(match[1]) > 65535:
        raise BrowserEndpointError()
    return 'ws://127.0.0.1:' + match[1] + match[2]


def tcp_rows():
    """Read the kernel's IPv4 connection table with a bounded size and time."""
    api = ctypes.WinDLL('iphlpapi', use_last_error=True)
    function = api.GetExtendedTcpTable
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(W.DWORD), W.BOOL, W.ULONG, ctypes.c_int, W.ULONG]
    function.restype = W.DWORD
    deadline = time.monotonic() + PEER_SCAN_TIMEOUT
    size = W.DWORD(0)
    # The table can grow between the size query and the read: retry, bounded.
    for _ in range(8):
        if size.value > MAX_TCP_TABLE_BYTES or time.monotonic() >= deadline:
            raise BrowserEndpointError()
        buffer = ctypes.create_string_buffer(max(size.value, ctypes.sizeof(W.DWORD)))
        size = W.DWORD(len(buffer))
        status = function(buffer, ctypes.byref(size), False, socket.AF_INET,
                          TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
        if status == 0:
            count = W.DWORD.from_buffer(buffer).value
            if ctypes.sizeof(W.DWORD) + count * ctypes.sizeof(_Row) > len(buffer):
                raise BrowserEndpointError()
            return (_Row * count).from_buffer(buffer, ctypes.sizeof(W.DWORD))
        if status != ERROR_INSUFFICIENT_BUFFER:
            raise BrowserEndpointError()
    raise BrowserEndpointError()


def server_pid(server_port, client_port, rows=None):
    """Find the one process that owns the server side of this exact connection."""
    loopback = int.from_bytes(socket.inet_aton('127.0.0.1'), 'little')
    # The table stores each port in network byte order in the low 16 bits.
    server, client = socket.htons(server_port), socket.htons(client_port)
    owners = [row.pid for row in (tcp_rows() if rows is None else rows)
              if row.state == MIB_TCP_STATE_ESTAB
              and row.local_address == loopback and row.remote_address == loopback
              and row.local_port & 0xffff == server and row.remote_port & 0xffff == client]
    if len(owners) != 1 or owners[0] <= 4:
        raise BrowserEndpointError()
    return owners[0]


def verify_peer(connection):
    """Require this user and desktop session on the server side of a socket.

    A listener check before connect permits port reuse between the check and
    the connection. The reciprocal ESTABLISHED row identifies this actual
    peer. The held process handle prevents PID reuse while the same row is
    read a second time. Keep this socket for the WebSocket handshake; never
    reconnect. Missing, ambiguous, oversized or slow tables refuse before any
    byte is sent.
    """
    try:
        local, remote = connection.getsockname(), connection.getpeername()
        if connection.family != socket.AF_INET or local[0] != '127.0.0.1' or remote[0] != '127.0.0.1':
            raise BrowserEndpointError()
        pid = server_pid(remote[1], local[1])
        handle, _ = security.verify_process(pid)
        try:
            if server_pid(remote[1], local[1]) != pid:
                raise BrowserEndpointError()
        finally:
            handle.Close()
    except Exception:
        raise BrowserEndpointError() from None
