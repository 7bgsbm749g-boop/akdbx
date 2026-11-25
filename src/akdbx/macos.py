"""macOS primitives for a local, browser-extension-only broker.

No window input, browser debugging, remote broker transport, or system changes.
The same private Unix socket and encrypted vault persistence contract applies.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import socket


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    """Read this connected peer's effective UID/GID and PID from Darwin."""
    libc = ctypes.CDLL(None, use_errno=True)
    getpeereid = libc.getpeereid
    getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
    getpeereid.restype = ctypes.c_int
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    if getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise OSError(ctypes.get_errno(), 'could not verify Unix peer credentials')
    # XNU sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=2. No process-table lookup or PID reuse race.
    pid = connection.getsockopt(0, 2)
    if pid <= 0:
        raise PermissionError('Unix peer PID unavailable')
    return pid, uid.value, gid.value


def socket_path(directory_fd: int, name: str) -> str:
    """Resolve an open directory with F_GETPATH and recheck its trusted ancestors.

    Darwin has no /proc descriptor paths. Its pathname remains protected by
    the same root/owner-only ancestor rules; same-user compromise is outside
    the documented broker boundary. The connected peer is independently checked.
    """
    from .runtime import open_private_runtime_directory
    import fcntl
    raw = fcntl.fcntl(directory_fd, 50, b'\0' * 1024)  # F_GETPATH, MAXPATHLEN
    path = Path(os.fsdecode(raw.split(b'\0', 1)[0]))
    if not path.is_absolute():
        raise PermissionError('runtime descriptor has no absolute path')
    _, check = open_private_runtime_directory(path, owner_uid=os.getuid())
    try:
        before, after = os.fstat(directory_fd), os.fstat(check)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise PermissionError('runtime directory changed')
    finally:
        os.close(check)
    result = os.fspath(path / name)
    if len(os.fsencode(result)) >= 104:
        raise ValueError('macOS Unix socket path must be shorter than 104 bytes; choose a shorter --socket path')
    return result


class NoWindowDelivery:
    """macOS browser fills use DOM pins; never fall back to keyboard input."""
    def capture(self, *args, **kwargs):
        from .target import TargetError
        raise TargetError('native window fills are not supported on macOS')

    def deliver(self, *args, **kwargs):
        from .target import DeliveryError
        raise DeliveryError(False)
