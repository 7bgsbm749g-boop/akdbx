"""macOS ACL, private Unix socket and window-delivery policy."""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import socket


def require_private_acl(fd: int) -> None:
    """Refuse extended allow ACEs, including inherited grants, on an open object.

    Deny-only ACLs (such as the normal home-directory delete protection) are
    accepted. This deliberately supports a narrower, auditable private-file
    contract instead of trying to reproduce Darwin's group/ACL evaluator.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    signatures = {
        'acl_get_fd_np': (ctypes.c_void_p, [ctypes.c_int, ctypes.c_int]),
        'acl_get_entry': (ctypes.c_int, [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]),
        'acl_get_tag_type': (ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]),
        'acl_free': (ctypes.c_int, [ctypes.c_void_p]),
    }
    for name, (result, arguments) in signatures.items():
        function = getattr(libc, name)
        function.restype, function.argtypes = result, arguments
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(fd, 0x100)  # ACL_TYPE_EXTENDED
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:  # This open object has no extended ACL.
            return
        raise PermissionError('cannot verify macOS ACL')
    try:
        entry, tag = ctypes.c_void_p(), ctypes.c_int()
        # Darwin permits at most 169 ACEs. Unknown types and iteration errors refuse.
        for index in range(170):
            ctypes.set_errno(0)
            if libc.acl_get_entry(acl, 0 if index == 0 else -1, ctypes.byref(entry)) != 0:
                if ctypes.get_errno() == errno.EINVAL:
                    return
                raise PermissionError('cannot inspect macOS ACL')
            if libc.acl_get_tag_type(entry, ctypes.byref(tag)) != 0 or tag.value != 2:  # ACL_EXTENDED_DENY
                raise PermissionError('extended allow ACLs are not supported on private macOS paths')
        raise PermissionError('macOS ACL exceeds the supported limit')
    finally:
        libc.acl_free(acl)


def prepare_runtime(path: Path, *, create_ancestors=False) -> None:
    from .runtime import prepare_private_runtime_directory
    _, fd = prepare_private_runtime_directory(path.parent, create_ancestors=create_ancestors)
    try:
        socket_path(fd, path.name)  # Preflight the actual Darwin path limit before opening listeners.
    finally:
        os.close(fd)


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


def directory_path(directory_fd: int) -> Path:
    """Resolve an open descriptor with Darwin F_GETPATH."""
    import fcntl
    raw = fcntl.fcntl(directory_fd, 50, bytes(1024))  # F_GETPATH, MAXPATHLEN
    path = Path(os.fsdecode(raw.split(bytes(1), 1)[0]))
    if not path.is_absolute():
        raise PermissionError('directory descriptor has no absolute path')
    return path


def socket_path(directory_fd: int, name: str) -> str:
    """Resolve an open directory with F_GETPATH and recheck its trusted ancestors.

    Darwin has no /proc descriptor paths. Its pathname remains protected by
    the same root/owner-only ancestor rules; same-user compromise is outside
    the documented broker boundary. The connected peer is independently checked.
    """
    from .runtime import open_private_runtime_directory
    path = directory_path(directory_fd)
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
