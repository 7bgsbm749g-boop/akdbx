from __future__ import annotations

import errno
import fcntl
import os
import socket
import stat
from pathlib import Path


SOCKET_PROBE_TIMEOUT = 0.2


def _validate_trusted_ancestor(info: os.stat_result, path: Path, owner_uid: int) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"runtime ancestor is not a directory: {path}")
    if info.st_uid not in {0, owner_uid}:
        raise RuntimeError(f"runtime ancestor has an untrusted owner: {path}")
    if info.st_mode & 0o022:
        # Root-owned sticky directories such as /tmp prevent another UID from
        # renaming a child it does not own. Other writable ancestors can be
        # used to replace the entire private runtime directory.
        if info.st_uid != 0 or not (info.st_mode & stat.S_ISVTX):
            raise RuntimeError(f"runtime ancestor is replaceable by another user: {path}")


def prepare_private_runtime_directory(
    directory: Path, *, owner_uid: int | None = None,
) -> tuple[Path, int]:
    """Create/verify a private leaf below trusted, non-symlinked ancestry.

    The returned descriptor anchors later lock, stat, and unlink operations to
    the verified leaf even if a pathname is concurrently changed.
    """
    return _open_private_runtime_directory(
        directory, owner_uid=owner_uid, create=True,
    )


def open_private_runtime_directory(
    directory: Path, *, owner_uid: int | None = None,
) -> tuple[Path, int]:
    """Open an existing private runtime leaf using the server's trust policy."""
    return _open_private_runtime_directory(
        directory, owner_uid=owner_uid, create=False,
    )


def _open_private_runtime_directory(
    directory: Path, *, owner_uid: int | None, create: bool,
) -> tuple[Path, int]:
    owner_uid = os.getuid() if owner_uid is None else owner_uid
    directory = Path(os.path.abspath(os.fspath(directory)))
    if directory == Path(directory.anchor):
        raise RuntimeError("runtime directory must not be the filesystem root")

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    current_path = Path(directory.anchor)
    current_fd = os.open(directory.anchor, flags)
    try:
        _validate_trusted_ancestor(os.fstat(current_fd), current_path, owner_uid)
        parts = directory.parts[1:]
        for part in parts[:-1]:
            try:
                child_fd = os.open(part, flags, dir_fd=current_fd)
            except OSError as exc:
                raise RuntimeError(
                    f"unsafe or missing runtime ancestor (including symlinked path): "
                    f"{current_path / part}"
                ) from exc
            os.close(current_fd)
            current_fd = child_fd
            current_path /= part
            _validate_trusted_ancestor(os.fstat(current_fd), current_path, owner_uid)

        leaf = parts[-1]
        if create:
            try:
                os.mkdir(leaf, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise RuntimeError("could not create private runtime directory") from exc
        try:
            leaf_fd = os.open(leaf, flags, dir_fd=current_fd)
        except OSError as exc:
            raise RuntimeError(
                "runtime path must be a real, non-symlinked directory"
            ) from exc
        info = os.fstat(leaf_fd)
        if info.st_uid != owner_uid:
            os.close(leaf_fd)
            raise RuntimeError("runtime directory is not owned by the broker user")
        if stat.S_IMODE(info.st_mode) != 0o700:
            os.close(leaf_fd)
            raise RuntimeError("runtime directory must have mode 0700")
        return directory, leaf_fd
    finally:
        os.close(current_fd)


def anchored_socket_path(directory_fd: int, socket_name: str) -> str:
    """Name a socket relative to an already verified directory descriptor."""
    if not socket_name or Path(socket_name).name != socket_name:
        raise ValueError("socket name must be a single path component")
    return f"/proc/self/fd/{directory_fd}/{socket_name}"


def acquire_lifecycle_lock(directory_fd: int, socket_name: str) -> int:
    lock_name = f".{socket_name}.lock"
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_name, flags, 0o600, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RuntimeError("unsafe socket lifecycle lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("socket is already managed by another process") from exc
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def remove_stale_socket(socket_path: Path, directory_fd: int, socket_name: str) -> None:
    """Refuse live/uncertain endpoints and unlink only an unchanged stale socket."""
    try:
        before = os.stat(socket_name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid():
        raise RuntimeError(f"refusing to replace unsafe socket path: {socket_path}")

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(SOCKET_PROBE_TIMEOUT)
    try:
        probe.connect(anchored_socket_path(directory_fd, socket_name))
    except OSError as exc:
        if exc.errno not in {errno.ECONNREFUSED, errno.ENOENT}:
            raise RuntimeError("cannot prove existing socket is stale") from exc
    else:
        raise RuntimeError("socket is already serving a live endpoint")
    finally:
        probe.close()

    try:
        after = os.stat(socket_name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid)
    if identity(after) != identity(before):
        raise RuntimeError("socket changed during stale cleanup")
    os.unlink(socket_name, dir_fd=directory_fd)


def unlink_socket_if_same(directory_fd: int, socket_name: str, identity: tuple[int, int] | None) -> None:
    try:
        info = os.stat(socket_name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (info.st_dev, info.st_ino) == identity:
        os.unlink(socket_name, dir_fd=directory_fd)
