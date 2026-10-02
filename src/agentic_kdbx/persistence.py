"""Encrypted-only persistence. No plaintext staging files or exception disclosure."""
from __future__ import annotations

import copy
import fcntl
import hashlib
import io
import os
import secrets
import stat
import time
from pathlib import Path


class SaveError(Exception):
    pass


class VaultStore:
    def __init__(self, database: Path):
        self.path = Path(database).expanduser().resolve(strict=True)
        self.expected = None
        self.recovery_required = False
        self.writable_path = False
        self.keyfile_path = None
        self.keyfile_digest = None

    def _directory(self, *, writing=True):
        # Anchor each component rather than racing lstat against a full-path open.
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        current = os.open(self.path.anchor, flags)
        try:
            for part in self.path.parent.parts[1:]:
                child = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = child
                info = os.fstat(current)
                if writing and (info.st_uid not in {0, os.getuid()} or (
                    info.st_mode & 0o022
                    and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
                )):
                    raise SaveError("unsafe vault directory; use trusted ancestry")
            result, current = current, None
            return result
        finally:
            if current is not None:
                os.close(current)

    def _read(self, directory, *, writing=True):
        fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or (writing and (before.st_uid != os.getuid() or before.st_nlink != 1)):
                raise SaveError("unsafe vault file")
            with os.fdopen(os.dup(fd), "rb") as stream:
                data = stream.read()
            after = os.fstat(fd)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(before) != identity(after):
                raise SaveError("vault changed on disk; restart and unlock")
            return data, (*identity(after), hashlib.sha256(data).digest())
        finally:
            os.close(fd)

    def open(self, password, keyfile=None):
        from pykeepass import PyKeePass
        directory = self._directory(writing=False)
        try:
            encrypted, snapshot = self._read(directory, writing=False)
            key_material = None
            if keyfile is not None:
                self.keyfile_path = Path(keyfile).expanduser().resolve(strict=True)
                key_bytes = self.keyfile_path.read_bytes()
                self.keyfile_digest = hashlib.sha256(key_bytes).digest()
                key_material = io.BytesIO(key_bytes)
            vault = PyKeePass(io.BytesIO(encrypted), password=password, keyfile=key_material)
            self._check_keyfile()
            if self._read(directory, writing=False)[1] != snapshot:
                raise SaveError("vault changed on disk; restart and unlock")
            self.expected = snapshot
            try:
                write_directory = self._directory()
                try:
                    self._read(write_directory)
                    self.writable_path = True
                finally:
                    os.close(write_directory)
            except (OSError, SaveError):
                pass
            vault._akdbx_store = self
            return vault
        finally:
            os.close(directory)

    def _check_keyfile(self):
        if self.keyfile_path is not None and hashlib.sha256(self.keyfile_path.read_bytes()).digest() != self.keyfile_digest:
            raise SaveError("key file changed on disk; restart and unlock")

    def commit(self, vault, mutate):
        """Return a reopened, verified candidate only after durable replacement."""
        if self.recovery_required:
            raise SaveError("save outcome uncertain; restart and unlock")
        directory = self._directory()
        lock = None
        staging = None
        replaced = False
        try:
            lock = os.open('.' + self.path.name + '.akdbx.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise SaveError("unsafe vault write lock")
            deadline = time.monotonic() + 4.0
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise SaveError("vault write busy; update not saved") from None
                    time.sleep(0.02)
            self._check_keyfile()
            previous, snapshot = self._read(directory)
            if snapshot != self.expected:
                raise SaveError("vault changed on disk; restart and unlock")
            # Work on a copy: failures must leave the active vault untouched.
            candidate = copy.deepcopy(vault)
            mutate(candidate)
            buffer = io.BytesIO()
            candidate.save(buffer)
            encrypted = buffer.getvalue()
            from pykeepass import PyKeePass
            verified = PyKeePass(io.BytesIO(encrypted), password=candidate.password, keyfile=candidate.keyfile)
            verified._akdbx_store = self
            # Every file below contains only an encrypted KDBX, never a password.
            backup = '.' + self.path.name + '.akdbx-backup-' + secrets.token_hex(12)
            self._write_file(directory, backup, previous)
            os.fsync(directory)
            staging = '.' + self.path.name + '.akdbx-write-' + secrets.token_hex(12)
            self._write_file(directory, staging, encrypted)
            if self._read(directory)[1] != snapshot:
                raise SaveError("vault changed on disk; restart and unlock")
            self._check_keyfile()
            parent = os.stat(self.path.parent, follow_symlinks=False)
            opened = os.fstat(directory)
            if (parent.st_dev, parent.st_ino) != (opened.st_dev, opened.st_ino):
                raise SaveError("vault directory changed; restart and unlock")
            os.replace(staging, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
            replaced = True
            staging = None
            os.fsync(directory)
            persisted, self.expected = self._read(directory)
            if persisted != encrypted:
                raise SaveError("save outcome uncertain; restart and unlock")
            return verified
        except Exception:
            if replaced:
                self.recovery_required = True
                raise SaveError("save outcome uncertain; restart and unlock") from None
            raise
        finally:
            if staging is not None:
                try:
                    os.unlink(staging, dir_fd=directory)
                except OSError:
                    pass
            if lock is not None:
                os.close(lock)
            os.close(directory)

    @staticmethod
    def _write_file(directory, name, data):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
