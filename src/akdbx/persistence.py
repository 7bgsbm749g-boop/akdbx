"""Encrypted-only persistence. No plaintext staging files or exception disclosure."""
from __future__ import annotations

import copy
import base64
import fcntl
import hashlib
import io
import json
import logging
import os
import secrets
import stat
import time
import threading
from contextlib import contextmanager
from pathlib import Path


class SaveError(Exception):
    pass


WRITE_TOKEN_BYTES = 12


def _file_identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


# Both shipped import names swap handlers on the same dependency logger.
if __name__ == 'akdbx.persistence':
    _OPEN_LOCK = threading.RLock()
else:
    from akdbx.persistence import _OPEN_LOCK


def open_encrypted(encrypted, password, keyfile=None):
    """Contain dependency diagnostics and reject silently unreadable fields."""
    from pykeepass import PyKeePass
    from pykeepass.kdbx_parsing.common import UnprotectedStream

    def strict_decode(adapter, tree, context, path):
        """Reject protected text that lxml cannot retain byte-for-byte."""
        cipher = adapter.get_cipher(adapter.protected_stream_key(context))
        for node in tree.xpath(adapter.protected_xpath):
            if node.text is not None:
                try:
                    node.text = cipher.decrypt(base64.b64decode(node.text)).decode('utf-8')
                except ValueError:
                    raise SaveError('protected record fields could not be verified; merge refused') from None
        return tree

    class Diagnostic(logging.Handler):
        failed = False

        def emit(self, record):
            if record.levelno >= logging.ERROR:
                self.failed = True
    # PyKeePass reports an inner protected-stream decode failure through this
    # logger and otherwise returns a partly decoded vault. Never archive that
    # as a verified logical version, and never forward dependency diagnostics.
    with _OPEN_LOCK:
        logger = logging.getLogger('pykeepass.kdbx_parsing.common')
        previous = logger.handlers, logger.propagate, logger.disabled, logger.level
        previous_decoder = UnprotectedStream._decode
        diagnostic = Diagnostic()
        logger.handlers, logger.propagate, logger.disabled = [diagnostic], False, False
        logger.setLevel(logging.ERROR)
        try:
            # PyKeePass otherwise strips XML-forbidden protected characters.
            # The shared import lock also serializes this temporary decoder.
            UnprotectedStream._decode = strict_decode
            vault = PyKeePass(io.BytesIO(encrypted), password=password, keyfile=keyfile)
            if diagnostic.failed or any(node.get('Protected') not in {'True', 'False'}
                                        for node in vault.tree.xpath('//Value[@Protected]')):
                raise SaveError('protected record fields could not be verified; merge refused')
            return vault
        finally:
            UnprotectedStream._decode = previous_decoder
            logger.handlers, logger.propagate, logger.disabled, level = previous
            logger.setLevel(level)
            diagnostic.close()


class VaultStore:
    def __init__(self, database: Path, *, strict_path=False):
        self.path = (Path(os.path.abspath(Path(database).expanduser())) if strict_path
                     else Path(database).expanduser().resolve(strict=True))
        self.expected = None
        self.verified_encrypted = None
        self.verified_capsules = None
        self.recovery_required = False
        self.keyfile_path = None
        self.keyfile_digest = None
        self.keyfile_expected = None

    @property
    def writable_path(self):
        return self._writable_path()

    @property
    def merge_writable_path(self):
        return self._writable_path(merging=True)

    def _writable_path(self, *, merging=False):
        """Check metadata and bound storage without vault/key reads, receipt scans or locking."""
        if self.expected is None:
            return False
        directory = target = lock = keyfile = external = None
        try:
            directory = self._directory()
            self._check_write_names(directory)
            if merging:
                self._check_merge_names(directory)
            target = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
            target_info = self._file_info(target)
            # Reconciliation must remain available for an externally edited target.
            if not merging and _file_identity(target_info) != self.expected[:5]:
                return False
            if not os.access('.', os.W_OK | os.X_OK, dir_fd=directory, effective_ids=True):
                return False
            if self.keyfile_path is not None:
                keyfile = self._open_keyfile()
                if not merging and _file_identity(os.fstat(keyfile)) != self.keyfile_expected:
                    return False
            lock = self._open_write_lock(directory, create=False)
            external = self.snapshot_directory(directory)
            if merging and external is not None:
                self._check_merge_names(external, replacement=False)
            return True
        except (OSError, SaveError):
            return False
        finally:
            for fd in (external, lock, keyfile, target, directory):
                if fd is not None:
                    os.close(fd)

    def check_write_inputs(self):
        """Revalidate changed key metadata before an ordinary write is prepared."""
        if self.keyfile_path is not None:
            keyfile = self._open_keyfile()
            try:
                changed = _file_identity(os.fstat(keyfile)) != self.keyfile_expected
            finally:
                os.close(keyfile)
            if changed:
                self._check_keyfile()
        return self.writable_path

    def _write_name(self, kind, token):
        return '.' + self.path.name + '.akdbx-' + kind + '-' + token

    def _check_write_names(self, directory):
        """Check required ordinary-save components against the anchored directory limit."""
        maximum = os.fpathconf(directory, 'PC_NAME_MAX')
        if maximum >= 0 and any(len(os.fsencode(self._write_name(kind, '0' * (2 * WRITE_TOKEN_BYTES)))) > maximum
                                for kind in ('backup', 'write')):
            raise SaveError('vault filename is too long for required write artifacts')

    def _check_merge_names(self, directory, *, replacement=True):
        """Check the longest merge component in its anchored destination."""
        name = self._write_name('merge', '0' * 32) + ('.replace' if replacement else '')
        maximum = os.fpathconf(directory, 'PC_NAME_MAX')
        if maximum >= 0 and len(os.fsencode(name)) > maximum:
            raise SaveError('vault filename is too long for required merge artifacts')

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

    def _file_info(self, fd, *, writing=True):
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (writing and (info.st_uid != os.getuid() or info.st_nlink != 1)):
            raise SaveError('unsafe vault file')
        return info

    def _read(self, directory, *, writing=True):
        fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = self._file_info(fd, writing=writing)
            with os.fdopen(os.dup(fd), "rb") as stream:
                data = stream.read()
            after = os.fstat(fd)
            if _file_identity(before) != _file_identity(after):
                raise SaveError("vault changed on disk; restart and unlock")
            return data, (*_file_identity(after), hashlib.sha256(data).digest())
        finally:
            os.close(fd)

    def open(self, password, keyfile=None):
        directory = self._directory(writing=False)
        try:
            encrypted, snapshot = self._read(directory, writing=False)
            key_material = None
            if keyfile is not None:
                self.keyfile_path = Path(keyfile).expanduser().resolve(strict=True)
                key_bytes = self._read_keyfile()
                self.keyfile_digest = hashlib.sha256(key_bytes).digest()
                key_material = io.BytesIO(key_bytes)
            vault = open_encrypted(encrypted, password, key_material)
            from .versions import archives
            self.verified_capsules = archives(vault)
            self._check_keyfile()
            if self._read(directory, writing=False)[1] != snapshot:
                raise SaveError("vault changed on disk; restart and unlock")
            self.expected = snapshot
            self.verified_encrypted = encrypted
            vault._akdbx_store = self
            self._check_merge_recovery(directory)
            return vault
        finally:
            os.close(directory)

    def _open_keyfile(self):
        """Refuse nonregular key artifacts without waiting for a FIFO or following a replaced leaf."""
        fd = os.open(self.keyfile_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SaveError('key file must be a regular file')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _read_keyfile(self, *, verify=False):
        """Read initial material, or verify its pinned length/digest with bounded memory."""
        with os.fdopen(self._open_keyfile(), 'rb') as stream:
            before = os.fstat(stream.fileno())
            if verify:
                if self.keyfile_expected is None or before.st_size != self.keyfile_expected[2]:
                    raise SaveError("key file changed on disk; restart and unlock")
                digest = hashlib.sha256()
                remaining = before.st_size
                while remaining:
                    chunk = stream.read(min(64 * 1024, remaining))
                    if not chunk:
                        raise SaveError("key file changed on disk; restart and unlock")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if stream.read(1) or digest.digest() != self.keyfile_digest:
                    raise SaveError("key file changed on disk; restart and unlock")
                data = None
            else:
                data = stream.read()
            after = os.fstat(stream.fileno())
            if _file_identity(before) != _file_identity(after):
                raise SaveError("key file changed on disk; restart and unlock")
            self.keyfile_expected = _file_identity(after)
            return data

    def _check_keyfile(self):
        if self.keyfile_path is not None:
            self._read_keyfile(verify=True)

    def _check_merge_recovery(self, directory):
        """An interrupted native merge must stay blocked across broker restarts."""
        self._scan_merge_recovery(directory)
        external = self.snapshot_directory(directory)
        if external is not None:
            try:
                self._scan_merge_recovery(external)
            finally:
                os.close(external)

    def snapshot_directory(self, directory, requested=None):
        """Persistently bind admission recovery to one private external directory.

        The small nonsecret locator stays beside the target, so omitting a CLI
        option after restart cannot hide an interrupted external transaction.
        No encrypted originals are placed beside the canonical vault.
        """
        marker = '.' + self.path.name + '.akdbx-admission.json'
        try:
            fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            fd = None
        bound = None
        if fd is not None:
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 4096):
                    raise SaveError('unsafe admission snapshot locator; recovery required')
                try:
                    value = json.loads(stream.read(4096))
                    bound = value['snapshot_directory']
                    if value['policy'] != 'snapshot-admission-v1' or not isinstance(bound, str):
                        raise ValueError
                except Exception:
                    raise SaveError('invalid admission snapshot locator; recovery required') from None
        if requested is None and bound is None:
            return None
        if requested is not None and (not isinstance(requested, str) or bound is not None and requested != bound):
            raise SaveError('admission snapshot directory differs from durable binding; refused')
        path = Path(bound if bound is not None else requested)
        if (not path.is_absolute() or str(path) != str(bound if bound is not None else requested)
                or '..' in path.parts or path.is_relative_to(self.path.parent)):
            raise SaveError('admission snapshots require an absolute external directory')
        # Use the same anchored ancestry checks as vault writes. The sentinel is
        # never opened and the final directory itself must be private.
        external = VaultStore(path / 'sentinel', strict_path=True)._directory()
        try:
            info = os.fstat(external)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise SaveError('admission snapshot directory must be owned and mode 0700')
            if bound is None:
                self._write_file(directory, marker, json.dumps({'snapshot_directory': str(path),
                                                               'policy': 'snapshot-admission-v1'}).encode())
                os.fsync(directory)
            result, external = external, None
            return result
        finally:
            if external is not None:
                os.close(external)

    @staticmethod
    def read_merge_receipt(bundle, operation_id):
        """Read a bounded receipt only from its private, correctly identified bundle."""
        info = os.fstat(bundle)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SaveError('unsafe merge receipt directory')
        fd = os.open('receipt.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=bundle)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
                raise SaveError('unsafe merge receipt')
            try:
                data = stream.read(16385)
                if len(data) > 16384:
                    raise ValueError
                receipt = json.loads(data)
                if (len(operation_id) != 32 or any(c not in '0123456789abcdef' for c in operation_id)
                        or not isinstance(receipt, dict) or receipt.get('operation_id') != operation_id):
                    raise ValueError
            except (ValueError, TypeError):
                raise SaveError('invalid merge receipt') from None
        return receipt

    def _scan_merge_recovery(self, directory):
        prefix = '.' + self.path.name + '.akdbx-merge-'
        for name in os.listdir(directory):
            if not name.startswith(prefix) or name.endswith('.replace'):
                continue
            bundle = None
            try:
                bundle = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                receipt = self.read_merge_receipt(bundle, name[len(prefix):])
                if receipt.get('state') not in {'saved', 'unchanged', 'checked', 'failed'}:
                    self.recovery_required = True
            except Exception:
                self.recovery_required = True
            finally:
                if bundle is not None:
                    os.close(bundle)

    def _open_write_lock(self, directory, *, create):
        """Open the same safe lock inode for readiness, saves and merges."""
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            fd = os.open('.' + self.path.name + '.akdbx.lock',
                         flags | (os.O_CREAT if create else 0), 0o600, dir_fd=directory)
        except FileNotFoundError:
            if not create:
                return None
            raise
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise SaveError('unsafe vault write lock')
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextmanager
    def advisory_lock(self, directory):
        """The same nonblocking disk lock for password writes and merges."""
        fd = self._open_write_lock(directory, create=True)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SaveError('vault write busy; merge not started') from None
            yield
        finally:
            os.close(fd)

    def check_current(self, directory, snapshot):
        if self._read(directory)[1] != snapshot:
            raise SaveError('vault changed on disk; restart and unlock')
        parent = os.stat(self.path.parent, follow_symlinks=False)
        opened = os.fstat(directory)
        if (parent.st_dev, parent.st_ino) != (opened.st_dev, opened.st_ino):
            raise SaveError('vault directory changed; restart and unlock')

    def commit(self, vault, mutate, *, verify_candidate=None):
        """Return a reopened, verified candidate only after durable replacement."""
        if self.recovery_required:
            raise SaveError("save outcome uncertain; restart and unlock")
        from .versions import archives, verify
        retained_versions = archives(vault)
        directory = self._directory()
        lock = None
        staging = None
        replaced = False
        replacement_attempted = False
        try:
            self._check_write_names(directory)
            lock = self._open_write_lock(directory, create=True)
            deadline = time.monotonic() + 4.0
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise SaveError("vault write busy; update not saved") from None
                    time.sleep(0.02)
            try:
                self._check_merge_recovery(directory)
            except Exception:
                self.recovery_required = True
                raise SaveError('merge recovery state could not be verified; recovery required') from None
            if self.recovery_required:
                raise SaveError('incomplete merge receipt; recovery required; update not saved')
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
            verified = open_encrypted(encrypted, candidate.password, candidate.keyfile)
            verify(verified, retained_versions)
            if verify_candidate is not None:
                verify_candidate(verified)
            verified._akdbx_store = self
            # Every file below contains only an encrypted KDBX, never a password.
            backup = self._write_name('backup', secrets.token_hex(WRITE_TOKEN_BYTES))
            self._write_file(directory, backup, previous)
            os.fsync(directory)
            staging = self._write_name('write', secrets.token_hex(WRITE_TOKEN_BYTES))
            self._write_file(directory, staging, encrypted)
            if self._read(directory)[1] != snapshot:
                raise SaveError("vault changed on disk; restart and unlock")
            self._check_keyfile()
            parent = os.stat(self.path.parent, follow_symlinks=False)
            opened = os.fstat(directory)
            if (parent.st_dev, parent.st_ino) != (opened.st_dev, opened.st_ino):
                raise SaveError("vault directory changed; restart and unlock")
            replacement_attempted = True
            os.replace(staging, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
            replaced = True
            staging = None
            os.fsync(directory)
            persisted, self.expected = self._read(directory)
            if persisted != encrypted:
                raise SaveError("save outcome uncertain; restart and unlock")
            self.verified_encrypted = encrypted
            self.verified_capsules = retained_versions
            return verified
        except Exception:
            if replacement_attempted and not replaced:
                # A rename can take effect even when its caller gets an error.
                # Only a proven unchanged original is a clean failed save.
                try:
                    self.check_current(directory, snapshot)
                except Exception:
                    replaced = True
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
