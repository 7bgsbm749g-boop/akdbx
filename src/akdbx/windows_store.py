"""Encrypted-only Windows saves with ACLs, locks and durable recovery receipts."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import secrets

import pywintypes
import win32con
import win32file

from .persistence import SaveError, open_encrypted
from . import windows_security as security


def digest(data):
    return hashlib.sha256(data).hexdigest()


class WindowsVaultStore:
    def __init__(self, database):
        # Do not resolve junctions/symlinks before validating them.
        self.path = Path(os.path.abspath(Path(database).expanduser()))
        self.expected = None
        self.verified_encrypted = None
        self.verified_capsules = None
        self.recovery_required = False
        self.keyfile_path = None
        self.keyfile_digest = None

    @property
    def writable_path(self):
        """Metadata-only readiness; safe to use at the keyboard boundary."""
        if self.expected is None or self.recovery_required:
            return False
        try:
            with security.trusted_directory(self.path.parent):
                # Opening a directory with add-file rights checks readiness
                # without creating a file or changing the vault.
                with security.checked_handle(self.path.parent, directory=True, private=False,
                        access=win32con.FILE_ADD_FILE | win32con.FILE_TRAVERSE | win32con.READ_CONTROL):
                    pass
                with security.checked_handle(self.path) as handle:
                    info = win32file.GetFileInformationByHandle(handle)
                    if info[0] & win32con.FILE_ATTRIBUTE_READONLY or (*info[:2], *info[3:]) != self.expected[:-1]:
                        return False
                # Every required artifact must fit both NTFS component and the
                # supported Win32 path budget before a site password is changed.
                longest = '.' + self.path.name + '.akdbx-commit-' + '0' * 32 + '.json'
                if (len(longest.encode('utf-16-le')) // 2 > 255
                        or len(str(self.path.parent / longest).encode('utf-16-le')) // 2 >= 260):
                    return False
                lock_path = self.path.parent / ('.' + self.path.name + '.akdbx.lock')
                try:
                    with security.checked_handle(lock_path, access=win32con.GENERIC_READ
                                                  | win32con.GENERIC_WRITE | win32con.READ_CONTROL):
                        pass
                except pywintypes.error as exc:
                    if exc.winerror != 2:
                        raise
                if self.keyfile_path is not None:
                    with security.checked_handle(self.keyfile_path) as handle:
                        info = win32file.GetFileInformationByHandle(handle)
                        if (*info[:2], *info[3:]) != self.keyfile_expected:
                            return False
            return True
        except (OSError, SaveError, pywintypes.error):
            return False

    def check_write_inputs(self):
        try:
            self._check_keyfile()
            with security.trusted_directory(self.path.parent):
                try:
                    self._check_recovery()
                except Exception:
                    self.recovery_required = True
                    raise
            return self.writable_path
        except (OSError, SaveError, pywintypes.error, ValueError):
            return False

    def _read(self):
        encrypted, identity = security.read_private(self.path)
        # Last-access time may change during a read. All other metadata and the
        # encrypted digest participate in the external-change check.
        snapshot = (*identity[:2], *identity[3:], digest(encrypted))
        return encrypted, snapshot

    def _check_keyfile(self):
        if self.keyfile_path is not None:
            key, info = security.read_private(self.keyfile_path, limit=1024 * 1024)
            if digest(key) != self.keyfile_digest:
                raise SaveError('key file changed on disk; restart and unlock')
            self.keyfile_expected = (*info[:2], *info[3:])

    def _check_recovery(self):
        prefix = '.' + self.path.name + '.akdbx-'
        for index, path in enumerate(self.path.parent.iterdir()):
            if index >= 10000:
                raise SaveError('Windows recovery directory exceeds the scan budget')
            if path.name.startswith(prefix + 'commit-') and path.name.endswith('.json'):
                data, _ = security.read_private(path, limit=16384)
                receipt = json.loads(data)
                if (not isinstance(receipt, dict) or receipt.get('policy') != 'windows-save-v1'
                        or receipt.get('state') != 'saved'
                        or any(not isinstance(receipt.get(key), str) or len(receipt[key]) != 64
                               or any(c not in '0123456789abcdef' for c in receipt[key])
                               for key in ('previous_sha256', 'candidate_sha256'))):
                    self.recovery_required = True
            elif path.name.startswith(prefix + 'merge-'):
                # Never hide a transaction made by the Linux backend.
                self.recovery_required = True
        # An admission binding means recovery may live elsewhere. Windows does
        # not implement this protocol and must not silently ignore its locator.
        if (self.path.parent / (prefix + 'admission.json')).exists():
            self.recovery_required = True

    def open(self, password, keyfile=None):
        with security.trusted_directory(self.path.parent):
            encrypted, snapshot = self._read()
            key_material = None
            if keyfile is not None:
                self.keyfile_path = Path(os.path.abspath(Path(keyfile).expanduser()))
                key, _ = security.read_private(self.keyfile_path, limit=1024 * 1024)
                self.keyfile_digest = digest(key)
                key_material = io.BytesIO(key)
            vault = open_encrypted(encrypted, password, key_material)
            from .versions import archives
            self.verified_capsules = archives(vault)
            self._check_keyfile()
            if self._read()[1] != snapshot:
                raise SaveError('vault changed on disk; restart and unlock')
            self._check_recovery()
            self.expected, self.verified_encrypted = snapshot, encrypted
            vault._akdbx_store = self
            return vault

    @staticmethod
    def _replace(source, destination):
        win32file.MoveFileEx(str(source), str(destination),
                             win32con.MOVEFILE_REPLACE_EXISTING | win32con.MOVEFILE_WRITE_THROUGH)

    def commit(self, vault, mutate, *, verify_candidate=None):
        if self.recovery_required:
            raise SaveError('save outcome uncertain; restart and unlock')
        from .versions import archives, verify
        retained = archives(vault)
        staging = receipt_temp = None
        attempted = False
        with security.trusted_directory(self.path.parent):
            if not self.check_write_inputs():
                raise SaveError('private writes unavailable; check vault/key changes and path safety')
            lock_path = self.path.parent / ('.' + self.path.name + '.akdbx.lock')
            with security.checked_handle(lock_path, access=win32con.GENERIC_READ | win32con.GENERIC_WRITE
                                         | win32con.READ_CONTROL, creation=win32con.OPEN_ALWAYS) as lock:
                overlapped = pywintypes.OVERLAPPED()
                try:
                    win32file.LockFileEx(lock, win32con.LOCKFILE_EXCLUSIVE_LOCK
                                         | win32con.LOCKFILE_FAIL_IMMEDIATELY, 1, 0, overlapped)
                except pywintypes.error:
                    raise SaveError('vault write busy; update not saved') from None
                try:
                    self._check_recovery()
                    if self.recovery_required:
                        raise SaveError('incomplete save receipt; recovery required; update not saved')
                    self._check_keyfile()
                    previous, snapshot = self._read()
                    if snapshot != self.expected:
                        raise SaveError('vault changed on disk; restart and unlock')
                    candidate = copy.deepcopy(vault)
                    mutate(candidate)
                    buffer = io.BytesIO()
                    candidate.save(buffer)
                    encrypted = buffer.getvalue()
                    if len(encrypted) > 128 * 1024 * 1024:
                        raise SaveError('encrypted vault exceeds the Windows input budget; update not saved')
                    verified = open_encrypted(encrypted, candidate.password, candidate.keyfile)
                    verify(verified, retained)
                    if verify_candidate is not None:
                        verify_candidate(verified)
                    identifier = secrets.token_hex(16)
                    prefix = '.' + self.path.name + '.akdbx-'
                    backup = self.path.parent / (prefix + 'backup-' + identifier)
                    staging = self.path.parent / (prefix + 'write-' + identifier)
                    receipt_path = self.path.parent / (prefix + 'commit-' + identifier + '.json')
                    receipt = {'state': 'prepared', 'previous_sha256': digest(previous),
                               'candidate_sha256': digest(encrypted), 'policy': 'windows-save-v1'}
                    security.write_new(backup, previous)
                    security.write_new(staging, encrypted)
                    # A receipt survives a crash around replacement and blocks
                    # further use after restart until the transaction is checked.
                    security.write_new(receipt_path, json.dumps(receipt).encode())
                    self._check_keyfile()
                    if self._read()[1] != snapshot:
                        raise SaveError('vault changed on disk; restart and unlock')
                    attempted = True
                    self._replace(staging, self.path)
                    staging = None
                    persisted, next_snapshot = self._read()
                    if persisted != encrypted:
                        raise SaveError('save outcome uncertain; restart and unlock')
                    receipt_temp = self.path.parent / (prefix + 'receipt-' + identifier)
                    security.write_new(receipt_temp, json.dumps({**receipt, 'state': 'saved'}).encode())
                    self._replace(receipt_temp, receipt_path)
                    receipt_temp = None
                    self.expected, self.verified_encrypted = next_snapshot, encrypted
                    self.verified_capsules = retained
                    verified._akdbx_store = self
                    return verified
                except Exception:
                    if attempted:
                        self.recovery_required = True
                        raise SaveError('save outcome uncertain; restart and unlock') from None
                    raise
                finally:
                    for path in (staging, receipt_temp):
                        if path is not None:
                            try:
                                path.unlink()
                            except OSError:
                                pass
                    win32file.UnlockFileEx(lock, 1, 0, overlapped)
