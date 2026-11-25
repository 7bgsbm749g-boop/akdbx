"""Encrypted-only Windows saves with ACLs, locks and durable recovery receipts."""
import copy
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import secrets

import pywintypes
import win32con
import win32file
import ntsecuritycon

from .persistence import SaveError, open_encrypted, serialize_encrypted
from . import windows_security as security

MOVEFILE_WRITE_THROUGH = 0x8
ADMISSION_POLICY = 'snapshot-admission-v1'
FINAL_MERGE_STATES = frozenset({'saved', 'unchanged', 'checked', 'failed'})


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_identity(info):
    """Volume and file index: one value for every name of the same file."""
    return info[4], info[8], info[9]


def read_merge_receipt(bundle, operation_id):
    """Read a bounded receipt only from its private, correctly identified bundle."""
    try:
        with security.checked_handle(bundle, directory=True):
            data, _ = security.read_private(Path(bundle) / 'receipt.json', limit=16384)
    except pywintypes.error as exc:
        if exc.winerror in {2, 3}:
            raise FileNotFoundError from None
        raise SaveError('unsafe merge receipt') from None
    except (PermissionError, ValueError):
        raise SaveError('unsafe merge receipt') from None
    try:
        receipt = json.loads(data)
        if (len(operation_id) != 32 or any(c not in '0123456789abcdef' for c in operation_id)
                or not isinstance(receipt, dict) or receipt.get('operation_id') != operation_id):
            raise ValueError
    except (ValueError, TypeError):
        raise SaveError('invalid merge receipt') from None
    return receipt


def fold_name(name):
    """Match Win32 filenames by simple per-character uppercase, as NTFS does.

    Full case mappings that change length (such as German sharp s) are left
    unchanged, because the NTFS upcase table maps one UTF-16 unit to one unit.
    """
    return ''.join(upper if len(upper := char.upper()) == 1 else char for char in name)


def long_name(path):
    """Spell an existing path with its on-disk long names.

    NTFS opens a file through its 8.3 short name too, but lock and recovery
    artifact names derive from the vault filename. GetLongPathName expands
    short components without resolving junctions or symlinks, so the reparse
    point checks still see the caller's path components.
    """
    try:
        import win32api
        return Path(win32api.GetLongPathName(str(path)))
    except Exception:  # A missing vault fails later, at its checked open.
        return path


class WindowsVaultStore:
    def __init__(self, database):
        # Do not resolve junctions/symlinks before validating them.
        self.path = long_name(Path(os.path.abspath(Path(database).expanduser())))
        self.expected = None
        self.verified_encrypted = None
        self.verified_capsules = None
        self.recovery_required = False
        self.keyfile_path = None
        self.keyfile_digest = None

    def _write_name(self, kind, token):
        return '.' + self.path.name + '.akdbx-' + kind + '-' + token

    @property
    def writable_path(self):
        """Metadata-only readiness; safe to use at the keyboard boundary."""
        return self._writable_path()

    @property
    def merge_writable_path(self):
        """Readiness for a merge, which may reconcile an externally edited target."""
        return self._writable_path(merging=True)

    def _writable_path(self, *, merging=False):
        if self.expected is None or self.recovery_required:
            return False
        try:
            with security.trusted_directory(self.path.parent):
                # Opening a directory with add-file rights checks readiness
                # without creating a file or changing the vault.
                with security.checked_handle(self.path.parent, directory=True, private=False,
                        access=ntsecuritycon.FILE_ADD_FILE | ntsecuritycon.FILE_TRAVERSE | win32con.READ_CONTROL):
                    pass
                with security.checked_handle(self.path) as handle:
                    info = win32file.GetFileInformationByHandle(handle)
                    if info[0] & win32con.FILE_ATTRIBUTE_READONLY or (
                            not merging and (*info[:2], *info[3:]) != self.expected[:-1]):
                        return False
                # Every required artifact must fit both NTFS component and the
                # supported Win32 path budget before a site password is changed.
                longest = '.' + self.path.name + '.akdbx-commit-' + '0' * 32 + '.json'
                if (len(longest.encode('utf-16-le')) // 2 > 255
                        or len(str(self.path.parent / longest).encode('utf-16-le')) // 2 >= 260):
                    return False
                if merging and not self.merge_names_fit(self.path.parent):
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
                        if not merging and (*info[:2], *info[3:]) != self.keyfile_expected:
                            return False
                if merging:
                    external = self.snapshot_directory()
                    if external is not None and not self.merge_names_fit(external, replacement=False):
                        return False
            return True
        except (OSError, SaveError, pywintypes.error, ValueError):
            return False

    def check_location(self, keyfile=None):
        """`akdbx setup`: the broker's path, ACL and size checks through handles.

        It reads no vault or key-file byte. It raises when the broker could
        not open the vault or key file, and returns why saves would be
        refused, or None when they would be allowed.
        """
        with security.trusted_directory(self.path.parent):
            with security.checked_handle(self.path) as handle:
                info = win32file.GetFileInformationByHandle(handle)
        if info[5] * 2**32 + info[6] > 128 * 1024 * 1024:
            raise ValueError('the vault is larger than 128 MiB')
        if keyfile is not None:
            key = long_name(Path(os.path.abspath(Path(keyfile).expanduser())))
            with security.trusted_directory(key.parent):
                with security.checked_handle(key) as handle:
                    key_info = win32file.GetFileInformationByHandle(handle)
            if key_info[5] * 2**32 + key_info[6] > 1024 * 1024:
                raise ValueError('the key file is larger than 1 MiB')
        if info[0] & win32con.FILE_ATTRIBUTE_READONLY:
            return 'the vault file is read-only'
        try:
            with security.trusted_directory(self.path.parent):
                with security.checked_handle(self.path.parent, directory=True, private=False,
                        access=ntsecuritycon.FILE_ADD_FILE | ntsecuritycon.FILE_TRAVERSE | win32con.READ_CONTROL):
                    pass
        except (OSError, pywintypes.error):
            return 'the vault folder does not let this user add the save files'
        longest = '.' + self.path.name + '.akdbx-commit-' + '0' * 32 + '.json'
        if (len(longest.encode('utf-16-le')) // 2 > 255
                or len(str(self.path.parent / longest).encode('utf-16-le')) // 2 >= 260
                or not self.merge_names_fit(self.path.parent)):
            return 'the vault path is too long for the save files'
        return None

    def merge_names_fit(self, directory, *, replacement=True):
        """Check the longest merge artifact against the NTFS and Win32 budgets."""
        bundle = self._write_name('merge', '0' * 32)
        names = [str(Path(directory) / bundle / 'candidate-final.kdbx')]
        if replacement:
            names.append(str(Path(directory) / (bundle + '.replace')))
        return (len((bundle + '.replace').encode('utf-16-le')) // 2 <= 255
                and all(len(name.encode('utf-16-le')) // 2 < 260 for name in names))

    def check_write_inputs(self):
        """Scan recovery only while holding the same disk lock as a save."""
        try:
            self._check_keyfile()
            with security.trusted_directory(self.path.parent):
                with self._advisory_lock():
                    try:
                        self._check_recovery()
                    except Exception:
                        self.recovery_required = True
                        raise
            return self.writable_path
        except (OSError, SaveError, pywintypes.error, ValueError):
            return False

    @contextmanager
    def _advisory_lock(self):
        """Exclude other Windows save/recovery operations without waiting."""
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
                yield
            finally:
                win32file.UnlockFileEx(lock, 1, 0, overlapped)

    def check_current(self, snapshot):
        if self._read()[1] != snapshot:
            raise SaveError('vault changed on disk; restart and unlock')

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
        """Scan the vault folder and any bound admission snapshot folder."""
        self._scan_recovery(self.path.parent)
        try:
            external = self.snapshot_directory()
        except Exception:
            # An unreadable or foreign locator can hide an interrupted
            # transaction. Block use; never treat it as a wrong password.
            self.recovery_required = True
            return
        if external is not None:
            try:
                self._scan_recovery(external)
            except SaveError:
                raise
            except Exception:
                self.recovery_required = True

    def snapshot_directory(self, requested=None):
        """Persistently bind admission recovery to one private external folder.

        The small nonsecret locator stays beside the target, so omitting a CLI
        option after restart cannot hide an interrupted external transaction.
        No encrypted originals are placed beside the canonical vault.
        """
        marker = self.path.parent / ('.' + self.path.name + '.akdbx-admission.json')
        bound = None
        try:
            raw = security.read_private_optional(marker, limit=4096)
        except Exception:
            raise SaveError('unsafe admission snapshot locator; recovery required') from None
        if raw is not None:
            try:
                value = json.loads(raw)
                bound = value['snapshot_directory']
                if value['policy'] != ADMISSION_POLICY or not isinstance(bound, str):
                    raise ValueError
            except Exception:
                raise SaveError('invalid admission snapshot locator; recovery required') from None
        if requested is None and bound is None:
            return None
        if requested is not None and (not isinstance(requested, str) or bound is not None and requested != bound):
            raise SaveError('admission snapshot directory differs from durable binding; refused')
        text = bound if bound is not None else requested
        path = Path(text)
        if (not path.is_absolute() or not path.drive or path.drive.startswith('\\\\') or str(path) != text
                # Windows path comparison ignores case, as the filesystem does.
                or '..' in path.parts or path == self.path.parent or self.path.parent in path.parents):
            raise SaveError('admission snapshots require an absolute external directory')
        # The same ancestry checks as vault writes; the folder itself is private.
        try:
            with security.trusted_directory(path.parent):
                with security.checked_handle(path, directory=True):
                    pass
        except (OSError, pywintypes.error):
            raise SaveError('admission snapshot directory must be private to this user') from None
        if bound is None:
            security.write_new(marker, json.dumps({'snapshot_directory': str(path),
                                                   'policy': ADMISSION_POLICY}).encode())
        return path

    def _scan_recovery(self, directory):
        """Bound recovery artifact reads without counting unrelated files."""
        # Windows filenames are case-insensitive: Vault.kdbx and vault.kdbx open
        # the same file, so their recovery artifacts must match either spelling.
        prefix = fold_name('.' + self.path.name + '.akdbx-')
        matched = 0
        with os.scandir(directory) as entries:
            for entry in entries:
                name = fold_name(entry.name)
                if not name.startswith(prefix):
                    continue
                matched += 1
                if matched > 10000:
                    raise SaveError('Windows recovery directory exceeds the scan budget')
                path = Path(directory) / entry.name
                if name.startswith(prefix + 'COMMIT-') and name.endswith('.JSON'):
                    try:
                        data, _ = security.read_private(path, limit=16384)
                        receipt = json.loads(data)
                    except ValueError:
                        self.recovery_required = True
                        continue
                    if (not isinstance(receipt, dict) or receipt.get('policy') != 'windows-save-v1'
                            or receipt.get('state') != 'saved'
                            or any(not isinstance(receipt.get(key), str) or len(receipt[key]) != 64
                                   or any(c not in '0123456789abcdef' for c in receipt[key])
                                   for key in ('previous_sha256', 'candidate_sha256'))):
                        self.recovery_required = True
                elif name.startswith(prefix + 'MERGE-'):
                    if name.endswith('.REPLACE'):
                        continue  # A staged encrypted copy; its bundle decides.
                    # An interrupted merge stays blocked across restarts. A
                    # bundle this backend cannot verify blocks use too.
                    try:
                        receipt = read_merge_receipt(path, entry.name[len(prefix) + len('merge-'):].lower())
                        if receipt.get('state') not in FINAL_MERGE_STATES:
                            self.recovery_required = True
                    except Exception:
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
            # A live prepared receipt is not failed recovery. Coordinate the
            # final disk checks/scan with saves before adopting unlocked state.
            with self._advisory_lock():
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
                             win32con.MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)

    def commit(self, vault, mutate, *, verify_candidate=None):
        if self.recovery_required:
            raise SaveError('save outcome uncertain; restart and unlock')
        from .versions import archives, verify
        retained = archives(vault)
        staging = receipt_temp = receipt_path = None
        receipt_owned = False
        attempted = False
        with security.trusted_directory(self.path.parent):
            if not self.check_write_inputs():
                raise SaveError('private writes unavailable; check vault/key changes and path safety')
            with self._advisory_lock():
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
                    encrypted = serialize_encrypted(candidate)
                    if len(encrypted) > 128 * 1024 * 1024:
                        raise SaveError('encrypted vault exceeds the Windows input budget; update not saved')
                    verified = open_encrypted(encrypted, candidate.password, candidate.keyfile)
                    verify(verified, retained)
                    if verify_candidate is not None:
                        verify_candidate(verified)
                    identifier = secrets.token_hex(16)
                    prefix = '.' + self.path.name + '.akdbx-'
                    backup = self.path.parent / (prefix + 'backup-' + identifier)
                    staging_path = self.path.parent / (prefix + 'write-' + identifier)
                    receipt_path = self.path.parent / (prefix + 'commit-' + identifier + '.json')
                    receipt = {'state': 'prepared', 'previous_sha256': digest(previous),
                               'candidate_sha256': digest(encrypted), 'policy': 'windows-save-v1'}
                    security.write_new(backup, previous)
                    security.write_new(staging_path, encrypted)
                    staging = staging_path
                    # A receipt survives a crash around replacement and blocks
                    # further use after restart until the transaction is checked.
                    security.write_new(receipt_path, json.dumps(receipt).encode())
                    receipt_owned = True
                    self._check_keyfile()
                    if self._read()[1] != snapshot:
                        raise SaveError('vault changed on disk; restart and unlock')
                    attempted = True
                    self._replace(staging, self.path)
                    staging = None
                    persisted, next_snapshot = self._read()
                    if persisted != encrypted:
                        raise SaveError('save outcome uncertain; restart and unlock')
                    receipt_temp_path = self.path.parent / (prefix + 'receipt-' + identifier)
                    security.write_new(receipt_temp_path, json.dumps({**receipt, 'state': 'saved'}).encode())
                    receipt_temp = receipt_temp_path
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
                    if receipt_owned:
                        try:
                            receipt_path.unlink()
                        except FileNotFoundError:
                            pass
                        except OSError:
                            self.recovery_required = True
                    # If receipt creation/cleanup failed, inspect what remains
                    # under the lock. Never unlink a pre-existing receipt whose
                    # CREATE_NEW failed, but latch any incomplete artifact.
                    if receipt_path is not None:
                        try:
                            self._check_recovery()
                        except Exception:
                            self.recovery_required = True
                    raise
                finally:
                    for path in (staging, receipt_temp):
                        if path is not None:
                            try:
                                path.unlink()
                            except OSError:
                                pass
