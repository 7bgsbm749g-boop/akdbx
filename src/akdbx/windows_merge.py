"""Windows transaction for KeePassXC merges and exact-byte snapshot admission.

The request checks, receipts, verification order and failure states are those
of `merge.py`. Only the file and engine primitives differ. Checked handles and
DACLs replace descriptor anchoring. `MoveFileEx(WRITE_THROUGH)` replaces rename
plus fsync. The engine is the machine-installed `keepassxc-cli.exe`, never a
PATH lookup. Only encrypted KDBX files and fixed, nonsecret receipts are staged.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import time

import pywintypes
import win32con
import win32file

from . import admission, selection, versions
from . import windows_security as security
from .merge import (ENGINE_TIMEOUT, MergeError, MergeManager, _check_ambiguity, _counts, _digest, _open,
                    supported_version, synchronize_deletions, verify_history)
from .persistence import SaveError
from .windows_store import WindowsVaultStore, read_merge_receipt

ERROR_ALREADY_EXISTS = 183
SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX = 0x1, 0x2, 0x8000


def engine_path():
    """The per-machine install location from the known-folder API; never PATH."""
    from win32com.shell import shell, shellcon
    return Path(shell.SHGetKnownFolderPath(shellcon.FOLDERID_ProgramFiles, 0, None)) / 'KeePassXC' / 'keepassxc-cli.exe'


@contextmanager
def trusted_engine(path):
    """Hold a machine-installed engine that only the system can replace.

    Linux requires a root-owned engine that no other account can write. Here
    the engine, its folder and every ancestor must be owned by SYSTEM,
    administrators or TrustedInstaller, and must give no other account a way
    to change them. The read-only handle denies write and delete sharing, so
    the checked file is the file that runs.
    """
    path = Path(path)
    with security.trusted_directory(path.parent):
        with security.checked_handle(path.parent, directory=True, private=False) as directory:
            security.check_machine_acl(directory)
            with security.managed_handle(win32file.CreateFile(
                    str(path), win32con.GENERIC_READ | win32con.READ_CONTROL, win32con.FILE_SHARE_READ,
                    None, win32con.OPEN_EXISTING, security.FILE_FLAG_OPEN_REPARSE_POINT, None)) as handle:
                info = win32file.GetFileInformationByHandle(handle)
                if info[0] & (win32con.FILE_ATTRIBUTE_REPARSE_POINT | win32con.FILE_ATTRIBUTE_DIRECTORY):
                    raise PermissionError('merge engine must be a regular file')
                security.check_machine_acl(handle)
                yield path


def engine_environment():
    # The engine needs only the system folder to load its libraries. No user
    # variable, proxy, plugin path or secret enters its environment.
    return {'SystemRoot': os.environ['SystemRoot']}


def engine_version():
    """Fail closed outside the tested engine release series."""
    try:
        with trusted_engine(engine_path()) as engine:
            result = subprocess.run([str(engine), '--version'], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True,
                                    env=engine_environment(), creationflags=subprocess.CREATE_NO_WINDOW)
        return supported_version(result.stdout.decode('ascii').strip())
    except Exception:
        pass
    return None


def run_engine(bundle, vault, key_path, *, source_name='source.kdbx'):
    """No secret argv/env/files. Raw engine output is discarded, even on error."""
    password = vault.password
    if not isinstance(password, str) or any(c in password for c in '\r\n\x00'):
        raise MergeError('merge requires a line-compatible master password')
    try:
        import ctypes
        # The engine inherits this error mode. Its crash path then ends the
        # process without a fault dialog or an error report of its memory.
        ctypes.windll.kernel32.SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)
        with ExitStack() as stack:
            engine = stack.enter_context(trusted_engine(engine_path()))
            args = [str(engine), 'merge', '--quiet', '--same-credentials']
            if vault.keyfile is not None:
                # Windows has no anonymous sealed file. Use the vault's own key
                # file, with write and delete sharing denied for the whole run,
                # after its bytes match the key that the broker holds.
                if key_path is None:
                    raise MergeError('merge engine failed; target not replaced')
                with security.trusted_directory(Path(key_path).parent):
                    stack.enter_context(security.managed_handle(win32file.CreateFile(
                        str(key_path), win32con.GENERIC_READ, win32con.FILE_SHARE_READ, None,
                        win32con.OPEN_EXISTING, security.FILE_FLAG_OPEN_REPARSE_POINT, None)))
                    key, _ = security.read_private(key_path, limit=1024 * 1024)
                if key != vault.keyfile.getvalue():
                    raise MergeError('merge engine failed; target not replaced')
                args += ['--key-file', str(key_path)]
            args += [str(Path(bundle) / 'candidate.kdbx'), str(Path(bundle) / source_name)]
            subprocess.run(args, input=(password + '\n').encode('utf-8'),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           env=engine_environment(), cwd=bundle, timeout=ENGINE_TIMEOUT, check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
    except MergeError:
        raise
    except Exception:
        raise MergeError('merge engine failed; target not replaced') from None


def read_snapshot(path):
    """Read one private encrypted file with the same snapshot shape as the store."""
    data, info = security.read_private(path)
    return data, (*info[:2], *info[3:], hashlib.sha256(data).hexdigest())


def same_file(left, right):
    # Volume serial and file index, at their positions in a store snapshot.
    return (left[3], left[7], left[8]) == (right[3], right[7], right[8])


def directory_identity(path):
    with security.checked_handle(path, directory=True) as handle:
        info = win32file.GetFileInformationByHandle(handle)
        return info[4], info[8], info[9]


def replace(source, destination):
    win32file.MoveFileEx(str(source), str(destination),
                         win32con.MOVEFILE_REPLACE_EXISTING | security.MOVEFILE_WRITE_THROUGH)


class WindowsMergeManager(MergeManager):
    def _engine_version(self):
        return engine_version()

    def _store(self):
        """Use normal opening's target identity for locked receipt recovery."""
        store = getattr(self.broker.vault, '_akdbx_store', None)
        if store is None and self.database is not None:
            # The KDBX itself can be absent while its recovery bundle survives.
            store = WindowsVaultStore(self.database)
        if store is None:
            raise MergeError('merge database unavailable')
        return store

    @staticmethod
    def _receipt(bundle, value):
        data = json.dumps(value, sort_keys=True).encode('utf-8') + b'\n'
        pending = Path(bundle) / 'receipt-next.json'
        # An interrupted previous receipt update is never silently overwritten.
        security.write_new(pending, data)
        replace(pending, Path(bundle) / 'receipt.json')

    def status(self, operation_id):
        operation_id = self._id(operation_id)
        store = self._store()
        name = store._write_name('merge', operation_id)
        try:
            with security.trusted_directory(store.path.parent):
                roots = [store.path.parent]
                external = store.snapshot_directory()
                if external is not None:
                    roots.append(external)
                for root in roots:
                    try:
                        value = read_merge_receipt(root / name, operation_id)
                    except FileNotFoundError:
                        continue
                    if value['state'] in {'preparing', 'prepared'}:
                        value.update(ok=False, state='uncertain',
                                     error='merge interrupted or active; do not retry; inspect retained encrypted files')
                    return {**value, 'receipt_path': str(root / name / 'receipt.json')}
        except (pywintypes.error, PermissionError):
            raise SaveError('unsafe merge receipt directory') from None
        raise MergeError('merge receipt not found; do not infer success')

    def begin(self, request):
        started = time.monotonic()
        plan = self._plan(request)
        admitting, group_verifier, operation_id = plan.admitting, plan.group_verifier, plan.operation_id
        refresh_target, preserve, receipt = plan.refresh_target, plan.preserve, plan.receipt
        source_path = Path(plan.source_path)
        store = self._store()
        name = store._write_name('merge', operation_id)
        bundle = None
        replaced = False
        adopted = False
        replacement_attempted = False
        candidate_ready = False
        target_snapshot = None
        try:
            with ExitStack() as stack:
                # Held handles deny delete sharing: no component of the vault
                # folder can be renamed or replaced during the transaction.
                stack.enter_context(security.trusted_directory(store.path.parent))
                try:
                    stack.enter_context(store._advisory_lock())
                except SaveError:
                    raise SaveError('vault write busy; merge not started') from None
                if not store.merge_names_fit(store.path.parent):
                    raise SaveError('vault filename is too long for required merge artifacts')
                # Refresh is reconciliation, never an override for an unresolved
                # operation. Check prior intents before creating this intent.
                store._check_recovery()
                if store.recovery_required:
                    raise MergeError('incomplete merge receipt; recovery required; refresh refused')
                root = store.snapshot_directory(request['snapshot_directory']) if admitting else store.path.parent
                if admitting:
                    stack.enter_context(security.trusted_directory(root))
                    if not store.merge_names_fit(root, replacement=False):
                        raise SaveError('vault filename is too long for required merge artifacts')
                root_identity = directory_identity(root) if admitting else None
                # The bound external root participates in recovery before any intent.
                store._check_recovery()
                if store.recovery_required:
                    raise MergeError('incomplete receipt; recovery required; operation refused')
                try:
                    win32file.CreateDirectoryW(str(root / name), security.private_attributes(directory=True))
                except pywintypes.error as exc:
                    if exc.winerror == ERROR_ALREADY_EXISTS:
                        return self.status(operation_id)
                    raise
                bundle = root / name
                stack.enter_context(security.checked_handle(bundle, directory=True))
                self._receipt(bundle, receipt)
                store._check_keyfile()
                previous, target_snapshot = store._read()
                stale = target_snapshot != store.expected
                if admitting and 'if_match' in request and request['if_match'] != _digest(previous):
                    raise MergeError('encrypted target precondition failed; admission refused')
                if stale and not refresh_target:
                    raise MergeError('target changed on disk; use explicit --refresh-target reconciliation')
                incoming, source_snapshot = read_snapshot(source_path)
                if same_file(target_snapshot, source_snapshot):
                    raise MergeError('source and target must be different files')
                snapshots = [('target.kdbx', previous), ('source.kdbx', incoming),
                             ('candidate.kdbx', incoming if admitting else previous)]
                if refresh_target:
                    broker_image = store.verified_encrypted
                    if (broker_image is None or store.expected is None
                            or hashlib.sha256(broker_image).hexdigest() != store.expected[-1]):
                        raise MergeError('verified broker image unavailable; refresh refused')
                    snapshots.append(('broker.kdbx', broker_image))
                for filename, data in snapshots:
                    security.write_new(bundle / filename, data)
                if admitting:
                    for filename, data in snapshots:
                        if read_snapshot(bundle / filename)[0] != data:
                            raise MergeError('encrypted input snapshot verification failed; admission refused')
                receipt.update(target_sha256=_digest(previous), source_sha256=_digest(incoming))
                current_open_started = time.monotonic()
                if refresh_target:
                    receipt.update(broker_sha256=_digest(broker_image), target_refreshed=stale)
                    try:
                        disk_vault = (self.broker.vault if admitting and broker_image == previous
                                      else _open(previous, self.broker.vault))
                        broker_vault = (self.broker.vault if admitting else disk_vault if broker_image == previous
                                        else _open(broker_image, self.broker.vault))
                    except Exception:
                        raise MergeError('current target or broker image cannot be opened with held credentials; refresh refused') from None
                    originals = (disk_vault, broker_vault)
                else:
                    originals = (self.broker.vault,)
                decrypted = time.monotonic()
                try:
                    other = _open(incoming, self.broker.vault)
                except Exception:
                    raise MergeError('source cannot be opened with broker credentials; different source credentials are unsupported') from None
                originals = (*originals, other)
                if admitting:
                    opened = time.monotonic()
                    # Avoid repeat validation of the identical current/held image.
                    states = (disk_vault,) if broker_image == previous else (disk_vault, broker_vault)
                    cached = {id(self.broker.vault): store.verified_capsules} if store.verified_capsules is not None else {}
                    details, admitted_capsules = admission.verify(other, states, trusted_archives=cached,
                                                                  group_verification=group_verifier)
                    encrypted, verified = incoming, other
                    receipt.update(details, timings={'current_decrypt_s': round(decrypted - current_open_started, 6),
                                                     'source_decrypt_s': round(opened - decrypted, 6),
                                                     'validation_s': round(time.monotonic() - opened, 6)})
                    validation_finished = time.monotonic()
                else:
                    _check_ambiguity(*originals, preserve=preserve)
                    ledger = versions.collect(originals, capture=preserve)

                    def complete_stage(data, stage_originals, *, final=False):
                        try:
                            stage = _open(data, self.broker.vault)
                        except Exception:
                            raise MergeError('encrypted merge candidate could not be reopened') from None
                        changed = False
                        if final:
                            changed = synchronize_deletions(stage, *originals)
                        changed = versions.ensure(stage, ledger) or changed
                        if changed:
                            buffer = io.BytesIO()
                            stage.save(buffer)
                            data = buffer.getvalue()
                            security.write_new(bundle / 'candidate-final.kdbx', data)
                            replace(bundle / 'candidate-final.kdbx', bundle / 'candidate.kdbx')
                            stage = _open(data, self.broker.vault)
                        versions.verify(stage, ledger)
                        if preserve:
                            if final:
                                versions.verify_selection(stage, originals)
                        else:
                            verify_history(stage, *stage_originals, allow_deletions=final)
                        return data, stage

                    if refresh_target and broker_image != previous:
                        run_engine(bundle, self.broker.vault, store.keyfile_path, source_name='broker.kdbx')
                        intermediate_bytes, _ = read_snapshot(bundle / 'candidate.kdbx')
                        intermediate_bytes, _ = complete_stage(intermediate_bytes, (disk_vault, broker_vault))
                        security.write_new(bundle / 'reconciled.kdbx', intermediate_bytes)
                    run_engine(bundle, self.broker.vault, store.keyfile_path)
                    # The engine's own save must still be a private regular file.
                    encrypted, _ = read_snapshot(bundle / 'candidate.kdbx')
                    encrypted, verified = complete_stage(encrypted, originals, final=True)
                if len(encrypted) > 128 * 1024 * 1024:
                    raise SaveError('encrypted vault exceeds the Windows input budget; target not replaced')
                if read_snapshot(bundle / 'candidate.kdbx')[0] != encrypted:
                    raise MergeError('encrypted admission stage differs from verified source; refused' if admitting
                                     else 'encrypted merge candidate changed; target not replaced')
                if admitting and directory_identity(root) != root_identity:
                    raise MergeError('snapshot directory changed; admission refused')
                candidate_ready = True
                store.check_current(target_snapshot)
                if read_snapshot(source_path)[1] != source_snapshot:
                    raise SaveError('vault changed on disk; restart and unlock')
                store._check_keyfile()
                receipt.update(state='prepared', candidate_sha256=_digest(encrypted),
                               before=_counts(self.broker.vault), after=_counts(verified),
                               changed=encrypted != previous)
                if refresh_target:
                    receipt['disk_before'] = _counts(disk_vault)
                if preserve:
                    receipt['preserved_versions'] = len(ledger)
                self._receipt(bundle, receipt)

                def recheck():
                    store.check_current(target_snapshot)
                    if read_snapshot(source_path)[1] != source_snapshot:
                        raise SaveError('vault changed on disk; restart and unlock')
                    store._check_keyfile()
                    if admitting and directory_identity(root) != root_identity:
                        raise MergeError('snapshot directory changed; admission refused')

                if request.get('check') or encrypted == previous:
                    if admitting and not request.get('check'):
                        recheck()
                    receipt.update(ok=True, state='checked' if request.get('check') else 'unchanged')
                else:
                    # Retain the candidate too. Move a separate encrypted file
                    # in the target folder, with the existing lock held.
                    staging = store.path.parent / (name + '.replace')
                    security.write_new(staging, encrypted)
                    try:
                        recheck()
                        replacement_attempted = True
                        replace(staging, store.path)
                        replaced = True
                        persisted, snapshot = store._read()
                        if persisted != encrypted:
                            raise MergeError('save outcome uncertain; restart and unlock')
                        adopted = True
                        store.expected = snapshot
                        store.verified_encrypted = encrypted
                        store.verified_capsules = admitted_capsules if admitting else versions.archives(verified)
                        verified._akdbx_store = store
                        self.broker.vault = verified
                        self.broker.writes.invalidate_revision(all_pending=True)
                        receipt.update(ok=True, state='saved')
                    finally:
                        try:
                            staging.unlink()
                        except FileNotFoundError:
                            pass
                if refresh_target and stale and not request.get('check') and not adopted:
                    # Even an unchanged target can be a new broker revision.
                    # Recheck identity before adoption.
                    recheck()
                    adopted = True
                    store.expected = target_snapshot
                    store.verified_encrypted = encrypted
                    store.verified_capsules = admitted_capsules if admitting else versions.archives(verified)
                    verified._akdbx_store = store
                    self.broker.vault = verified
                    self.broker.writes.invalidate_revision(all_pending=True)
                if admitting:
                    receipt['timings']['total_s'] = round(time.monotonic() - started, 6)
                    receipt['timings']['durability_s'] = round(time.monotonic() - validation_finished, 6)
                self._receipt(bundle, receipt)
                return {**receipt, 'receipt_path': str(bundle / 'receipt.json')}
        except (KeyboardInterrupt, SystemExit):
            if bundle is not None:
                store.recovery_required = True
            raise
        except Exception as exc:
            if replacement_attempted and not replaced:
                # A failing move can report an error after the name changed.
                # Only a proven unchanged target is a failure before
                # replacement; every other result requires recovery.
                try:
                    store.check_current(target_snapshot)
                except Exception:
                    replaced = True
            if replaced or adopted:
                store.recovery_required = True
            error = (str(exc) if isinstance(exc, (MergeError, SaveError, versions.PreservationError))
                     else 'merge failed; save not confirmed')
            receipt.update(ok=False, state='uncertain' if replaced or adopted else 'failed', error=error)
            from .group_selection import GroupSelectionError
            if isinstance(exc, (selection.SelectionError, admission.AdmissionError, GroupSelectionError)):
                receipt['verification_diagnostics'] = exc.diagnostics
            if bundle is not None:
                # Best effort only; an earlier preparing/prepared receipt stays
                # truthful when the filesystem stops accepting I/O.
                try:
                    self._receipt(bundle, receipt)
                except Exception:
                    store.recovery_required = True
                    receipt.update(state='uncertain', error='merge receipt could not be finalized; recovery required')
                if not candidate_ready:
                    try:
                        (bundle / 'candidate.kdbx').unlink()
                    except OSError:
                        pass
                receipt['receipt_path'] = str(bundle / 'receipt.json')
            return receipt
