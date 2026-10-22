"""UUID-aware KeePassXC merges. Only encrypted files and fixed status leave here."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import resource
import stat
import subprocess
from pathlib import Path

from .persistence import SaveError, VaultStore, open_encrypted
from . import selection, versions

ENGINE = Path('/usr/bin/keepassxc-cli')
ENGINE_TIMEOUT = 180
ID_PATTERN = re.compile(r'[a-f0-9]{32}\Z')


class MergeError(Exception):
    """Fixed, nonsecret messages only."""


def engine_version():
    """Fail closed outside the tested engine release series; never use PATH."""
    try:
        info = ENGINE.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            return None
        result = subprocess.run([str(ENGINE), '--version'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, check=True, env={'LANG': 'C.UTF-8'})
        version = result.stdout.decode('ascii').strip()
        if re.fullmatch(r'2\.7\.\d+', version) and int(version.split('.')[2]) >= 10:
            return version
    except Exception:
        pass
    return None


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _open(encrypted, vault):
    keyfile = io.BytesIO(vault.keyfile.getvalue()) if vault.keyfile is not None else None
    return open_encrypted(encrypted, vault.password, keyfile)


def _entry_signature(entry):
    return versions.entry_signature(entry)


def _check_ambiguity(*vaults, preserve=False):
    for vault in vaults:
        ids = [item.uuid for item in [*vault.entries, *vault.groups]]
        if len(ids) != len(set(ids)):
            raise MergeError('duplicate UUIDs; merge refused')
    records = {}
    for vault in vaults:
        versions.archives(vault)
        for entry in versions.active_entries(vault):
            for item in [entry, *entry.history]:
                key = (item.uuid, selection.modification_time(item))
                signature = _entry_signature(item)
                if not preserve and key in records and records[key] != signature:
                    raise MergeError('conflicting same-second records; merge refused; originals retained')
                records[key] = signature


def _counts(vault):
    entries = list(versions.active_entries(vault))
    archive_groups = [group for group in vault.groups if versions.is_archive_group(group)]
    return {'entries': len(entries), 'groups': len(vault.groups) - len(archive_groups),
            'history': sum(len(e.history) for e in entries),
            'attachments': sum(len(e.attachments) for e in entries),
            'archived_versions': sum(len(group.entries) for group in archive_groups),
            'deletions': len(vault.tree.findall('./Root/DeletedObjects/DeletedObject'))}


def synchronize_deletions(candidate, *originals):
    """CLI KeepNewer omits deletion sync. Apply KeePass UUID/time semantics.

    This operates on database objects, never title matches or entry XML joins.
    Keep even obsolete tombstones; an edit newer than a deletion survives.
    Use the earliest deletion for a UUID, as KeePassXC Synchronize does.
    """
    from lxml import etree
    deleted = {}
    for vault in originals:
        for record in vault.tree.findall('./Root/DeletedObjects/DeletedObject'):
            identity = record.findtext('UUID')
            stamp = selection.decode_time(record.findtext('DeletionTime'), vault.version)
            if identity not in deleted or stamp < deleted[identity][0]:
                deleted[identity] = (stamp, copy.deepcopy(record))
    changed = False
    for entry in list(versions.active_entries(candidate)):
        record = deleted.get(entry._element.findtext('UUID'))
        if record is not None and selection.modification_time(entry) <= record[0]:
            candidate.delete_entry(entry)
            changed = True
    for group in sorted(candidate.groups, key=lambda g: len(g.path), reverse=True):
        record = deleted.get(group._element.findtext('UUID'))
        if (group != candidate.root_group and not versions.is_archive_group(group) and record is not None and selection.modification_time(group) <= record[0]
                and not group.entries and not group.subgroups):
            candidate.delete_group(group)
            changed = True
    container = candidate.tree.find('./Root/DeletedObjects')
    if container is None:
        container = etree.SubElement(candidate.tree.find('./Root'), 'DeletedObjects')
    current = {r.findtext('UUID'): selection.decode_time(r.findtext('DeletionTime'), candidate.version) for r in container}
    expected = {key: value[0] for key, value in deleted.items()}
    if current != expected:
        for record in list(container):
            container.remove(record)
        for key in sorted(deleted):
            container.append(deleted[key][1])
        changed = True
    return changed


def verify_history(candidate, *originals, allow_deletions=True):
    """Refuse engine history pruning instead of silently losing old values."""
    retained = {e.uuid: {(selection.modification_time(h), _entry_signature(h)) for h in [e, *e.history]} for e in candidate.entries}
    deletions = {r.findtext('UUID'): selection.decode_time(r.findtext('DeletionTime'), candidate.version)
                 for r in candidate.tree.findall('./Root/DeletedObjects/DeletedObject')}
    for vault in originals:
        for entry in vault.entries:
            if entry.uuid not in retained:
                deleted = deletions.get(entry._element.findtext('UUID'))
                if allow_deletions and deleted is not None and selection.modification_time(entry) <= deleted:
                    continue
                raise MergeError('merge would discard an entry without a valid deletion; target not replaced')
            if any((selection.modification_time(h), _entry_signature(h)) not in retained[entry.uuid] for h in [entry, *entry.history]):
                raise MergeError('merge would discard entry history or fields; target not replaced')


def run_engine(bundle, vault, *, source_name='source.kdbx'):
    """No secret argv/env/files. Raw engine output is discarded, even on error."""
    password = vault.password
    if not isinstance(password, str) or any(c in password for c in '\r\n\x00'):
        raise MergeError('merge requires a line-compatible master password')
    args = [str(ENGINE), 'merge', '--quiet', '--same-credentials']
    key_fd = None
    try:
        # Prevent a crashing native child from writing secrets in a core file.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if vault.keyfile is not None:
            import fcntl
            key_fd = os.memfd_create('akdbx-key', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            os.write(key_fd, vault.keyfile.getvalue())
            os.lseek(key_fd, 0, os.SEEK_SET)
            fcntl.fcntl(key_fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            args += ['--key-file', f'/proc/self/fd/{key_fd}']
        args += [str(bundle / 'candidate.kdbx'), str(bundle / source_name)]
        subprocess.run(args, input=(password + '\n').encode('utf-8'),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       pass_fds=(() if key_fd is None else (key_fd,)),
                       env={'LANG': 'C.UTF-8', 'QT_LOGGING_RULES': '*.debug=false'},
                       cwd=bundle, timeout=ENGINE_TIMEOUT, check=True)
    except MergeError:
        raise
    except Exception:
        raise MergeError('merge engine failed; target not replaced') from None
    finally:
        if key_fd is not None:
            os.close(key_fd)


class MergeManager:
    def __init__(self, broker):
        self.broker = broker
        self.database = None
        # Probe lazily once per process; status must not repeatedly spawn tools.
        self._engine_checked = False
        self._version = None

    def capabilities(self):
        if not self._engine_checked:
            self._version = engine_version()
            self._engine_checked = True
        store = getattr(self.broker.vault, '_akdbx_store', None)
        return {'merge_available': bool(self._version and store and store.writable_path and not store.recovery_required),
                'merge_engine': ('keepassxc-cli ' + self._version) if self._version else None,
                'merge_same_credentials_only': True, 'merge_protocol': 1,
                'merge_refresh_target_supported': True,
                'merge_preserve_conflicts_supported': versions.supported(),
                'merge_preservation_policy': versions.POLICY if versions.supported() else None,
                'merge_active_verification': selection.VERIFICATION if versions.supported() else None,
                'merge_diagnostics': selection.DIAGNOSTICS}

    def _store(self):
        store = getattr(self.broker.vault, '_akdbx_store', None)
        if store is None and self.database is not None:
            store = VaultStore(self.database, strict_path=True)
        if store is None:
            raise MergeError('merge database unavailable')
        return store

    @staticmethod
    def _id(value):
        if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
            raise MergeError('operation ID must be 32 lowercase hexadecimal characters')
        return value

    @staticmethod
    def _bundle_name(store, operation_id):
        return '.' + store.path.name + '.akdbx-merge-' + operation_id

    @staticmethod
    def _receipt(directory, value):
        data = json.dumps(value, sort_keys=True).encode('utf-8') + b'\n'
        name = 'receipt-next.json'
        # An interrupted previous receipt update is never silently overwritten.
        VaultStore._write_file(directory, name, data)
        os.replace(name, 'receipt.json', src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)

    def status(self, operation_id):
        operation_id = self._id(operation_id)
        store = self._store()
        directory = store._directory()
        bundle_fd = None
        try:
            name = self._bundle_name(store, operation_id)
            bundle_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            info = os.fstat(bundle_fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise MergeError('unsafe merge receipt directory')
            fd = os.open('receipt.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=bundle_fd)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise MergeError('unsafe merge receipt')
                value = json.loads(stream.read(16384))
            if value['operation_id'] != operation_id:
                raise MergeError('invalid merge receipt')
            if value['state'] in {'preparing', 'prepared'}:
                value.update(ok=False, state='uncertain', error='merge interrupted or active; do not retry; inspect retained encrypted files')
            return {**value, 'receipt_path': str(store.path.parent / name / 'receipt.json')}
        except FileNotFoundError:
            raise MergeError('merge receipt not found; do not infer success') from None
        finally:
            if bundle_fd is not None:
                os.close(bundle_fd)
            os.close(directory)

    def begin(self, request):
        operation_id = self._id(request.get('operation_id'))
        if not self.capabilities()['merge_available']:
            raise MergeError('merge unavailable; require safe writable vault and KeePassXC CLI >=2.7.10,<2.8')
        if any(type(request.get(field, False)) is not bool for field in ('check', 'refresh_target', 'preserve_conflicts')):
            raise MergeError('invalid merge check option')
        refresh_target = request.get('refresh_target', False)
        preserve = request.get('preserve_conflicts', False)
        if 'active_verification' in request and (not preserve or request['active_verification'] != selection.VERIFICATION):
            raise MergeError('unsupported active verification request; merge not started')
        if preserve and not versions.supported():
            raise MergeError('preservation requires tested PyKeePass 4.2.0; merge refused')
        source_path = request.get('source')
        if not isinstance(source_path, str) or not Path(source_path).is_absolute() or '\x00' in source_path:
            raise MergeError('merge source must be an absolute file path')
        store = self._store()
        source = VaultStore(Path(source_path), strict_path=True)
        directory = source_directory = bundle_fd = None
        receipt = {'ok': False, 'operation_id': operation_id, 'state': 'preparing',
                   'check': request.get('check', False), 'refresh_target': refresh_target,
                   'preserve_conflicts': preserve, 'preservation_policy': versions.POLICY if preserve else None,
                   'active_verification': selection.VERIFICATION if preserve else None,
                   'engine': self._version}
        replaced = False
        adopted = False
        replacement_attempted = False
        candidate_ready = False
        try:
            directory = store._directory()
            with store.advisory_lock(directory):
                name = self._bundle_name(store, operation_id)
                # Refresh is reconciliation, never an override for an unresolved
                # operation. Check prior intents before creating this intent.
                store._check_merge_recovery(directory)
                if store.recovery_required:
                    raise MergeError('incomplete merge receipt; recovery required; refresh refused')
                try:
                    os.mkdir(name, 0o700, dir_fd=directory)
                except FileExistsError:
                    return self.status(operation_id)
                bundle_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                bundle = store.path.parent / name
                self._receipt(bundle_fd, receipt)
                os.fsync(directory)
                store._check_keyfile()
                previous, target_snapshot = store._read(directory)
                stale = target_snapshot != store.expected
                if stale and not refresh_target:
                    raise MergeError('target changed on disk; use explicit --refresh-target reconciliation')
                source_directory = source._directory()
                incoming, source_snapshot = source._read(source_directory)
                if target_snapshot[:2] == source_snapshot[:2]:
                    raise MergeError('source and target must be different files')
                snapshots = [('target.kdbx', previous), ('source.kdbx', incoming), ('candidate.kdbx', previous)]
                if refresh_target:
                    broker_image = store.verified_encrypted
                    if (broker_image is None or store.expected is None
                            or hashlib.sha256(broker_image).digest() != store.expected[-1]):
                        raise MergeError('verified broker image unavailable; refresh refused')
                    snapshots.append(('broker.kdbx', broker_image))
                for filename, data in snapshots:
                    VaultStore._write_file(bundle_fd, filename, data)
                os.fsync(bundle_fd)
                receipt.update(target_sha256=_digest(previous), source_sha256=_digest(incoming))
                if refresh_target:
                    receipt.update(broker_sha256=_digest(broker_image), target_refreshed=stale)
                    try:
                        disk_vault = _open(previous, self.broker.vault)
                        broker_vault = disk_vault if broker_image == previous else _open(broker_image, self.broker.vault)
                    except Exception:
                        raise MergeError('current target or broker image cannot be opened with held credentials; refresh refused') from None
                    originals = (disk_vault, broker_vault)
                else:
                    originals = (self.broker.vault,)
                try:
                    other = _open(incoming, self.broker.vault)
                except Exception:
                    raise MergeError('source cannot be opened with broker credentials; different source credentials are unsupported') from None
                originals = (*originals, other)
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
                        VaultStore._write_file(bundle_fd, 'candidate-final.kdbx', data)
                        os.replace('candidate-final.kdbx', 'candidate.kdbx', src_dir_fd=bundle_fd, dst_dir_fd=bundle_fd)
                        stage = _open(data, self.broker.vault)
                    versions.verify(stage, ledger)
                    if preserve:
                        if final:
                            versions.verify_selection(stage, originals)
                    else:
                        verify_history(stage, *stage_originals, allow_deletions=final)
                    return data, stage
                if refresh_target and broker_image != previous:
                    run_engine(bundle, self.broker.vault, source_name='broker.kdbx')
                    intermediate_bytes, _ = VaultStore(bundle / 'candidate.kdbx', strict_path=True)._read(bundle_fd)
                    intermediate_bytes, intermediate = complete_stage(intermediate_bytes, (disk_vault, broker_vault))
                    VaultStore._write_file(bundle_fd, 'reconciled.kdbx', intermediate_bytes)
                    os.fsync(bundle_fd)
                run_engine(bundle, self.broker.vault)
                candidate_store = VaultStore(bundle / 'candidate.kdbx', strict_path=True)
                encrypted, _ = candidate_store._read(bundle_fd)
                encrypted, verified = complete_stage(encrypted, originals, final=True)
                fd = os.open('candidate.kdbx', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=bundle_fd)
                try:
                    os.fchmod(fd, 0o600)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(bundle_fd)
                candidate_ready = True
                store.check_current(directory, target_snapshot)
                source.check_current(source_directory, source_snapshot)
                store._check_keyfile()
                receipt.update(state='prepared', candidate_sha256=_digest(encrypted),
                               before=_counts(self.broker.vault), after=_counts(verified),
                               changed=encrypted != previous)
                if refresh_target:
                    receipt['disk_before'] = _counts(disk_vault)
                if preserve:
                    receipt['preserved_versions'] = len(ledger)
                self._receipt(bundle_fd, receipt)
                if request.get('check') or encrypted == previous:
                    receipt.update(ok=True, state='checked' if request.get('check') else 'unchanged')
                else:
                    # Retain the candidate too. Rename a separate encrypted file
                    # from the target directory, with the existing lock held.
                    staging = name + '.replace'
                    VaultStore._write_file(directory, staging, encrypted)
                    try:
                        store.check_current(directory, target_snapshot)
                        source.check_current(source_directory, source_snapshot)
                        store._check_keyfile()
                        replacement_attempted = True
                        os.replace(staging, store.path.name, src_dir_fd=directory, dst_dir_fd=directory)
                        replaced = True
                        os.fsync(directory)
                        persisted, snapshot = store._read(directory)
                        if persisted != encrypted:
                            raise MergeError('save outcome uncertain; restart and unlock')
                        adopted = True
                        store.expected = snapshot
                        store.verified_encrypted = encrypted
                        verified._akdbx_store = store
                        self.broker.vault = verified
                        self.broker.writes.invalidate_revision(all_pending=True)
                        receipt.update(ok=True, state='saved')
                    finally:
                        try:
                            os.unlink(staging, dir_fd=directory)
                        except FileNotFoundError:
                            pass
                if refresh_target and stale and not request.get('check') and not adopted:
                    # Even an unchanged target can be a new broker revision.
                    # Establish durability and recheck identity before adoption.
                    fd = os.open(store.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.fsync(directory)
                    store.check_current(directory, target_snapshot)
                    source.check_current(source_directory, source_snapshot)
                    store._check_keyfile()
                    adopted = True
                    store.expected = target_snapshot
                    store.verified_encrypted = encrypted
                    verified._akdbx_store = store
                    self.broker.vault = verified
                    self.broker.writes.invalidate_revision(all_pending=True)
                self._receipt(bundle_fd, receipt)
                return {**receipt, 'receipt_path': str(bundle / 'receipt.json')}
        except (KeyboardInterrupt, SystemExit):
            if bundle_fd is not None:
                store.recovery_required = True
            raise
        except Exception as exc:
            if replacement_attempted and not replaced:
                # A failing rename wrapper/filesystem can report an error after
                # the name changed. Only a proven unchanged target is a failure
                # before replacement; every other result requires recovery.
                try:
                    store.check_current(directory, target_snapshot)
                except Exception:
                    replaced = True
            if replaced or adopted:
                store.recovery_required = True
            error = (str(exc) if isinstance(exc, (MergeError, SaveError, versions.PreservationError)) else 'merge failed; save not confirmed')
            receipt.update(ok=False, state='uncertain' if replaced or adopted else 'failed', error=error)
            if isinstance(exc, selection.SelectionError):
                receipt['verification_diagnostics'] = exc.diagnostics
            if bundle_fd is not None:
                # Best effort only; a previously fsynced preparing/prepared
                # receipt stays truthful when the filesystem stops accepting I/O.
                try:
                    self._receipt(bundle_fd, receipt)
                except Exception:
                    pass
                if not candidate_ready:
                    try:
                        os.unlink('candidate.kdbx', dir_fd=bundle_fd)
                    except OSError:
                        pass
                receipt['receipt_path'] = str(bundle / 'receipt.json')
            return receipt
        finally:
            for fd in (bundle_fd, source_directory, directory):
                if fd is not None:
                    os.close(fd)
