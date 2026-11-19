"""Native Windows merge and snapshot admission with the pinned KeePassXC engine.

Synthetic KDBX fixtures only. The engine is the machine-installed
`keepassxc-cli.exe` when it passes the production trust and version checks.
A developer machine may instead name a verified portable 2.7.10 copy in
`AKDBX_TEST_ENGINE`; only the install-location check is replaced then.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid

import pytest

if sys.platform != 'win32':
    pytest.skip('native Windows APIs required', allow_module_level=True)

from lxml import etree
import win32con
import win32file
import win32security
from pykeepass import PyKeePass, create_database

from akdbx import admission, versions, windows_merge, windows_rpc as rpc, windows_security as security
from akdbx.broker import Broker, open_vault_with_password
from test_windows_native import native_https_config, private_dir, synthetic_vault  # noqa: F401
from test_windows_unlock import certificates  # noqa: F401

MASTER = '  synthetic !%+& punctuation é 🗝️  '
SECRET = 'synthetic-entry-secret-never-returned'
BASE_TIME = datetime(2024, 1, 1, tzinfo=timezone.utc)
PUBLIC = 'D:P(A;;FA;;;WD)'


@pytest.fixture(autouse=True)
def engine(monkeypatch):
    """Use the installed trusted engine, or an explicitly named verified copy."""
    if windows_merge.engine_version() is not None:
        return windows_merge.engine_path()
    portable = os.environ.get('AKDBX_TEST_ENGINE')
    if not portable or not Path(portable).is_file():
        message = 'Windows merge tests require KeePassXC CLI 2.7.10 or newer, below 2.8'
        if os.environ.get('AKDBX_REQUIRE_WINDOWS_ENGINE') == '1':
            pytest.fail(message)
        pytest.skip(message)

    @contextmanager
    def named_engine(_path):
        # The same held, no-write-sharing handle as production; only the
        # per-machine install location and its ownership are not required.
        with security.managed_handle(win32file.CreateFile(
                portable, win32con.GENERIC_READ, win32con.FILE_SHARE_READ, None, win32con.OPEN_EXISTING, 0, None)):
            yield Path(portable)
    monkeypatch.setattr(windows_merge, 'trusted_engine', named_engine)
    assert windows_merge.engine_version() is not None, 'the named test engine is outside the supported series'
    return Path(portable)


def write(path, vault):
    buffer = io.BytesIO()
    vault.save(buffer)
    if path.exists():
        path.unlink()
    security.write_new(path, buffer.getvalue())


def disk(path, keyfile=None):
    return PyKeePass(io.BytesIO(path.read_bytes()), password=MASTER, keyfile=str(keyfile) if keyfile else None)


def tombstone(vault, obj, stamp):
    deleted = etree.SubElement(vault.tree.find('./Root/DeletedObjects'), 'DeletedObject')
    etree.SubElement(deleted, 'UUID').text = obj._element.findtext('UUID')
    etree.SubElement(deleted, 'DeletionTime').text = vault._encode_time(stamp)
    obj.delete()


def base_vault(keyfile=None):
    vault = create_database(io.BytesIO(), password=MASTER, keyfile=io.BytesIO(keyfile) if keyfile else None)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value = 1
    params['M'].value = 1024 * 1024
    vault.kdbx.header.value.minor_version = 1
    group = vault.add_group(vault.root_group, 'Synthetic group')
    deleted_group = vault.add_group(vault.root_group, 'Delete empty group')
    deleted_group.mtime = BASE_TIME
    for title in ('Shared', 'Delete me', 'Edit after deletion'):
        entry = vault.add_entry(group, title, 'synthetic-account', SECRET)
        entry.mtime = BASE_TIME
    vault.database_name = 'Synthetic target metadata'
    buffer = io.BytesIO()
    vault.save(buffer)
    return buffer.getvalue()


@pytest.fixture(scope='module')
def base():
    return base_vault()


def edited(data, change, keyfile=None):
    vault = PyKeePass(io.BytesIO(data), password=MASTER, keyfile=io.BytesIO(keyfile) if keyfile else None)
    change(vault)
    buffer = io.BytesIO()
    vault.save(buffer)
    return buffer.getvalue()


@pytest.fixture
def pair(private_dir, base):
    target, source = private_dir / 'target.kdbx', private_dir / 'source.kdbx'
    security.write_new(target, edited(base, lambda v: v.add_entry(v.root_group, 'Left only', 'left', SECRET,
                                                                  url='https://synthetic.test')))
    security.write_new(source, edited(base, lambda v: v.add_entry(v.root_group, 'Right only', 'right', SECRET)))
    broker = Broker(open_vault_with_password(target, MASTER), object())
    return broker, target, source


def merge(pair, **options):
    broker, _, source = pair
    return broker.dispatch({'action': 'merge', 'source': str(source), 'operation_id': uuid.uuid4().hex, **options})


def bundle(result):
    return Path(result['receipt_path']).parent


def assert_private(path, *, directory=False):
    with security.checked_handle(path, directory=directory):
        pass


def test_status_reports_the_engine_and_every_merge_capability(pair, engine):
    broker, _, _ = pair
    status = broker.dispatch({'action': 'ping'})
    assert status['merge_available'] is True and status['merge_engine'].startswith('keepassxc-cli 2.7.')
    assert status['merge_same_credentials_only'] and status['merge_refresh_target_supported']
    assert status['merge_preserve_conflicts_supported'] and status['merge_preservation_policy'] == 'capsule-v1'
    assert status['merge_active_verification'] == 'semantic-v1' and status['admission_supported'] is True
    assert status['admission_policy'] == admission.POLICY and status['admission_group_protocol'] == 2


def test_diverged_round_trip_preview_repeat_and_receipt(pair, capsys, caplog):
    broker, target, source = pair
    original, incoming = target.read_bytes(), source.read_bytes()
    selected = broker.dispatch({'action': 'search', 'query': 'Shared'})['entries'][0]
    checked = merge(pair, check=True)
    assert checked['state'] == 'checked' and checked['changed'], checked
    assert target.read_bytes() == original and source.read_bytes() == incoming
    assert not broker.dispatch({'action': 'search', 'query': 'Right only'})['entries']
    result = merge(pair)
    assert result['ok'] and result['state'] == 'saved', result
    assert {e.title for e in disk(target).entries} >= {'Left only', 'Right only', 'Shared'}
    assert broker.dispatch({'action': 'search', 'query': 'Right only'})['entries']
    # A merge is a new vault revision: earlier handles no longer fill.
    assert not broker.dispatch({'action': 'fill', 'handle': selected['handle'], 'mode': 'username',
                                'target': '0' * 64, 'target_protocol': 1})['ok']
    assert source.read_bytes() == incoming
    files = bundle(result)
    assert (files / 'target.kdbx').read_bytes() == original
    assert (files / 'source.kdbx').read_bytes() == incoming
    assert (files / 'candidate.kdbx').read_bytes() == target.read_bytes()
    assert_private(files, directory=True)
    for path in files.iterdir():
        assert_private(path)
        assert MASTER.encode() not in path.read_bytes() and SECRET.encode() not in path.read_bytes()
    # The replaced vault stays private and has no leftover staging file.
    assert_private(target)
    assert not list(target.parent.glob('*.replace'))
    saved = target.read_bytes()
    again = merge(pair)
    assert again['ok'] and again['state'] == 'unchanged' and not again['changed'], again
    assert target.read_bytes() == saved
    # Reusing a known operation ID retrieves its receipt, with no second save.
    assert merge(pair, operation_id=result['operation_id']) == result
    assert broker.dispatch({'action': 'merge-status', 'operation_id': result['operation_id']}) == result
    assert json.loads(Path(result['receipt_path']).read_text())['state'] == 'saved'
    assert MASTER not in json.dumps(result) + capsys.readouterr().out + caplog.text
    # A password save after the merge uses the adopted state.
    assert broker.dispatch({'action': 'ping'})['writes_available'] is False  # No private page in this test.
    assert not broker.dispatch({'action': 'ping'})['recovery_required']


def test_newest_edit_history_and_deletions_follow_keepass_rules(private_dir, base):
    target, source = private_dir / 'target.kdbx', private_dir / 'source.kdbx'

    def local(vault):
        shared = vault.find_entries(title='Shared', first=True)
        shared.save_history()
        shared.password = 'synthetic-local-older'
        shared.mtime = BASE_TIME + timedelta(days=1)

    def remote(vault):
        shared = vault.find_entries(title='Shared', first=True)
        shared.save_history()
        shared.password = 'synthetic-remote-newer'
        shared.mtime = BASE_TIME + timedelta(days=2)
        shared.set_custom_property('Synthetic field', 'preserved', protect=True)
        shared.add_attachment(vault.add_binary(b'synthetic attachment'), 'synthetic.txt')
        tombstone(vault, vault.find_entries(title='Delete me', first=True), BASE_TIME + timedelta(days=4))
        tombstone(vault, vault.find_groups(name='Delete empty group', first=True), BASE_TIME + timedelta(days=4))
        tombstone(vault, vault.find_entries(title='Edit after deletion', first=True), BASE_TIME + timedelta(days=4))

    def revive(vault):
        local(vault)
        revived = vault.find_entries(title='Edit after deletion', first=True)
        revived.save_history()
        revived.password = 'synthetic-edit-newer-than-deletion'
        revived.mtime = BASE_TIME + timedelta(days=5)
    security.write_new(target, edited(base, revive))
    security.write_new(source, edited(base, remote))
    broker = Broker(open_vault_with_password(target, MASTER), object())
    result = merge((broker, target, source))
    assert result['ok'] and result['state'] == 'saved', result
    merged = disk(target)
    shared = merged.find_entries(title='Shared', first=True)
    assert shared.password == 'synthetic-remote-newer'
    assert {'synthetic-local-older', SECRET} <= {version.password for version in shared.history}
    assert shared.get_custom_property('Synthetic field') == 'preserved'
    assert shared.attachments[0].data == b'synthetic attachment'
    assert merged.find_entries(title='Delete me', first=True) is None
    assert merged.find_groups(name='Delete empty group', first=True) is None
    # An edit newer than its deletion survives, and the tombstones are kept.
    assert merged.find_entries(title='Edit after deletion', first=True).password == 'synthetic-edit-newer-than-deletion'
    assert len(merged.tree.findall('./Root/DeletedObjects/DeletedObject')) == 3
    assert result['after']['deletions'] == 3


def test_equal_second_conflict_fails_closed_then_preservation_keeps_both(pair):
    broker, target, source = pair
    source_bytes = edited(source.read_bytes(), lambda v: setattr(v.find_entries(title='Shared', first=True),
                                                                 'password', 'synthetic-ambiguous'))
    source.unlink()
    security.write_new(source, source_bytes)
    before = target.read_bytes()
    result = merge(pair)
    assert not result['ok'] and 'same-second' in result['error'], result
    assert target.read_bytes() == before
    assert (bundle(result) / 'target.kdbx').read_bytes() == before
    assert not (bundle(result) / 'candidate.kdbx').exists()
    # The explicit reconciliation keeps every logical version in the vault.
    preserved = merge(pair, refresh_target=True, preserve_conflicts=True, active_verification='semantic-v1')
    assert preserved['ok'] and preserved['state'] == 'saved', preserved
    assert preserved['preservation_policy'] == 'capsule-v1' and preserved['active_verification'] == 'semantic-v1'
    assert preserved['preserved_versions'] >= 2
    merged = disk(target)
    # The current disk target wins an active timestamp tie.
    assert merged.find_entries(title='Shared', first=True).password == SECRET
    assert preserved['after']['archived_versions'] >= 1
    assert versions.archives(merged)


@pytest.mark.parametrize('damage', ['different-key', 'invalid-file', 'hard-link', 'same-file', 'public-source',
                                    'public-parent', 'missing', 'relative', 'directory'])
def test_invalid_source_preserves_target(pair, private_dir, damage):
    broker, target, source = pair
    before = target.read_bytes()
    request_source = str(source)
    if damage == 'different-key':
        other = create_database(io.BytesIO(), password='another synthetic master')
        source.unlink()
        write(source, other)
    elif damage == 'invalid-file':
        source.unlink()
        security.write_new(source, b'synthetic invalid encrypted database')
    elif damage == 'hard-link':
        os.link(source, private_dir / 'second-name.kdbx')
    elif damage == 'same-file':
        request_source = str(target).upper()
    elif damage == 'public-source':
        win32security.SetFileSecurity(str(source), win32security.DACL_SECURITY_INFORMATION,
                                      win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PUBLIC, 1))
    elif damage == 'public-parent':
        folder = private_dir / 'shared'
        win32file.CreateDirectory(str(folder), security.private_attributes(directory=True))
        moved = folder / 'source.kdbx'
        security.write_new(moved, source.read_bytes())
        win32security.SetFileSecurity(str(folder), win32security.DACL_SECURITY_INFORMATION,
                                      win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PUBLIC, 1))
        request_source = str(moved)
    elif damage == 'missing':
        source.unlink()
    elif damage == 'relative':
        request_source = 'source.kdbx'
    elif damage == 'directory':
        request_source = str(private_dir)
    result = broker.dispatch({'action': 'merge', 'source': request_source, 'operation_id': uuid.uuid4().hex})
    assert not result['ok'], result
    assert MASTER not in json.dumps(result)
    assert target.read_bytes() == before
    assert not broker.dispatch({'action': 'ping'})['recovery_required']
    assert broker.dispatch({'action': 'search', 'query': 'Left only'})['entries']


def test_stale_target_needs_explicit_refresh_and_keeps_the_external_edit(pair):
    broker, target, source = pair
    external = edited(target.read_bytes(), lambda v: v.add_entry(v.root_group, 'External only', 'external', SECRET))
    target.unlink()
    security.write_new(target, external)
    result = merge(pair)
    assert not result['ok'] and 'explicit --refresh-target' in result['error'], result
    assert target.read_bytes() == external
    refreshed = merge(pair, refresh_target=True)
    assert refreshed['ok'] and refreshed['state'] == 'saved' and refreshed['target_refreshed'], refreshed
    assert {e.title for e in disk(target).entries} >= {'Left only', 'Right only', 'External only', 'Shared'}
    files = bundle(refreshed)
    assert (files / 'target.kdbx').read_bytes() == external
    assert (files / 'broker.kdbx').exists() and (files / 'reconciled.kdbx').exists()
    assert broker.dispatch({'action': 'search', 'query': 'External only'})['entries']


def test_unchanged_external_file_is_adopted_by_refresh(pair):
    broker, target, source = pair
    # The source already equals the external target: nothing to replace.
    external = edited(target.read_bytes(), lambda v: v.add_entry(v.root_group, 'External only', 'external', SECRET))
    for path in (target, source):
        path.unlink()
        security.write_new(path, external)
    selected = broker.dispatch({'action': 'search', 'query': 'Shared'})['entries'][0]
    result = merge(pair, refresh_target=True)
    assert result['ok'] and result['target_refreshed'], result
    assert broker.dispatch({'action': 'search', 'query': 'External only'})['entries']
    assert not broker.dispatch({'action': 'fill', 'handle': selected['handle'], 'mode': 'username',
                                'target': '0' * 64, 'target_protocol': 1})['ok']
    assert not broker.dispatch({'action': 'ping'})['recovery_required']


def test_target_or_source_changed_during_the_engine_is_not_overwritten(pair, monkeypatch):
    broker, target, source = pair
    real = windows_merge.run_engine
    for victim in (target, source):
        changed = edited(victim.read_bytes(), lambda v: v.add_entry(v.root_group, 'Raced ' + victim.name, 'race', SECRET))

        def racing(bundle, vault, key_path, **options):
            real(bundle, vault, key_path, **options)
            victim.unlink()
            security.write_new(victim, changed)
        monkeypatch.setattr(windows_merge, 'run_engine', racing)
        result = merge(pair)
        assert not result['ok'] and result['state'] == 'failed', result
        assert victim.read_bytes() == changed
        monkeypatch.setattr(windows_merge, 'run_engine', real)
        if victim is target:
            # Reconcile explicitly before the second race.
            assert merge(pair, refresh_target=True)['ok']


@pytest.mark.parametrize('failure', ['engine', 'reopen', 'public-candidate', 'snapshot', 'stage', 'replace',
                                     'replace-after', 'receipt'])
def test_save_faults_never_claim_success_or_leak(pair, monkeypatch, capsys, caplog, failure):
    broker, target, source = pair
    before, incoming = target.read_bytes(), source.read_bytes()

    def fail(*args, **kwargs):
        raise OSError(MASTER + SECRET)
    real_engine, real_write, real_replace = windows_merge.run_engine, security.write_new, windows_merge.replace
    if failure == 'engine':
        monkeypatch.setattr(windows_merge, 'run_engine', fail)
    elif failure in {'reopen', 'public-candidate'}:
        def corrupt(files, vault, key_path, **options):
            real_engine(files, vault, key_path, **options)
            candidate = Path(files) / 'candidate.kdbx'
            if failure == 'reopen':
                candidate.unlink()
                real_write(candidate, b'synthetic invalid candidate')
            else:
                win32security.SetFileSecurity(str(candidate), win32security.DACL_SECURITY_INFORMATION,
                                              win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PUBLIC, 1))
        monkeypatch.setattr(windows_merge, 'run_engine', corrupt)
    elif failure in {'snapshot', 'stage'}:
        def fault_write(path, data):
            if Path(path).name == 'source.kdbx' and failure == 'snapshot' or str(path).endswith('.replace') and failure == 'stage':
                fail()
            return real_write(path, data)
        monkeypatch.setattr(security, 'write_new', fault_write)
    else:
        def fault_replace(staged, destination):
            if Path(destination) == target:
                if failure == 'replace':
                    fail()
                real_replace(staged, destination)
                if failure == 'replace-after':
                    fail()
                if failure == 'receipt':
                    monkeypatch.setattr(windows_merge.WindowsMergeManager, '_receipt', staticmethod(fail))
            else:
                real_replace(staged, destination)
        monkeypatch.setattr(windows_merge, 'replace', fault_replace)
    result = merge(pair)
    assert not result['ok'], result
    assert source.read_bytes() == incoming
    assert MASTER not in json.dumps(result) + capsys.readouterr().out + caplog.text
    assert SECRET not in json.dumps(result) + caplog.text
    if failure in {'replace-after', 'receipt'}:
        assert result['state'] == 'uncertain'
        assert broker.dispatch({'action': 'ping'})['recovery_required']
        assert not broker.dispatch({'action': 'search', 'query': 'Shared'})['ok']
        assert (bundle(result) / 'target.kdbx').read_bytes() == before
        assert disk(target).find_entries(title='Right only', first=True)
        # The block survives a restart; the retained files stay readable.
        monkeypatch.undo()
        restarted = Broker(open_vault_with_password(target, MASTER), object())
        assert restarted.dispatch({'action': 'ping'})['recovery_required'] is True
        status = restarted.dispatch({'action': 'merge-status', 'operation_id': result['operation_id']})
        assert status['state'] == 'uncertain' and not status['ok']
    else:
        assert result['state'] == 'failed' and target.read_bytes() == before
        assert broker.vault.find_entries(title='Right only', first=True) is None
        assert not broker.dispatch({'action': 'ping'})['recovery_required']
    assert not list(target.parent.glob('*.replace'))


def test_disk_lock_and_in_process_concurrency(pair, monkeypatch):
    broker, target, _ = pair
    store = broker.vault._akdbx_store
    with security.trusted_directory(target.parent):
        with store._advisory_lock():
            assert 'busy' in merge(pair)['error']
    entered, release = threading.Event(), threading.Event()
    real = windows_merge.run_engine

    def waiting(files, vault, key_path, **options):
        entered.set()
        assert release.wait(20)
        real(files, vault, key_path, **options)
    monkeypatch.setattr(windows_merge, 'run_engine', waiting)
    results = []
    thread = threading.Thread(target=lambda: results.append(merge(pair)))
    thread.start()
    try:
        assert entered.wait(20)
        assert 'busy' in merge(pair)['error']
        # A password save also waits for this lock; it does not corrupt the merge.
        assert broker.dispatch({'action': 'ping'})['ok']
    finally:
        release.set()
        thread.join(60)
    assert results[0]['ok'], results


def test_interrupted_merge_blocks_after_restart_and_receipt_stays_readable(pair, monkeypatch):
    broker, target, _ = pair
    real = windows_merge.WindowsMergeManager._receipt

    def interrupted(files, value):
        real(files, value)
        if value['state'] == 'prepared':
            raise KeyboardInterrupt('synthetic interruption')
    monkeypatch.setattr(windows_merge.WindowsMergeManager, '_receipt', staticmethod(interrupted))
    before = target.read_bytes()
    operation_id = uuid.uuid4().hex
    with pytest.raises(KeyboardInterrupt):
        merge(pair, operation_id=operation_id)
    assert target.read_bytes() == before
    restarted = Broker(open_vault_with_password(target, MASTER), object())
    assert restarted.dispatch({'action': 'ping'})['recovery_required']
    status = restarted.dispatch({'action': 'merge-status', 'operation_id': operation_id})
    assert status['state'] == 'uncertain' and not status['ok']
    assert (bundle(status) / 'candidate.kdbx').exists()
    assert not restarted.dispatch({'action': 'search'})['ok']
    # Refresh is reconciliation, never an override for an unresolved operation.
    for blocked in (broker, restarted):
        retry = blocked.dispatch({'action': 'merge', 'source': str(pair[2]), 'operation_id': uuid.uuid4().hex,
                                  'refresh_target': True})
        assert not retry['ok'] and retry['error'] == 'save outcome uncertain; restart and unlock', retry
    assert target.read_bytes() == before
    # A locked broker still reads the durable receipt by its vault path.
    locked = Broker(None, object())
    locked.merges.database = target
    assert locked.merges.status(operation_id)['state'] == 'uncertain'


def test_finished_merge_folder_that_another_user_could_change_blocks_use(pair):
    broker, target, _ = pair
    result = merge(pair, check=True)
    assert result['ok'], result
    assert not Broker(open_vault_with_password(target, MASTER), object()).dispatch({'action': 'ping'})['recovery_required']
    win32security.SetFileSecurity(str(bundle(result)), win32security.DACL_SECURITY_INFORMATION,
                                  win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PUBLIC, 1))
    # Its receipt can no longer be trusted, so it cannot prove a finished state.
    reopened = Broker(open_vault_with_password(target, MASTER), object())
    assert reopened.dispatch({'action': 'ping'})['recovery_required']
    assert not reopened.dispatch({'action': 'search'})['ok']
    status = reopened.dispatch({'action': 'merge-status', 'operation_id': result['operation_id']})
    assert not status['ok'] and 'unsafe merge receipt' in status['error']


def test_shared_keyfile_is_used_from_its_own_file_and_a_changed_key_is_refused(private_dir, monkeypatch):
    key = b'synthetic-merge-key-material-only \x00\x01'
    keyfile = private_dir / 'synthetic.key'
    security.write_new(keyfile, key)
    base = base_vault(key)
    target, source = private_dir / 'target.kdbx', private_dir / 'source.kdbx'
    security.write_new(target, edited(base, lambda v: v.add_entry(v.root_group, 'Left only', 'left', SECRET), key))
    security.write_new(source, edited(base, lambda v: v.add_entry(v.root_group, 'Right only', 'right', SECRET), key))
    broker = Broker(open_vault_with_password(target, MASTER, keyfile), object())
    seen = []
    real = subprocess.run

    def recording(arguments, **options):
        seen.append((list(arguments), dict(options)))
        return real(arguments, **options)
    monkeypatch.setattr(windows_merge.subprocess, 'run', recording)
    result = merge((broker, target, source))
    assert result['ok'] and result['state'] == 'saved', result
    arguments, options = seen[-1]
    assert arguments[arguments.index('--key-file') + 1] == str(keyfile)
    # No secret in the arguments or environment; the password goes to stdin only.
    assert MASTER not in ' '.join(arguments) and set(options['env']) == {'SystemRoot'}
    assert options['stdout'] == options['stderr'] == subprocess.DEVNULL
    assert {e.title for e in disk(target, keyfile).entries} >= {'Left only', 'Right only'}
    assert sorted(p.name for p in private_dir.iterdir() if p.suffix == '.key') == ['synthetic.key']
    # A key file changed on disk is not the key that this broker holds.
    newer = edited(source.read_bytes(), lambda v: v.add_entry(v.root_group, 'Later', 'later', SECRET), key)
    source.unlink()
    security.write_new(source, newer)
    keyfile.unlink()
    security.write_new(keyfile, b'another synthetic key')
    before = target.read_bytes()
    refused = merge((broker, target, source))
    assert not refused['ok'] and target.read_bytes() == before, refused


def test_line_break_master_password_is_refused_without_running_the_engine(pair, monkeypatch):
    _, target, source = pair
    password = MASTER + '\n'
    for path in (target, source):
        vault = disk(path)
        vault.password = password
        write(path, vault)
    broker = Broker(open_vault_with_password(target, password), object())
    assert broker.dispatch({'action': 'ping'})['merge_available']  # The version probe ran already.
    monkeypatch.setattr(windows_merge.subprocess, 'run', lambda *a, **k: pytest.fail('engine ran'))
    before = target.read_bytes()
    result = merge((broker, target, source))
    assert not result['ok'] and 'line-compatible' in result['error']
    assert target.read_bytes() == before


def test_engine_timeout_discards_output_and_preserves_inputs(pair, monkeypatch, capsys, caplog):
    broker, target, source = pair
    before = target.read_bytes()
    assert broker.dispatch({'action': 'ping'})['merge_available']  # The version probe ran already.

    def timeout(arguments, **options):
        raise subprocess.TimeoutExpired(arguments, 1, output=MASTER.encode(), stderr=SECRET.encode())
    monkeypatch.setattr(windows_merge.subprocess, 'run', timeout)
    result = merge(pair)
    assert not result['ok'] and result['error'] == 'merge engine failed; target not replaced'
    assert target.read_bytes() == before
    assert MASTER not in json.dumps(result) + capsys.readouterr().out + caplog.text


def test_unsupported_engine_version_fails_closed(pair, monkeypatch):
    broker, target, _ = pair
    for version in (b'2.7.9\r\n', b'2.8.0\r\n', b'2.7.10-snapshot\r\n', b'\xff'):
        class Result:
            stdout = version
        monkeypatch.setattr(windows_merge.subprocess, 'run', lambda *a, **k: Result())
        assert windows_merge.engine_version() is None
    manager = windows_merge.WindowsMergeManager(broker)
    monkeypatch.setattr(windows_merge, 'engine_version', lambda: None)
    assert manager.capabilities()['merge_available'] is False


def test_pending_generated_password_is_invalidated_by_a_merge(pair):
    broker, target, _ = pair
    broker.writes.public_base = 'https://localhost:9443'
    selected = broker.dispatch({'action': 'search', 'query': 'Left only'})['entries'][0]
    pending = broker.dispatch({'action': 'generate-password', 'handle': selected['handle'],
                               'metadata': {k: selected[k] for k in ('title', 'username', 'url', 'group')}})
    assert pending['ok'], pending
    assert merge(pair)['ok']
    assert broker.dispatch({'action': 'write-status', 'write_handle': pending['write_handle']})['state'] == 'failed'


# Snapshot admission ---------------------------------------------------------

@pytest.fixture
def case(private_dir, base):
    folder, snapshots = private_dir / 'vault', private_dir / 'snapshots'
    for path in (folder, snapshots):
        win32file.CreateDirectory(str(path), security.private_attributes(directory=True))
    target, source = folder / 'target.kdbx', private_dir / 'incoming.kdbx'
    vault = PyKeePass(io.BytesIO(base), password=MASTER)
    versions.ensure(vault, versions.collect([vault], capture=True))
    write(target, vault)
    security.write_new(source, target.read_bytes())
    broker = Broker(open_vault_with_password(target, MASTER), object())
    return broker, target, source, snapshots


def admit(case, **options):
    broker, target, source, snapshots = case
    return broker.dispatch({'action': 'admit', 'source': str(source), 'snapshot_directory': str(snapshots),
                            'policy': admission.POLICY, 'verification': admission.VERIFICATION,
                            'operation_id': uuid.uuid4().hex, **options})


def newer(source, *, password='synthetic newer phone value', day=2):
    def change(vault):
        entry = vault.find_entries(title='Shared', first=True)
        entry.save_history()
        entry.password = password
        entry.mtime = BASE_TIME + timedelta(days=day)
    data = edited(source.read_bytes(), change)
    source.unlink()
    security.write_new(source, data)


def test_admission_keeps_exact_bytes_and_external_snapshots(case, caplog, capsys):
    broker, target, source, snapshots = case
    before = target.read_bytes()
    handle = broker.dispatch({'action': 'search', 'query': 'Shared'})['entries'][0]['handle']
    newer(source)
    incoming = source.read_bytes()
    ledger = versions.archives(broker.vault)
    checked = admit(case, check=True)
    assert checked['state'] == 'checked' and checked['exact_bytes'], checked
    assert target.read_bytes() == before
    result = admit(case)
    assert result['ok'] and result['state'] == 'saved', result
    assert result['policy'] == admission.POLICY and result['verification'] == admission.VERIFICATION
    assert result['group_protocol'] == 2 and result['group_verification'] == admission.GROUP_VERIFICATION
    assert target.read_bytes() == incoming == source.read_bytes()
    assert broker.vault.find_entries(title='Shared', first=True).password == 'synthetic newer phone value'
    assert not broker.dispatch({'action': 'fill', 'handle': handle, 'mode': 'username',
                                'target': '0' * 64, 'target_protocol': 1})['ok']
    assert versions.archives(disk(target)) == ledger
    for name, data in (('target.kdbx', before), ('broker.kdbx', before), ('source.kdbx', incoming),
                       ('candidate.kdbx', incoming)):
        assert (bundle(result) / name).read_bytes() == data
    assert bundle(result).parent == snapshots
    # No encrypted original is placed beside the canonical vault.
    assert not [p for p in target.parent.iterdir() if 'akdbx-merge' in p.name]
    locator = json.loads((target.parent / ('.' + target.name + '.akdbx-admission.json')).read_text())
    assert locator == {'snapshot_directory': str(snapshots), 'policy': admission.POLICY}
    for path in bundle(result).iterdir():
        assert_private(path)
        assert MASTER.encode() not in path.read_bytes() and SECRET.encode() not in path.read_bytes()
    assert admit(case, operation_id=result['operation_id']) == result
    assert broker.dispatch({'action': 'merge-status', 'operation_id': result['operation_id']}) == result
    assert admit(case)['state'] == 'unchanged'
    response = json.dumps(result) + caplog.text + capsys.readouterr().out
    for secret in (MASTER, SECRET, 'Shared', 'synthetic newer phone value'):
        assert secret not in response


@pytest.mark.parametrize('change', ['missing', 'older', 'if-match', 'wrong-key'])
def test_admission_refusal_preserves_the_canonical_file(case, change):
    broker, target, source, snapshots = case
    before = target.read_bytes()
    options = {}
    if change == 'missing':
        data = edited(source.read_bytes(), lambda v: v.delete_entry(v.find_entries(title='Shared', first=True)))
        source.unlink()
        security.write_new(source, data)
    elif change == 'older':
        newer(source, day=-1)
    elif change == 'if-match':
        newer(source)
        options['if_match'] = '0' * 64
    else:
        source.unlink()
        write(source, create_database(io.BytesIO(), password='another synthetic master'))
    result = admit(case, **options)
    assert not result['ok'] and result['state'] == 'failed', result
    assert target.read_bytes() == before
    assert not broker.dispatch({'action': 'ping'})['recovery_required']
    assert broker.dispatch({'action': 'search', 'query': 'Shared'})['entries']
    if change in {'missing', 'older'}:
        # Fixed aggregate categories only; no record identity or field value.
        assert result['verification_diagnostics'] and 'Shared' not in json.dumps(result)
        # The refused inputs stay in the external snapshot folder.
        assert (bundle(result) / 'source.kdbx').read_bytes() == source.read_bytes()


@pytest.mark.parametrize('unsafe', ['public-snapshots', 'inside-vault', 'rebind', 'missing-locator-target',
                                    'relative', 'same-file', 'merge-options', 'missing-directory'])
def test_snapshot_binding_and_identity_guards(case, private_dir, unsafe):
    broker, target, source, snapshots = case
    newer(source)
    before = target.read_bytes()
    options = {}
    if unsafe == 'public-snapshots':
        win32security.SetFileSecurity(str(snapshots), win32security.DACL_SECURITY_INFORMATION,
                                      win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(PUBLIC, 1))
    elif unsafe == 'inside-vault':
        nested = target.parent / 'snapshots'
        win32file.CreateDirectory(str(nested), security.private_attributes(directory=True))
        options['snapshot_directory'] = str(nested)
    elif unsafe in {'rebind', 'missing-locator-target'}:
        assert admit(case, check=True)['ok']
        if unsafe == 'rebind':
            other = private_dir / 'other-snapshots'
            win32file.CreateDirectory(str(other), security.private_attributes(directory=True))
            options['snapshot_directory'] = str(other)
        else:
            # Lost external storage must not be treated as no interrupted work.
            os.rename(snapshots, private_dir / 'retained-snapshots')
    elif unsafe == 'relative':
        options['snapshot_directory'] = 'snapshots'
    elif unsafe == 'same-file':
        options['source'] = str(target)
    elif unsafe == 'merge-options':
        options['refresh_target'] = True
    else:
        options['snapshot_directory'] = str(private_dir / 'absent')
    result = admit(case, **options)
    assert not result['ok'], result
    assert target.read_bytes() == before
    if unsafe == 'missing-locator-target':
        restarted = Broker(open_vault_with_password(target, MASTER), object())
        assert restarted.dispatch({'action': 'ping'})['recovery_required']


def test_interrupted_admission_in_the_external_folder_blocks_after_restart(case, monkeypatch):
    broker, target, source, snapshots = case
    newer(source)
    real = windows_merge.WindowsMergeManager._receipt

    def interrupted(files, value):
        real(files, value)
        if value['state'] == 'prepared':
            raise KeyboardInterrupt('synthetic interruption')
    monkeypatch.setattr(windows_merge.WindowsMergeManager, '_receipt', staticmethod(interrupted))
    operation_id = uuid.uuid4().hex
    with pytest.raises(KeyboardInterrupt):
        admit(case, operation_id=operation_id)
    monkeypatch.undo()
    # The CLI option is not needed again: the locator beside the vault binds the folder.
    restarted = Broker(open_vault_with_password(target, MASTER), object())
    assert restarted.dispatch({'action': 'ping'})['recovery_required']
    status = restarted.dispatch({'action': 'merge-status', 'operation_id': operation_id})
    assert status['state'] == 'uncertain' and bundle(status).parent == snapshots


def test_installed_cli_merges_admits_and_reads_status_after_restart(case, native_https_config, engine, monkeypatch):
    """Real broker process, named pipe and private HTTPS unlock."""
    broker, target, source, snapshots = case
    if engine != windows_merge.engine_path():
        pytest.skip('a separate broker process needs the machine-installed engine')
    origin, certificate, key, submit = native_https_config
    newer(source)
    pipe = rpc.PREFIX + 'akdbx-test-' + uuid.uuid4().hex
    command = [sys.executable, '-m', 'akdbx.cli', '--socket', pipe, '--unlock-origin', origin]
    serve = [*command, 'serve', str(target), '--tls-cert', str(certificate), '--tls-key', str(key),
             '--notification-state', str(target.parent / 'unlock-notifications.json')]

    def run(*arguments, expect=0):
        result = subprocess.run([*command, *arguments], capture_output=True, text=True, timeout=120)
        assert result.returncode == expect, (arguments[0], result.returncode, result.stdout, result.stderr)
        assert MASTER not in result.stdout + result.stderr
        return json.loads(result.stdout)

    def started():
        server = subprocess.Popen(serve, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 15
        while subprocess.run([*command, 'status'], capture_output=True, timeout=10).returncode != 0:
            assert server.poll() is None and time.monotonic() < deadline, 'Windows CLI broker did not start'
            time.sleep(.05)
        return server
    server = started()
    try:
        locked = run('status')
        waiting = run('admit', str(source), '--policy', 'snapshot-admission-v1', '--snapshot-dir', str(snapshots),
                      '--check', expect=1)
        assert waiting['error'] == 'vault locked' and 'continuation' in waiting
        assert submit(locked['unlock_url'], {'password': MASTER})[0] == 200
        status = run('status')
        assert status['merge_available'] and status['admission_supported']
        checked = run('admit', str(source), '--policy', 'snapshot-admission-v1', '--snapshot-dir', str(snapshots), '--check')
        assert checked['state'] == 'checked' and checked['exact_bytes']
        saved = run('admit', str(source), '--policy', 'snapshot-admission-v1', '--snapshot-dir', str(snapshots))
        assert saved['state'] == 'saved' and target.read_bytes() == source.read_bytes()
        extra = target.parent.parent / 'extra.kdbx'
        security.write_new(extra, edited(target.read_bytes(), lambda v: v.add_entry(v.root_group, 'Merged by CLI', 'cli', SECRET)))
        merged = run('merge', str(extra), '--refresh-target', '--preserve-conflicts')
        assert merged['state'] == 'saved' and merged['active_verification'] == 'semantic-v1'
        assert run('search', 'Merged by CLI')['entries']
    finally:
        server.terminate()
        server.wait(timeout=10)
    server = started()
    try:
        # A restarted, still locked broker reads both durable receipts.
        assert run('merge-status', saved['operation_id'])['state'] == 'saved'
        assert run('merge-status', merged['operation_id'])['state'] == 'saved'
    finally:
        server.terminate()
        server.wait(timeout=10)
