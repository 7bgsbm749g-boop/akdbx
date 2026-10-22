"""External replacement reconciliation. All files and brokers are synthetic."""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pykeepass import PyKeePass

from agentic_kdbx import cli, merge as merging
from agentic_kdbx.broker import Broker, open_vault_with_password
from agentic_kdbx.persistence import VaultStore
from test_broker import RecordingTyper, running_broker
from test_merge import MASTER, SECRET, BASE_TIME, base, tombstone


@pytest.fixture
def refresh_case(tmp_path, base, request):
    keyfile = None
    if getattr(request, 'param', False):
        keyfile = tmp_path / 'synthetic.key'
        keyfile.write_bytes(b'synthetic-refresh-key-material-only')
    target = tmp_path / 'target.kdbx'
    source = tmp_path / 'incoming.kdbx'
    shutil.copyfile(base, target)
    if keyfile:
        initial = PyKeePass(target, password=MASTER)
        initial.keyfile = str(keyfile)
        initial.save()
    broker = Broker(open_vault_with_password(target, MASTER, keyfile), RecordingTyper())
    phone = PyKeePass(base, password=MASTER)
    phone.add_entry(phone.root_group, 'Broker only', 'broker-account', SECRET, url='https://broker.test')
    shared = phone.find_entries(title='Shared', first=True)
    shared.password = 'synthetic-broker-conflict'
    shared.mtime = BASE_TIME + timedelta(days=1)
    tombstone(phone, phone.find_entries(title='Delete me', first=True), BASE_TIME + timedelta(days=4))
    tombstone(phone, phone.find_groups(name='Delete empty group', first=True), BASE_TIME + timedelta(days=4))
    phone.keyfile = str(keyfile) if keyfile else None
    phone_path = tmp_path / 'prior-phone-save.kdbx'
    phone.save(phone_path)
    first = broker.dispatch({'action': 'merge', 'source': str(phone_path), 'operation_id': uuid.uuid4().hex})
    assert first['state'] == 'saved', first
    broker_bytes = target.read_bytes()
    assert broker.vault._akdbx_store.verified_encrypted == broker_bytes
    external = PyKeePass(base, password=MASTER)
    external.add_entry(external.root_group, 'External only', 'external-account', SECRET)
    shared = external.find_entries(title='Shared', first=True)
    shared.password = 'synthetic-external-conflict'
    shared.mtime = BASE_TIME + timedelta(days=2)
    tombstone(external, external.find_entries(title='Edit after deletion', first=True), BASE_TIME + timedelta(days=4))
    external.keyfile = str(keyfile) if keyfile else None
    replacement = tmp_path / 'windows-replacement.kdbx'
    external.save(replacement)
    os.replace(replacement, target)
    incoming = PyKeePass(base, password=MASTER)
    incoming.add_entry(incoming.root_group, 'Incoming only', 'incoming-account', SECRET)
    shared = incoming.find_entries(title='Shared', first=True)
    shared.password = 'synthetic-incoming-conflict'
    shared.mtime = BASE_TIME + timedelta(days=3)
    shared.set_custom_property('Synthetic refresh field', 'preserved', protect=True)
    binary = incoming.add_binary(b'synthetic refresh attachment')
    shared.add_attachment(binary, 'synthetic-refresh.txt')
    revived = incoming.find_entries(title='Edit after deletion', first=True)
    revived.password = 'synthetic-edit-newer-than-deletion'
    revived.mtime = BASE_TIME + timedelta(days=5)
    incoming.keyfile = str(keyfile) if keyfile else None
    incoming.save(source)
    return SimpleNamespace(broker=broker, target=target, source=source, broker_bytes=broker_bytes,
                           external_bytes=target.read_bytes(), incoming_bytes=source.read_bytes(), keyfile=keyfile)


def refresh(case, **options):
    return case.broker.dispatch({'action': 'merge', 'source': str(case.source),
                                'operation_id': uuid.uuid4().hex, 'refresh_target': True, **options})


def opened(case, path):
    return PyKeePass(path, password=MASTER, keyfile=str(case.keyfile) if case.keyfile else None)


def bundle(result):
    return Path(result['receipt_path']).parent


def assert_three_inputs(case, vault):
    assert {e.title for e in vault.entries} >= {'Broker only', 'External only', 'Incoming only'}
    shared = vault.find_entries(title='Shared', first=True)
    assert shared.password == 'synthetic-incoming-conflict'
    assert {'synthetic-broker-conflict', 'synthetic-external-conflict', SECRET} <= {e.password for e in shared.history}
    assert shared.mtime == BASE_TIME + timedelta(days=3)
    assert shared.attachments[0].data == b'synthetic refresh attachment'
    assert shared.get_custom_property('Synthetic refresh field') == 'preserved'
    assert vault.find_entries(title='Delete me', first=True) is None
    assert vault.find_groups(name='Delete empty group', first=True) is None
    revived = vault.find_entries(title='Edit after deletion', first=True)
    assert revived.password == 'synthetic-edit-newer-than-deletion'
    assert any(h.password == SECRET for h in revived.history)
    assert len(vault.tree.findall('./Root/DeletedObjects/DeletedObject')) >= 3


def test_refresh_retains_all_three_inputs_preview_save_and_repeated_merge(refresh_case, capsys, caplog):
    case = refresh_case
    broker = case.broker
    store = broker.vault._akdbx_store
    original_vault, original_expected = broker.vault, store.expected
    default = refresh(case, refresh_target=False)
    assert not default['ok'] and 'target changed' in default['error']
    assert case.target.read_bytes() == case.external_bytes
    broker.writes.public_base = 'https://node.example:9443'
    selected = broker.dispatch({'action': 'search', 'query': 'Broker only'})['entries'][0]
    pending = broker.dispatch({'action': 'generate-password', 'handle': selected['handle'],
                               'metadata': {k: selected[k] for k in ('title', 'username', 'url', 'group')}})
    assert pending['ok']
    selected = broker.dispatch({'action': 'search', 'query': 'Broker only'})['entries'][0]
    checked = refresh(case, check=True)
    assert checked['ok'] and checked['state'] == 'checked' and checked['target_refreshed']
    assert broker.vault is original_vault and store.expected == original_expected
    assert store.verified_encrypted == case.broker_bytes
    assert selected['handle'] in broker._handles
    assert broker.writes.get(pending['write_handle']).state == 'pending'
    assert case.target.read_bytes() == case.external_bytes
    assert_three_inputs(case, opened(case, bundle(checked) / 'candidate.kdbx'))
    result = refresh(case)
    assert result['ok'] and result['state'] == 'saved' and result['refresh_target']
    assert_three_inputs(case, opened(case, case.target))
    assert_three_inputs(case, broker.vault)
    assert case.source.read_bytes() == case.incoming_bytes
    assert store.verified_encrypted == case.target.read_bytes()
    assert store.expected != original_expected
    assert broker.writes.get(pending['write_handle']).state == 'failed'
    assert broker.writes.get(pending['write_handle']).password is None
    assert selected['handle'] not in broker._handles
    assert (bundle(result) / 'broker.kdbx').read_bytes() == case.broker_bytes
    assert (bundle(result) / 'target.kdbx').read_bytes() == case.external_bytes
    assert (bundle(result) / 'source.kdbx').read_bytes() == case.incoming_bytes
    assert opened(case, bundle(result) / 'reconciled.kdbx').find_entries(title='Broker only', first=True)
    for path in bundle(result).iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert all(s.encode() not in path.read_bytes() for s in (MASTER, SECRET))
    repeated = refresh(case)
    # A source that still carries deleted entries can cause native add/delete
    # work again. The logical result and retained histories stay idempotent.
    assert repeated['ok'] and repeated['after'] == result['after'], repeated
    assert_three_inputs(case, opened(case, case.target))
    assert not repeated['target_refreshed']
    assert all(s not in json.dumps(result) + capsys.readouterr().out + caplog.text for s in (MASTER, SECRET))


@pytest.mark.parametrize('refresh_case', [True], indirect=True)
def test_refresh_shared_keyfile_uses_held_material(refresh_case):
    case = refresh_case
    result = refresh(case)
    assert result['ok'], result
    assert_three_inputs(case, opened(case, case.target))
    case.keyfile.write_bytes(b'synthetic changed key file')
    before = case.target.read_bytes()
    assert not refresh(case)['ok']
    assert case.target.read_bytes() == before


@pytest.mark.parametrize('damage', ['wrong-key', 'invalid-file'])
def test_bad_current_target_does_not_reset_broker_or_overwrite(refresh_case, damage, capsys, caplog):
    case = refresh_case
    store, vault = case.broker.vault._akdbx_store, case.broker.vault
    expected = store.expected
    if damage == 'wrong-key':
        wrong = opened(case, case.target)
        wrong.password = 'synthetic-unrelated-current-key'
        wrong.save()
    else:
        case.target.write_bytes(b'synthetic invalid external target')
    bad_bytes = case.target.read_bytes()
    result = refresh(case)
    assert not result['ok'] and 'cannot be opened with held credentials' in result['error']
    assert case.target.read_bytes() == bad_bytes and case.source.read_bytes() == case.incoming_bytes
    assert case.broker.vault is vault and store.expected == expected
    assert store.verified_encrypted == case.broker_bytes
    assert (bundle(result) / 'broker.kdbx').read_bytes() == case.broker_bytes
    assert not store.recovery_required
    assert MASTER not in json.dumps(result) + capsys.readouterr().out + caplog.text


@pytest.mark.parametrize('phase', ['broker', 'incoming'])
def test_external_race_during_each_native_stage_preserves_latest_target(refresh_case, monkeypatch, phase):
    case = refresh_case
    engine = merging.run_engine
    latest = opened(case, case.target)
    latest.add_entry(latest.root_group, 'Concurrent external entry', 'external', SECRET)
    latest_bytes = None
    def racing(bundle_path, vault, **kwargs):
        nonlocal latest_bytes
        engine(bundle_path, vault, **kwargs)
        if (kwargs.get('source_name') == 'broker.kdbx') == (phase == 'broker'):
            next_path = case.target.with_name('next-external.kdbx')
            latest.save(next_path)
            os.replace(next_path, case.target)
            latest_bytes = case.target.read_bytes()
    monkeypatch.setattr(merging, 'run_engine', racing)
    result = refresh(case)
    assert not result['ok'] and 'changed on disk' in result['error']
    assert case.target.read_bytes() == latest_bytes
    assert case.broker.vault._akdbx_store.verified_encrypted == case.broker_bytes
    assert (bundle(result) / 'target.kdbx').read_bytes() == case.external_bytes


@pytest.mark.parametrize('phase', ['broker', 'incoming', 'replace', 'durability', 'receipt'])
def test_refresh_faults_preserve_snapshots_and_truthful_state(refresh_case, monkeypatch, phase, capsys, caplog):
    case = refresh_case
    old_vault = case.broker.vault
    store = old_vault._akdbx_store
    def fail(*args, **kwargs):
        raise OSError(MASTER + SECRET)
    if phase in {'broker', 'incoming'}:
        engine = merging.run_engine
        def failed_engine(bundle_path, vault, **kwargs):
            if (kwargs.get('source_name') == 'broker.kdbx') == (phase == 'broker'):
                fail()
            return engine(bundle_path, vault, **kwargs)
        monkeypatch.setattr(merging, 'run_engine', failed_engine)
    else:
        replace = os.replace
        def failed_replace(src, dst, **kwargs):
            if dst == case.target.name:
                if phase == 'replace':
                    fail()
                replace(src, dst, **kwargs)
                if phase == 'durability':
                    monkeypatch.setattr(os, 'fsync', fail)
                if phase == 'receipt':
                    monkeypatch.setattr(merging.MergeManager, '_receipt', staticmethod(fail))
            else:
                replace(src, dst, **kwargs)
        monkeypatch.setattr(os, 'replace', failed_replace)
    result = refresh(case)
    assert not result['ok']
    for name, data in [('broker.kdbx', case.broker_bytes), ('target.kdbx', case.external_bytes), ('source.kdbx', case.incoming_bytes)]:
        assert (bundle(result) / name).read_bytes() == data
    if phase in {'durability', 'receipt'}:
        assert result['state'] == 'uncertain' and store.recovery_required
        assert not case.broker.dispatch({'action': 'search'})['ok']
    else:
        assert result['state'] == 'failed' and not store.recovery_required
        assert case.target.read_bytes() == case.external_bytes
        assert case.broker.vault is old_vault and store.verified_encrypted == case.broker_bytes
    assert case.source.read_bytes() == case.incoming_bytes
    output = capsys.readouterr()
    assert all(s not in json.dumps(result) + output.out + output.err + caplog.text for s in (MASTER, SECRET))


@pytest.mark.parametrize('state', ['prepared', 'uncertain', 'missing', 'invalid'])
def test_refresh_cannot_bypass_an_incomplete_prior_receipt(refresh_case, state):
    case = refresh_case
    store = case.broker.vault._akdbx_store
    prior = case.target.parent / ('.' + case.target.name + '.akdbx-merge-' + uuid.uuid4().hex)
    prior.mkdir(mode=0o700)
    if state != 'missing':
        receipt = prior / 'receipt.json'
        receipt.write_text('not valid JSON' if state == 'invalid' else json.dumps({'state': state}))
        receipt.chmod(0o600)
    result = refresh(case)
    assert not result['ok'] and 'recovery required' in result['error']
    assert store.recovery_required
    assert case.target.read_bytes() == case.external_bytes
    assert store.verified_encrypted == case.broker_bytes


@pytest.mark.parametrize('metadata_change', [False, True])
def test_unchanged_external_file_is_durably_adopted_and_invalidates_handles(refresh_case, metadata_change):
    case = refresh_case
    old_vault = case.broker.vault
    store = old_vault._akdbx_store
    prior_expected = store.expected
    replacement = case.target.with_name('identical-external.kdbx')
    replacement.write_bytes(case.broker_bytes)
    if metadata_change:
        v = opened(case, replacement)
        v.database_name = 'Synthetic external database setting'
        v.save()
    os.replace(replacement, case.target)
    external = case.target.read_bytes()
    case.source.write_bytes(external)
    handle = case.broker.dispatch({'action': 'search', 'query': 'Broker only'})['entries'][0]['handle']
    result = refresh(case)
    assert result['ok'] and result['state'] == 'unchanged' and result['target_refreshed']
    assert not result['changed'] and case.target.read_bytes() == external
    assert case.broker.vault is not old_vault and store.expected != prior_expected
    assert store.verified_encrypted == external and handle not in case.broker._handles
    if metadata_change:
        assert case.broker.vault.database_name == 'Synthetic external database setting'
    assert refresh(case, refresh_target=False)['ok']


def test_password_write_updates_the_retained_broker_image(refresh_case):
    case = refresh_case
    # Start from the verified broker state for a synthetic password save, then
    # simulate the same external Windows replacement once more.
    case.target.write_bytes(case.broker_bytes)
    case.broker.vault = open_vault_with_password(case.target, MASTER)
    store = case.broker.vault._akdbx_store
    def change(vault):
        entry = vault.find_entries(title='Broker only', first=True)
        entry.save_history()
        entry.password = 'synthetic-broker-password-write'
        entry.mtime = BASE_TIME + timedelta(days=20)
    case.broker.vault = store.commit(case.broker.vault, change)
    latest_verified = case.target.read_bytes()
    assert store.verified_encrypted == latest_verified
    replacement = case.target.with_name('windows-again.kdbx')
    replacement.write_bytes(case.external_bytes)
    os.replace(replacement, case.target)
    result = refresh(case)
    assert result['ok'], result
    assert (bundle(result) / 'broker.kdbx').read_bytes() == latest_verified
    assert opened(case, case.target).find_entries(title='Broker only', first=True).password == 'synthetic-broker-password-write'


def test_real_cli_reconciles_without_another_unlock(refresh_case, tmp_path):
    case = refresh_case
    socket = tmp_path / 'private' / 'rpc.sock'
    executable = Path(sys.executable).parent / 'akdbx'
    prefix = [str(executable), '--socket', str(socket)]
    def command(*args, expected=0):
        completed = subprocess.run([*prefix, *args], capture_output=True, text=True, timeout=30)
        assert completed.returncode == expected, completed.stderr
        assert all(s not in completed.stdout + completed.stderr for s in (MASTER, SECRET))
        return json.loads(completed.stdout)
    with running_broker(socket, case.broker):
        status = command('status')
        assert status['version'] == '0.5.0' and status['merge_refresh_target_supported']
        assert not command('merge', str(case.source), expected=1)['ok']
        checked = command('merge', str(case.source), '--refresh-target', '--check')
        assert checked['state'] == 'checked'
        result = command('merge', str(case.source), '--refresh-target')
        assert result['state'] == 'saved'
        assert command('merge-status', result['operation_id'])['state'] == 'saved'
        for title in ('Broker only', 'External only', 'Incoming only'):
            assert command('search', title)['entries']
    assert_three_inputs(case, opened(case, case.target))


def test_cli_refuses_old_broker_before_sending_refresh(monkeypatch, capsys):
    calls = []
    def old_broker(path, payload, **kwargs):
        calls.append(payload)
        return {'ok': True, 'version': '0.3.0', 'locked': False, 'merge_available': True}
    monkeypatch.setattr(cli, 'request', old_broker)
    assert cli.main(['merge', '/synthetic/source.kdbx', '--refresh-target']) == 1
    result = json.loads(capsys.readouterr().out)
    assert 'merge not sent' in result['error'] and calls == [{'action': 'ping'}]


@pytest.mark.parametrize('image', [None, b'synthetic invalid encrypted image'])
def test_missing_or_inconsistent_verified_image_is_not_reset(refresh_case, image):
    case = refresh_case
    store = case.broker.vault._akdbx_store
    expected = store.expected
    store.verified_encrypted = image
    result = refresh(case)
    assert not result['ok'] and 'verified broker image unavailable' in result['error']
    assert store.verified_encrypted == image and store.expected == expected
    assert case.target.read_bytes() == case.external_bytes


def test_ambiguous_broker_vs_external_edit_fails_before_native_dispatch(refresh_case, monkeypatch):
    case = refresh_case
    external = opened(case, case.target)
    external.find_entries(title='Shared', first=True).mtime = BASE_TIME + timedelta(days=1)
    external.save()
    before = case.target.read_bytes()
    def unexpected(*args, **kwargs):
        pytest.fail('ambiguous records reached native merge')
    monkeypatch.setattr(merging, 'run_engine', unexpected)
    result = refresh(case)
    assert not result['ok'] and 'same-second' in result['error']
    assert case.target.read_bytes() == before


def test_intermediate_reopen_and_preservation_checks_are_required(refresh_case, monkeypatch):
    case = refresh_case
    engine = merging.run_engine
    def lose_entry(bundle_path, vault, **kwargs):
        engine(bundle_path, vault, **kwargs)
        if kwargs.get('source_name') == 'broker.kdbx':
            candidate_path = bundle_path / 'candidate.kdbx'
            candidate = opened(case, candidate_path)
            candidate.delete_entry(candidate.find_entries(title='Broker only', first=True))
            candidate.save()
    monkeypatch.setattr(merging, 'run_engine', lose_entry)
    result = refresh(case)
    assert not result['ok'] and 'without a valid deletion' in result['error']
    assert case.target.read_bytes() == case.external_bytes
    assert case.broker.vault._akdbx_store.verified_encrypted == case.broker_bytes


def test_refresh_interruption_remains_blocked_without_reset(refresh_case, monkeypatch):
    case = refresh_case
    receipt = merging.MergeManager._receipt
    def interrupt(directory, value):
        receipt(directory, value)
        if value['state'] == 'prepared':
            raise KeyboardInterrupt
    monkeypatch.setattr(merging.MergeManager, '_receipt', staticmethod(interrupt))
    operation_id = uuid.uuid4().hex
    with pytest.raises(KeyboardInterrupt):
        refresh(case, operation_id=operation_id)
    store = case.broker.vault._akdbx_store
    assert store.recovery_required and store.verified_encrypted == case.broker_bytes
    assert case.target.read_bytes() == case.external_bytes
    status = case.broker.dispatch({'action': 'merge-status', 'operation_id': operation_id})
    assert not status['ok'] and status['state'] == 'uncertain'
    assert (bundle(status) / 'broker.kdbx').read_bytes() == case.broker_bytes
    restarted = Broker(open_vault_with_password(case.target, MASTER), RecordingTyper())
    assert restarted.dispatch({'action': 'ping'})['recovery_required']
    assert not refresh(SimpleNamespace(broker=restarted, source=case.source))['ok']


def test_refresh_source_race_and_concurrent_operation_are_rejected(refresh_case, monkeypatch):
    case = refresh_case
    engine = merging.run_engine
    entered, release = threading.Event(), threading.Event()
    def blocked(bundle_path, vault, **kwargs):
        if kwargs.get('source_name') == 'broker.kdbx':
            entered.set()
            assert release.wait(10)
        engine(bundle_path, vault, **kwargs)
        if not kwargs:
            case.source.write_bytes(case.incoming_bytes + b'synthetic external source change')
    monkeypatch.setattr(merging, 'run_engine', blocked)
    results = []
    worker = threading.Thread(target=lambda: results.append(refresh(case)))
    worker.start()
    try:
        assert entered.wait(10)
        assert 'busy' in refresh(case)['error']
    finally:
        release.set()
        worker.join(10)
    assert not results[0]['ok'] and 'changed on disk' in results[0]['error']
    assert case.target.read_bytes() == case.external_bytes


def test_refresh_request_is_strictly_opt_in(refresh_case):
    case = refresh_case
    result = refresh(case, refresh_target='true')
    assert not result['ok'] and 'invalid' in result['error']
    assert case.target.read_bytes() == case.external_bytes


@pytest.mark.parametrize('refresh_case', [True], indirect=True)
def test_keyfile_change_during_reconciliation_is_not_accepted(refresh_case, monkeypatch):
    case = refresh_case
    engine = merging.run_engine
    def changed_key(bundle_path, vault, **kwargs):
        engine(bundle_path, vault, **kwargs)
        if kwargs.get('source_name') == 'broker.kdbx':
            case.keyfile.write_bytes(b'synthetic key changed during native merge')
    monkeypatch.setattr(merging, 'run_engine', changed_key)
    result = refresh(case)
    assert not result['ok'] and 'key file changed' in result['error']
    assert case.target.read_bytes() == case.external_bytes
    assert case.broker.vault._akdbx_store.verified_encrypted == case.broker_bytes


def test_receipt_failure_after_unchanged_adoption_requires_recovery(refresh_case, monkeypatch):
    case = refresh_case
    replacement = case.target.with_name('same-revision-new-inode.kdbx')
    replacement.write_bytes(case.broker_bytes)
    os.replace(replacement, case.target)
    case.source.write_bytes(case.broker_bytes)
    receipt = merging.MergeManager._receipt
    def failed_receipt(directory, value):
        if value['state'] == 'unchanged':
            raise OSError(MASTER)
        receipt(directory, value)
    monkeypatch.setattr(merging.MergeManager, '_receipt', staticmethod(failed_receipt))
    result = refresh(case)
    assert not result['ok'] and result['state'] == 'uncertain'
    assert case.target.read_bytes() == case.broker_bytes
    assert case.broker.vault._akdbx_store.recovery_required
    assert MASTER not in json.dumps(result)
    assert not case.broker.dispatch({'action': 'search'})['ok']


def test_nonregular_replacement_at_unchanged_adoption_does_not_block_or_reset(refresh_case, monkeypatch):
    case = refresh_case
    replacement = case.target.with_name('same-image.kdbx')
    replacement.write_bytes(case.broker_bytes)
    os.replace(replacement, case.target)
    case.source.write_bytes(case.broker_bytes)
    ready = False
    receipt = merging.MergeManager._receipt
    real_open = os.open
    def prepared(directory, value):
        nonlocal ready
        receipt(directory, value)
        if value['state'] == 'prepared':
            ready = True
    def race_open(name, flags, *args, **kwargs):
        nonlocal ready
        if ready and name == case.target.name:
            assert flags & os.O_NONBLOCK
            ready = False
            case.target.unlink()
            os.mkfifo(case.target)
        return real_open(name, flags, *args, **kwargs)
    monkeypatch.setattr(merging.MergeManager, '_receipt', staticmethod(prepared))
    monkeypatch.setattr(os, 'open', race_open)
    result = refresh(case)
    assert not result['ok']
    assert stat.S_ISFIFO(case.target.stat().st_mode)
    assert case.broker.vault._akdbx_store.verified_encrypted == case.broker_bytes
    case.target.unlink()
