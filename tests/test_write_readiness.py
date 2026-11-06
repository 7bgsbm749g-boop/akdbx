"""Real permission/lock checks use only owned synthetic vaults and recording keys."""
import fcntl
import importlib
import io
import os
import shutil
import uuid
from datetime import datetime, timezone

import pytest
from pykeepass import PyKeePass, create_database

from akdbx import admission
from akdbx.broker import Broker, open_vault_with_password
from test_broker import RecordingTyper, target_request
from test_writes import MASTER, OLD, begin, commit, fills, reopened, template


def open_broker(path):
    broker = Broker(open_vault_with_password(path, MASTER), RecordingTyper())
    broker.writes.public_base = 'https://node.example:9443'
    return broker


@pytest.fixture
def vault_path(tmp_path, template):
    directory = tmp_path / 'vault'
    directory.mkdir(mode=0o700)
    path = directory / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    path.chmod(0o400)
    return path


@pytest.fixture(scope='module')
def keyed_template(tmp_path_factory):
    folder = tmp_path_factory.mktemp('keyed-readiness-template')
    key = folder / 'synthetic.key'
    key.write_bytes(bytes(range(32)))
    key.chmod(0o400)
    vault = create_database(io.BytesIO(), password=MASTER, keyfile=str(key))
    parameters = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    parameters['I'].value = 1
    parameters['M'].value = 1024 * 1024
    web = vault.add_group(vault.root_group, 'Web')
    entry = vault.add_entry(web, 'Synthetic site', 'synthetic-account', OLD,
                            url='https://example.test/login')
    entry.mtime = datetime(2020, 1, 1, tzinfo=timezone.utc)
    path = folder / 'synthetic.kdbx'
    vault.save(path)
    return path, key.read_bytes()


def keyed_broker(tmp_path, keyed_template, namespace, typer=None):
    template, material = keyed_template
    folder = tmp_path / 'vault'
    folder.mkdir(mode=0o700)
    path, key = folder / 'synthetic.kdbx', tmp_path / 'synthetic.key'
    shutil.copyfile(template, path)
    key.write_bytes(material)
    key.chmod(0o400)
    module = importlib.import_module(namespace + '.broker')
    broker = module.Broker(module.open_vault_with_password(path, MASTER, key),
                           typer or RecordingTyper())
    broker.writes.public_base = 'https://node.example:9443'
    return broker, path, key


def change_input(path, key, fault):
    if fault == 'key':
        key.chmod(0o600)
        key.write_bytes(bytes(reversed(range(32))))
        key.chmod(0o400)
    else:
        vault = PyKeePass(path, password=MASTER, keyfile=str(key))
        vault.find_entries(title='Synthetic site', first=True).notes = 'External edit retained'
        vault.save(path)


def prepare_generated(broker, action):
    if action == 'generate-password':
        return begin(broker, action)
    return broker.dispatch(dict(action=action, metadata=dict(title='New generated',
        username='signup-user', url='https://example.test/signup', group='Web')))


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('action', ['generate-password', 'generate-entry'])
@pytest.mark.parametrize('fault', ['key', 'target'])
@pytest.mark.parametrize('timing', ['before', 'staged', 'one-fill'])
@pytest.mark.parametrize('prior_failed_save', [False, True])
def test_stale_inputs_refuse_generated_resets_before_delivery(
    tmp_path, keyed_template, namespace, action, fault, timing, prior_failed_save,
):
    broker, path, key = keyed_broker(tmp_path, keyed_template, namespace)
    try:
        observed = broker.dispatch(dict(action='create-entry', metadata=dict(title='Observation',
            username='observer', url='https://observation.example.test', group='Web'))) if prior_failed_save else None
        prepared = None if timing == 'before' else prepare_generated(broker, action)
        references = [] if prepared is None else list(prepared['fill_handles'].values())
        if timing == 'one-fill':
            assert broker.dispatch(dict(action='fill-generated', handle=references.pop(0),
                target_url='https://example.test/reset', **target_request(broker)))['ok']
        prior_events = list(broker.typer.events)
        change_input(path, key, fault)
        before = path.read_bytes()
        if observed is not None:
            failed = broker.writes.submit(broker.writes.get(observed['write_handle']),
                                           'synthetic chosen', 'synthetic chosen', True)
            assert not failed['ok'] and ('key file changed' if fault == 'key' else 'vault changed') in failed['error']
        assert broker.dispatch(dict(action='ping'))['writes_available'] is False
        if prepared is None:
            assert not prepare_generated(broker, action)['ok']
        else:
            for reference in references:
                result = broker.dispatch(dict(action='fill-generated', handle=reference,
                    target_url='https://example.test/reset', **target_request(broker)))
                assert not result['ok'], result
            assert not commit(broker, prepared)['ok']
        assert not prepare_generated(broker, action)['ok']
        assert broker.typer.events == prior_events and path.read_bytes() == before
        saved = PyKeePass(path, password=MASTER, keyfile=io.BytesIO(keyed_template[1]))
        assert saved.find_entries(title='Synthetic site', first=True).password == OLD
        selected = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
        assert broker.dispatch(dict(action='fill', handle=selected['handle'], mode='password',
            **target_request(broker)))['ok']
        assert broker.typer.events[-1] == ('type', OLD)
        if fault == 'key':
            key.chmod(0o600)
            key.write_bytes(keyed_template[1])
            key.chmod(0o400)
            assert broker.dispatch(dict(action='ping'))['writes_available'] is True
            recovered = prepare_generated(broker, action)
            assert recovered['ok'] and all(result['ok'] for result in fills(broker, recovered))
            assert commit(broker, recovered)['state'] == 'saved'
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('action', ['generate-password', 'generate-entry'])
@pytest.mark.parametrize('fault', ['key', 'target'])
@pytest.mark.parametrize('hook', ['caller', 'backend'])
def test_generated_delivery_rechecks_input_identity_after_preflight(
    tmp_path, keyed_template, namespace, action, fault, hook,
):
    changed = [False]
    def change_once():
        if not changed[0]:
            change_input(path, key, fault)
            changed[0] = True

    class StepTyper(RecordingTyper):
        def deliver(self, identity, steps, ready, *, guard=None):
            if hook == 'backend':
                change_once()
            return super().deliver(identity, steps, ready, guard=guard)

    def caller_ready():
        if hook == 'caller':
            change_once()
        return True

    broker, path, key = keyed_broker(tmp_path, keyed_template, namespace, StepTyper())
    try:
        prepared = prepare_generated(broker, action)
        assert prepared['ok']
        result = broker.dispatch(dict(action='fill-generated',
            handle=prepared['fill_handles']['password'], target_url='https://example.test/reset',
            start_deadline=broker.clock() + importlib.import_module(namespace + '.broker').FILL_START_TIMEOUT,
            **target_request(broker)), delivery_ready=caller_ready)
        assert changed[0] and not result['ok'], result
        assert not broker.typer.events
        assert broker.dispatch(dict(action='ping'))['writes_available'] is False
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('action', ['merge', 'admit'])
def test_stale_ordinary_inputs_keep_explicit_reconciliation_available(
    vault_path, tmp_path, namespace, action,
):
    vault_path.chmod(0o600)
    source = tmp_path / 'incoming.kdbx'
    module = importlib.import_module(namespace + '.broker')
    broker = module.Broker(module.open_vault_with_password(vault_path, MASTER), RecordingTyper())
    broker.writes.public_base = 'https://node.example:9443'
    try:
        external = reopened(vault_path)
        external.add_entry(external.root_group, 'External addition', 'external-account', OLD,
                           url='https://external.example.test')
        external.save(vault_path)
        shutil.copyfile(vault_path, source)
        status = broker.dispatch(dict(action='ping'))
        assert not status['writes_available'] and status['merge_available']
        request = dict(action=action, source=str(source), operation_id=uuid.uuid4().hex)
        if action == 'admit':
            snapshots = tmp_path / 'snapshots'
            snapshots.mkdir(mode=0o700)
            request.update(policy=admission.POLICY, verification=admission.VERIFICATION,
                           snapshot_directory=str(snapshots))
        else:
            request['refresh_target'] = True
        result = broker.dispatch(request)
        assert result['ok'] and result['state'] in {'saved', 'unchanged'}, result.get('error', result)
        assert result['target_refreshed'] is True
        assert broker.dispatch(dict(action='ping'))['writes_available']
        assert broker.vault.find_entries(title='External addition', first=True) is not None
        generated = begin(broker, 'generate-password')
        assert generated['ok'] and all(result['ok'] for result in fills(broker, generated))
        assert commit(broker, generated)['state'] == 'saved'
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
def test_unchanged_key_input_checks_do_not_read_bodies_or_scan_receipts(
    tmp_path, keyed_template, namespace, monkeypatch,
):
    broker, path, key = keyed_broker(tmp_path, keyed_template, namespace)
    def forbidden(*args, **kwargs):
        raise AssertionError('readiness must use metadata for unchanged inputs')
    try:
        store = broker.vault._akdbx_store
        monkeypatch.setattr(store, '_read', forbidden)
        monkeypatch.setattr(store, '_read_keyfile', forbidden)
        monkeypatch.setattr(store, '_check_keyfile', forbidden)
        monkeypatch.setattr(store, '_scan_merge_recovery', forbidden)
        assert broker.dispatch(dict(action='ping'))['writes_available']
        generated = begin(broker, 'generate-password')
        assert generated['ok'] and all(result['ok'] for result in fills(broker, generated))
    finally:
        broker.unlock_notifications.close()


def lock_path(path):
    return path.with_name('.' + path.name + '.akdbx.lock')


@pytest.mark.parametrize('action', ['generate-password', 'generate-entry'])
@pytest.mark.parametrize('unicode_name', [False, True])
@pytest.mark.parametrize('too_long', [False, True])
def test_required_write_artifact_names_fit_directory_limit(template, tmp_path, action, unicode_name, too_long):
    maximum = os.pathconf(tmp_path, 'PC_NAME_MAX')
    budget = maximum - len(b'..akdbx-backup-') - 24
    length = budget + too_long
    basename = ('é' * (length // 2) + 'a' * (length % 2)) if unicode_name else 'a' * length
    path = tmp_path / basename
    shutil.copyfile(template, path)
    broker = open_broker(path)
    before = path.read_bytes()
    try:
        assert broker.dispatch(dict(action='ping'))['writes_available'] is (not too_long)
        if action == 'generate-password':
            prepared = begin(broker, action)
        else:
            prepared = broker.dispatch(dict(action=action, metadata=dict(title='New synthetic',
                username='new-user', url='https://example.test/new-signup', group='Web')))
        if too_long:
            assert not prepared['ok'] and not broker.writes.operations
            assert not broker.typer.events and path.read_bytes() == before
            selected = broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
            assert broker.dispatch(dict(action='fill', handle=selected['handle'], mode='password',
                                        **target_request(broker)))['ok']
            assert broker.typer.events == [('type', OLD)]
            return
        assert prepared['ok'] and all(result['ok'] for result in fills(broker, prepared))
        assert commit(broker, prepared)['state'] == 'saved'
        title = 'Synthetic site' if action == 'generate-password' else 'New synthetic'
        assert reopened(path).find_entries(title=title, first=True).password == broker.typer.events[0][1]
        backups = list(path.parent.glob('.*.akdbx-backup-*'))
        assert len(backups) == 1 and backups[0].read_bytes() == before
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('action', ['merge', 'admit'])
@pytest.mark.parametrize('unicode_name', [False, True])
@pytest.mark.parametrize('extra_bytes', [0, 1, 8])
def test_merge_names_have_separate_readiness_from_ordinary_saves(
    template, tmp_path, action, unicode_name, extra_bytes,
):
    """Exercise real replacement names while ordinary encrypted saves still fit."""
    import uuid
    directory = tmp_path / 'vault'
    directory.mkdir(mode=0o700)
    maximum = os.pathconf(tmp_path, 'PC_NAME_MAX')
    length = maximum - len(b'..akdbx-merge-') - 32 - len(b'.replace') + extra_bytes
    basename = ('é' * (length // 2) + 'a' * (length % 2)) if unicode_name else 'a' * length
    path = directory / basename
    source = tmp_path / 'incoming.kdbx'
    shutil.copyfile(template, path)
    broker = open_broker(path)
    try:
        capabilities = broker.dispatch(dict(action='ping'))
        assert capabilities['writes_available']
        assert capabilities['merge_available'] is (extra_bytes == 0)
        prepared = begin(broker, 'generate-password')
        assert prepared['ok'] and all(result['ok'] for result in fills(broker, prepared))
        assert commit(broker, prepared)['state'] == 'saved'
        before = path.read_bytes()
        shutil.copyfile(path, source)
        incoming = reopened(source)
        incoming.add_entry(incoming.root_group, 'Incoming only', 'incoming-user', OLD)
        incoming.save()
        source_before = source.read_bytes()
        existing = set(tmp_path.iterdir())
        vault_files = set(directory.iterdir())
        request = dict(action=action, source=str(source), operation_id=uuid.uuid4().hex)
        if action == 'admit':
            snapshots = tmp_path / 'snapshots'
            snapshots.mkdir(mode=0o700)
            existing.add(snapshots)
            request.update(policy=admission.POLICY, verification=admission.VERIFICATION,
                           snapshot_directory=str(snapshots))
        result = broker.dispatch(request)
        assert source.read_bytes() == source_before
        if extra_bytes:
            assert not result['ok'] and 'unavailable' in result['error']
            assert path.read_bytes() == before and set(tmp_path.iterdir()) == existing
            assert set(directory.iterdir()) == vault_files
            if action == 'admit':
                assert not list(snapshots.iterdir())
            return
        assert result['ok'] and result['state'] == 'saved', result.get('error')
        saved = reopened(path)
        assert saved.find_entries(title='Incoming only', first=True).password == OLD
        assert saved.find_entries(title='Synthetic site', first=True).password == broker.typer.events[0][1]
        assert not list(directory.glob('*.replace'))
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('fault', ['missing-root', 'root-mode', 'locator-unreadable',
                                   'locator-mode', 'locator-fifo', 'locator-symlink', 'locator-invalid'])
@pytest.mark.parametrize('staged', [False, True])
def test_bound_recovery_storage_is_ready_before_generation_and_delivery(
    vault_path, tmp_path, monkeypatch, fault, staged,
):
    """Known recovery-storage faults cannot reach a generated site reset."""
    if fault == 'locator-unreadable' and os.geteuid() == 0:
        pytest.skip('root bypasses file read permissions')
    import uuid
    snapshots = tmp_path / 'snapshots'
    snapshots.mkdir(mode=0o700)
    source = tmp_path / 'incoming.kdbx'
    shutil.copyfile(vault_path, source)
    broker = open_broker(vault_path)
    checked = broker.dispatch(dict(action='admit', source=str(source), check=True,
        operation_id=uuid.uuid4().hex, policy=admission.POLICY,
        verification=admission.VERIFICATION, snapshot_directory=str(snapshots)))
    assert checked['ok'] and checked['state'] == 'checked', checked
    locator = vault_path.with_name('.' + vault_path.name + '.akdbx-admission.json')
    original_locator = locator.read_bytes()
    prepared = begin(broker, 'generate-password') if staged else None
    if staged:
        assert prepared['ok'], prepared
    original = vault_path.read_bytes(), source.read_bytes()
    moved = tmp_path / 'temporarily-unavailable'
    saved_locator = locator.with_name('synthetic-saved-locator')
    if fault == 'missing-root':
        snapshots.rename(moved)
    elif fault == 'root-mode':
        snapshots.chmod(0o755)
    elif fault.startswith('locator-'):
        if fault in {'locator-unreadable', 'locator-mode'}:
            locator.chmod(0 if fault == 'locator-unreadable' else 0o644)
        elif fault == 'locator-invalid':
            locator.write_bytes(b'{')
        else:
            locator.rename(saved_locator)
            if fault == 'locator-fifo':
                os.mkfifo(locator, 0o600)
            else:
                locator.symlink_to(saved_locator)

    def no_receipt_scan(*args):
        raise AssertionError('readiness must not scan receipt directories')

    try:
        with monkeypatch.context() as patch:
            patch.setattr(broker.vault._akdbx_store, '_scan_merge_recovery', no_receipt_scan)
            if staged:
                result = broker.dispatch(dict(action='fill-generated',
                    handle=prepared['fill_handles']['password'], target_url='https://example.test/reset',
                    **target_request(broker)))
                assert not result['ok'], result
            else:
                assert broker.dispatch(dict(action='ping'))['writes_available'] is False
                assert not begin(broker, 'generate-password')['ok']
                assert not broker.writes.operations
        assert not broker.typer.events
        assert (vault_path.read_bytes(), source.read_bytes()) == original
    finally:
        if fault == 'missing-root':
            moved.rename(snapshots)
        elif fault == 'root-mode':
            snapshots.chmod(0o700)
        elif fault in {'locator-fifo', 'locator-symlink'}:
            locator.unlink()
            saved_locator.rename(locator)
        else:
            locator.chmod(0o600)
            locator.write_bytes(original_locator)
    assert broker.dispatch(dict(action='ping'))['writes_available'] is True
    if staged:
        broker.dispatch(dict(action='cancel-write', write_handle=prepared['write_handle']))
    fresh = begin(broker, 'generate-password')
    assert fresh['ok'] and all(result['ok'] for result in fills(broker, fresh))
    assert commit(broker, fresh)['state'] == 'saved'
    assert reopened(vault_path).find_entries(title='Synthetic site', first=True).password == broker.typer.events[0][1]


@pytest.mark.parametrize('kind', ['read-only', 'public', 'symlink', 'directory', 'fifo', 'hardlink'])
def test_unusable_existing_lock_blocks_resets_but_keeps_read_only_fill(vault_path, tmp_path, kind):
    if kind == 'read-only' and os.geteuid() == 0:
        pytest.skip('requires real permission denial')
    lock = lock_path(vault_path)
    if kind == 'symlink':
        other = tmp_path / 'owned-other-lock'
        other.write_bytes(b'synthetic lock')
        other.chmod(0o600)
        lock.symlink_to(other)
    elif kind == 'directory':
        lock.mkdir(mode=0o700)
    elif kind == 'fifo':
        os.mkfifo(lock, 0o600)
    elif kind == 'hardlink':
        other = tmp_path / 'owned-other-lock'
        other.write_bytes(b'synthetic lock')
        other.chmod(0o600)
        os.link(other, lock)
    else:
        lock.write_bytes(b'synthetic lock')
        lock.chmod(0o400 if kind == 'read-only' else 0o644)
    before = vault_path.read_bytes()
    identity = lock.lstat()
    broker = open_broker(vault_path)
    status = broker.dispatch({'action': 'ping'})
    assert status['locked'] is False and status['recovery_required'] is False
    assert status['writes_available'] is False and status['merge_available'] is False
    result = begin(broker, 'generate-password')
    assert result['ok'] is False and 'fill_handles' not in result
    assert not broker.writes.operations
    selected = broker.dispatch({'action': 'search', 'query': 'Synthetic site'})['entries'][0]
    assert broker.dispatch({'action': 'fill', **target_request(broker),
                            'handle': selected['handle'], 'mode': 'password'})['ok']
    assert broker.typer.events == [('type', OLD)] and vault_path.read_bytes() == before
    after = lock.lstat()
    assert (after.st_ino, after.st_mode, after.st_nlink) == (identity.st_ino, identity.st_mode, identity.st_nlink)


@pytest.mark.parametrize('existing', [False, True])
def test_private_or_absent_lock_allows_atomic_save_of_read_only_vault(vault_path, existing):
    lock = lock_path(vault_path)
    if existing:
        lock.write_bytes(b'synthetic lock sentinel')
        lock.chmod(0o600)
        inode = lock.stat().st_ino
    broker = open_broker(vault_path)
    assert broker.dispatch({'action': 'ping'})['writes_available'] is True
    assert lock.exists() is existing
    prepared = begin(broker, 'generate-password')
    assert prepared['ok'] and all(result['ok'] for result in fills(broker, prepared))
    assert commit(broker, prepared)['state'] == 'saved'
    assert reopened(vault_path).find_entries(title='Synthetic site', first=True).password == broker.typer.events[0][1]
    if existing:
        assert lock.stat().st_ino == inode and lock.read_bytes() == b'synthetic lock sentinel'


@pytest.mark.skipif(os.geteuid() == 0, reason='requires real permission denial')
def test_readiness_refreshes_after_directory_permissions_change(vault_path):
    directory = vault_path.parent
    directory.chmod(0o500)
    try:
        broker = open_broker(vault_path)
        assert broker.dispatch({'action': 'ping'})['writes_available'] is False
        directory.chmod(0o700)
        assert broker.dispatch({'action': 'ping'})['writes_available'] is True
        prepared = begin(broker, 'generate-password')
        assert prepared['ok'] and all(result['ok'] for result in fills(broker, prepared))
        assert commit(broker, prepared)['state'] == 'saved'
    finally:
        directory.chmod(0o700)


@pytest.mark.skipif(os.geteuid() == 0, reason='requires real permission denial')
def test_readiness_refreshes_after_lock_permissions_change(vault_path):
    lock = lock_path(vault_path)
    lock.write_bytes(b'synthetic lock')
    lock.chmod(0o600)
    broker = open_broker(vault_path)
    assert broker.dispatch({'action': 'ping'})['writes_available'] is True
    lock.chmod(0o400)
    try:
        assert broker.dispatch({'action': 'ping'})['writes_available'] is False
        assert begin(broker, 'generate-password')['ok'] is False
    finally:
        lock.chmod(0o600)
    assert broker.dispatch({'action': 'ping'})['writes_available'] is True
    prepared = begin(broker, 'generate-password')
    assert prepared['ok'] and all(result['ok'] for result in fills(broker, prepared))
    assert commit(broker, prepared)['state'] == 'saved'


def test_temporary_lock_contention_does_not_disable_readiness(vault_path):
    lock = lock_path(vault_path)
    lock.write_bytes(b'synthetic lock')
    lock.chmod(0o600)
    fd = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        broker = open_broker(vault_path)
        assert broker.dispatch({'action': 'ping'})['writes_available'] is True
    finally:
        os.close(fd)
    assert broker.dispatch({'action': 'ping'})['writes_available'] is True
