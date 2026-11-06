"""Real permission/lock checks use only owned synthetic vaults and recording keys."""
import fcntl
import os
import shutil

import pytest

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
