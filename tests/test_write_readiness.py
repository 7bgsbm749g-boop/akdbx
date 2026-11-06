"""Real permission/lock checks use only owned synthetic vaults and recording keys."""
import fcntl
import os
import shutil

import pytest

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
