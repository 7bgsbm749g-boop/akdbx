"""Synthetic key-file faults run in bounded children so a regression cannot hang pytest."""
import io
import json
import subprocess
import sys

import pytest
from pykeepass import PyKeePass

from akdbx import admission
from akdbx.broker import Broker, open_vault_with_password
from test_broker import RecordingTyper
from test_merge import MASTER, base


@pytest.fixture
def keyfile_case(tmp_path, base):
    keyfile = tmp_path / 'synthetic.key'
    keyfile.write_bytes(b'synthetic key material only' * 2)
    keyfile.chmod(0o400)
    directory = tmp_path / 'canonical'
    directory.mkdir(mode=0o700)
    target, source = directory / 'target.kdbx', tmp_path / 'source.kdbx'
    vault = PyKeePass(io.BytesIO(base.read_bytes()), password=MASTER)
    vault.keyfile = str(keyfile)
    vault.save(target)
    vault.add_entry(vault.root_group, 'Synthetic incoming', 'synthetic', 'synthetic')
    vault.save(source)
    snapshots = tmp_path / 'snapshots'
    snapshots.mkdir(mode=0o700)
    return target, source, keyfile, snapshots


FIFO_PROBE = '''
import json, os, sys, uuid
from pathlib import Path
from akdbx import admission
from akdbx.broker import Broker, open_vault_with_password
from akdbx.persistence import SaveError
from akdbx.web_unlock import start_unlock_server

target, source, keyfile, snapshots = map(Path, sys.argv[1:5])
action = sys.argv[5]
master = json.load(sys.stdin)['master']
before = target.read_bytes(), source.read_bytes()

class NoKeyboard:
    def capture(self, *args):
        raise AssertionError('no input target is permitted')
    def deliver(self, *args, **kwargs):
        raise AssertionError('no typing is permitted')

if action != 'open':
    broker = Broker(open_vault_with_password(target, master, keyfile), NoKeyboard())
keyfile.unlink()
os.mkfifo(keyfile, 0o600)
if action == 'open':
    try:
        open_vault_with_password(target, master, keyfile)
    except SaveError:
        pass
    else:
        raise AssertionError('FIFO key file was accepted')
elif action == 'recheck':
    try:
        broker.vault._akdbx_store._check_keyfile()
    except SaveError:
        pass
    else:
        raise AssertionError('FIFO key-file replacement was accepted')
else:
    endpoint = target.parent / 'private' / 'unlock.sock'
    server, _ = start_unlock_server(broker, target, keyfile, endpoint,
                                   'https://unlock.example.test:9443')
    try:
        assert not broker.dispatch(dict(action='ping'))['writes_available']
        if action == 'save':
            result = broker.dispatch(dict(action='create-passwordless-entry', auth_method='email_code',
                metadata=dict(title='Synthetic identity', username='synthetic',
                              url='https://keyfile.example.test', group='')))
        else:
            request = dict(action=action, source=str(source), check=True, operation_id=uuid.uuid4().hex)
            if action == 'admit':
                request.update(snapshot_directory=str(snapshots), policy=admission.POLICY,
                               verification=admission.VERIFICATION)
            result = broker.dispatch(request)
        assert not result['ok'], result
        assert broker._vault_lock.acquire(blocking=False)
        broker._vault_lock.release()
    finally:
        server.shutdown()
        server.server_close()
    assert not endpoint.exists()
assert (target.read_bytes(), source.read_bytes()) == before
assert keyfile.is_fifo()
print('nonregular key refused; encrypted inputs unchanged; normal cleanup complete')
'''


@pytest.mark.parametrize('action', ['open', 'recheck', 'save', 'merge', 'admit'])
def test_fifo_keyfile_cannot_block_supported_operations(keyfile_case, action):
    """An owned timeout kills and reaps even the old FIFO-blocked interpreter."""
    target, source, keyfile, snapshots = keyfile_case
    result = subprocess.run(
        [sys.executable, '-c', FIFO_PROBE, str(target), str(source), str(keyfile), str(snapshots), action],
        input=json.dumps({'master': MASTER}), text=True, capture_output=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert 'normal cleanup complete' in result.stdout and not result.stderr


@pytest.mark.parametrize('alias', [False, True])
def test_readonly_regular_keyfile_and_initial_alias_remain_usable(keyfile_case, tmp_path, alias):
    target, source, keyfile, snapshots = keyfile_case
    configured = keyfile
    if alias:
        configured = tmp_path / 'synthetic-key-alias'
        configured.symlink_to(keyfile)
    original = keyfile.read_bytes()
    before = target.read_bytes()
    broker = Broker(open_vault_with_password(target, MASTER, configured), RecordingTyper())
    broker.writes.public_base = 'https://unlock.example.test:9443'
    import uuid
    for action in ('merge', 'admit'):
        request = dict(action=action, source=str(source), check=True, operation_id=uuid.uuid4().hex)
        if action == 'admit':
            request.update(snapshot_directory=str(snapshots), policy=admission.POLICY,
                           verification=admission.VERIFICATION)
        checked = broker.dispatch(request)
        assert checked['ok'] and checked['state'] == 'checked', checked
        assert target.read_bytes() == before
    result = broker.dispatch(dict(action='create-passwordless-entry', auth_method='email_code',
        metadata=dict(title='Synthetic identity', username='synthetic', url='https://keyfile.example.test', group='')))
    assert result['ok'] and result['state'] == 'saved', result
    reopened = open_vault_with_password(target, MASTER, configured)
    assert reopened.find_entries(title='Synthetic identity', first=True) is not None
    assert target.read_bytes() != before and keyfile.read_bytes() == original
    assert keyfile.stat().st_mode & 0o777 == 0o400 and not broker.typer.events
