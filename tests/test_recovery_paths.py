"""Receipt recovery uses synthetic vaults and isolated sockets, without unlock."""
from __future__ import annotations

import os
import json
import shutil
import threading
import uuid
from pathlib import Path

import pytest
from pykeepass import PyKeePass

from akdbx import admission, cli
from akdbx.broker import Broker, open_vault_with_password
from akdbx.web_unlock import start_unlock_server
from test_broker import RecordingTyper, running_broker
from test_merge import MASTER, base


@pytest.mark.parametrize('external', [False, True])
@pytest.mark.parametrize('locked', [False, True])
def test_fifo_receipt_is_refused_without_retaining_vault_lock(base, tmp_path, external, locked):
    """Malformed recovery files must not turn a status query into a stuck broker."""
    directory = tmp_path / 'canonical'
    directory.mkdir(mode=0o700)
    target = directory / 'target.kdbx'
    shutil.copyfile(base, target)
    before = target.read_bytes()
    broker = Broker(open_vault_with_password(target, MASTER), RecordingTyper())
    receipt_root = directory
    if external:
        receipt_root = tmp_path / 'snapshots'
        receipt_root.mkdir(mode=0o700)
        store = broker.vault._akdbx_store
        anchor = store._directory()
        try:
            os.close(store.snapshot_directory(anchor, str(receipt_root)))
        finally:
            os.close(anchor)
    if locked:
        broker = Broker(None, RecordingTyper())
        broker.merges.database = target
    operation_id = uuid.uuid4().hex
    bundle = receipt_root / ('.' + target.name + '.akdbx-merge-' + operation_id)
    bundle.mkdir(mode=0o700)
    receipt = bundle / 'receipt.json'
    os.mkfifo(receipt, 0o600)
    results = []
    worker = threading.Thread(target=lambda: results.append(broker.dispatch(
        {'action': 'merge-status', 'operation_id': operation_id})))
    worker.start()
    worker.join(1)
    blocked = worker.is_alive()
    if blocked:
        # Keep this owned FIFO connected until the old blocking reader exits.
        fd = os.open(receipt, os.O_RDWR | os.O_NONBLOCK)
        try:
            worker.join(2)
        finally:
            os.close(fd)
    assert not worker.is_alive(), 'owned receipt lookup did not exit'
    assert not blocked, 'receipt open blocked before regular-file validation'
    assert results == [{'ok': False, 'error': 'unsafe merge receipt'}]
    assert broker._vault_lock.acquire(blocking=False)
    broker._vault_lock.release()
    assert target.read_bytes() == before and not broker.typer.events


@pytest.fixture
def recovery_case(tmp_path, base):
    """Create a real target, an incoming addition and an external backup root."""
    directory = tmp_path / 'canonical'
    directory.mkdir(mode=0o700)
    snapshots = tmp_path / 'snapshots'
    snapshots.mkdir(mode=0o700)
    target, source = directory / 'target.kdbx', tmp_path / 'incoming.kdbx'
    shutil.copyfile(base, target)
    shutil.copyfile(base, source)
    incoming = PyKeePass(source, password=MASTER)
    incoming.add_entry(incoming.root_group, 'Synthetic addition', 'synthetic', 'synthetic value')
    incoming.save(source)
    return target, source, snapshots


@pytest.mark.parametrize('external', [False, True])
@pytest.mark.parametrize('change', ['checked', 'prepared', 'receipt-mode', 'bundle-0755',
                                   'bundle-0777', 'hardlink', 'wrong-id', 'missing-id'])
def test_restart_recovery_requires_trusted_receipt_identity(recovery_case, external, change):
    """A terminal state cannot clear recovery when its metadata or identity is unsafe."""
    target, source, snapshots = recovery_case
    broker = Broker(open_vault_with_password(target, MASTER), RecordingTyper())
    operation_id = uuid.uuid4().hex
    request = dict(action='admit' if external else 'merge', source=str(source),
                   operation_id=operation_id, check=True)
    if external:
        request.update(snapshot_directory=str(snapshots), policy=admission.POLICY,
                       verification=admission.VERIFICATION)
    checked = broker.dispatch(request)
    assert checked['ok'] and checked['state'] == 'checked', checked
    receipt = Path(checked['receipt_path'])
    if change in {'prepared', 'wrong-id', 'missing-id'}:
        value = json.loads(receipt.read_bytes())
        if change == 'prepared':
            value['state'] = 'prepared'
        elif change == 'wrong-id':
            value['operation_id'] = uuid.uuid4().hex
        else:
            del value['operation_id']
        receipt.write_text(json.dumps(value))
    elif change == 'receipt-mode':
        receipt.chmod(0o644)
    elif change.startswith('bundle-'):
        receipt.parent.chmod(int(change.removeprefix('bundle-'), 8))
    elif change == 'hardlink':
        os.link(receipt, receipt.with_name('synthetic-link.json'))
    before = target.read_bytes(), receipt.read_bytes()
    restarted = Broker(open_vault_with_password(target, MASTER), RecordingTyper())
    restarted.writes.public_base = 'https://unlock.example.test:9443'
    status = restarted.dispatch({'action': 'ping'})
    blocked = change != 'checked'
    assert status['recovery_required'] is blocked
    assert status['writes_available'] is (not blocked)
    result = restarted.dispatch({'action': 'merge-status', 'operation_id': operation_id})
    assert result['ok'] is (not blocked), result
    assert (target.read_bytes(), receipt.read_bytes()) == before
    assert not restarted.typer.events


def configured_path(tmp_path, target, alias_kind):
    """Keep file aliases differently named so a wrong receipt namespace fails."""
    if alias_kind == 'file':
        alias = tmp_path / 'alias.kdbx'
        alias.symlink_to(target)
        return alias
    if alias_kind == 'directory':
        alias = tmp_path / 'alias-directory'
        alias.symlink_to(target.parent, target_is_directory=True)
        return alias / target.name
    return target


@pytest.mark.parametrize('alias_kind', ['file', 'directory', 'none'])
@pytest.mark.parametrize('operation', ['merge', 'admit'])
@pytest.mark.parametrize('phase', ['saved', 'prepared'])
@pytest.mark.parametrize('target_present', [True, False])
def test_locked_alias_receipt_recovery(recovery_case, tmp_path, monkeypatch,
                                     alias_kind, operation, phase, target_present):
    """Restart status must find the same durable receipt without reading a key."""
    target, source, snapshots = recovery_case
    configured = configured_path(tmp_path, target, alias_kind)
    broker = Broker(open_vault_with_password(configured, MASTER), RecordingTyper())
    operation_id = uuid.uuid4().hex
    request = dict(action=operation, source=str(source), operation_id=operation_id)
    if operation == 'admit':
        request.update(snapshot_directory=str(snapshots), policy=admission.POLICY,
                       verification=admission.VERIFICATION)
    if phase == 'prepared':
        real_receipt = broker.merges._receipt

        def interrupt(directory, value):
            """Retain the prepared intent and interrupt before replacement."""
            real_receipt(directory, value)
            if value['state'] == 'prepared':
                raise KeyboardInterrupt('synthetic interruption')

        monkeypatch.setattr(broker.merges, '_receipt', interrupt)
        with pytest.raises(KeyboardInterrupt):
            broker.dispatch(request)
    else:
        saved = broker.dispatch(request)
        assert saved['ok'] and saved['state'] == 'saved', saved

    root = snapshots if operation == 'admit' else target.parent
    receipt_path = root / ('.' + target.name + '.akdbx-merge-' + operation_id) / 'receipt.json'
    receipt_before = receipt_path.read_bytes()
    locator = target.parent / ('.' + target.name + '.akdbx-admission.json')
    locator_before = locator.read_bytes() if operation == 'admit' else None
    if not target_present:
        target.unlink()

    def no_decryption(*args, **kwargs):
        raise AssertionError('locked receipt lookup must not decrypt the vault')

    monkeypatch.setattr('akdbx.persistence.open_encrypted', no_decryption)
    restarted = Broker(None, RecordingTyper())
    socket_path = tmp_path / 'runtime' / 'rpc.sock'
    server, _ = start_unlock_server(restarted, configured, None, socket_path.with_name('web.sock'),
                                    'https://node.example:9443', opener=no_decryption)
    try:
        with running_broker(socket_path, restarted):
            result = cli.request(socket_path, dict(action='merge-status', operation_id=operation_id))
        assert result['state'] == ('saved' if phase == 'saved' else 'uncertain'), result
        assert result['ok'] is (phase == 'saved')
        assert result['operation_id'] == operation_id
        assert Path(result['receipt_path']) == receipt_path
        assert restarted.locked and not restarted.typer.events
        assert receipt_path.read_bytes() == receipt_before
        assert target.exists() is target_present
        if operation == 'admit':
            assert locator.read_bytes() == locator_before
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize('unsafe', ['directory', 'receipt-symlink', 'receipt-mode', 'receipt-corrupt'])
def test_alias_recovery_preserves_safety_checks(recovery_case, tmp_path, unsafe):
    """Resolving a target alias must not excuse unsafe ancestry or receipts."""
    target, source, _ = recovery_case
    configured = configured_path(tmp_path, target, 'file')
    broker = Broker(open_vault_with_password(configured, MASTER), RecordingTyper())
    saved = broker.dispatch(dict(action='merge', source=str(source), operation_id=uuid.uuid4().hex))
    assert saved['ok'], saved
    receipt = Path(saved['receipt_path'])
    if unsafe == 'directory':
        target.parent.chmod(0o777)
    elif unsafe == 'receipt-symlink':
        original = receipt.with_name('original.json')
        receipt.rename(original)
        receipt.symlink_to(original)
    elif unsafe == 'receipt-mode':
        receipt.chmod(0o644)
    else:
        receipt.write_bytes(b'not a receipt')
    restarted = Broker(None, RecordingTyper())
    restarted.merges.database = configured
    result = restarted.dispatch(dict(action='merge-status', operation_id=saved['operation_id']))
    assert not result['ok'] and restarted.locked and not restarted.typer.events
