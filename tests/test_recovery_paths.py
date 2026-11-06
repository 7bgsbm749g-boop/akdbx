"""Receipt recovery uses synthetic vaults and isolated sockets, without unlock."""
from __future__ import annotations

import shutil
import uuid
from pathlib import Path

import pytest
from pykeepass import PyKeePass

from akdbx import admission, cli
from akdbx.broker import Broker, open_vault_with_password
from akdbx.web_unlock import start_unlock_server
from test_broker import RecordingTyper, running_broker
from test_merge import MASTER, base


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
