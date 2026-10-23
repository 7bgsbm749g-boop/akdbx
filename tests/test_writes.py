"""All vaults, credentials, HTTP submissions and keyboard targets here are synthetic."""
from __future__ import annotations

import io
import json
import os
import shutil
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode, urlsplit

import pytest
from pykeepass import PyKeePass, create_database

from agentic_kdbx import cli
from agentic_kdbx.broker import Broker, open_vault_with_password
from agentic_kdbx.persistence import VaultStore
from agentic_kdbx.web_unlock import start_unlock_server
from agentic_kdbx.writes import metadata
from test_broker import RecordingTyper, running_broker
from test_web_unlock import call

MASTER = 'synthetic-write-master-only'
OLD = 'synthetic-old-password-only'
CHOSEN = 'synthetic-chosen-password-only'


@pytest.fixture(scope='module')
def template(tmp_path_factory):
    path = tmp_path_factory.mktemp('write-template') / 'synthetic.kdbx'
    vault = create_database(io.BytesIO(), password=MASTER)
    # Reduce KDF cost only in these newly generated synthetic test databases.
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value = 1
    params['M'].value = 1024 * 1024
    web = vault.add_group(vault.root_group, 'Web')
    e = vault.add_entry(web, 'Synthetic site', 'synthetic-account', OLD, url='https://example.test/login', notes='preserve notes')
    e.set_custom_property('custom', 'preserve property')
    vault.add_entry(web, 'Unrelated', 'another-account', 'synthetic-unrelated-secret', url='https://other.test')
    vault.add_entry(vault.root_group, 'Root entry', 'root-user', OLD, url='https://root.test')
    buffer = io.BytesIO()
    vault.save(buffer)
    path.write_bytes(buffer.getvalue())
    return path


@pytest.fixture
def deployed(tmp_path, template):
    path = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    vault = open_vault_with_password(path, MASTER)
    typer = RecordingTyper()
    broker = Broker(vault, typer)
    socket = tmp_path / 'private' / 'write-web.sock'
    server, _ = start_unlock_server(broker, path, None, socket, 'https://node.example:9443')
    try:
        yield broker, typer, path, socket
    finally:
        server.shutdown()
        server.server_close()


def begin(broker, action='update-password', **changes):
    selected = broker.dispatch({'action': 'search', 'query': 'Synthetic site'})['entries'][0]
    values = {key: selected[key] for key in ('title', 'username', 'url', 'group')}
    values.update(changes.pop('metadata', {}))
    return broker.dispatch({'action': action, 'handle': selected['handle'], 'metadata': values, **changes})


def private_post(socket, result, password=CHOSEN, confirmation=CHOSEN, confirmed='yes', **kwargs):
    parts = urlsplit(result['private_url'])
    path = parts.path + '?' + parts.query
    return call(socket, 'POST', path, urlencode({'password': password, 'confirmation': confirmation, 'confirmed': confirmed}), **kwargs)


def fills(broker, result, target='https://example.test/reset'):
    return [broker.dispatch({'action': 'fill-generated', 'handle': ref, 'target_url': target}) for ref in result['fill_handles'].values()]


def commit(broker, result, accepted=True):
    return broker.dispatch({'action': 'commit-password', 'write_handle': result['write_handle'], 'site_accepted': accepted})


def reopened(path):
    return PyKeePass(str(path), password=MASTER)


def test_private_update_preserves_vault_and_is_immediately_fillable(deployed, capsys, caplog):
    broker, typer, path, socket = deployed
    stale = broker.dispatch({'action': 'search', 'query': 'Synthetic site'})['entries'][0]['handle']
    prepared = begin(broker)
    parts = urlsplit(prepared['private_url'])
    pagepath = parts.path + '?' + parts.query
    code, headers, page = call(socket, 'GET', pagepath)
    assert code == 200 and headers['Cache-Control'] == 'no-store'
    assert b'synthetic-account' in page and CHOSEN.encode() not in page
    assert call(socket, 'GET', pagepath, identity=False)[0] == 404
    assert private_post(socket, prepared, confirmation='mismatch')[0] == 409
    assert private_post(socket, prepared, confirmed='no')[0] == 409
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD
    code, _, page = private_post(socket, prepared)
    assert code == 200 and CHOSEN.encode() not in page and MASTER.encode() not in page
    assert private_post(socket, prepared)[0] == 404
    assert broker.dispatch({'action': 'write-status', 'write_handle': prepared['write_handle']}) == {'ok': True, 'state': 'saved'}
    assert not broker.dispatch({'action': 'fill', 'handle': stale})['ok']
    vault = reopened(path)
    entry = vault.find_entries(title='Synthetic site', first=True)
    assert entry.password == CHOSEN and entry.notes == 'preserve notes'
    assert entry.get_custom_property('custom') == 'preserve property'
    assert entry.history[-1].password == OLD
    assert vault.find_entries(title='Unrelated', first=True).password == 'synthetic-unrelated-secret'
    fresh = broker.dispatch({'action': 'search', 'query': 'Synthetic site'})['entries'][0]['handle']
    assert broker.dispatch({'action': 'fill', 'handle': fresh, 'mode': 'password'})['ok']
    assert typer.events == [('type', CHOSEN)]
    backups = list(path.parent.glob('.*.akdbx-backup-*'))
    assert len(backups) == 1
    assert reopened(backups[0]).find_entries(title='Synthetic site', first=True).password == OLD
    for item in [path, *backups]:
        assert stat.S_IMODE(item.stat().st_mode) == 0o600
        assert all(secret.encode() not in item.read_bytes() for secret in (MASTER, OLD, CHOSEN))
    assert not list(path.parent.glob('.*.akdbx-write-*'))
    captured = capsys.readouterr()
    assert all(secret not in captured.out + captured.err + caplog.text + json.dumps(prepared) for secret in (MASTER, OLD, CHOSEN))


def test_create_user_confirmation_duplicates_and_group_safety(deployed):
    broker, _, path, socket = deployed
    values = {'title': 'New synthetic', 'username': 'new-account', 'url': 'https://new.test/login', 'group': 'Web'}
    prepared = broker.dispatch({'action': 'create-entry', 'metadata': values})
    assert prepared['ok'] and private_post(socket, prepared)[0] == 200
    assert reopened(path).find_entries(title='New synthetic', first=True).password == CHOSEN
    assert broker.dispatch({'action': 'search', 'query': 'New synthetic'})['entries']
    assert not broker.dispatch({'action': 'create-entry', 'metadata': {**values, 'title': 'Different title', 'group': '', 'url': 'https://new.test/different'}})['ok']
    assert not broker.dispatch({'action': 'create-entry', 'metadata': {**values, 'url': 'https://missing.test', 'group': 'missing'}})['ok']
    assert len(reopened(path).entries) == 4


@pytest.mark.parametrize('field,value', [('title', 'Wrong entry'), ('username', 'wrong-account'), ('url', 'https://wrong.test'), ('group', '')])
def test_wrong_entry_metadata_rejected_and_handle_consumed(deployed, field, value):
    broker, _, path, _ = deployed
    selected = broker.dispatch({'action': 'search', 'query': 'Synthetic site'})['entries'][0]
    values = {key: selected[key] for key in ('title', 'username', 'url', 'group')}
    result = broker.dispatch({'action': 'update-password', 'handle': selected['handle'], 'metadata': {**values, field: value}})
    assert not result['ok'] and 'mismatch' in result['error']
    assert not broker.dispatch({'action': 'fill', 'handle': selected['handle']})['ok']
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD


def test_generation_two_fills_site_acceptance_and_same_persisted_secret(deployed, capsys, caplog):
    broker, typer, path, _ = deployed
    result = begin(broker, 'generate-password', length=32, symbols='-_!')
    assert result['ok'] and 'private_url' not in result
    assert not commit(broker, result)['ok']
    assert all(r['ok'] for r in fills(broker, result))
    generated = typer.events[0][1]  # Only a recording synthetic keyboard sees it.
    assert len(generated) == 32 and typer.events == [('type', generated)] * 2
    assert set(generated) <= set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_!')
    assert all(any(c in group for c in generated) for group in ('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789', '-_!'))
    assert not commit(broker, result, accepted=False)['ok']
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD
    assert commit(broker, result) == {'ok': True, 'state': 'saved'}
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == generated
    assert not commit(broker, result)['ok']
    assert not any(r['ok'] for r in fills(broker, result))
    assert all(op.password is None for op in broker.writes.operations.values())
    captured = capsys.readouterr()
    assert generated not in captured.out + captured.err + caplog.text + json.dumps(result)


@pytest.mark.parametrize('policy', [{'length': 8}, {'length': True}, {'length': 129}, {'symbols': '\n'}, {'symbols': 'abc'}])
def test_unsafe_generation_policy_rejected(deployed, policy):
    broker, typer, _, _ = deployed
    assert not begin(broker, 'generate-password', **policy)['ok']
    assert typer.events == []


def test_target_mismatch_and_consumed_generated_references(deployed):
    broker, typer, path, _ = deployed
    result = begin(broker, 'generate-password', symbols='')
    assert not any(r['ok'] for r in fills(broker, result, target='https://attacker.test/reset'))
    assert not any(r['ok'] for r in fills(broker, result))
    assert not commit(broker, result)['ok'] and typer.events == []
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD


@pytest.mark.parametrize('reason', ['cancel', 'expire', 'restart'])
def test_rejection_cancel_expiry_restart_discard_staged_secret(deployed, reason):
    broker, typer, path, _ = deployed
    result = begin(broker, 'generate-password')
    assert all(r['ok'] for r in fills(broker, result))
    if reason == 'cancel':
        assert broker.dispatch({'action': 'cancel-write', 'write_handle': result['write_handle']})['state'] == 'cancelled'
        assert broker.writes.get(result['write_handle']).password is None
    elif reason == 'expire':
        broker.clock = lambda: time.monotonic() + 600
    else:
        broker = Broker(open_vault_with_password(path, MASTER), RecordingTyper())
    assert not commit(broker, result)['ok']
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD
    broker.writes._prune()
    assert all(op.password is None for op in broker.writes.operations.values())


def test_stale_parallel_updates_do_not_overwrite(deployed):
    broker, _, path, socket = deployed
    first, second = begin(broker), begin(broker)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda result: private_post(socket, result)[0], [first, second]))
    assert sorted(outcomes) == [200, 409]
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == CHOSEN


def test_external_vault_change_is_preserved(deployed):
    broker, _, path, socket = deployed
    prepared = begin(broker)
    external = reopened(path)
    external.find_entries(title='Unrelated', first=True).notes = 'external change'
    external.save()
    original = path.read_bytes()
    code, _, page = private_post(socket, prepared)
    assert code == 409 and b'changed on disk' in page
    assert path.read_bytes() == original
    assert broker.vault.find_entries(title='Synthetic site', first=True).password == OLD
    assert reopened(path).find_entries(title='Unrelated', first=True).notes == 'external change'


@pytest.mark.parametrize('failure', ['serialize', 'backup', 'replace', 'durability'])
def test_save_failure_no_false_success_and_no_disclosure(deployed, monkeypatch, caplog, capsys, failure):
    broker, _, path, socket = deployed
    prepared = begin(broker)
    original = path.read_bytes()
    def fail(*args, **kwargs):
        raise OSError(CHOSEN + MASTER)
    if failure == 'serialize':
        monkeypatch.setattr(PyKeePass, 'save', fail)
    elif failure == 'backup':
        monkeypatch.setattr(VaultStore, '_write_file', fail)
    elif failure == 'replace':
        monkeypatch.setattr(os, 'replace', fail)
    else:
        real_replace = os.replace
        def replace_then_fail(*args, **kwargs):
            real_replace(*args, **kwargs)
            monkeypatch.setattr(os, 'fsync', fail)
        monkeypatch.setattr(os, 'replace', replace_then_fail)
    code, _, page = private_post(socket, prepared)
    assert code == 409
    assert all(secret.encode() not in page for secret in (CHOSEN, MASTER))
    if failure != 'durability':
        assert path.read_bytes() == original
        assert broker.vault.find_entries(title='Synthetic site', first=True).password == OLD
    else:
        assert b'uncertain' in page and broker.dispatch({'action': 'ping'})['recovery_required']
        assert not broker.dispatch({'action': 'search', 'query': 'Synthetic site'})['ok']
        assert list(path.parent.glob('.*.akdbx-backup-*'))
    assert not list(path.parent.glob('.*.akdbx-write-*'))
    captured = capsys.readouterr()
    assert all(secret not in captured.out + captured.err + caplog.text for secret in (CHOSEN, MASTER))


def test_generated_save_failure_discards_stage_preserves_old_vault(deployed, monkeypatch):
    broker, _, path, _ = deployed
    result = begin(broker, 'generate-password')
    assert all(r['ok'] for r in fills(broker, result))
    monkeypatch.setattr(os, 'replace', lambda *a, **kw: (_ for _ in ()).throw(OSError('synthetic failure')))
    assert not commit(broker, result)['ok']
    assert broker.writes.get(result['write_handle']).password is None
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD


def test_two_independent_brokers_serialized_against_same_file(tmp_path, template):
    path = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    brokers = [Broker(open_vault_with_password(path, MASTER), RecordingTyper()) for _ in range(2)]
    for broker in brokers:
        broker.writes.public_base = 'https://node.example:9443'
    results = [begin(b) for b in brokers]
    def submit(pair):
        b, result = pair
        with b._vault_lock:
            return b.writes.submit(b.writes.get(result['write_handle']), CHOSEN, CHOSEN, True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(submit, zip(brokers, results)))
    assert sum(r['ok'] for r in outcomes) == 1
    assert any('changed on disk' in r.get('error', '') for r in outcomes)
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == CHOSEN


def test_deployed_cli_wire_flow_and_origin_validation(deployed, capsys, caplog):
    broker, typer, path, socket = deployed
    prefix = ['--socket', str(socket.with_name('cli.sock')), '--unlock-origin', 'https://node.example:9443']
    def command(*args, expected=0):
        assert cli.main([*prefix, *args]) == expected
        captured = capsys.readouterr()
        assert not captured.err
        assert MASTER not in captured.out and OLD not in captured.out
        return json.loads(captured.out)
    with running_broker(socket.with_name('cli.sock'), broker):
        status = command('status')
        assert status['version'] == '0.7.0' and status['writes_available']
        selected = command('search', 'Synthetic site')['entries'][0]
        args = [arg for field in ('title', 'username', 'url', 'group') for arg in ('--' + field, selected[field])]
        generated = command('generate-password', selected['handle'], *args, '--length', '28', '--symbols', '')
        for ref in generated['fill_handles'].values():
            assert command('fill-generated', ref, '--target-url', 'https://example.test/reset')['ok']
        assert command('commit-password', generated['write_handle'], '--site-accepted')['state'] == 'saved'
        assert command('write-status', generated['write_handle'])['state'] == 'saved'
        fresh = command('search', 'Synthetic site')['entries'][0]
        prepared = command('update-password', fresh['handle'], *args)
        cli._validate_response(prepared, 'https://node.example:9443')
        with pytest.raises(cli.ProtocolError):
            cli._validate_response(prepared, 'https://different.test:9443')
        assert command('cancel-write', prepared['write_handle'])['state'] == 'cancelled'
        assert private_post(socket, prepared)[0] == 404
    generated_secret = typer.events[0][1]
    assert generated_secret not in caplog.text
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == generated_secret


def test_actual_installed_executable_against_running_synthetic_broker(deployed, capsys):
    import subprocess
    import sys
    from pathlib import Path
    broker, typer, path, socket = deployed
    executable = Path(sys.executable).parent / 'akdbx'
    prefix = [str(executable), '--socket', str(socket.with_name('installed-cli.sock')), '--unlock-origin', 'https://node.example:9443']
    def command(*args):
        result = subprocess.run([*prefix, *args], text=True, capture_output=True, timeout=30)
        assert result.returncode == 0 and not result.stderr
        assert all(secret not in result.stdout for secret in (MASTER, OLD, CHOSEN))
        return json.loads(result.stdout)
    version = subprocess.run([str(executable), '--version'], text=True, capture_output=True, check=True)
    assert version.stdout.strip() == '0.7.0'
    with running_broker(socket.with_name('installed-cli.sock'), broker):
        assert command('status')['writes_available']
        selected = command('search', 'Synthetic site')['entries'][0]
        arguments = [arg for key in ('title', 'username', 'url', 'group') for arg in ('--' + key, selected[key])]
        generated = command('generate-password', selected['handle'], *arguments)
        for ref in generated['fill_handles'].values():
            assert command('fill-generated', ref, '--target-url', 'https://example.test/reset')['ok']
        assert command('commit-password', generated['write_handle'], '--site-accepted')['state'] == 'saved'
        assert command('write-status', generated['write_handle'])['state'] == 'saved'
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == typer.events[0][1]


def test_identical_entry_metadata_is_ambiguous(deployed):
    broker, _, _, _ = deployed
    original = broker.vault.find_entries(title='Synthetic site', first=True)
    broker.vault.add_entry(original.group, original.title, original.username, OLD, url=original.url, force_creation=True)
    assert not begin(broker, 'generate-password')['ok']


def test_unsafe_write_ancestry_preserves_read_only_unlock(tmp_path, template):
    unsafe = tmp_path / 'replaceable'
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    path = unsafe / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    broker = Broker(open_vault_with_password(path, MASTER), RecordingTyper())
    broker.writes.public_base = 'https://node.example:9443'
    assert not broker.dispatch({'action': 'ping'})['writes_available']
    selected = broker.dispatch({'action': 'search', 'query': 'Synthetic site'})['entries'][0]
    assert broker.dispatch({'action': 'fill', 'handle': selected['handle'], 'mode': 'password'})['ok']
    assert not begin(broker)['ok']


def test_generated_deadline_disconnect_and_typing_failure_prevent_commit(deployed, monkeypatch):
    broker, typer, path, _ = deployed
    prepared = begin(broker, 'generate-password')
    password_ref = prepared['fill_handles']['password']
    assert not broker.dispatch({'action': 'fill-generated', 'handle': password_ref, 'target_url': 'https://example.test/reset', 'start_deadline': time.monotonic() - 1})['ok']
    assert typer.events == []
    assert not commit(broker, prepared)['ok']
    prepared = begin(broker, 'generate-password')
    assert not broker.dispatch({'action': 'fill-generated', 'handle': prepared['fill_handles']['password'], 'target_url': 'https://example.test/reset', 'start_deadline': time.monotonic() + 1}, delivery_ready=lambda: False)['ok']
    assert typer.events == []
    prepared = begin(broker, 'generate-password')
    def failure(text):
        raise RuntimeError(text)
    monkeypatch.setattr(typer, 'type_text', failure)
    response = fills(broker, prepared)
    assert all(r == {'ok': False, 'error': 'autofill failed'} for r in response)
    assert not commit(broker, prepared)['ok']
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD


def test_idle_expiry_cleanup_discards_generated_secret(deployed):
    broker, _, _, _ = deployed
    result = begin(broker, 'generate-password')
    op = broker.writes.get(result['write_handle'])
    broker.clock = lambda: time.monotonic() + 600
    deadline = time.monotonic() + 2
    while op.password is not None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert op.password is None


def test_private_cancellation_expiry_controls_and_duplicate_race(deployed):
    broker, _, path, socket = deployed
    prepared = begin(broker)
    assert private_post(socket, prepared, password='unsafe\nvalue', confirmation='unsafe\nvalue')[0] == 409
    assert broker.dispatch({'action': 'cancel-write', 'write_handle': prepared['write_handle']})['state'] == 'cancelled'
    assert private_post(socket, prepared)[0] == 404
    values = {'title': 'Race entry', 'username': 'race-user', 'url': 'https://race.test', 'group': ''}
    first, second = [broker.dispatch({'action': 'create-entry', 'metadata': values}) for _ in range(2)]
    assert private_post(socket, first)[0] == 200
    assert private_post(socket, second)[0] == 409
    assert len(reopened(path).find_entries(username='race-user')) == 1
    prepared = begin(broker)
    broker.clock = lambda: time.monotonic() + 600
    assert private_post(socket, prepared)[0] == 404


def test_disk_change_during_serialization_is_detected(deployed, monkeypatch):
    broker, _, path, socket = deployed
    prepared = begin(broker)
    external_bytes = None
    real_save = PyKeePass.save
    def concurrent_save(vault, *args, **kwargs):
        nonlocal external_bytes
        real_save(vault, *args, **kwargs)
        if isinstance(args[0], io.BytesIO):
            external = reopened(path)
            external.find_entries(title='Unrelated', first=True).notes = 'racing writer'
            real_save(external)
            external_bytes = path.read_bytes()
    monkeypatch.setattr(PyKeePass, 'save', concurrent_save)
    assert private_post(socket, prepared)[0] == 409
    assert path.read_bytes() == external_bytes
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD


def test_save_keeps_keyfile_and_attachments(tmp_path):
    keyfile = tmp_path / 'synthetic.key'
    keyfile.write_bytes(bytes(range(32)))
    path = tmp_path / 'keyed.kdbx'
    vault = create_database(io.BytesIO(), password=MASTER, keyfile=str(keyfile))
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    entry = vault.add_entry(vault.root_group, 'Synthetic site', 'synthetic-account', OLD, url='https://example.test/login')
    entry.add_attachment(vault.add_binary(b'synthetic attachment'), 'attachment.txt')
    vault.save(str(path))
    broker = Broker(open_vault_with_password(path, MASTER, keyfile), RecordingTyper())
    broker.writes.public_base = 'https://node.example:9443'
    result = begin(broker)
    op = broker.writes.get(result['write_handle'])
    with broker._vault_lock:
        assert broker.writes.submit(op, CHOSEN, CHOSEN, True)['ok']
    saved = PyKeePass(str(path), password=MASTER, keyfile=str(keyfile))
    entry = saved.find_entries(title='Synthetic site', first=True)
    assert entry.password == CHOSEN and entry.attachments[0].data == b'synthetic attachment'


def test_generated_origin_port_zero_and_insecure_site_rejected(deployed):
    broker, typer, _, _ = deployed
    generated = begin(broker, 'generate-password')
    assert not any(r['ok'] for r in fills(broker, generated, target='https://example.test:0/reset'))
    entry = broker.vault.find_entries(title='Synthetic site', first=True)
    entry.url = 'http://example.test/login'
    assert not begin(broker, 'generate-password')['ok']
    assert typer.events == []


def test_legacy_broker_capability_and_secret_free_timeout_reports(monkeypatch, capsys):
    cli._validate_response({'ok': True, 'locked': False}, 'https://node.example:9443')
    for field in ('writes_available', 'recovery_required', 'locked'):
        with pytest.raises(cli.ProtocolError):
            cli._validate_response({'ok': True, field: 'false'}, 'https://node.example:9443')
    monkeypatch.setattr(cli, 'request', lambda *a, **kw: (_ for _ in ()).throw(TimeoutError()))
    assert cli.main(['commit-password', 'synthetic-opaque-reference', '--site-accepted']) == 2
    output = capsys.readouterr()
    assert output.out == '' and 'uncertain' in output.err and 'write-status' in output.err
    assert cli.main(['fill-generated', 'synthetic-opaque-reference', '--target-url', 'https://example.test']) == 2
    output = capsys.readouterr()
    assert output.out == '' and 'do not retry automatically' in output.err


def test_changed_keyfile_never_rekeys_vault(tmp_path):
    keyfile = tmp_path / 'synthetic.key'
    original_key = bytes(range(32))
    keyfile.write_bytes(original_key)
    path = tmp_path / 'keyed.kdbx'
    vault = create_database(io.BytesIO(), password=MASTER, keyfile=str(keyfile))
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    vault.add_entry(vault.root_group, 'Synthetic site', 'synthetic-account', OLD, url='https://example.test/login')
    vault.save(str(path))
    broker = Broker(open_vault_with_password(path, MASTER, keyfile), RecordingTyper())
    broker.writes.public_base = 'https://node.example:9443'
    result = begin(broker, 'generate-password')
    assert all(r['ok'] for r in fills(broker, result))
    original_vault = path.read_bytes()
    keyfile.write_bytes(bytes(reversed(range(32))))
    outcome = commit(broker, result)
    assert not outcome['ok'] and 'key file changed' in outcome['error']
    assert path.read_bytes() == original_vault
    saved = PyKeePass(str(path), password=MASTER, keyfile=io.BytesIO(original_key))
    assert saved.find_entries(title='Synthetic site', first=True).password == OLD


def test_unexpected_private_handler_exception_never_logs_secret(deployed, monkeypatch, capsys, caplog):
    from http.client import RemoteDisconnected
    broker, _, _, socket = deployed
    prepared = begin(broker)
    def unexpected(*args, **kwargs):
        raise RuntimeError(CHOSEN + MASTER)
    monkeypatch.setattr(broker.writes, 'submit', unexpected)
    with pytest.raises((RemoteDisconnected, ConnectionResetError)):
        private_post(socket, prepared)
    captured = capsys.readouterr()
    assert all(secret not in captured.out + captured.err + caplog.text for secret in (CHOSEN, MASTER))
    assert broker.dispatch({'action': 'ping'})['ok']
