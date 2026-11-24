"""edit-entry and create-group: metadata-only edits of login entries and new empty groups.

All vaults, credentials and targets are synthetic.
"""
from __future__ import annotations

import json

import pytest

from akdbx import cli
from akdbx.broker import Broker
from test_broker import Entry, RecordingTyper, Vault, running_broker
from test_entry_organize import MASTER, SECRET, deploy, reopened, selected, templates  # noqa: F401  (fixture)


@pytest.fixture
def deployed(tmp_path, templates):
    broker, path, socket, server = deploy(tmp_path, templates['bin'])
    try:
        yield broker, path, socket
    finally:
        server.shutdown()
        server.server_close()


def edit(broker, entry=None, **changes):
    entry = entry or selected(broker)
    return broker.dispatch({'action': 'edit-entry', 'handle': entry['handle'], 'changes': changes, 'entry_edit_protocol': 1})


def create(broker, name, parent=''):
    return broker.dispatch({'action': 'create-group', 'parent': parent, 'name': name, 'group_create_protocol': 1})


def test_status_reports_edit_and_group_protocols():
    status = Broker(Vault([]), RecordingTyper()).dispatch({'action': 'ping'})
    assert status['entry_edit_protocol'] == 1 and status['group_create_protocol'] == 1


def test_edit_changes_title_username_and_same_site_url_only(deployed):
    broker, path, _ = deployed
    before = reopened(path).find_entries(title='Synthetic site', first=True)
    history, mtime = len(before.history), before.mtime
    edited = edit(broker, title='Main synthetic account', username='renamed-account',
                  url='https://login.example.test/signin')
    assert edited == {'ok': True, 'state': 'saved', 'changed': 'edited',
                      'previous': {'title': 'Synthetic site', 'username': 'synthetic-account',
                                   'url': 'https://example.test/login', 'group': 'Web'},
                      'metadata': {'title': 'Main synthetic account', 'username': 'renamed-account',
                                   'url': 'https://login.example.test/signin', 'group': 'Web'}}
    assert SECRET not in json.dumps(edited)
    entry = reopened(path).find_entries(title='Main synthetic account', first=True)
    assert entry.uuid == before.uuid and entry.password == SECRET and entry.notes == 'keep notes'
    assert entry.get_custom_property('custom') == 'keep property'
    assert len(entry.history) == history + 1 and entry.history[-1].title == 'Synthetic site'
    assert entry.mtime > mtime
    assert selected(broker, 'Main synthetic')['username'] == 'renamed-account'


@pytest.mark.parametrize('changes,error', [
    ({'url': 'https://other.test/'}, 'same site'),
    ({'url': 'http://example.test/login'}, 'same site'),
    ({'url': 'https://example.test.evil.example/'}, 'same site'),
    ({'title': ''}, 'invalid'),
    ({'title': ' padded'}, 'invalid'),
    ({'title': 'x' * 300}, 'invalid'),
    ({'username': 'bad\nname'}, 'invalid'),
    ({'title': 'Synthetic site'}, 'already has'),
])
def test_edit_refuses_cross_site_urls_and_bad_values(deployed, changes, error):
    broker, path, _ = deployed
    before = path.read_bytes()
    result = edit(broker, **changes)
    assert result['ok'] is False and error in result['error'], result
    assert path.read_bytes() == before


def test_edit_request_shape(deployed):
    broker, path, _ = deployed
    entry = selected(broker)
    before = path.read_bytes()
    for request in ({'changes': {}}, {'changes': {'password': 'x'}}, {'changes': {'group': 'Favourites'}},
                    {'changes': {'title': 1}}, {'entry_edit_protocol': 2}, {'extra': True}):
        payload = {'action': 'edit-entry', 'handle': entry['handle'], 'changes': {'title': 'New'},
                   'entry_edit_protocol': 1, **request}
        assert 'accept only' in broker.dispatch(payload)['error']
    assert path.read_bytes() == before


def test_title_edit_keeps_an_entry_whose_url_is_not_https(tmp_path):
    import io
    import shutil
    from pykeepass import create_database
    from test_entry_organize import deploy as deploy_vault
    template = tmp_path / 'plain.kdbx'
    vault = create_database(io.BytesIO(), password=MASTER)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    vault.add_entry(vault.root_group, 'Old title', 'someone@example.test', SECRET, url='accounts.example.test')
    buffer = io.BytesIO()
    vault.save(buffer)
    template.write_bytes(buffer.getvalue())
    folder = tmp_path / 'run'
    folder.mkdir(mode=0o700)
    broker, path, _, server = deploy_vault(folder, template)
    try:
        assert edit(broker, entry=selected(broker, 'Old title'), title='New title')['ok']
        entry = reopened(path).find_entries(title='New title', first=True)
        assert entry.url == 'accounts.example.test' and entry.password == SECRET
        refused = edit(broker, entry=selected(broker, 'New title'), url='https://accounts.example.test/')
        assert 'no HTTPS site URL' in refused['error']
    finally:
        server.shutdown()
        server.server_close()
        shutil.rmtree(folder, ignore_errors=True)


def test_create_group_then_move_into_it(deployed):
    broker, path, _ = deployed
    assert create(broker, 'Google accounts') == {'ok': True, 'state': 'saved', 'changed': 'created', 'group': 'Google accounts'}
    assert create(broker, 'Child', parent='Web') == {'ok': True, 'state': 'saved', 'changed': 'created', 'group': 'Web/Child'}
    vault = reopened(path)
    assert vault.find_groups(path=['Google accounts']) is not None and vault.find_groups(path=['Web', 'Child']) is not None
    entry = selected(broker)
    moved = broker.dispatch({'action': 'move-entry', 'handle': entry['handle'], 'to_group': 'Google accounts',
                             'entry_organize_protocol': 1})
    assert moved['ok'] and moved['group'] == 'Google accounts'


@pytest.mark.parametrize('name,parent,error', [
    ('Favourites', '', 'already exists'),
    ('favourites', '', 'already exists'),
    ('a/b', '', 'invalid group name'),
    ('', '', 'invalid group name'),
    (' x', '', 'invalid group name'),
    ('New', 'Missing', 'missing or ambiguous'),
    ('Inside', 'Recycle Bin', 'inside the recycle bin'),
])
def test_create_group_refusals(deployed, name, parent, error):
    broker, path, _ = deployed
    before = path.read_bytes()
    result = create(broker, name, parent)
    assert result['ok'] is False and error in result['error'], result
    assert path.read_bytes() == before


def test_cli_edit_and_create_group_wire_flow(deployed, capsys):
    broker, path, socket = deployed
    sock = socket.with_name('cli.sock')
    prefix = ['--socket', str(sock), '--unlock-origin', 'https://node.example:9443']

    def command(*args, expected=0):
        assert cli.main([*prefix, *args]) == expected
        captured = capsys.readouterr()
        assert SECRET not in captured.out + captured.err and MASTER not in captured.out + captured.err
        return json.loads(captured.out) if captured.out else captured.err

    with running_broker(sock, broker):
        status = command('status')
        assert status['entry_edit_protocol'] == 1 and status['group_create_protocol'] == 1
        handle = command('search', 'Synthetic site')['entries'][0]['handle']
        edited = command('edit-entry', '--title', 'Main synthetic account', '--', handle)
        assert edited['ok'] and edited['metadata']['title'] == 'Main synthetic account'
        handle = command('search', 'Main synthetic')['entries'][0]['handle']
        assert command('edit-entry', '--', handle, expected=1)['ok'] is False
        assert command('create-group', '--name', 'Archive 2026', '--parent', 'Web')['group'] == 'Web/Archive 2026'
    assert reopened(path).find_entries(title='Main synthetic account', first=True).group.name == 'Web'


def test_cli_refuses_old_broker_without_sending(monkeypatch, capsys):
    sent = []

    def fake(socket_path, payload, **kwargs):
        sent.append(payload['action'])
        return {'ok': True, 'version': '0.38.0'}
    monkeypatch.setattr(cli, 'request', fake)
    assert cli.main(['--socket', '/nonexistent', 'edit-entry', '--title', 'x', '--', 'a' * 64]) == 1
    assert cli.main(['--socket', '/nonexistent', 'create-group', '--name', 'x']) == 1
    assert sent == ['ping', 'ping'] and 'protocol 1' in capsys.readouterr().out


@pytest.mark.parametrize('action', ['edit-entry', 'create-group'])
def test_edits_hold_the_vault_lock(action, monkeypatch):
    import threading
    broker = Broker(Vault([Entry()]), RecordingTyper())
    observed = []

    def probe(request):
        result = []
        worker = threading.Thread(target=lambda: result.append(broker._vault_lock.acquire(blocking=False)))
        worker.start()
        worker.join()
        observed.append(result[0])
        return {'ok': True}
    monkeypatch.setattr(broker.writes, 'edit_entry' if action == 'edit-entry' else 'create_group', probe)
    broker.dispatch({'action': action})
    assert observed == [False]
