"""move-entry / delete-entry: metadata-only moves between existing groups and into the recycle bin.

All vaults, credentials and targets are synthetic.
"""
from __future__ import annotations

import io
import json
import shutil
from datetime import datetime, timezone

import pytest
from pykeepass import PyKeePass, create_database

from akdbx import cli
from akdbx.broker import Broker, open_vault_with_password
from akdbx.web_unlock import start_unlock_server
from test_broker import Entry, RecordingTyper, Vault, running_broker

MASTER = 'synthetic-organize-master-only'
SECRET = 'synthetic-organize-password-only'
OTHER = 'synthetic-organize-other-only'


def build(path, *, recycle_bin=True, bin_enabled=True):
    vault = create_database(io.BytesIO(), password=MASTER)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value = 1
    params['M'].value = 1024 * 1024
    web = vault.add_group(vault.root_group, 'Web')
    vault.add_group(vault.root_group, 'Favourites')
    vault.add_group(web, 'Nested')
    entry = vault.add_entry(web, 'Synthetic site', 'synthetic-account', SECRET, url='https://example.test/login', notes='keep notes')
    entry.set_custom_property('custom', 'keep property')
    entry._set_times_property('LocationChanged', datetime(2020, 1, 1, tzinfo=timezone.utc))
    vault.add_entry(web, 'Unrelated', 'other-account', OTHER, url='https://other.test')
    if recycle_bin:
        vault._create_or_get_recyclebin_group()
    if not bin_enabled:
        vault._xpath('/KeePassFile/Meta/RecycleBinEnabled', first=True).text = 'False'
    buffer = io.BytesIO()
    vault.save(buffer)
    path.write_bytes(buffer.getvalue())


@pytest.fixture(scope='module')
def templates(tmp_path_factory):
    folder = tmp_path_factory.mktemp('organize-templates')
    made = {}
    for name, options in {'bin': {}, 'nobin': {'recycle_bin': False}, 'off': {'bin_enabled': False}}.items():
        made[name] = folder / f'{name}.kdbx'
        build(made[name], **options)
    return made


def deploy(tmp_path, template):
    path = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    broker = Broker(open_vault_with_password(path, MASTER), RecordingTyper())
    socket = tmp_path / 'private' / 'organize-web.sock'
    server, _ = start_unlock_server(broker, path, None, socket, 'https://node.example:9443')
    return broker, path, socket, server


@pytest.fixture
def deployed(tmp_path, templates):
    broker, path, socket, server = deploy(tmp_path, templates['bin'])
    try:
        yield broker, path, socket
    finally:
        server.shutdown()
        server.server_close()


def reopened(path):
    return PyKeePass(str(path), password=MASTER)


def selected(broker, query='Synthetic site'):
    return broker.dispatch({'action': 'search', 'query': query})['entries'][0]


def organize(broker, action='move-entry', to_group='Favourites', entry=None, **overrides):
    entry = entry or selected(broker)
    request = {'action': action, 'handle': entry['handle'], 'entry_organize_protocol': 1,
               'metadata': {key: entry[key] for key in ('title', 'username', 'url', 'group')}}
    if action == 'move-entry':
        request['to_group'] = to_group
    request.update(overrides)
    return broker.dispatch(request)


def test_status_reports_entry_organize_protocol():
    assert Broker(Vault([]), RecordingTyper()).dispatch({'action': 'ping'})['entry_organize_protocol'] == 1


def test_move_changes_only_the_group_and_location_time(deployed):
    broker, path, _ = deployed
    before = reopened(path).find_entries(title='Synthetic site', first=True)
    history, mtime = len(before.history), before.mtime
    moved = organize(broker)
    assert moved == {'ok': True, 'state': 'saved', 'changed': 'moved', 'group': 'Favourites',
                     'metadata': {'title': 'Synthetic site', 'username': 'synthetic-account',
                                  'url': 'https://example.test/login', 'group': 'Web'}}
    assert SECRET not in json.dumps(moved) and MASTER not in json.dumps(moved)
    vault = reopened(path)
    entry = vault.find_entries(title='Synthetic site', first=True)
    assert entry.group.name == 'Favourites' and entry.uuid == before.uuid
    assert entry.password == SECRET and entry.notes == 'keep notes'
    assert entry.get_custom_property('custom') == 'keep property'
    assert len(entry.history) == history and entry.mtime == mtime
    assert entry._get_times_property('LocationChanged') > datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert vault.find_entries(title='Unrelated', first=True).group.name == 'Web'
    assert len(list(path.parent.glob('.*.akdbx-backup-*'))) == 1
    assert selected(broker)['group'] == 'Favourites'
    # Nested and top-level destinations use the exact group path.
    assert organize(broker, to_group='Web/Nested')['group'] == 'Web/Nested'
    assert organize(broker, to_group='')['group'] == ''
    assert reopened(path).find_entries(title='Synthetic site', first=True).group.is_root_group


def test_delete_moves_into_the_existing_recycle_bin(deployed):
    broker, path, _ = deployed
    deleted = organize(broker, action='delete-entry')
    assert deleted['ok'] and deleted['changed'] == 'deleted' and deleted['group'] == 'Recycle Bin'
    vault = reopened(path)
    entry = vault.find_entries(title='Synthetic site', first=True)
    assert entry.group.uuid == vault.recyclebin_group.uuid and entry.password == SECRET
    # Deleting again or moving into the bin by name refuses; KeePassXC empties it.
    before = path.read_bytes()
    assert 'already in the recycle bin' in organize(broker, action='delete-entry')['error']
    other = selected(broker, 'Unrelated')
    assert 'use delete-entry' in organize(broker, entry=other, to_group='Recycle Bin')['error']
    assert path.read_bytes() == before


@pytest.mark.parametrize('name,error', [('nobin', 'recycle bin is off or not created'),
                                        ('off', 'recycle bin is off or not created')])
def test_delete_refuses_without_an_enabled_recycle_bin(tmp_path, templates, name, error):
    broker, path, _, server = deploy(tmp_path, templates[name])
    try:
        before = path.read_bytes()
        result = organize(broker, action='delete-entry')
        assert result['ok'] is False and error in result['error'], result
        assert path.read_bytes() == before
        assert reopened(path).find_entries(title='Synthetic site', first=True).group.name == 'Web'
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize('to_group,error', [('Missing', 'missing or ambiguous'),
                                            ('Web', 'already in that group'),
                                            ('web', 'missing or ambiguous')])
def test_move_refuses_missing_and_same_groups(deployed, to_group, error):
    broker, path, _ = deployed
    before = path.read_bytes()
    result = organize(broker, to_group=to_group)
    assert result['ok'] is False and error in result['error'], result
    assert path.read_bytes() == before


def test_request_shape_metadata_and_handles(deployed):
    broker, path, _ = deployed
    entry = selected(broker)
    before = path.read_bytes()
    wrong = dict(entry, title='Other title')
    assert 'metadata mismatch' in organize(broker, entry=wrong)['error']
    for extra in ({'password': 'x'}, {'entry_organize_protocol': 2}, {'metadata': 'x'}):
        assert not organize(broker, entry=entry, **extra)['ok']
    delete_with_group = {'action': 'delete-entry', 'handle': entry['handle'], 'entry_organize_protocol': 1,
                         'to_group': 'Favourites',
                         'metadata': {key: entry[key] for key in ('title', 'username', 'url', 'group')}}
    assert 'accept only' in broker.dispatch(delete_with_group)['error']
    assert 'search again' in organize(broker, entry=dict(entry, handle='0' * 64))['error']
    assert path.read_bytes() == before
    # A successful move invalidates every outstanding handle.
    fresh, stale = selected(broker), selected(broker, 'Unrelated')
    result = organize(broker, entry=fresh)
    assert result['ok'], result
    assert 'search again' in organize(broker, entry=stale)['error']


def test_future_location_time_refuses(deployed):
    broker, path, _ = deployed
    broker.wall_clock = lambda: datetime(2019, 1, 1, tzinfo=timezone.utc).timestamp()
    before = path.read_bytes()
    assert 'future-dated' in organize(broker)['error']
    assert path.read_bytes() == before


def test_cli_move_and_delete_wire_flow(deployed, capsys):
    broker, path, socket = deployed
    sock = socket.with_name('cli.sock')
    prefix = ['--socket', str(sock), '--unlock-origin', 'https://node.example:9443']

    def command(*args, expected=0):
        assert cli.main([*prefix, *args]) == expected
        captured = capsys.readouterr()
        assert SECRET not in captured.out + captured.err and MASTER not in captured.out + captured.err
        return json.loads(captured.out) if captured.out else captured.err

    def fields(name):
        entry = command('search', name)['entries'][0]
        return entry['handle'], ['--title', entry['title'], '--username', entry['username'],
                                 '--url', entry['url'], '--group', entry['group']]

    with running_broker(sock, broker):
        assert command('status')['entry_organize_protocol'] == 1
        handle, meta = fields('Synthetic site')
        moved = command('move-entry', *meta, '--to-group', 'Favourites', '--', handle)
        assert moved['ok'] and moved['group'] == 'Favourites'
        handle, meta = fields('Unrelated')
        assert command('move-entry', *meta, '--to-group', 'Missing', '--', handle, expected=1)['ok'] is False
        handle, meta = fields('Unrelated')
        deleted = command('delete-entry', *meta, '--', handle)
        assert deleted['ok'] and deleted['changed'] == 'deleted'
    vault = reopened(path)
    assert vault.find_entries(title='Synthetic site', first=True).group.name == 'Favourites'
    assert vault.find_entries(title='Unrelated', first=True).group.uuid == vault.recyclebin_group.uuid


def test_cli_refuses_old_broker_without_sending(monkeypatch, capsys):
    sent = []

    def fake(socket_path, payload, **kwargs):
        sent.append(payload['action'])
        return {'ok': True, 'version': '0.37.0'}
    monkeypatch.setattr(cli, 'request', fake)
    args = ['--title', 't', '--username', 'u', '--url', 'https://a.example/', '--group', '']
    assert cli.main(['--socket', '/nonexistent', 'delete-entry', *args, '--', 'a' * 64]) == 1
    assert sent == ['ping'] and 'entry organize protocol 1' in capsys.readouterr().out


def test_cli_rejects_a_receipt_for_another_group(monkeypatch, capsys):
    def fake(socket_path, payload, **kwargs):
        if payload['action'] == 'ping':
            return {'ok': True, 'entry_organize_protocol': 1}
        return {'ok': True, 'state': 'saved', 'changed': 'moved', 'metadata': payload['metadata'], 'group': 'Elsewhere'}
    monkeypatch.setattr(cli, 'request', fake)
    args = ['--title', 't', '--username', 'u', '--url', 'https://a.example/', '--group', 'Web']
    assert cli.main(['--socket', '/nonexistent', 'move-entry', *args, '--to-group', 'Favourites', '--', 'a' * 64]) == 2
    assert 'receipt rejected' in capsys.readouterr().err


@pytest.mark.parametrize('action', ['move-entry', 'delete-entry'])
def test_entry_moves_hold_the_vault_lock(action, monkeypatch):
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
    monkeypatch.setattr(broker.writes, 'organize_entry', probe)
    broker.dispatch({'action': action, 'handle': 'h', 'metadata': {}, 'entry_organize_protocol': 1})
    assert observed == [False]
