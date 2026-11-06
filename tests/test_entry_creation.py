"""Accepted metadata must survive real encrypted creation through both import names."""
import importlib
import json
import shutil
import stat

import pytest
from pykeepass import PyKeePass

from test_broker import RecordingTyper, target_request
from test_writes import MASTER, OLD, template


FLOWS = ['chosen', 'generated', 'google', 'github', 'email_code']


def create(broker, flow, values):
    if flow in {'google', 'github', 'email_code'}:
        return broker.dispatch(dict(action='create-passwordless-entry' if flow == 'email_code'
                                    else 'create-sso-entry', auth_method=flow, metadata=values)), ''
    prepared = broker.dispatch(dict(action='generate-entry' if flow == 'generated' else 'create-entry',
                                    metadata=values))
    if not prepared['ok']:
        return prepared, None
    operation = broker.writes.get(prepared['write_handle'])
    password = operation.password if flow == 'generated' else 'synthetic chosen password'
    if flow == 'generated':
        for reference in prepared['fill_handles'].values():
            result = broker.dispatch(dict(action='fill-generated', handle=reference,
                target_url=values['url'], **target_request(broker)))
            assert result['ok'], result
        result = broker.dispatch(dict(action='commit-password', write_handle=prepared['write_handle'],
                                      site_accepted=True))
    else:
        result = broker.writes.submit(operation, password, password, True)
    assert password not in json.dumps(result)
    return result, password


def setup_creation(namespace, template, tmp_path, title, account, unnamed=False,
                   url='https://first.example.test/login'):
    path = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    vault = PyKeePass(path, password=MASTER)
    original = vault.find_entries(title='Synthetic site', first=True)
    original.title, original.username, original.url = title, account, url
    identity = original.uuid
    if unnamed:
        empty = vault.add_group(vault.root_group, '')
        vault.add_group(empty, 'Web')
    vault.save(path)
    module = importlib.import_module(namespace + '.broker')
    broker = module.Broker(module.open_vault_with_password(path, MASTER), RecordingTyper())
    broker.writes.public_base = 'https://unlock.example.test:9443'
    return broker, path, identity


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('flow', FLOWS)
@pytest.mark.parametrize('stored_host,new_host,duplicate', [
    ('faß.test', 'fass.test', False),
    ('faß.test', 'xn--fa-hia.test', True),
    ('FAẞ.test', 'xn--fa-hia.test', True),
    ('bücher.test', 'xn--bcher-kva.test', True),
    ('☕.test', 'xn--53h.test', True),
])
def test_creation_compares_international_origins_without_deviation_folding(
    template, tmp_path, namespace, flow, stored_host, new_host, duplicate,
):
    broker, path, identity = setup_creation(namespace, template, tmp_path, 'Original',
        'CaseUser@example.test', url='https://' + stored_host + '/login')
    before = path.read_bytes()
    original_count = len(broker.vault.entries)
    try:
        values = dict(title='New identity', username='caseuser@EXAMPLE.TEST',
                      url='https://' + new_host + '/register', group='Web')
        result, _ = create(broker, flow, values)
        saved = PyKeePass(path, password=MASTER)
        assert saved.find_entries(uuid=identity, first=True).password == OLD
        if duplicate:
            assert not result['ok'] and 'duplicate site/account' in result['error'], result
            assert len(saved.entries) == original_count and path.read_bytes() == before
            assert not broker.typer.events and not broker.writes.operations
            assert not list(path.parent.glob('.*.akdbx-backup-*'))
        else:
            assert result['ok'] and result['state'] == 'saved', result
            assert len(saved.entries) == original_count + 1 and path.read_bytes() != before
            assert len(list(path.parent.glob('.*.akdbx-backup-*'))) == 1
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('host', ['faß.test', 'under_score.test'])
def test_chosen_creation_preserves_supported_host_spellings(template, tmp_path, namespace, host):
    stored = 'xn--fa-hia.test' if host == 'faß.test' else host
    broker, path, _ = setup_creation(namespace, template, tmp_path, 'Original',
        'account', url='https://' + stored + '/login')
    before = path.read_bytes()
    try:
        result, _ = create(broker, 'chosen', dict(title='Other label', username='account',
            url='https://' + host + '/register', group='Web'))
        assert not result['ok'] and 'duplicate site/account' in result['error'], result
        assert path.read_bytes() == before and not broker.writes.operations
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('flow', FLOWS)
@pytest.mark.parametrize('quoted', ['none', 'title', 'account', 'unicode', 'unnamed'])
def test_distinct_origin_creation_keeps_exact_accepted_metadata(template, tmp_path, namespace, flow, quoted):
    """Different origins permit identical labels/accounts, including literal double quotes."""
    title = 'Sign in "Admin"' if quoted == 'title' else 'Sign in'
    account = '"user"@example.test' if quoted == 'account' else 'synthetic@example.test'
    if quoted == 'unicode':
        title, account = 'Entrée "Admin" 🔑 �', 'usér@example.test'
    broker, path, identity = setup_creation(namespace, template, tmp_path, title, account,
                                           unnamed=quoted == 'unnamed')
    values = dict(title=title, username=account, url='https://second.example.test/login', group='Web')
    try:
        result, password = create(broker, flow, values)
        assert result['ok'] and result['state'] == 'saved', result
        reopened = PyKeePass(path, password=MASTER)
        original = reopened.find_entries(uuid=identity, first=True)
        assert (original.title, original.username, original.url, original.password) == (
            title, account, 'https://first.example.test/login', OLD)
        added = [entry for entry in reopened.entries if entry.url == values['url']]
        assert len(added) == 1
        entry = added[0]
        assert (entry.title, entry.username, entry.password or '') == (title, account, password)
        assert entry.uuid != identity and entry.group.uuid == original.group.uuid
        if quoted == 'unnamed':
            assert any(group.name is None for group in reopened.groups)
            assert len([group for group in reopened.groups if group.name == 'Web']) == 2
        if password:
            assert entry._element.find('String[Key="Password"]/Value').get('Protected') == 'True'
        if flow in {'google', 'github', 'email_code'}:
            assert entry.get_custom_property('akdbx.auth-method') == flow
            marker = 'akdbx.passwordless' if flow == 'email_code' else 'akdbx.passwordless-sso'
            assert entry.get_custom_property(marker) == 'v1'
        if flow == 'generated':
            assert broker.typer.events == [('type', password), ('type', password)]
        else:
            assert not broker.typer.events
        search = broker.dispatch(dict(action='search', query=title))
        assert {item['url'] for item in search['entries']} == {original.url, values['url']}
        assert OLD not in json.dumps(search)
        if password:
            assert password not in json.dumps(search)
        if quoted == 'unicode':
            selected = next(item for item in search['entries'] if item['url'] == values['url'])
            assert broker.dispatch(dict(action='fill', handle=selected['handle'], mode='username',
                                        **target_request(broker)))['ok']
            assert broker.typer.events[-1] == ('type', account)
        backups = list(path.parent.glob('.*.akdbx-backup-*'))
        assert len(backups) == 1 and stat.S_IMODE(backups[0].stat().st_mode) == 0o600
        assert PyKeePass(backups[0], password=MASTER).find_entries(uuid=identity, first=True).password == OLD
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('flow', FLOWS)
@pytest.mark.parametrize('field,value', [('title', 'bad\ufffe'), ('title', 'bad\ud800'), ('username', 'bad\uffff'),
                                       ('username', 'bad\u0085@example.test')])
def test_unusable_creation_metadata_refused_before_staging(template, tmp_path, namespace, flow, field, value):
    broker, path, _ = setup_creation(namespace, template, tmp_path, 'Original', 'original@example.test')
    before = path.read_bytes()
    values = dict(title='New account', username='new@example.test',
                  url='https://second.example.test/login', group='Web')
    values[field] = value
    action = {'chosen': 'create-entry', 'generated': 'generate-entry',
              'email_code': 'create-passwordless-entry'}.get(flow, 'create-sso-entry')
    try:
        request = dict(action=action, metadata=values)
        if flow in {'google', 'github', 'email_code'}:
            request['auth_method'] = flow
        result = broker.dispatch(request)
        assert not result['ok'], result
        assert not broker.writes.operations and not broker.typer.events
        assert path.read_bytes() == before and not list(path.parent.glob('.*.akdbx-backup-*'))
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('flow', ['chosen', 'generated'])
@pytest.mark.parametrize('title', ['Display\u0085Name', 'Supplementary \U0001fffe'])
def test_xml_valid_display_metadata_is_retained(template, tmp_path, namespace, flow, title):
    broker, path, identity = setup_creation(namespace, template, tmp_path, 'Original', 'original@example.test')
    values = dict(title=title, username='new@example.test', url='https://second.example.test', group='Web')
    try:
        result, password = create(broker, flow, values)
        assert result['ok'] and result['state'] == 'saved', result
        vault = PyKeePass(path, password=MASTER)
        added = next(entry for entry in vault.entries if entry.url == values['url'])
        assert added.title == title and added.password == password
        assert vault.find_entries(uuid=identity, first=True).password == OLD
    finally:
        broker.unlock_notifications.close()


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('flow', FLOWS)
def test_true_site_account_duplicates_remain_refused(template, tmp_path, namespace, flow):
    broker, path, identity = setup_creation(namespace, template, tmp_path, 'Original', 'CaseUser@example.test')
    before = path.read_bytes()
    try:
        values = dict(title='Different title', username='caseuser@EXAMPLE.TEST',
                      url='https://first.example.test/different-path', group='')
        result, _ = create(broker, flow, values)
        assert not result['ok'] and 'duplicate site/account' in result['error']
        assert path.read_bytes() == before and not broker.typer.events
        assert not broker.writes.operations and not list(path.parent.glob('.*.akdbx-backup-*'))
    finally:
        broker.unlock_notifications.close()
