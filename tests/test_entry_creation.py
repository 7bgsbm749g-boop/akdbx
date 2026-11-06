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


def setup_creation(namespace, template, tmp_path, title, account):
    path = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    vault = PyKeePass(path, password=MASTER)
    original = vault.find_entries(title='Synthetic site', first=True)
    original.title, original.username, original.url = title, account, 'https://first.example.test/login'
    identity = original.uuid
    vault.save(path)
    module = importlib.import_module(namespace + '.broker')
    broker = module.Broker(module.open_vault_with_password(path, MASTER), RecordingTyper())
    broker.writes.public_base = 'https://unlock.example.test:9443'
    return broker, path, identity


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('flow', FLOWS)
@pytest.mark.parametrize('quoted', ['none', 'title', 'account'])
def test_distinct_origin_creation_keeps_exact_accepted_metadata(template, tmp_path, namespace, flow, quoted):
    """Different origins permit identical labels/accounts, including literal double quotes."""
    title = 'Sign in "Admin"' if quoted == 'title' else 'Sign in'
    account = '"user"@example.test' if quoted == 'account' else 'synthetic@example.test'
    broker, path, identity = setup_creation(namespace, template, tmp_path, title, account)
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
        assert entry.uuid != identity and entry.group.name == 'Web'
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
        backups = list(path.parent.glob('.*.akdbx-backup-*'))
        assert len(backups) == 1 and stat.S_IMODE(backups[0].stat().st_mode) == 0o600
        assert PyKeePass(backups[0], password=MASTER).find_entries(uuid=identity, first=True).password == OLD
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
