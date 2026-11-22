"""Private identity saves use only synthetic data and isolated vaults."""
import json
from urllib.parse import urlencode, urlsplit

import pytest

from akdbx import cli
from akdbx.broker import Broker
from akdbx.identities import FIELDS, MARKER, property_key
from test_broker import Entry, RecordingTyper, Vault, running_broker, x11_target_request
from test_web_unlock import call
from test_writes import deployed, reopened, template

IDENTITY = dict.fromkeys(FIELDS, '') | {
    'name': 'Synthetic Élodie Example',
    'given-name': 'Élodie',
    'family-name': 'Example',
    'address-line1': '12 Synthetic Avenue',
    'address-line2': 'Suite B',
    'address-level2': 'Synthetic\u200c City',
    'address-level1': 'Synthetic Province',
    'postal-code': '00042',
    'country': 'NZ',
    'country-name': 'New Zealand',
    'tel': '+49 000 000000',
    'email': 'synthetic-only@example.test',
}
LABEL = 'Sample shipping'


def begin(broker, fields=None, **metadata):
    extra = {} if fields is None else dict(fields=fields)
    return broker.dispatch(dict(action='create-identity', identity_protocol=1,
                                metadata=dict(title=LABEL, group='Web') | metadata, **extra))


def search(broker, query=LABEL):
    return broker.dispatch(dict(action='search-identities', identity_protocol=1, query=query))


def private_path(prepared):
    parts = urlsplit(prepared['private_url'])
    return parts.path + '?' + parts.query


def post(socket, prepared, **changes):
    return call(socket, 'POST', private_path(prepared), urlencode(IDENTITY | {'confirmed': 'yes'} | changes))


def test_private_save_reopens_protected_and_stays_out_of_login_and_logs(deployed, capsys, caplog):
    broker, typer, path, web = deployed
    pending = begin(broker)
    code, headers, page = call(web, 'GET', private_path(pending))
    assert code == 200 and headers['Cache-Control'] == 'no-store'
    assert b'Save identity to AKDBX' in page and LABEL.encode() in page
    assert call(web, 'GET', private_path(pending), identity=False)[0] == 404
    assert post(web, pending, confirmed='no')[0] == 409
    assert post(web, pending, country='not a code')[0] == 409
    assert post(web, pending, **{'address-line1': 'line\nbreak'})[0] == 409
    assert post(web, pending, injected='unused')[0] == 400
    assert search(broker)['entries'] == []
    code, _, receipt = post(web, pending)
    assert code == 200 and b'Identity saved to vault. You may close this page.' in receipt
    assert b'<title>AKDBX: Success</title>' in receipt and b'data-save-result="saved"' in receipt
    assert post(web, pending)[0] == 404
    entry = reopened(path).find_entries(title=LABEL, first=True)
    assert entry.get_custom_property(MARKER) == 'v1'
    for key, value in IDENTITY.items():
        field = property_key(key)
        node = entry._element.find(f'./String[Key="{field}"]/Value')
        if value:
            assert node.get('Protected') == 'True'
            assert entry.get_custom_property(field) == value
        else:
            assert node is None
    result = search(broker, 'SHIPPING')
    assert len(result['entries']) == 1
    found = result['entries'][0]
    assert set(found) == {'handle', 'title', 'group'}
    assert (found['title'], found['group']) == (LABEL, 'Web')
    assert search(broker, IDENTITY['email'])['entries'] == []
    assert broker.dispatch(dict(action='search', query=LABEL))['entries'] == []
    refused = broker.dispatch(dict(action='fill', mode='username', handle=found['handle'],
                                   **x11_target_request(broker)))
    assert refused == {'ok': False, 'error': 'identity record requires identity fill; no keys sent'}
    assert typer.events == []
    login_metadata = dict(title=LABEL, group='Web', username='synthetic-account', url='https://example.test')
    for action in ('setup-totp', 'update-password', 'generate-password'):
        handle = search(broker)['entries'][0]['handle']
        assert broker.dispatch(dict(action=action, handle=handle, metadata=login_metadata)) == {
            'ok': False, 'error': 'identity record cannot be used for login writes'}
    handle = search(broker)['entries'][0]['handle']
    assert broker.dispatch(dict(action='add-url', handle=handle, additional_urls_protocol=1,
                                url='https://example.test')) == {
        'ok': False, 'error': 'identity record has no site URLs'}
    response = broker.dispatch(dict(action='write-status', write_handle=pending['write_handle']))
    assert response == dict(ok=True, state='saved')
    captured = capsys.readouterr()
    for value in (v for v in IDENTITY.values() if len(v) > 2):
        assert value not in page.decode() + receipt.decode() + json.dumps(result) + captured.out + captured.err + caplog.text


def test_identity_save_refuses_wrong_group_extra_payload_duplicate_and_stale_page(deployed):
    broker, _, path, web = deployed
    assert not begin(broker, group='Missing')['ok']
    assert not begin(broker, email=IDENTITY['email'])['ok']
    stale = begin(broker, title='Other shipping')
    saved = begin(broker)
    assert post(web, saved)[0] == 200
    assert post(web, stale)[0] == 404
    assert broker.dispatch(dict(action='write-status', write_handle=stale['write_handle']))['state'] == 'failed'
    assert post(web, begin(broker))[0] == 409
    assert len(reopened(path).find_entries(title=LABEL)) == 1


def test_cli_refuses_an_old_broker_and_withholds_unexpected_fields(monkeypatch, capsys):
    calls = []

    def old_broker(_, payload, **kwargs):
        calls.append(payload)
        return dict(ok=True, locked=False)

    monkeypatch.setattr(cli, 'request', old_broker)
    assert cli.main(['search-identities', LABEL]) == 1
    assert calls == [{'action': 'ping'}]
    assert 'request not sent' in capsys.readouterr().out

    def extra_field(_, payload, **kwargs):
        if payload['action'] == 'ping':
            return dict(ok=True, identity_protocol=1, identity_delivery='cdp-identity-element-v1')
        return dict(ok=True, entries=[dict(title=LABEL, group='Web', handle='a' * 64, email=IDENTITY['email'])])

    monkeypatch.setattr(cli, 'request', extra_field)
    assert cli.main(['search-identities', LABEL]) == 2
    output = capsys.readouterr()
    assert not output.out and IDENTITY['email'] not in output.err
    assert 'response withheld' in output.err


class SyntheticIdentity(Entry):
    def get_custom_property(self, key):
        return 'v1' if key == MARKER else None


def test_search_filters_run_before_label_limit(tmp_path, capsys):
    entries = [SyntheticIdentity(uuid=str(i), title=LABEL, path=(f'Group {i}', LABEL)) for i in range(21)]
    entries += [SyntheticIdentity(uuid=f'partial-{i}', title=f'Home {i}', path=('Web', f'Home {i}'))
                for i in range(20)]
    for mask in range(1, 22):
        variant = ''.join(c.upper() if mask & (1 << i) else c for i, c in enumerate('homebase'))
        entries.append(SyntheticIdentity(uuid=f'variant-{mask}', title=variant, path=('Web', variant)))
    entries += [SyntheticIdentity(uuid='exact', title='Home', path=('Web', 'Home')),
                SyntheticIdentity(uuid='exact-case', title='homebase', path=('Web', 'homebase'))]
    broker = Broker(Vault(entries), RecordingTyper())
    assert len(search(broker)['entries']) == 20
    rpc = tmp_path / 'private' / 'identity-rpc.sock'
    with running_broker(rpc, broker):
        assert cli.main(['--socket', str(rpc), 'search-identities', LABEL, '--group', 'Group 20']) == 0
        grouped = json.loads(capsys.readouterr().out)['entries']
        assert cli.main(['--socket', str(rpc), 'search-identities', 'Home', '--exact', '--group', 'Web']) == 0
        exact = json.loads(capsys.readouterr().out)['entries']
        assert cli.main(['--socket', str(rpc), 'search-identities', 'homebase', '--exact', '--group', 'Web']) == 0
        exact_case = json.loads(capsys.readouterr().out)['entries']
    assert len(grouped) == 1 and grouped[0]['group'] == 'Group 20'
    assert len(exact) == 1 and exact[0]['title'] == 'Home'
    assert len(exact_case) == 1 and exact_case[0]['title'] == 'homebase'


def test_search_returns_labels_that_fit_the_wire_budget(tmp_path, capsys):
    entries = [SyntheticIdentity(uuid=str(i), title=LABEL, path=(str(i) + 'X' * 4000, LABEL))
               for i in range(20)]
    broker = Broker(Vault(entries), RecordingTyper())
    rpc = tmp_path / 'private' / 'identity-rpc.sock'
    with running_broker(rpc, broker):
        assert cli.main(['--socket', str(rpc), 'search-identities', LABEL]) == 0
    found = json.loads(capsys.readouterr().out)['entries']
    assert 0 < len(found) < 20
    assert found[0]['group'] == entries[0].path[0]


def test_cli_withholds_contradictory_fill_receipt(monkeypatch, capsys):
    from akdbx.browser_card import failure

    def contradictory(_, payload, **kwargs):
        if payload['action'] == 'ping':
            return dict(ok=True, locked=False, identity_protocol=1, identity_browser_configured=True,
                        identity_delivery='cdp-identity-element-v1')
        return failure(True, kind='identity') | {'delivery': 'not-started'}

    monkeypatch.setattr(cli, 'request', contradictory)
    assert cli.main(['fill-identity', '--field', 'tel', '--target', 'a' * 64, '--', 'b' * 64]) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'response withheld' in captured.err


@pytest.mark.parametrize('url', [
    'https://node.example:9443/identity',
    'https://node.example:9443/identity?token=malformed',
    'https://wrong.example:9443/identity?token=' + 'a' * 43,
])
def test_cli_withholds_invalid_private_save_link(url, tmp_path, capsys, monkeypatch):
    broker = Broker(Vault([]), RecordingTyper())
    monkeypatch.setattr(broker.identities, 'begin', lambda _: dict(
        ok=True, state='pending', write_handle='a' * 64, private_url=url))
    rpc = tmp_path / 'private' / 'identity-rpc.sock'
    with running_broker(rpc, broker):
        code = cli.main(['--socket', str(rpc), '--unlock-origin', 'https://node.example:9443',
                         'create-identity', '--title', LABEL, '--group', 'Web'])
    captured = capsys.readouterr()
    assert code == 2 and not captured.out
    assert url not in captured.err and 'response withheld' in captured.err


@pytest.mark.parametrize('title,group,exact', [
    (LABEL, 'Other group', True),
    (LABEL.upper(), 'Web', True),
    ('Unrelated', 'Web', False),
])
def test_cli_withholds_search_entries_outside_requested_filters(title, group, exact, monkeypatch, capsys):
    def mismatch(_, payload, **kwargs):
        if payload['action'] == 'ping':
            return dict(ok=True, identity_protocol=1, identity_delivery='cdp-identity-element-v1')
        return dict(ok=True, entries=[dict(title=title, group=group, handle='a' * 64)])

    monkeypatch.setattr(cli, 'request', mismatch)
    args = ['search-identities', LABEL, '--group', 'Web']
    if exact:
        args += ['--exact']
    assert cli.main(args) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'response withheld' in captured.err


def test_literal_slash_and_nested_group_collision_issues_no_handles():
    entries = [
        SyntheticIdentity(uuid='literal', title=LABEL, path=('Work/Travel', LABEL)),
        SyntheticIdentity(uuid='nested', title=LABEL, path=('Work', 'Travel', LABEL)),
        SyntheticIdentity(uuid='clear', title=LABEL, path=('Personal', LABEL)),
    ]
    broker = Broker(Vault(entries), RecordingTyper())
    result = broker.dispatch(dict(action='search-identities', identity_protocol=1,
                                  query=LABEL, exact=True, group='Work/Travel'))
    assert result == dict(ok=True, entries=[])
    assert not broker._handles
    result = search(broker)
    assert [entry['group'] for entry in result['entries']] == ['Personal']


def test_ambiguous_labels_do_not_consume_result_slots():
    entries = [SyntheticIdentity(uuid=f'{i}-{suffix}', title=f'Home {i}', path=('Ambiguous', f'Home {i}'))
               for i in range(20) for suffix in ('a', 'b')]
    entries.append(SyntheticIdentity(uuid='unique', title='Home', path=('Personal', 'Home')))
    broker = Broker(Vault(entries), RecordingTyper())
    result = search(broker, 'Home')
    assert [entry['group'] for entry in result['entries']] == ['Personal']
    assert len(broker._handles) == 1


@pytest.mark.parametrize('second', [
    dict(title=LABEL, group='Web', handle='b' * 64),
    dict(title=LABEL, group='Other', handle='a' * 64),
])
def test_cli_withholds_ambiguous_search_receipts(second, monkeypatch, capsys):
    def ambiguous(_, payload, **kwargs):
        if payload['action'] == 'ping':
            return dict(ok=True, identity_protocol=1, identity_delivery='cdp-identity-element-v1')
        return dict(ok=True, entries=[dict(title=LABEL, group='Web', handle='a' * 64), second])

    monkeypatch.setattr(cli, 'request', ambiguous)
    assert cli.main(['search-identities', LABEL]) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'response withheld' in captured.err


def field_names(page):
    import re
    return set(re.findall(rb'<input id="[^"]*" name="([^"]+)"', page)) - {b'confirmed'}


def test_field_subset_page_shows_and_stores_only_requested_fields(deployed, capsys):
    broker, _, path, web = deployed
    pending = begin(broker, fields=['tel'])
    assert set(pending) == {'ok', 'state', 'write_handle', 'private_url'}
    code, _, page = call(web, 'GET', private_path(pending))
    assert code == 200 and field_names(page) == {b'tel'}
    assert b'Phone number' in page and b'Email address' not in page
    assert b'class="portal-submit"' in page and b'data-save-form' in page
    tel = {'tel': IDENTITY['tel'], 'confirmed': 'yes'}
    # Exactly the requested fields plus the confirmation are accepted.
    assert call(web, 'POST', private_path(pending), urlencode(tel | {'email': IDENTITY['email']}))[0] == 400
    assert call(web, 'POST', private_path(pending), urlencode(IDENTITY | {'confirmed': 'yes'}))[0] == 400
    assert call(web, 'POST', private_path(pending), urlencode({'confirmed': 'yes'}))[0] == 400
    code, _, rejected = call(web, 'POST', private_path(pending), urlencode({'tel': ' ', 'confirmed': 'yes'}))
    assert code == 409 and b'data-save-result="rejected"' in rejected and b'>Failure</h1>' in rejected
    code, _, receipt = call(web, 'POST', private_path(pending), urlencode(tel))
    assert code == 200 and b'Identity saved to vault. You may close this page.' in receipt
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle'])) == dict(ok=True, state='saved')
    entry = reopened(path).find_entries(title=LABEL, first=True)
    assert entry.get_custom_property(MARKER) == 'v1'
    stored = {s.find('Key').text for s in entry._element.findall('./String')}
    assert {key for key in stored if key.startswith(MARKER + '.')} == {property_key('tel')}
    node = entry._element.find(f'./String[Key="{property_key("tel")}"]/Value')
    assert node.get('Protected') == 'True' and entry.get_custom_property(property_key('tel')) == IDENTITY['tel']
    captured = capsys.readouterr()
    assert IDENTITY['tel'] not in page.decode() + receipt.decode() + captured.out + captured.err


@pytest.mark.parametrize('fields', [[], ['phone'], ['tel', 'tel'], 'tel', [1], ['street-address']])
def test_invalid_field_subsets_are_refused(deployed, fields):
    broker = deployed[0]
    assert begin(broker, fields=fields) == {'ok': False, 'error': 'identity operation refused; check label, group and vault readiness'}
    assert all(op.uuid is None for op in broker.writes.operations.values())


def test_country_subset_uppercases_and_checks_the_code(deployed):
    broker, _, path, web = deployed
    pending = begin(broker, fields=['country', 'email'])
    page = call(web, 'GET', private_path(pending))[2]
    assert field_names(page) == {b'country', b'email'}
    form = {'country': 'nz', 'email': '', 'confirmed': 'yes'}
    assert call(web, 'POST', private_path(pending), urlencode(form | {'country': 'NZL'}))[0] == 409
    assert call(web, 'POST', private_path(pending), urlencode(form))[0] == 200
    entry = reopened(path).find_entries(title=LABEL, first=True)
    assert entry.get_custom_property(property_key('country')) == 'NZ'
    assert entry.get_custom_property(property_key('email')) is None


def test_cli_sends_fields_only_to_a_broker_that_supports_them(monkeypatch, capsys):
    calls = []
    caps = dict(ok=True, identity_protocol=1, identity_delivery='cdp-identity-element-v1')

    def broker(_, payload, **kwargs):
        calls.append(payload)
        if payload['action'] == 'ping':
            return caps
        return dict(ok=True, state='pending', write_handle='a' * 64,
                    private_url='https://node.example:9443/identity?token=' + 'b' * 43)

    monkeypatch.setattr(cli, 'request', broker)
    args = ['create-identity', '--title', LABEL, '--group', 'Web', '--fields', 'email,tel']
    assert cli.main(args) == 1
    assert calls == [{'action': 'ping'}] and 'identity fields protocol 1' in capsys.readouterr().out
    caps['identity_fields_protocol'] = 1
    calls.clear()
    assert cli.main(args) == 0
    assert calls[1] == dict(action='create-identity', identity_protocol=1,
                            metadata=dict(title=LABEL, group='Web'), fields=['email', 'tel'])
    calls.clear()
    assert cli.main(args[:-2]) == 0
    assert 'fields' not in calls[1]
    for bad in ('phone', 'tel,tel', '', 'tel,'):
        with pytest.raises(SystemExit) as exit_info:
            cli.main([*args[:-1], bad])
        assert exit_info.value.code == 2


def update(broker, handle, fields, **metadata):
    return broker.dispatch(dict(action='update-identity', identity_protocol=1, handle=handle, fields=fields,
                                metadata=dict(title=LABEL, group='Web') | metadata))


def saved_identity(broker, web, **values):
    pending = begin(broker, fields=list(values))
    assert call(web, 'POST', private_path(pending), urlencode(values | {'confirmed': 'yes'}))[0] == 200


def stored(entry):
    return {key[len(MARKER) + 1:]: entry.get_custom_property(key) for key in entry.custom_properties
            if key.startswith(MARKER + '.')}


def protected(entry, field):
    return entry._element.find(f'./String[Key="{property_key(field)}"]/Value').get('Protected') == 'True'


def test_update_adds_or_changes_only_the_chosen_fields_and_keeps_history(deployed, capsys, caplog):
    broker, _, path, web = deployed
    saved_identity(broker, web, name=IDENTITY['name'], email=IDENTITY['email'])
    before = reopened(path).find_entries(title=LABEL, first=True)
    assert stored(before) == {'name': IDENTITY['name'], 'email': IDENTITY['email']} and before.history == []
    handle = search(broker)['entries'][0]['handle']
    pending = update(broker, handle, ['tel'])
    assert set(pending) == {'ok', 'state', 'write_handle', 'private_url'} and pending['state'] == 'pending'
    code, _, page = call(web, 'GET', private_path(pending))
    assert code == 200 and field_names(page) == {b'tel'}
    assert b'Update AKDBX identity' in page and b'Update identity in AKDBX' in page and b'Saved values are not shown' in page
    # The page never shows a stored value; the input is empty.
    assert b'value="' not in page.split(b'<form', 1)[1].replace(b'value="yes"', b'')
    # Only the chosen field is accepted.
    assert call(web, 'POST', private_path(pending), urlencode({'tel': IDENTITY['tel'], 'email': 'x@example.test',
                                                               'confirmed': 'yes'}))[0] == 400
    assert call(web, 'POST', private_path(pending), urlencode({'name': 'Other', 'confirmed': 'yes'}))[0] == 400
    code, _, receipt = call(web, 'POST', private_path(pending), urlencode({'tel': IDENTITY['tel'], 'confirmed': 'yes'}))
    assert code == 200 and b'Identity saved to vault. You may close this page.' in receipt
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle'])) == dict(ok=True, state='saved')
    entry = reopened(path).find_entries(title=LABEL, first=True)
    assert entry.uuid == before.uuid and entry.get_custom_property(MARKER) == 'v1'
    assert stored(entry) == {'name': IDENTITY['name'], 'email': IDENTITY['email'], 'tel': IDENTITY['tel']}
    assert all(protected(entry, field) for field in ('name', 'email', 'tel'))
    # The previous version stays in the entry history, as for password updates.
    assert len(entry.history) == 1 and stored(entry.history[0]) == stored(before)
    assert entry.mtime > before.mtime
    # A second update changes an existing field; an empty field keeps its value.
    handle = search(broker)['entries'][0]['handle']
    pending = update(broker, handle, ['email', 'name'])
    form = {'email': 'changed-synthetic@example.test', 'name': '', 'confirmed': 'yes'}
    assert call(web, 'POST', private_path(pending), urlencode(form))[0] == 200
    entry = reopened(path).find_entries(title=LABEL, first=True)
    assert stored(entry) == {'name': IDENTITY['name'], 'email': 'changed-synthetic@example.test', 'tel': IDENTITY['tel']}
    assert protected(entry, 'email') and protected(entry, 'name') and len(entry.history) == 2
    assert len(reopened(path).find_entries(title=LABEL)) == 1
    captured = capsys.readouterr()
    output = page.decode() + receipt.decode() + json.dumps(pending) + captured.out + captured.err + caplog.text
    for value in (IDENTITY['name'], IDENTITY['email'], IDENTITY['tel'], 'changed-synthetic@example.test'):
        assert value not in output


def test_update_with_only_empty_fields_stays_open(deployed):
    broker, _, path, web = deployed
    saved_identity(broker, web, tel=IDENTITY['tel'])
    pending = update(broker, search(broker)['entries'][0]['handle'], ['email', 'name'])
    code, _, page = call(web, 'POST', private_path(pending), urlencode({'email': '', 'name': '', 'confirmed': 'yes'}))
    assert code == 409 and b'data-save-result="rejected"' in page
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle']))['state'] == 'pending'
    assert reopened(path).find_entries(title=LABEL, first=True).history == []


REFUSED_UPDATE = {'ok': False, 'error': 'identity operation refused; check label, group and vault readiness'}


def test_update_refuses_stale_wrong_or_duplicate_selection(deployed):
    broker, _, path, web = deployed
    saved_identity(broker, web, tel=IDENTITY['tel'])
    handle = search(broker)['entries'][0]['handle']
    # A wrong title or group is refused and consumes the handle.
    assert update(broker, handle, ['email'], title='Sample') == REFUSED_UPDATE
    assert update(broker, handle, ['email']) == REFUSED_UPDATE
    assert update(broker, search(broker)['entries'][0]['handle'], ['email'], group='') == REFUSED_UPDATE
    assert update(broker, 'f' * 64, ['email']) == REFUSED_UPDATE
    # Fields are required and limited to the identity fields.
    for fields in (None, [], ['street-address'], ['email', 'email']):
        request = dict(action='update-identity', identity_protocol=1, handle=search(broker)['entries'][0]['handle'],
                       metadata=dict(title=LABEL, group='Web'))
        if fields is not None:
            request['fields'] = fields
        assert broker.dispatch(request) == REFUSED_UPDATE
    # A login entry's handle cannot select an identity.
    login = broker.dispatch(dict(action='search', query='Synthetic site'))['entries']
    assert login and update(broker, login[0]['handle'], ['email']) == REFUSED_UPDATE
    assert update(broker, broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]['handle'], ['email'],
                  title='Synthetic site') == REFUSED_UPDATE
    # A second identity with the same title and group makes the selection ambiguous.
    handle = search(broker)['entries'][0]['handle']
    from pykeepass.entry import Entry
    vault = broker.vault
    twin = Entry(title=LABEL, username='', password='', kp=vault)
    vault.find_groups(name='Web', first=True).append(twin)
    twin.set_custom_property(MARKER, 'v1')
    assert update(broker, handle, ['email']) == REFUSED_UPDATE
    assert all(op.uuid is None for op in broker.writes.operations.values())


def test_update_page_refuses_a_changed_vault_and_a_renamed_identity(deployed):
    broker, _, path, web = deployed
    saved_identity(broker, web, tel=IDENTITY['tel'])
    stale = update(broker, search(broker)['entries'][0]['handle'], ['email'])
    other = begin(broker, title='Other shipping', fields=['tel'])
    assert call(web, 'POST', private_path(other), urlencode({'tel': IDENTITY['tel'], 'confirmed': 'yes'}))[0] == 200
    code, _, page = call(web, 'POST', private_path(stale), urlencode({'email': IDENTITY['email'], 'confirmed': 'yes'}))
    assert code == 404 and b'data-save-result="stale"' in page and b'>Failure</h1>' in page
    assert broker.dispatch(dict(action='write-status', write_handle=stale['write_handle']))['state'] == 'failed'
    entry = reopened(path).find_entries(title=LABEL, first=True)
    assert stored(entry) == {'tel': IDENTITY['tel']} and entry.history == []


def test_cli_update_identity_needs_the_update_protocol(monkeypatch, capsys):
    calls = []
    caps = dict(ok=True, identity_protocol=1, identity_delivery='cdp-identity-element-v1', identity_fields_protocol=1)

    def broker(_, payload, **kwargs):
        calls.append(payload)
        if payload['action'] == 'ping':
            return caps
        return dict(ok=True, state='pending', write_handle='a' * 64,
                    private_url='https://node.example:9443/identity?token=' + 'b' * 43)

    monkeypatch.setattr(cli, 'request', broker)
    args = ['update-identity', '--title', LABEL, '--group', 'Web', '--fields', 'tel', '--', 'c' * 64]
    assert cli.main(args) == 1
    assert calls == [{'action': 'ping'}] and 'identity update protocol 1' in capsys.readouterr().out
    caps['identity_update_protocol'] = 1
    calls.clear()
    assert cli.main(args) == 0
    assert calls[1] == dict(action='update-identity', identity_protocol=1, handle='c' * 64,
                            metadata=dict(title=LABEL, group='Web'), fields=['tel'])
    with pytest.raises(SystemExit) as exit_info:
        cli.main(['update-identity', '--title', LABEL, '--group', 'Web', '--', 'c' * 64])
    assert exit_info.value.code == 2
