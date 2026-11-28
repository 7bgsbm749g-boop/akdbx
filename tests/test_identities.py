"""Private identity saves use only synthetic data and isolated vaults."""
import json
from urllib.parse import urlencode, urlsplit

import pytest

from akdbx import cli
from akdbx.broker import Broker
from akdbx.identities import FIELDS, MARKER, property_key
from akdbx.writes import WriteError
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
    'tel': '+49 30 000000',
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
    assert response == dict(ok=True, state='saved', title=LABEL, group='Web')
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
    """The identity value fields on the page, without its title and confirmation."""
    import re
    return set(re.findall(rb'<input id="[^"]*" name="([^"]+)"', page)) - {b'confirmed', b'title'}


def test_field_subset_page_shows_and_stores_only_requested_fields(deployed, capsys):
    broker, _, path, web = deployed
    pending = begin(broker, fields=['tel'])
    assert set(pending) == {'ok', 'state', 'write_handle', 'private_url', 'expires_in', 'expires_at'}
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
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle'])) == dict(
        ok=True, state='saved', title=LABEL, group='Web')
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
    assert broker.writes.operations == {}


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
    assert set(pending) == {'ok', 'state', 'write_handle', 'private_url', 'expires_in', 'expires_at'} and pending['state'] == 'pending'
    code, _, page = call(web, 'GET', private_path(pending))
    assert code == 200 and field_names(page) == {b'tel'}
    assert b'Update AKDBX identity' in page and b'Update identity in AKDBX' in page and b'Saved values are not shown' in page
    # The page never shows a stored value; the input is empty. Only the
    # non-secret title is filled in, so the user can rename the identity.
    assert b'value="' not in page.split(b'<form', 1)[1].replace(b'value="yes"', b'').replace(
        f'id="title" name="title" type="text" autocomplete="off" maxlength="4096" value="{LABEL}"'.encode(), b'')
    # Only the chosen field is accepted.
    assert call(web, 'POST', private_path(pending), urlencode({'tel': IDENTITY['tel'], 'email': 'x@example.test',
                                                               'confirmed': 'yes'}))[0] == 400
    assert call(web, 'POST', private_path(pending), urlencode({'name': 'Other', 'confirmed': 'yes'}))[0] == 400
    code, _, receipt = call(web, 'POST', private_path(pending), urlencode({'tel': IDENTITY['tel'], 'confirmed': 'yes'}))
    assert code == 200 and b'Identity saved to vault. You may close this page.' in receipt
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle'])) == dict(
        ok=True, state='saved', title=LABEL, group='Web')
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


def test_refused_update_protocol_still_consumes_the_handle(deployed):
    broker, _, _, web = deployed
    saved_identity(broker, web, tel=IDENTITY['tel'])
    handle = search(broker)['entries'][0]['handle']
    request = dict(action='update-identity', handle=handle, fields=['email'], metadata=dict(title=LABEL, group='Web'))
    assert broker.dispatch(request) == REFUSED_UPDATE
    assert broker.dispatch(dict(request, identity_protocol=2)) == REFUSED_UPDATE
    assert update(broker, handle, ['email']) == REFUSED_UPDATE


def test_update_selects_a_unique_identity_under_an_ambiguous_group_path(deployed):
    broker, _, path, web = deployed
    vault = broker.vault
    web_group = vault.find_groups(name='Web', first=True)
    # A group literally named "Work/Travel" and a "Travel" subgroup of "Work".
    vault.add_group(web_group, 'Work/Travel')
    travel = vault.add_group(vault.add_group(web_group, 'Work'), 'Travel')
    from pykeepass.entry import Entry
    entry = Entry(title=LABEL, username='', password='', kp=vault)
    travel.append(entry)
    entry.set_custom_property(MARKER, 'v1')
    entry.set_custom_property(property_key('tel'), IDENTITY['tel'], protect=True)
    found = search(broker)['entries']
    assert [(e['title'], e['group']) for e in found] == [(LABEL, 'Web/Work/Travel')]
    pending = update(broker, found[0]['handle'], ['email'], group='Web/Work/Travel')
    assert pending['ok'] and pending['state'] == 'pending'


@pytest.mark.parametrize('saved, national, code', [
    ('+44 7000 000000', '7000000000', '44'),
    ('+44 7000-000000', '7000000000', '44'),
    ('0044 20 0000 0000', '2000000000', '44'),
    ('+1 (000) 000-0000', '0000000000', '1'),
    ('+7 900 000 00 00', '9000000000', '7'),
    ('+358 40 0000000', '400000000', '358'),
    ('+49 30 000000', '30000000', '49'),
    ('+39 06 0000 0000', '0600000000', '39'),
    ('+852 0000 0000', '00000000', '852'),
    ('+33\u202f6\u202f00\u202f00\u202f00\u202f00', '600000000', '33'),
    ('+44\u00a07000\u2009000000', '7000000000', '44'),
])
def test_national_format_removes_only_the_country_calling_code(saved, national, code):
    from akdbx.identities import national_number
    assert national_number(saved) == national
    assert national_number(saved, code) == national
    with pytest.raises(Exception):
        national_number(saved, '999')


@pytest.mark.parametrize('saved', ['07000 000000', '7000000000', '+44 7000 000000 ext 2', '+44', '+44 7000 (000000',
                                   '+44 70OO 000000', '++44 7000 000000', '+44 7000 000000 0000 0000',
                                   '+44 20 7000 (0)000', '+44 (0)20 7000 0000', '+39 (0)6 0000 0000',
                                   '+225 (0)7 00 00 00 00', '+0044 20 0000 0000', '+44 7000 000000\u200b'])
def test_national_format_refuses_a_number_it_cannot_split_safely(saved):
    from akdbx.identities import national_number
    with pytest.raises(Exception):
        national_number(saved)


@pytest.mark.parametrize('saved, code, national', [
    ('07000 000000', '44', '7000000000'),
    ('07000-000-000', '44', '7000000000'),
    ('020 0000 0000', '44', '2000000000'),
    ('0800 000 0000', '44', '8000000000'),
    ('\u00a007000\u2009000000 ', '44', '7000000000'),
    ('030 000000', '49', '30000000'),
    ('06 00 00 00 00', '33', '600000000'),
    ('04 0000 0000', '61', '400000000'),
    ('020 000 0000', '31', '200000000'),
    ('(020) 0000 0000', '44', '2000000000'),
    ('(07000) 000000', '44', '7000000000'),
    ('( 020 ) 0000-0000', '44', '2000000000'),
    ('(02) 0000 0000', '61', '200000000'),
])
def test_trunk_zero_number_with_its_calling_code_drops_only_the_trunk_zero(saved, code, national):
    from akdbx.identities import international_number, national_number
    assert national_number(saved, code) == national
    assert international_number(saved, code) == '+' + code + national


@pytest.mark.parametrize('saved, code', [
    ('07000 000000', None),     # the country is unknown
    ('07000 000000', '39'),     # Italy: the 0 is part of the number
    ('06 0000 0000', '39'),
    ('0549 000000', '378'),     # San Marino
    ('07 00 00 00 00', '225'),  # Côte d'Ivoire: the 0 is part of the number
    ('8 900 000 00 00', '7'),   # Russia: trunk prefix 8, not 0
    ('06 1 000 0000', '36'),    # Hungary: trunk prefix 06
    ('011 15 0000 0000', '54'),  # Argentina: mobile digits around the trunk 0
    ('021 0000 0000', '55'),    # Brazil: carrier selection after the trunk 0
    ('0600 000000', '34'),      # Spain: no trunk prefix
    ('090 0000 0000', '81'),    # Japan: some numbers begin with 0
    ('0 0000 000000', '44'),    # 0 followed by 0
    ('007000 000000', '44'),    # 00 is the international prefix, then a bad code
    ('07000 0000', '44'),       # a length the UK does not use
    ('07000 0000000', '44'),
    ('(0)7000 000000', '44'),   # a (0) marker, not a trunk prefix
    ('(0) 7000 000000', '44'),
    ('(00) 7000 000000', '44'),
    ('((07000)) 000000', '44'),
    ('(07000 000000', '44'),
    ('07000) 000000', '44'),
    ('07000 (0)00000', '44'),
    ('07000 000000 ext 2', '44'),
    ('7000 000000', '44'),      # no trunk prefix
    ('', '44'),
    ('0', '44'),
])
def test_trunk_zero_number_refuses_what_it_cannot_place_safely(saved, code):
    from akdbx.identities import international_number, national_number
    for split in (national_number, international_number):
        with pytest.raises(Exception):
            split(saved, code)


@pytest.mark.parametrize('saved', ['+44 07000 000000', '0044 07000 000000', '+49 030 000000', '+33 06 00 00 00 00'])
def test_trunk_zero_after_the_calling_code_refuses(saved):
    # "+4407..." is the wrong number a page with a +44 picker made from "07...".
    from akdbx.identities import international_number, national_number
    for split in (national_number, international_number):
        with pytest.raises(Exception):
            split(saved)


@pytest.mark.parametrize('saved, code, international', [
    ('+44 7000 000000', '44', '+447000000000'),
    ('0044 20 0000 0000', '44', '+442000000000'),
    ('+1 (000) 000-0000', '1', '+10000000000'),
    ('+39 06 0000 0000', '39', '+390600000000'),
    ('+358 40 0000000', '358', '+358400000000'),
])
def test_international_format_normalizes_an_international_number(saved, code, international):
    from akdbx.identities import international_number
    assert international_number(saved) == international
    assert international_number(saved, code) == international
    with pytest.raises(Exception):
        international_number(saved, '999')


def test_trunk_zero_table_keeps_the_trunk_digit_rule():
    from akdbx.identities import TRUNK_ZERO, TWO_DIGIT_CODES, calling_code
    assert {'39', '378', '379', '225', '229', '7', '36', '54', '55', '34', '81', '1'}.isdisjoint(TRUNK_ZERO)
    assert TRUNK_ZERO['44'] == '7 9 10'
    for code, lengths in TRUNK_ZERO.items():
        # A real calling code, in the prefix-free set calling_code() splits.
        assert calling_code(code + '0' * 12) == code and (len(code) != 2 or code in TWO_DIGIT_CODES)
        assert all(4 <= int(n) <= 14 and len(code) + int(n) <= 15 for n in lengths.split())


def test_phone_refusals_never_show_the_number():
    from akdbx.identities import international_number, national_number
    for saved, code in [('07123 456789', '39'), ('07123 456789', None), ('+44 07123 456789', '44'),
                        ('07123 456789', '33')]:
        for split in (national_number, international_number):
            with pytest.raises(Exception) as refused:
                split(saved, code)
            assert '123' not in str(refused.value) + repr(refused.value)


def test_identity_status_advertises_field_purpose_and_the_national_format():
    status = Broker(Vault([]), RecordingTyper()).dispatch(dict(action='ping'))
    assert status['identity_field_purpose_protocol'] == 1
    assert status['identity_tel_formats'] == ['national', 'international']


class PhoneIdentity(Entry):
    def get_custom_property(self, key):
        return {MARKER: 'v1', property_key('tel'): IDENTITY['tel'], property_key('email'): IDENTITY['email']}.get(key)


class RecordingTargets:
    """Stands in for the browser: records what would be delivered, never a real field."""

    def __init__(self):
        self.delivered, self.closed = [], 0

    def consume(self, token):
        return dict(field='tel' if token == 't' * 64 else 'email')

    def fill(self, pin, value, field, ready, deadline, *, notify_page=False):
        self.delivered.append((field, value))
        return dict(ok=True, filled=field, identity_delivery='cdp-identity-element-v1')

    def _close(self, pin):
        self.closed += 1


@pytest.mark.parametrize('extra, delivered', [
    ({}, IDENTITY['tel']),
    ({'notify_page': 1}, None),
    ({'format': 'national'}, '30000000'),
    ({'format': 'national', 'calling_code': '49'}, '30000000'),
    ({'format': 'national', 'calling_code': '44'}, None),
    ({'format': 'international'}, '+4930000000'),
    ({'format': 'international', 'calling_code': '49'}, '+4930000000'),
    ({'format': 'international', 'calling_code': '44'}, None),
    ({'calling_code': '49'}, None),
    ({'format': 'e164'}, None),
    ({'format': 'national', 'calling_code': '+49'}, None),
    ({'format': 'national', 'calling_code': 49}, None),
])
def test_fill_formats_only_the_delivered_tel_value(extra, delivered):
    from akdbx.browser_card import failure
    broker = Broker(Vault([PhoneIdentity(uuid='phone', title=LABEL, path=('Web', LABEL))]), RecordingTyper())
    broker.identity_targets = targets = RecordingTargets()
    handle = search(broker)['entries'][0]['handle']
    receipt = broker.dispatch(dict(action='fill-identity', identity_protocol=1, handle=handle, target='t' * 64,
                                   field='tel', start_deadline=broker.clock() + 3, **extra))
    if delivered is None:
        assert receipt == failure(kind='identity') and targets.delivered == []
    else:
        assert receipt['ok'] and targets.delivered == [('tel', delivered)]
    assert targets.closed == 1
    # The saved value stays as it is.
    assert broker.vault.entries[0].get_custom_property(property_key('tel')) == IDENTITY['tel']


def test_national_format_applies_only_to_tel():
    from akdbx.browser_card import failure
    broker = Broker(Vault([PhoneIdentity(uuid='phone', title=LABEL, path=('Web', LABEL))]), RecordingTyper())
    broker.identity_targets = targets = RecordingTargets()
    handle = search(broker)['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill-identity', identity_protocol=1, handle=handle, target='e' * 64,
                                field='email', format='national', start_deadline=broker.clock() + 3)) == failure(kind='identity')
    assert targets.delivered == []


PIN = ['pin-identity-target', '--page-id', 'P', '--frame-id', 'F', '--top-url', 'https://shop.example/',
       '--frame-url', 'https://shop.example/', '--selector', '#phone', '--field', 'tel']
CAPS = dict(ok=True, locked=False, identity_protocol=1, identity_delivery='cdp-identity-element-v1',
            identity_browser_configured=True, default_fill_route='cdp')


@pytest.mark.parametrize('args, caps, error', [
    (['fill-identity', '--field', 'tel', '--notify-page', '--target', 'a' * 64, '--', 'b' * 64], CAPS,
     'broker lacks identity page notification support'),
    (PIN + ['--field-purpose', 'tel'], CAPS, 'broker lacks identity field purpose protocol 1'),
    (PIN + ['--allow-autocomplete-off'], CAPS | dict(identity_field_purpose_protocol=1),
     '--allow-autocomplete-off needs --field-purpose'),
    (PIN + ['--field-purpose', 'email'], CAPS | dict(identity_field_purpose_protocol=1),
     '--field-purpose must name the same detail as --field'),
    (['fill-identity', '--field', 'tel', '--format', 'national', '--target', 'a' * 64, '--', 'b' * 64], CAPS,
     'broker lacks the national tel format'),
    (['fill-identity', '--field', 'email', '--format', 'national', '--target', 'a' * 64, '--', 'b' * 64],
     CAPS | dict(identity_tel_formats=['national']), '--format applies only to --field tel'),
    (['fill-identity', '--field', 'tel', '--calling-code', '44', '--target', 'a' * 64, '--', 'b' * 64],
     CAPS | dict(identity_tel_formats=['national']), '--calling-code needs --format'),
    (['fill-identity', '--field', 'tel', '--format', 'national', '--calling-code', '+44', '--target', 'a' * 64,
      '--', 'b' * 64], CAPS | dict(identity_tel_formats=['national']), '--calling-code needs --format'),
    (['fill-identity', '--field', 'tel', '--format', 'international', '--calling-code', '44', '--target', 'a' * 64,
      '--', 'b' * 64], CAPS | dict(identity_tel_formats=['national']), 'broker lacks the international tel format'),
])
def test_cli_refuses_purpose_and_format_options_before_sending(args, caps, error, monkeypatch, capsys):
    calls = []

    def broker(_, payload, **kwargs):
        calls.append(payload)
        return caps
    monkeypatch.setattr(cli, 'request', broker)
    assert cli.main(args) == 1
    assert calls == [{'action': 'ping'}]
    assert json.loads(capsys.readouterr().out)['error'].startswith(error)


def test_cli_sends_the_purpose_and_format_options(monkeypatch, capsys):
    sent = []
    caps = CAPS | dict(identity_field_purpose_protocol=1, identity_tel_formats=['national'])

    def broker(_, payload, **kwargs):
        if payload['action'] == 'ping':
            return caps
        sent.append(payload)
        if payload['action'] == 'pin-identity-target':
            return dict(ok=True, field='tel', target='c' * 64, expires_in=30, identity_delivery='cdp-identity-element-v1')
        return dict(ok=True, filled='tel', identity_delivery='cdp-identity-element-v1')
    monkeypatch.setattr(cli, 'request', broker)
    assert cli.main(PIN + ['--field-purpose', 'tel', '--allow-autocomplete-off']) == 0
    assert cli.main(['fill-identity', '--field', 'tel', '--format', 'national', '--calling-code', '44',
                     '--target', 'a' * 64, '--', 'b' * 64]) == 0
    assert sent[0]['field_purpose'] == 'tel' and sent[0]['allow_autocomplete_off'] is True
    assert sent[1]['format'] == 'national' and sent[1]['calling_code'] == '44'
    assert cli.main(PIN) == 0 and cli.main(['fill-identity', '--field', 'tel', '--target', 'a' * 64, '--', 'b' * 64]) == 0
    assert not {'field_purpose', 'allow_autocomplete_off'} & set(sent[2]) and not {'format', 'calling_code'} & set(sent[3])
    capsys.readouterr()


@pytest.mark.parametrize('extra', [dict(field_purpose='email'), dict(allow_autocomplete_off=True),
                                   dict(field_purpose='tel', allow_autocomplete_off=False),
                                   dict(field_purpose='tel', allow_autocomplete_off='yes')])
def test_broker_refuses_an_inconsistent_purpose_before_any_browser_call(extra):
    from akdbx.browser_card import CardTargetError, field_purpose
    with pytest.raises(CardTargetError):
        field_purpose('identity', dict(field='tel', **extra))
    # A card pin takes a purpose for its own fields only, and never with a processor.
    for card in (dict(field='cc-exp', field_purpose='cc-exp'), dict(field='cc-number', field_purpose='cc-csc'),
                 dict(field='cc-number', field_purpose='cc-number', processor='stripe'),
                 dict(field='cc-number', allow_autocomplete_off=True)):
        with pytest.raises(CardTargetError):
            field_purpose('card', card)
    assert field_purpose('card', dict(field='cc-number', field_purpose='cc-number')) == ('cc-number', False)
    assert field_purpose('identity', dict(field='tel')) == (False, False)
    assert field_purpose('identity', dict(field='tel', field_purpose='tel', allow_autocomplete_off=True)) == ('tel', True)


def page_post(web, pending, **form):
    return call(web, 'POST', private_path(pending), urlencode(form | {'confirmed': 'yes'}))


def test_page_rename_saves_the_new_title_in_the_same_write(deployed):
    broker, _, path, web = deployed
    saved_identity(broker, web, tel=IDENTITY['tel'])
    before = reopened(path).find_entries(title=LABEL, first=True)
    pending = update(broker, search(broker)['entries'][0]['handle'], ['email'])
    code, _, page = call(web, 'GET', private_path(pending))
    # The title is an editable field that shows the current title.
    assert code == 200 and f'name="title" type="text" autocomplete="off" maxlength="4096" value="{LABEL}"'.encode() in page
    code, _, receipt = page_post(web, pending, email=IDENTITY['email'], title='Renamed shipping')
    assert code == 200 and '“Renamed shipping” in Web.'.encode() in receipt
    # The agent finds the identity again by the title that was saved.
    status = dict(ok=True, state='saved', title='Renamed shipping', group='Web')
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle'])) == status
    assert [(e['title'], e['group']) for e in search(broker, '')['entries']] == [('Renamed shipping', 'Web')]
    # The receipt kept after a lock has the saved title too.
    broker.writes.keep_receipts()
    assert broker.writes.status(pending['write_handle']) == status
    vault = reopened(path)
    assert vault.find_entries(title=LABEL) == []
    entry = vault.find_entries(title='Renamed shipping', first=True)
    assert entry.uuid == before.uuid
    assert stored(entry) == {'tel': IDENTITY['tel'], 'email': IDENTITY['email']} and protected(entry, 'email')
    # One write: one history version, which has the old title and fields.
    assert len(entry.history) == 1 and entry.history[0].title == LABEL and stored(entry.history[0]) == stored(before)


def test_create_page_saves_a_new_title(deployed):
    broker, _, path, web = deployed
    pending = begin(broker, fields=['tel'])
    assert page_post(web, pending, tel=IDENTITY['tel'], title='Home shipping')[0] == 200
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle'])) == dict(
        ok=True, state='saved', title='Home shipping', group='Web')
    vault = reopened(path)
    assert vault.find_entries(title=LABEL) == []
    assert stored(vault.find_entries(title='Home shipping', first=True)) == {'tel': IDENTITY['tel']}


@pytest.mark.parametrize('form', [{}, {'title': LABEL}, {'title': ''}, {'title': '  '}])
def test_an_unchanged_or_empty_title_keeps_the_old_title(deployed, form):
    broker, _, path, web = deployed
    saved_identity(broker, web, tel=IDENTITY['tel'])
    pending = update(broker, search(broker)['entries'][0]['handle'], ['email'])
    assert page_post(web, pending, email=IDENTITY['email'], **form)[0] == 200
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle'])) == dict(
        ok=True, state='saved', title=LABEL, group='Web')
    entries = reopened(path).find_entries(title=LABEL)
    assert len(entries) == 1 and stored(entries[0]) == {'tel': IDENTITY['tel'], 'email': IDENTITY['email']}


@pytest.mark.parametrize('title', ['line\nbreak', 'tab\there', 'line separator', 'é' * 2049])
def test_an_invalid_title_keeps_the_page_open_and_saves_nothing(deployed, title):
    broker, _, path, web = deployed
    saved_identity(broker, web, tel=IDENTITY['tel'])
    before = reopened(path).find_entries(title=LABEL, first=True)
    pending = update(broker, search(broker)['entries'][0]['handle'], ['email'])
    code, _, page = page_post(web, pending, email=IDENTITY['email'], title=title)
    assert code == 409 and b'data-save-result="rejected"' in page
    assert b'Enter a title without line breaks or control characters, up to 4096 bytes.' in page
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle'])) == dict(
        ok=True, state='pending')
    entry = reopened(path).find_entries(title=LABEL, first=True)
    assert stored(entry) == stored(before) and entry.history == []
    # The page stays open: a corrected title saves.
    assert page_post(web, pending, email=IDENTITY['email'], title='Fixed shipping')[0] == 200
    assert reopened(path).find_entries(title='Fixed shipping', first=True).uuid == before.uuid


def test_a_title_another_identity_has_in_the_group_is_refused_on_the_page(deployed):
    broker, _, path, web = deployed
    saved_identity(broker, web, tel=IDENTITY['tel'])
    other = begin(broker, fields=['email'], title='Other shipping')
    assert page_post(web, other, email=IDENTITY['email'])[0] == 200
    pending = update(broker, search(broker, LABEL)['entries'][0]['handle'], ['email'])
    code, _, page = page_post(web, pending, email=IDENTITY['email'], title='Other shipping')
    assert code == 409 and b'data-save-result="rejected"' in page
    assert b'An identity with this title already exists in this group. Choose another title.' in page
    created = begin(broker, fields=['tel'], title='Third shipping')
    code, _, page = page_post(web, created, tel=IDENTITY['tel'], title=LABEL)
    assert code == 409 and b'An identity with this title already exists in this group.' in page
    vault = reopened(path)
    assert stored(vault.find_entries(title=LABEL, first=True)) == {'tel': IDENTITY['tel']}
    assert len(vault.find_entries(title='Other shipping')) == 1 and vault.find_entries(title='Third shipping') == []
    # The page stays open for another title.
    assert page_post(web, pending, email=IDENTITY['email'], title='Work shipping')[0] == 200
    vault = reopened(path)
    assert vault.find_entries(title=LABEL) == [] and len(vault.find_entries(title='Work shipping')) == 1


# Phone-digit pins (0.55.1): one box of a split "last digits of your number" challenge.
@pytest.mark.parametrize('saved, count, digits', [
    ('+1 (555) 010-0128', 4, '0128'),
    ('+44 7700 900 528', 4, '0528'),
    ('0049/30.000-00028', 2, '28'),
    ('5550100128', 8, '50100128'),
])
def test_last_digits_keep_only_the_digits_of_the_saved_number(saved, count, digits):
    from akdbx.identities import last_digits
    assert last_digits(saved, count) == digits


@pytest.mark.parametrize('saved, count', [
    ('+1 23', 4),                    # Too short for the boxes.
    ('128', 4),
    ('+1 555 010 0128 ext 12', 4),   # An extension would move the last digits.
    ('+1 555 010 0128 x12', 4),
    ('+1 555 010 0128 +', 4),        # A + only opens the number.
    ('+1 555 010 ١٢', 4),  # Only ASCII digits count.
    ('+1 555;010 0128', 4),
])
def test_last_digits_refuse_a_value_they_cannot_read_safely(saved, count):
    from akdbx.identities import last_digits
    with pytest.raises(WriteError) as refused:
        last_digits(saved, count)
    assert saved not in str(refused.value) and '0128' not in str(refused.value)


class DigitTargets(RecordingTargets):
    """A phone-digit pin of 'of_last' boxes, as the CDP route records it."""

    def __init__(self, of_last=4):
        super().__init__()
        self.of_last = of_last

    def consume(self, token):
        return dict(field='tel', request=dict(field='tel', phone_digit=1, of_last=self.of_last))


class SyntheticPhone(Entry):
    tel = '+1 (555) 010-0128'  # Synthetic only.

    def get_custom_property(self, key):
        return {MARKER: 'v1', property_key('tel'): self.tel}.get(key)


@pytest.mark.parametrize('tel, extra, delivered', [
    ('+1 (555) 010-0128', {}, '0128'),
    ('+1 (555) 010-0128', {'notify_page': True}, '0128'),
    ('+1 23', {}, None),                                   # Fewer digits than boxes.
    ('+1 (555) 010-0128', {'format': 'national'}, None),   # A digit pin takes no format.
    ('+1 (555) 010-0128', {'format': 'international', 'calling_code': '1'}, None),
])
def test_a_phone_digit_pin_receives_only_the_last_digits(tel, extra, delivered):
    """The broker sends the pinned box's script the last digits it checks; the box's own script writes one."""
    from akdbx.browser_card import failure
    entry = SyntheticPhone(uuid='phone', title=LABEL, path=('Web', LABEL))
    entry.tel = tel
    broker = Broker(Vault([entry]), RecordingTyper())
    broker.identity_targets = targets = DigitTargets()
    handle = search(broker)['entries'][0]['handle']
    receipt = broker.dispatch(dict(action='fill-identity', identity_protocol=1, handle=handle, target='t' * 64,
                                   field='tel', start_deadline=broker.clock() + 3, **extra))
    if delivered is None:
        assert receipt == failure(kind='identity') and targets.delivered == []
    else:
        assert receipt == dict(ok=True, filled='tel', identity_delivery='cdp-identity-element-v1')
        assert targets.delivered == [('tel', delivered)]
    assert tel not in json.dumps(receipt) and targets.closed == 1


@pytest.mark.parametrize('extra', [
    dict(phone_digit=1), dict(of_last=4), dict(phone_digit=0, of_last=4), dict(phone_digit=5, of_last=4),
    dict(phone_digit=1, of_last=1), dict(phone_digit=1, of_last=9), dict(phone_digit=True, of_last=4),
    dict(phone_digit='1', of_last=4), dict(phone_digit=1, of_last=4.0),
    dict(phone_digit=1, of_last=4, field_purpose='tel'), dict(phone_digit=1, of_last=4, field='email'),
])
def test_broker_refuses_an_invalid_phone_digit_pin_before_any_browser_call(extra):
    from akdbx.browser_card import CardTargetError
    from akdbx.browser_identity import BrowserIdentities, digit_spec

    def no_browser(profile):
        pytest.fail('an invalid phone-digit pin reached the browser')
    request = dict(field='tel') | extra
    with pytest.raises(CardTargetError):
        digit_spec(request)
    targets = BrowserIdentities('/nonexistent/profile', connector=no_browser)
    with pytest.raises(CardTargetError):
        targets.pin(dict(action='pin-identity-target', identity_protocol=1, page_id='P', frame_id='F',
                         top_url='https://shop.example/', frame_url='https://shop.example/', selector='#d',
                         **request))
    assert digit_spec(dict(field='tel')) is None
    assert digit_spec(dict(field='tel', phone_digit=2, of_last=4)) == (1, 4)


def test_identity_status_advertises_the_phone_digit_protocol():
    status = Broker(Vault([]), RecordingTyper()).dispatch(dict(action='ping'))
    assert status['identity_phone_digit_protocol'] == 1


DIGIT_CAPS = CAPS | dict(identity_phone_digit_protocol=1)


@pytest.mark.parametrize('extra, caps, error', [
    (['--phone-digit', '1', '--of-last', '4'], CAPS, 'broker lacks identity phone digit protocol 1'),
    (['--phone-digit', '1'], DIGIT_CAPS, '--phone-digit and --of-last go together'),
    (['--of-last', '4'], DIGIT_CAPS, '--phone-digit and --of-last go together'),
    (['--phone-digit', '5', '--of-last', '4'], DIGIT_CAPS, '--of-last must be 2 to 8'),
    (['--phone-digit', '0', '--of-last', '4'], DIGIT_CAPS, '--of-last must be 2 to 8'),
    (['--phone-digit', '1', '--of-last', '9'], DIGIT_CAPS, '--of-last must be 2 to 8'),
    (['--phone-digit', '1', '--of-last', '4', '--field-purpose', 'tel'],
     DIGIT_CAPS | dict(identity_field_purpose_protocol=1), '--phone-digit does not combine with --field-purpose'),
])
def test_cli_refuses_phone_digit_options_before_sending(extra, caps, error, monkeypatch, capsys):
    calls = []

    def broker(_, payload, **kwargs):
        calls.append(payload)
        return caps
    monkeypatch.setattr(cli, 'request', broker)
    assert cli.main(PIN + extra) == 1
    assert calls == [{'action': 'ping'}]
    assert json.loads(capsys.readouterr().out)['error'].startswith(error)


def test_cli_refuses_a_phone_digit_for_another_field(monkeypatch, capsys):
    monkeypatch.setattr(cli, 'request', lambda _, payload, **kwargs: DIGIT_CAPS)
    args = [a if a != 'tel' else 'email' for a in PIN]
    assert cli.main(args + ['--phone-digit', '1', '--of-last', '4']) == 1
    assert json.loads(capsys.readouterr().out)['error'].startswith('--phone-digit applies only to --field tel')


def test_cli_sends_the_phone_digit_and_the_box_count(monkeypatch, capsys):
    sent = []

    def broker(_, payload, **kwargs):
        if payload['action'] == 'ping':
            return DIGIT_CAPS
        sent.append(payload)
        return dict(ok=True, field='tel', target='c' * 64, expires_in=30, identity_delivery='cdp-identity-element-v1')
    monkeypatch.setattr(cli, 'request', broker)
    assert cli.main(PIN + ['--phone-digit', '2', '--of-last', '4']) == 0
    assert sent[0]['phone_digit'] == 2 and sent[0]['of_last'] == 4 and 'field_purpose' not in sent[0]
    capsys.readouterr()
