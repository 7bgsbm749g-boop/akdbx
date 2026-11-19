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


def begin(broker, **metadata):
    return broker.dispatch(dict(action='create-identity', identity_protocol=1,
                                metadata=dict(title=LABEL, group='Web') | metadata))


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
    assert code == 200 and b'Identity saved to AKDBX' in receipt
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
    assert not refused['ok'] and typer.events == []
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
