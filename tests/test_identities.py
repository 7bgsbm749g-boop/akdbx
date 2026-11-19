"""Private identity saves use only synthetic data and isolated vaults."""
import json
from urllib.parse import urlencode, urlsplit

from akdbx import cli
from akdbx.identities import FIELDS, MARKER, property_key
from test_broker import x11_target_request
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
    for action in ('setup-totp', 'update-password', 'generate-password', 'add-url'):
        handle = search(broker)['entries'][0]['handle']
        payload = dict(additional_urls_protocol=1, url='https://example.test') if action == 'add-url' else {}
        assert not broker.dispatch(dict(action=action, handle=handle, **payload))['ok']
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
