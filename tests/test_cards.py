"""Synthetic cards only. Private saves are tested through the real HTTP route."""
import json
from urllib.parse import urlencode, urlsplit

import pytest

from akdbx.cards import FIELDS, MARKER, read_card, validate
from akdbx import cli
from akdbx.browser_card import DELIVERY, failure
from test_writes import deployed, template, reopened, MASTER
from test_web_unlock import call
from test_broker import target_request

CARD = dict(name='Synthetic Cardholder', number='4111111111111111', month='09', year='2031', csc='123')


def begin(broker, **changes):
    return broker.dispatch(dict(action='create-card', card_protocol=1,
                                metadata=dict(title='Synthetic Visa', group='Web'), **changes))


def post(socket, prepared, values=None, **changes):
    parts = urlsplit(prepared['private_url'])
    data = dict(CARD if values is None else values, confirmed='yes')
    data.update(changes)
    return call(socket, 'POST', parts.path + '?' + parts.query, urlencode(data))


def search(broker):
    return broker.dispatch(dict(action='search-cards', card_protocol=1))


def save(deployed):
    broker, _, path, socket = deployed
    prepared = begin(broker)
    assert prepared['ok']
    assert post(socket, prepared)[0] == 200
    return search(broker)['entries'][0]


def test_private_card_save_reopens_exact_protected_fields_and_hides_values(deployed, capsys, caplog):
    broker, typer, path, socket = deployed
    prepared = begin(broker)
    parts = urlsplit(prepared['private_url'])
    route = parts.path + '?' + parts.query
    code, headers, page = call(socket, 'GET', route)
    assert code == 200 and headers['Cache-Control'] == 'no-store'
    assert 'frame-ancestors' in headers['Content-Security-Policy']
    assert CARD['number'].encode() not in page
    assert call(socket, 'GET', route, identity=False)[0] == 404
    assert post(socket, prepared)[0] == 200
    assert post(socket, prepared)[0] == 404
    assert broker.dispatch(dict(action='write-status', write_handle=prepared['write_handle'])) == dict(ok=True, state='saved')
    entry = reopened(path).find_entries(title='Synthetic Visa', first=True)
    assert entry.username in {None, ''} and entry.password in {None, ''}
    assert read_card(entry) == CARD
    for field in FIELDS.values():
        assert entry._element.find('./String[Key="' + field + '"]/Value').get('Protected') == 'True'
    result = search(broker)
    assert {k: v for k, v in result['entries'][0].items() if k != 'handle'} == dict(title='Synthetic Visa', group='Web', brand='visa', last_four='1111')
    assert all(e['title'] != 'Synthetic Visa' for e in broker.dispatch(dict(action='search'))['entries'])
    output = capsys.readouterr()
    for secret in (MASTER, CARD['number'], CARD['name']):
        assert secret not in output.out + output.err + caplog.text + json.dumps(result) + json.dumps(prepared)
        assert secret.encode() not in path.read_bytes()
    assert typer.events == []


def test_update_preserves_history_unrelated_entries_and_consumes_handle(deployed):
    selected = save(deployed)
    broker, _, path, socket = deployed
    result = broker.dispatch(dict(action='update-card', card_protocol=1, handle=selected['handle'],
                                  metadata=dict(title=selected['title'], group=selected['group'])))
    updated = dict(CARD, number='5555555555554444', csc='456', year='2032')
    assert post(socket, result, updated)[0] == 200
    entry = reopened(path).find_entries(title=selected['title'], first=True)
    assert read_card(entry) == updated
    assert read_card(entry.history[-1]) == CARD
    assert reopened(path).find_entries(title='Synthetic site', first=True).username == 'synthetic-account'
    assert search(broker)['entries'][0]['brand'] == 'mastercard'
    assert not broker.dispatch(dict(action='update-card', card_protocol=1, handle=selected['handle'],
                                    metadata=dict(title=selected['title'], group=selected['group'])))['ok']


@pytest.mark.parametrize('changes', [dict(number='4111111111111112'), dict(number='４' * 16),
    dict(name='bad\tname'), dict(number='4111\n111111111111'), dict(month='13'), dict(month='9'),
    dict(year='31'), dict(csc='1'), dict(name=''), dict(extra='ignored?')])
def test_bad_card_never_changes_encrypted_vault_or_echoes_input(deployed, changes):
    broker, _, path, socket = deployed
    original = path.read_bytes()
    prepared = begin(broker)
    code, _, page = post(socket, prepared, dict(CARD, **changes))
    assert code in {400, 409}
    assert path.read_bytes() == original
    assert CARD['number'].encode() not in page


def test_optional_security_code_and_formatted_number(deployed):
    broker, _, path, socket = deployed
    assert post(socket, begin(broker), dict(CARD, csc='', number='4111 1111-1111 1111'))[0] == 200
    assert read_card(reopened(path).find_entries(title='Synthetic Visa', first=True)) == dict(CARD, csc='')


def test_cancel_expiry_wrong_route_and_stale_writes_never_save(deployed):
    broker, _, path, socket = deployed
    first = begin(broker)
    route = urlsplit(first['private_url'])
    assert call(socket, 'GET', '/write?' + route.query)[0] == 404
    assert broker.dispatch(dict(action='cancel-write', write_handle=first['write_handle']))['state'] == 'cancelled'
    assert post(socket, first)[0] == 404
    first, second = begin(broker), begin(broker)
    assert post(socket, first)[0] == 200
    assert post(socket, second)[0] == 404
    op = broker.dispatch(
        dict(action='create-card', card_protocol=1, metadata=dict(title='Expired card', group='Web')))
    broker.writes.operations[op['write_handle']].expires = broker.clock() - 1
    assert post(socket, op)[0] == 404
    assert len(search(broker)['entries']) == 1


def test_cards_refuse_login_fill_and_password_writes_even_with_internal_handle(deployed):
    save(deployed)
    broker, typer, _, _ = deployed
    entry = next(e for e in broker.vault.entries if e.get_custom_property(MARKER))
    for mode in ('login', 'username', 'password'):
        result = broker.dispatch(dict(action='fill', handle=broker._new_handle(entry), mode=mode, **target_request(broker)))
        assert not result['ok']
    for action in ('update-password', 'generate-password', 'setup-totp'):
        assert not broker.dispatch(dict(action=action, handle=broker._new_handle(entry), metadata={}))['ok']
    assert typer.events == []


@pytest.mark.parametrize('changes', [dict(card_protocol=True), dict(card_protocol=0), dict(password='secret'), dict(number=CARD['number'])])
def test_protocol_and_secret_rpc_arguments_refused(deployed, changes):
    broker, _, path, _ = deployed
    request = dict(action='create-card', card_protocol=1, metadata=dict(title='Synthetic Visa', group='Web'))
    assert not broker.dispatch(dict(request, **changes))['ok']
    assert not search(broker)['entries']


def test_duplicate_and_unconfirmed_save_leave_vault_unchanged(deployed):
    save(deployed)
    broker, _, path, socket = deployed
    before = path.read_bytes()
    assert post(socket, begin(broker))[0] == 409
    assert post(socket, begin(broker), confirmed='no')[0] == 409
    assert path.read_bytes() == before


def test_corrupt_empty_card_marker_cannot_reenable_password_path(deployed):
    save(deployed)
    broker, typer, _, _ = deployed
    entry = next(e for e in broker.vault.entries if e.get_custom_property(MARKER))
    entry.set_custom_property(MARKER, '')
    entry.username, entry.password = 'must-not-type-name', 'must-not-type-password'
    assert all(e['title'] != entry.title for e in broker.dispatch(dict(action='search'))['entries'])
    assert not search(broker)['entries']
    assert not broker.dispatch(dict(action='fill', handle=broker._new_handle(entry), mode='login', **target_request(broker)))['ok']
    assert typer.events == []


def test_reopen_verification_refuses_lost_field_protection_before_replacing_vault(deployed, monkeypatch):
    from pykeepass import PyKeePass
    broker, _, path, socket = deployed
    before = path.read_bytes()
    prepared = begin(broker)
    original = PyKeePass.save
    def lose_protection(vault, *args, **kwargs):
        for entry in vault.entries:
            if entry.get_custom_property(MARKER):
                entry.set_custom_property(FIELDS['number'], CARD['number'], protect=False)
        return original(vault, *args, **kwargs)
    monkeypatch.setattr(PyKeePass, 'save', lose_protection)
    assert post(socket, prepared)[0] == 409
    assert path.read_bytes() == before
    assert search(broker)['entries'] == []


def test_external_vault_change_refuses_card_save_and_preserves_external_bytes(deployed):
    broker, _, path, socket = deployed
    prepared = begin(broker)
    external = reopened(path)
    external.add_entry(external.root_group, 'Synthetic external edit', 'account', 'synthetic-external-value')
    external.save()
    before = path.read_bytes()
    assert post(socket, prepared)[0] == 409
    assert path.read_bytes() == before
    assert reopened(path).find_entries(title='Synthetic external edit', first=True)


def test_cli_checks_protocol_and_withholds_secret_bearing_receipts(monkeypatch, capsys):
    calls = []
    def request(_socket, payload, **kwargs):
        calls.append(payload)
        return dict(ok=True, cards_supported=True, card_protocol=1, card_delivery=DELIVERY) if payload['action'] == 'ping' else dict(ok=True, filled='cc-number', card_delivery=DELIVERY, number=CARD['number'])
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['fill-card', 'h', '--target', 't', '--field', 'cc-number']) == 2
    output = capsys.readouterr()
    assert CARD['number'] not in output.out + output.err
    assert calls[-1]['card_protocol'] == 1
    calls.clear()
    monkeypatch.setattr(cli, 'request', lambda _s, payload, **kw: calls.append(payload) or dict(ok=True, cards_supported=True, card_protocol=True, card_delivery=DELIVERY))
    assert cli.main(['search-cards', 'Visa']) == 1
    assert calls == [dict(action='ping')]
