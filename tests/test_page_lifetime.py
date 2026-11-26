"""Optional private save page lifetime for identities and cards (synthetic data only)."""
import re
from urllib.parse import urlencode, urlsplit

import pytest

from akdbx import cli
from akdbx.identities import REFUSED
from akdbx.writes import PAGE_MINUTES_MAX, expiry_text
from test_cards import CARD, post as post_card, search as search_cards
from test_identities import LABEL, private_path, search as search_identities
from test_web_unlock import call
from test_writes import deployed, reopened, template  # noqa: F401

STAMP = r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z'
EMAIL = 'synthetic-only@example.test'


@pytest.fixture
def clocked(deployed):
    """The deployed broker with a monotonic and a wall clock that the test moves."""
    broker, typer, path, web = deployed
    now = dict(mono=1000.0, wall=1_800_000_000.0)
    broker.clock = lambda: now['mono']
    broker.wall_clock = lambda: now['wall']

    def advance(seconds):
        now['mono'] += seconds
        now['wall'] += seconds
    return broker, path, web, now, advance


def identity(broker, **extra):
    return broker.dispatch(dict(action='create-identity', identity_protocol=1, fields=['email'],
                                metadata=dict(title=LABEL, group='Web'), **extra))


def update_identity(broker, **extra):
    handle = search_identities(broker)['entries'][0]['handle']
    return broker.dispatch(dict(action='update-identity', identity_protocol=1, handle=handle, fields=['email'],
                                metadata=dict(title=LABEL, group='Web'), **extra))


def card(broker, **extra):
    return broker.dispatch(dict(action='create-card', card_protocol=1,
                                metadata=dict(title='Synthetic Visa', group='Web'), **extra))


def update_card(broker, **extra):
    selected = search_cards(broker)['entries'][0]
    return broker.dispatch(dict(action='update-card', card_protocol=1, handle=selected['handle'],
                                metadata=dict(title=selected['title'], group=selected['group']), **extra))


def post_identity(web, prepared, email=EMAIL):
    return call(web, 'POST', private_path(prepared), urlencode({'email': email, 'confirmed': 'yes'}))


def check_receipt(prepared, now, seconds, route):
    assert set(prepared) == {'ok', 'state', 'write_handle', 'private_url', 'expires_in', 'expires_at'}
    assert prepared['ok'] is True and prepared['state'] == 'pending'
    assert urlsplit(prepared['private_url']).path == route
    assert prepared['expires_in'] == seconds
    assert re.fullmatch(STAMP, prepared['expires_at'])
    assert prepared['expires_at'] == expiry_text(now['wall'] + seconds)


def page_expiry(web, prepared):
    code, _, page = call(web, 'GET', private_path(prepared))
    assert code == 200
    stamp = prepared['expires_at']
    note = (f'This page works until <time datetime="{stamp}" data-local-time>{stamp[11:16]} UTC</time>. '
            'It stops sooner if the vault locks. After that, ask for a new save page.')
    return note.encode() in page


def test_default_lifetime_stays_five_minutes_and_page_shows_it(clocked):
    broker, path, web, now, advance = clocked
    first = identity(broker)
    check_receipt(first, now, 300, '/identity')
    assert broker.writes.get(first['write_handle']).expires == now['mono'] + 300
    assert page_expiry(web, first)
    advance(299)
    assert post_identity(web, first)[0] == 200
    pending_card = card(broker)
    check_receipt(pending_card, now, 300, '/card')
    assert page_expiry(web, pending_card)
    advance(299)
    assert post_card(web, pending_card)[0] == 200
    late = card(broker)
    advance(300)
    code, _, page = post_card(web, late)
    assert code == 404 and b'data-save-result="expired"' in page
    assert len(search_cards(broker)['entries']) == 1


@pytest.mark.parametrize('prepare,route', [(identity, '/identity'), (card, '/card')])
def test_twenty_five_minutes_keeps_every_save_check(clocked, prepare, route):
    broker, path, web, now, advance = clocked
    pending = prepare(broker, valid_minutes=25)
    check_receipt(pending, now, 25 * 60, route)
    assert page_expiry(web, pending)
    # The token is still required.
    assert call(web, 'GET', route + '?token=' + 'a' * 43)[0] == 404
    advance(25 * 60 - 1)
    save = post_identity if route == '/identity' else post_card
    assert save(web, pending)[0] == 200
    # Single use: the saved page does not save again.
    code, _, page = save(web, pending)
    assert code == 404 and b'data-save-result="saved"' in page


@pytest.mark.parametrize('prepare,update', [(identity, update_identity), (card, update_card)])
def test_updates_take_the_lifetime_and_stay_revision_bound(clocked, prepare, update):
    broker, path, web, now, advance = clocked
    save = post_identity if prepare is identity else post_card
    assert save(web, prepare(broker))[0] == 200
    pending = update(broker, valid_minutes=25)
    check_receipt(pending, now, 25 * 60, '/identity' if prepare is identity else '/card')
    other = update(broker, valid_minutes=25)
    advance(20 * 60)
    assert save(web, other)[0] == 200
    # Another save changed the vault: the long page is stale, not saved.
    code, _, page = save(web, pending)
    assert code == 404 and b'data-save-result="stale"' in page


@pytest.mark.parametrize('prepare', [identity, card])
def test_a_long_page_expires_at_its_time(clocked, prepare):
    broker, path, web, now, advance = clocked
    pending = prepare(broker, valid_minutes=25)
    advance(25 * 60)
    save = post_identity if prepare is identity else post_card
    code, _, page = save(web, pending)
    assert code == 404 and b'data-save-result="expired"' in page
    assert broker.dispatch(dict(action='write-status', write_handle=pending['write_handle']))['ok'] is False
    if prepare is identity:
        assert search_identities(broker)['entries'] == []
    else:
        assert search_cards(broker)['entries'] == []


@pytest.mark.parametrize('minutes', [PAGE_MINUTES_MAX + 1, 60, 0, -5, True, 25.0, '25', None])
@pytest.mark.parametrize('prepare', [identity, card])
def test_lifetime_outside_one_to_thirty_minutes_is_refused(clocked, prepare, minutes):
    broker, path, web, now, advance = clocked
    result = prepare(broker, valid_minutes=minutes)
    assert result['ok'] is False and 'write_handle' not in result and 'private_url' not in result
    assert result['error'] == (REFUSED if prepare is identity
                               else 'card operation refused; check selection and destination')
    assert broker.writes.operations == {}


@pytest.mark.parametrize('update', [update_identity, update_card])
def test_refused_update_lifetime_still_consumes_the_search_handle(clocked, update):
    broker, path, web, now, advance = clocked
    save = post_identity if update is update_identity else post_card
    assert save(web, (identity if update is update_identity else card)(broker))[0] == 200
    if update is update_identity:
        handle = search_identities(broker)['entries'][0]['handle']
        request = dict(action='update-identity', identity_protocol=1, handle=handle, fields=['email'],
                       metadata=dict(title=LABEL, group='Web'))
    else:
        selected = search_cards(broker)['entries'][0]
        request = dict(action='update-card', card_protocol=1, handle=selected['handle'],
                       metadata=dict(title=selected['title'], group=selected['group']))
    assert broker.dispatch(dict(request, valid_minutes=31))['ok'] is False
    assert broker.dispatch(dict(request, valid_minutes=25))['ok'] is False


@pytest.mark.parametrize('prepare', [identity, card])
def test_lifetime_never_outlasts_the_vault_lock_timeout(clocked, prepare):
    """A page stops when the vault locks, and opening it is not vault activity."""
    broker, path, web, now, advance = clocked
    broker.session.timeout = 600
    refused = prepare(broker, valid_minutes=11)
    assert refused['ok'] is False and broker.writes.operations == {}
    check_receipt(prepare(broker, valid_minutes=10), now, 600, '/' + ('identity' if prepare is identity else 'card'))
    # The default page is cut to a lock timeout below five minutes.
    broker.session.timeout = 120
    short = prepare(broker)
    check_receipt(short, now, 120, '/' + ('identity' if prepare is identity else 'card'))
    assert broker.writes.get(short['write_handle']).expires == now['mono'] + 120


def test_ping_reports_the_lifetime_protocol(deployed):
    broker = deployed[0]
    caps = broker.dispatch(dict(action='ping'))
    assert caps['save_page_lifetime_protocol'] == 1 and caps['save_page_max_minutes'] == 30


IDENTITY_CAPS = dict(ok=True, identity_protocol=1, identity_delivery='cdp-identity-element-v1',
                     identity_fields_protocol=1, identity_update_protocol=1)
CARD_CAPS = dict(ok=True, cards_supported=True, card_protocol=1, card_delivery='cdp-card-element-v1')
LIFETIME_CAPS = dict(save_page_lifetime_protocol=1, save_page_max_minutes=30, lock_timeout_seconds=3600)


def receipt(route, seconds=None):
    result = dict(ok=True, state='pending', write_handle='a' * 64,
                  private_url='https://node.example:9443' + route + '?token=' + 'b' * 43)
    if seconds is not None:
        result.update(expires_in=seconds, expires_at='2027-01-15T08:25:00Z')
    return result


COMMANDS = [
    (['create-identity', '--title', LABEL, '--group', 'Web'], IDENTITY_CAPS, '/identity'),
    (['update-identity', 'c' * 64, '--title', LABEL, '--group', 'Web', '--fields', 'email'], IDENTITY_CAPS, '/identity'),
    (['create-card', '--title', 'Synthetic Visa', '--group', 'Web'], CARD_CAPS, '/card'),
    (['update-card', 'c' * 64, '--title', 'Synthetic Visa', '--group', 'Web'], CARD_CAPS, '/card'),
]


@pytest.mark.parametrize('args,caps,route', COMMANDS)
def test_cli_sends_the_lifetime_and_checks_the_reported_expiry(monkeypatch, capsys, args, caps, route):
    calls = []
    replies = {}

    def broker(_, payload, **kwargs):
        calls.append(payload)
        return replies['ping'] if payload['action'] == 'ping' else replies['save']

    monkeypatch.setattr(cli, 'request', broker)
    replies.update(ping=caps | LIFETIME_CAPS, save=receipt(route, 25 * 60))
    assert cli.main([*args, '--valid-minutes', '25']) == 0
    assert calls[1]['valid_minutes'] == 25
    assert '"expires_at": "2027-01-15T08:25:00Z"' in capsys.readouterr().out
    # The default: no valid_minutes in the request, five minutes in the receipt.
    calls.clear()
    replies['save'] = receipt(route, 300)
    assert cli.main(args) == 0 and 'valid_minutes' not in calls[1]
    # An older broker sends no expiry; that is valid only without --valid-minutes.
    replies.update(ping=caps, save=receipt(route))
    assert cli.main(args) == 0
    calls.clear()
    assert cli.main([*args, '--valid-minutes', '25']) == 1
    assert len(calls) == 1 and 'save page lifetime protocol 1' in capsys.readouterr().out
    # A page longer than the vault lock timeout is refused before sending.
    calls.clear()
    replies.update(ping=caps | LIFETIME_CAPS | dict(lock_timeout_seconds=600))
    assert cli.main([*args, '--valid-minutes', '11']) == 1
    assert len(calls) == 1 and 'vault lock timeout (600 seconds' in capsys.readouterr().out
    replies['save'] = receipt(route, 600)
    assert cli.main([*args, '--valid-minutes', '10']) == 0
    # The default page may be cut to a shorter lock timeout.
    replies.update(ping=caps | LIFETIME_CAPS | dict(lock_timeout_seconds=120), save=receipt(route, 120))
    assert cli.main(args) == 0
    replies['save'] = receipt(route, 301)
    assert cli.main(args) == 2
    capsys.readouterr()
    # A receipt with another lifetime than the one asked for is withheld.
    replies.update(ping=caps | LIFETIME_CAPS, save=receipt(route, 300))
    assert cli.main([*args, '--valid-minutes', '25']) == 2
    replies['save'] = dict(receipt(route, 25 * 60), expires_at='soon')
    assert cli.main([*args, '--valid-minutes', '25']) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'response withheld' in captured.err


@pytest.mark.parametrize('value', ['31', '0', '-1', '2.5', 'ten', '', '025000'])
@pytest.mark.parametrize('args,caps,route', COMMANDS)
def test_cli_refuses_a_lifetime_above_the_maximum_before_sending(monkeypatch, capsys, args, caps, route, value):
    calls = []
    monkeypatch.setattr(cli, 'request', lambda _, payload, **kwargs: calls.append(payload))
    with pytest.raises(SystemExit) as exit_info:
        cli.main([*args, '--valid-minutes', value])
    assert exit_info.value.code == 2 and calls == []
    assert 'from 1 to 30' in capsys.readouterr().err
