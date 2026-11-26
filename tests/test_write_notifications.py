"""Write-result webhooks for every private save page. Synthetic forms, vaults and receivers only."""
import json
import time

import pytest

from akdbx import cli
from akdbx.broker import Broker
from akdbx.card_notifications import CardSaveNotifications
from akdbx.write_notifications import WriteNotifications
from test_broker import RecordingTyper, running_broker
from test_import_totp import account, migration, nonce, private
from test_totp import KEY, URI, post_setup, prepare
from test_web_unlock import wait_for
from test_writes import CHOSEN, begin as password_begin, deployed, private_post, template
import test_cards
import test_identities

URL = 'https://callback.example/private-write-token'


def request(handle, url=URL):
    return dict(action='subscribe-write', notification_protocol=1, write_handle=handle, webhook_url=url)


def terminal(manager, key):
    wait_for(lambda: manager.status(key).get('state') in {'delivered', 'failed', 'cancelled'})
    return manager.status(key)


@pytest.fixture
def events(deployed):
    broker = deployed[0]
    broker.write_notifications.close()
    broker.card_save_notifications.close()
    sent, cards = [], []
    manager = WriteNotifications(expire_handler=broker._expire_write, sender=lambda *args: sent.append(args))
    broker.write_notifications = manager
    broker.card_save_notifications = CardSaveNotifications(expire_handler=broker._expire_card_save,
                                                           sender=lambda *args: cards.append(args))
    try:
        yield manager, sent, cards
    finally:
        manager.close()
        broker.card_save_notifications.close()


# Each page kind: how to prepare it, a correctable mistake, and a save.
def _password(broker, socket):
    prepared = password_begin(broker)
    return prepared, lambda: private_post(socket, prepared, confirmation='synthetic-typo'), \
        lambda: private_post(socket, prepared)


def _totp(broker, socket):
    prepared = prepare(broker)
    return prepared, lambda: post_setup(socket, prepared, setup='not a key'), lambda: post_setup(socket, prepared)


def _identity(broker, socket):
    prepared = test_identities.begin(broker)
    return prepared, lambda: test_identities.post(socket, prepared, confirmed=''), \
        lambda: test_identities.post(socket, prepared)


def _card(broker, socket):
    prepared = test_cards.begin(broker)
    return prepared, lambda: test_cards.post(socket, prepared, dict(test_cards.CARD, month='9')), \
        lambda: test_cards.post(socket, prepared)


PAGES = dict(password=_password, totp=_totp, identity=_identity, card=_card)
SECRETS = (CHOSEN, KEY, URI, test_cards.CARD['number'], test_cards.CARD['name'],
           test_identities.IDENTITY['email'], test_identities.IDENTITY['address-line1'])


@pytest.mark.parametrize('kind', PAGES)
def test_each_page_save_sends_one_event_without_values_handle_or_url(deployed, events, kind):
    broker, typer, _, socket = deployed
    manager, sent, _ = events
    prepared, mistake, save = PAGES[kind](broker, socket)
    registration = request(prepared['write_handle'])
    receipt = broker.dispatch(registration)
    key = receipt['subscription_id']
    assert receipt == dict(ok=True, subscription_id=key, state='subscribed', attempts=0, result=None, expires_in=None)
    # A correctable mistake keeps the page open and sends nothing.
    assert mistake()[0] != 200
    assert broker.dispatch(dict(action='write-status', write_handle=prepared['write_handle']))['state'] == 'pending'
    assert not sent
    assert save()[0] == 200
    assert terminal(manager, key)['result'] == 'saved'
    [(url, payload)] = sent
    assert url == URL and payload == dict(event='akdbx.write-result', state='saved', subscription_id=key,
                                          event_id=payload['event_id'])
    # A retry with the same URL reuses the subscription; a late one gets the result.
    assert broker.dispatch(registration)['subscription_id'] == key
    late = broker.dispatch(request(prepared['write_handle'], URL + '-late'))
    assert late['state'] == 'pending' and terminal(manager, late['subscription_id'])['result'] == 'saved'
    encoded = json.dumps(sent) + json.dumps(receipt) + json.dumps(late)
    assert not any(value in encoded for value in (*SECRETS, prepared['write_handle'], prepared['private_url']))
    assert not typer.events


@pytest.mark.parametrize('kind', PAGES)
@pytest.mark.parametrize('result', ['cancelled', 'failed', 'expired'])
def test_each_page_cancel_stale_and_expiry_resume_the_waiter(deployed, events, kind, result):
    broker, _, _, socket = deployed
    manager, sent, _ = events
    prepared = PAGES[kind](broker, socket)[0]
    handle = prepared['write_handle']
    receipt = broker.dispatch(request(handle))
    if result == 'cancelled':
        assert broker.dispatch(dict(action='cancel-write', write_handle=handle))['state'] == result
    elif result == 'failed':
        # Another save changes the vault: the open page is stale at once.
        with broker._vault_lock:
            broker.writes.invalidate_revision()
    else:
        # The real one-shot page deadline, not a polling job.
        manager.status(receipt['subscription_id'], cancel=True)
        broker.writes.operations[handle].expires = broker.clock() + .03
        receipt = broker.dispatch(request(handle, URL + '-expiry'))
    assert terminal(manager, receipt['subscription_id'])['result'] == result
    assert sent[-1][1]['state'] == result
    assert not manager._timers


def test_private_totp_import_save_sends_the_event(deployed, events):
    broker, _, _, socket = deployed
    manager, sent, _ = events
    prepared = prepare(broker)
    receipt = broker.dispatch(request(prepared['write_handle']))
    payload = migration([account()])
    assert private(socket, prepared, '/totp/import', {'payloads': json.dumps([payload])})[0] == 200
    assert manager.status(receipt['subscription_id'])['state'] == 'subscribed'
    assert private(socket, prepared, '/totp/review',
                   {'choice': '0', 'nonce': nonce(broker, prepared), 'confirmed': 'yes'})[0] == 200
    assert terminal(manager, receipt['subscription_id'])['result'] == 'saved'
    assert payload not in json.dumps(sent) and KEY not in json.dumps(sent)


def test_card_page_wakes_card_save_and_write_subscriptions_once_each(deployed, events):
    broker, _, _, socket = deployed
    manager, sent, cards = events
    prepared = test_cards.begin(broker)
    write = broker.dispatch(request(prepared['write_handle']))
    card = broker.dispatch(dict(request(prepared['write_handle'], URL + '-card'), action='subscribe-card-save'))
    assert test_cards.post(socket, prepared)[0] == 200
    assert terminal(manager, write['subscription_id'])['result'] == 'saved'
    assert terminal(broker.card_save_notifications, card['subscription_id'])['result'] == 'saved'
    assert [p['event'] for _, p in sent] == ['akdbx.write-result']
    assert [p['event'] for _, p in cards] == ['akdbx.card-save']


def test_cancel_subscription_keeps_the_page_and_sends_nothing(deployed, events):
    broker, _, _, socket = deployed
    manager, sent, _ = events
    prepared = password_begin(broker)
    receipt = broker.dispatch(request(prepared['write_handle']))
    cancelled = broker.dispatch(dict(action='unsubscribe-write', subscription_id=receipt['subscription_id']))
    assert cancelled['state'] == 'cancelled' and not manager._timers
    assert private_post(socket, prepared)[0] == 200
    assert not sent


def test_generated_unknown_and_malformed_requests_are_refused(deployed, events):
    broker = deployed[0]
    refused = dict(ok=False, error='unknown or expired private write')
    assert broker.dispatch(request('a' * 64)) == refused
    generated = password_begin(broker, 'generate-password')
    assert 'fill_handles' in generated and broker.dispatch(request(generated['write_handle'])) == refused
    prepared = password_begin(broker)
    for changes in [dict(notification_protocol=True), dict(ttl=60), dict(webhook_url='http://invalid.test')]:
        assert not broker.dispatch(dict(request(prepared['write_handle']), **changes))['ok']
    assert not broker.dispatch(dict(action='write-subscription-status', subscription_id='b' * 32))['ok']


@pytest.mark.parametrize('error', [OSError, RuntimeError])
def test_notification_storage_failure_cannot_change_a_confirmed_save(deployed, events, monkeypatch, error):
    broker, _, _, socket = deployed
    manager, sent, _ = events
    prepared = test_identities.begin(broker)
    receipt = broker.dispatch(request(prepared['write_handle']))

    def fail():
        raise error('synthetic notification disk failure')
    monkeypatch.setattr(manager, '_persist', fail)
    assert test_identities.post(socket, prepared)[0] == 200
    assert broker.dispatch(dict(action='write-status', write_handle=prepared['write_handle']))['state'] == 'saved'
    status = manager.status(receipt['subscription_id'])
    assert status['state'] == 'failed' and status['result'] == 'saved' and not sent
    monkeypatch.undo()


@pytest.mark.parametrize('saved', [False, True])
def test_restart_keeps_callback_and_event_id_but_no_handle(tmp_path, saved):
    path = tmp_path / 'private' / 'events.json.writes'
    handle = 'c' * 64
    manager = WriteNotifications(expire_handler=lambda _: None, state_path=path)
    # Hold delivery to model a process exit right after the commit.
    manager._start_worker = lambda: None
    receipt = manager.subscribe_save(request(handle), state='pending', expires=time.monotonic() + 300)
    if saved:
        manager.publish_save(handle, 'saved')
    text = path.read_text()
    assert handle not in text and path.stat().st_mode & 0o777 == 0o600
    event = json.loads(text)[0]['event_id']
    manager.close()
    sent = []
    restored = WriteNotifications(expire_handler=lambda _: None, state_path=path,
                                  sender=lambda *args: sent.append(args))
    try:
        assert not sent  # nothing goes out before the broker endpoint is ready
        restored.resume()
        status = terminal(restored, receipt['subscription_id'])
        assert status['result'] == ('saved' if saved else 'interrupted')
        assert sent[0][1] == dict(event='akdbx.write-result', state=status['result'],
                                  subscription_id=receipt['subscription_id'], event_id=event)
        assert json.loads(path.read_text()) == []
    finally:
        restored.close()


def test_broker_restart_restores_write_subscriptions_from_their_own_file(tmp_path):
    state = tmp_path / 'state' / 'unlock-notifications.json'
    handle = 'd' * 64
    first = Broker(None, RecordingTyper(), notification_state_path=state)
    try:
        first.write_notifications._start_worker = lambda: None
        receipt = first.write_notifications.subscribe_save(request(handle), state='pending',
                                                           expires=time.monotonic() + 300)
        assert receipt['state'] == 'subscribed'
    finally:
        for notifier in (first.unlock_notifications, first.card_save_notifications, first.write_notifications,
                         first.pairing_notifications, first.sms_notifications):
            notifier.close()
    written = state.with_name(state.name + '.writes')
    assert written.exists() and handle not in written.read_text()
    second = Broker(None, RecordingTyper(), notification_state_path=state)
    sent = []
    second.write_notifications._sender = lambda *args: sent.append(args)
    try:
        second.resume_notifications()
        status = terminal(second.write_notifications, receipt['subscription_id'])
        assert status['result'] == 'interrupted' and sent[0][1]['state'] == 'interrupted'
    finally:
        for notifier in (second.unlock_notifications, second.card_save_notifications, second.write_notifications,
                         second.pairing_notifications, second.sms_notifications):
            notifier.close()


def test_cli_reads_the_url_from_a_private_file_and_never_prints_it(deployed, events, tmp_path, capsys, monkeypatch):
    broker = deployed[0]
    prepared = password_begin(broker)
    file = tmp_path / 'callback'
    file.write_text(URL)
    file.chmod(0o600)
    socket = tmp_path / 'rpc' / 'broker.sock'
    prefix = ['--socket', str(socket)]
    with running_broker(socket, broker):
        assert cli.main([*prefix, 'subscribe-write', prepared['write_handle'], '--webhook-url-file', str(file)]) == 0
        captured = capsys.readouterr()
        receipt = json.loads(captured.out)
        assert URL not in captured.out + captured.err and receipt['expires_in'] is None
        for command, expected in [('write-subscription-status', 'subscribed'), ('unsubscribe-write', 'cancelled')]:
            assert cli.main([*prefix, command, receipt['subscription_id']]) == 0
            captured = capsys.readouterr()
            assert json.loads(captured.out)['state'] == expected and URL not in captured.out + captured.err
    calls = []

    def old(*args, **kwargs):
        calls.append(args[1])
        return dict(ok=True, card_save_notifications_supported=True, card_save_notifications_protocol=1)
    monkeypatch.setattr(cli, 'request', old)
    assert cli.main(['subscribe-write', 'a' * 64, '--webhook-url-file', '/absent']) == 1
    assert calls == [dict(action='ping')]
    assert 'subscription request not sent' in capsys.readouterr().out
    assert cli.main(['subscribe-write', 'not-a-handle', '--webhook-url-file', '/absent']) == 2
    assert calls == [dict(action='ping')]


def test_cli_withholds_a_receipt_with_unexpected_fields(monkeypatch, capsys, tmp_path):
    file = tmp_path / 'callback'
    file.write_text(URL)
    file.chmod(0o600)

    def broker(_, payload, **kwargs):
        if payload['action'] == 'ping':
            return dict(ok=True, write_notifications_supported=True, write_notifications_protocol=1,
                        write_notifications_until_result=True)
        return dict(ok=True, subscription_id='e' * 32, state='subscribed', attempts=0, result=None,
                    expires_in=None, webhook_url=payload['webhook_url'])
    monkeypatch.setattr(cli, 'request', broker)
    assert cli.main(['subscribe-write', 'a' * 64, '--webhook-url-file', str(file)]) == 2
    captured = capsys.readouterr()
    assert URL not in captured.out + captured.err and 'withheld' in captured.err
