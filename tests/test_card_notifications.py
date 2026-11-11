"""Synthetic card forms and event receivers; no live vault or browser."""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from akdbx import cli
from akdbx.card_notifications import CardSaveNotifications
from test_cards import CARD, begin, post
from test_writes import deployed, template
from test_web_unlock import wait_for
from test_broker import running_broker

URL = 'https://callback.example/private-card-token'


def request(handle, url=URL):
    return dict(action='subscribe-card-save', notification_protocol=1,
                write_handle=handle, webhook_url=url)


def terminal(manager, key):
    wait_for(lambda: manager.status(key).get('state') in {'delivered', 'failed', 'cancelled'})
    return manager.status(key)


@pytest.fixture
def events(deployed):
    broker, _, _, _ = deployed
    broker.card_save_notifications.close()
    sent = []
    manager = CardSaveNotifications(expire_handler=broker._expire_card_save,
                                    sender=lambda *args: sent.append(args))
    broker.card_save_notifications = manager
    try:
        yield manager, sent
    finally:
        manager.close()


def test_real_save_and_late_registration_deliver_once_without_secrets(deployed, events):
    broker, typer, _, socket = deployed
    manager, sent = events
    prepared = begin(broker)
    registration = request(prepared['write_handle'])
    receipt = broker.dispatch(registration)
    assert receipt['state'] == 'subscribed' and receipt['expires_in'] is None
    assert not sent
    # A typo is not a terminal result; the existing form remains retryable.
    assert post(socket, prepared, dict(CARD, month='9'))[0] == 409
    assert not sent
    assert post(socket, prepared)[0] == 200
    key = receipt['subscription_id']
    assert terminal(manager, key)['result'] == 'saved'
    assert len(sent) == 1
    payload = sent[0][1]
    assert payload == dict(event='akdbx.card-save', state='saved', subscription_id=key,
                           event_id=payload['event_id'])
    assert broker.dispatch(registration)['subscription_id'] == key
    late = broker.dispatch(request(prepared['write_handle'], URL + '-late'))
    assert terminal(manager, late['subscription_id'])['result'] == 'saved'
    encoded = json.dumps(sent) + json.dumps(receipt)
    assert all(value not in encoded for value in (CARD['name'], CARD['number'],
                                                 prepared['write_handle'], prepared['private_url']))
    assert not typer.events


def test_register_save_race_and_multiple_callbacks(deployed, events):
    broker, _, _, socket = deployed
    manager, sent = events
    prepared = begin(broker)
    barrier = threading.Barrier(2)
    def subscribe():
        barrier.wait(2)
        return broker.dispatch(request(prepared['write_handle']))
    def save():
        barrier.wait(2)
        return post(socket, prepared)[0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        registered, saved = pool.submit(subscribe), pool.submit(save)
        receipt = registered.result(5)
        assert saved.result(5) == 200
    assert terminal(manager, receipt['subscription_id'])['result'] == 'saved'
    assert len(sent) == 1


@pytest.mark.parametrize('result', ['cancelled', 'failed', 'expired'])
def test_terminal_form_results_resume_waiter(deployed, events, result):
    broker, _, _, _ = deployed
    manager, _ = events
    prepared = begin(broker)
    handle = prepared['write_handle']
    receipt = broker.dispatch(request(handle))
    if result == 'cancelled':
        assert broker.dispatch(dict(action='cancel-write', write_handle=handle))['state'] == result
    elif result == 'failed':
        with broker._vault_lock:
            broker.writes.invalidate_revision()
    else:
        # Exercise the real one-shot deadline, not a polling job.
        manager.status(receipt['subscription_id'], cancel=True)
        broker.writes.operations[handle].expires = broker.clock() + .03
        receipt = broker.dispatch(request(handle, URL + '-expiry'))
    assert terminal(manager, receipt['subscription_id'])['result'] == result
    assert not manager._timers


def test_cancel_subscription_does_not_cancel_form_or_notify(deployed, events):
    broker, _, _, socket = deployed
    manager, sent = events
    prepared = begin(broker)
    receipt = broker.dispatch(request(prepared['write_handle']))
    assert broker.dispatch(dict(action='unsubscribe-card-save', subscription_id=receipt['subscription_id']))['state'] == 'cancelled'
    assert not manager._timers
    assert post(socket, prepared)[0] == 200
    assert not sent


def test_failed_persistence_and_unrelated_write_cannot_report_saved(deployed, events, monkeypatch):
    broker, _, _, socket = deployed
    manager, _ = events
    first, second = begin(broker), begin(broker)
    one = broker.dispatch(request(first['write_handle']))
    two = broker.dispatch(request(second['write_handle'], URL + '-other'))
    assert post(socket, first)[0] == 200
    assert terminal(manager, one['subscription_id'])['result'] == 'saved'
    assert terminal(manager, two['subscription_id'])['result'] == 'failed'
    prepared = begin(broker)
    receipt = broker.dispatch(request(prepared['write_handle'], URL + '-failure'))
    def fail(*args, **kwargs):
        raise OSError('synthetic failure')
    monkeypatch.setattr(broker.vault._akdbx_store, 'commit', fail)
    assert post(socket, prepared)[0] == 409
    assert terminal(manager, receipt['subscription_id'])['result'] == 'failed'


@pytest.mark.parametrize('saved', [False, True])
def test_restart_retains_callback_and_event_identity_without_write_secrets(tmp_path, saved):
    path = tmp_path / 'private' / 'events.json'
    handle = 'a' * 64
    manager = CardSaveNotifications(expire_handler=lambda _: None, state_path=path)
    # Hold delivery to model process exit immediately after commit.
    manager._start_worker = lambda: None
    receipt = manager.subscribe_save(request(handle), state='pending', expires=time.monotonic() + 300)
    if saved:
        manager.publish_save(handle, 'saved')
    data = json.loads(path.read_text())
    assert handle not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    event = data[0]['event_id']
    manager.close()
    sent = []
    restored = CardSaveNotifications(expire_handler=lambda _: None, state_path=path,
                                      sender=lambda *args: sent.append(args))
    try:
        assert not sent
        restored.resume()
        status = terminal(restored, receipt['subscription_id'])
        assert status['result'] == ('saved' if saved else 'interrupted')
        assert sent[0][1]['event_id'] == event
        assert json.loads(path.read_text()) == []
    finally:
        restored.close()


def test_cli_register_status_cancel_and_old_broker_refusal(deployed, events, tmp_path, capsys, monkeypatch):
    broker, _, _, _ = deployed
    manager, _ = events
    prepared = begin(broker)
    file = tmp_path / 'callback'
    file.write_text(URL)
    file.chmod(0o600)
    socket = tmp_path / 'rpc' / 'broker.sock'
    prefix = ['--socket', str(socket)]
    with running_broker(socket, broker):
        assert cli.main([*prefix, 'subscribe-card-save', prepared['write_handle'], '--webhook-url-file', str(file)]) == 0
        output = capsys.readouterr().out
        receipt = json.loads(output)
        assert URL not in output and receipt['expires_in'] is None
        for command, expected in [('card-save-subscription-status', 'subscribed'), ('unsubscribe-card-save', 'cancelled')]:
            assert cli.main([*prefix, command, receipt['subscription_id']]) == 0
            assert json.loads(capsys.readouterr().out)['state'] == expected
    calls = []
    def old(*args, **kwargs):
        calls.append(args[1])
        return dict(ok=True, cards_supported=True, card_protocol=1)
    monkeypatch.setattr(cli, 'request', old)
    assert cli.main(['subscribe-card-save', 'a' * 64, '--webhook-url-file', '/absent']) == 1
    assert calls == [dict(action='ping')]
    assert 'subscription request not sent' in capsys.readouterr().out


def test_wrong_kind_unknown_handle_protocol_and_ttl_are_refused(deployed, events):
    broker, _, _, _ = deployed
    assert not broker.dispatch(request('a' * 64))['ok']
    from test_writes import begin as password_begin
    password = password_begin(broker)
    assert not broker.dispatch(request(password['write_handle']))['ok']
    prepared = begin(broker)
    for changes in [dict(notification_protocol=True), dict(ttl=60), dict(webhook_url='http://invalid.test')]:
        assert not broker.dispatch(dict(request(prepared['write_handle']), **changes))['ok']


@pytest.mark.parametrize('error', [OSError, RuntimeError])
def test_notification_storage_failure_cannot_change_confirmed_card_save(deployed, events, monkeypatch, error):
    broker, _, _, socket = deployed
    manager, sent = events
    prepared = begin(broker)
    receipt = broker.dispatch(request(prepared['write_handle']))
    def fail():
        raise error('synthetic notification disk failure')
    monkeypatch.setattr(manager, '_persist', fail)
    assert post(socket, prepared)[0] == 200
    assert broker.dispatch(dict(action='write-status', write_handle=prepared['write_handle']))['state'] == 'saved'
    status = manager.status(receipt['subscription_id'])
    assert status['state'] == 'failed' and status['result'] == 'saved' and not sent
    monkeypatch.undo()
