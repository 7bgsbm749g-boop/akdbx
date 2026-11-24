"""SMS webhooks: one event per subscription, with only the source and message id. Synthetic values only."""
import json
from types import SimpleNamespace

import pytest

from akdbx import sms_cli
from akdbx.broker import Broker
from akdbx.sms_notifications import SmsNotifications
from test_broker import Entry, RecordingTyper, Vault
from test_web_unlock import wait_for

URL = 'https://callback.example/private-sms-token'
TEXT = 'G-482913 is your Google verification code.'


def request(url=URL, **extra):
    return dict(action='subscribe-sms', sms_protocol=1, notification_protocol=1, webhook_url=url, **extra)


@pytest.fixture
def events(tmp_path):
    sent = []
    broker = Broker(Vault([Entry()]), RecordingTyper(), sms_sources_path=tmp_path / 'state' / 'sms.json')
    broker.sms_notifications.close()
    broker.sms_notifications = SmsNotifications(sender=lambda *args: sent.append(args))
    broker.sms.on_text = broker.sms_notifications.publish_text
    try:
        yield broker, sent
    finally:
        broker.sms_notifications.close()


def terminal(broker, key):
    manager = broker.sms_notifications
    wait_for(lambda: manager.status(key).get('state') in {'delivered', 'failed', 'cancelled'})
    return manager.status(key)


def test_next_text_sends_one_event_with_only_the_source_and_message_id(events):
    broker, sent = events
    token = broker.sms.add_source('iphone', 'shortcut')
    receipt = broker.dispatch(request())
    key = receipt['subscription_id']
    assert receipt == dict(ok=True, subscription_id=key, state='subscribed', attempts=0, source=None,
                           message_id=None, expires_in=None)
    assert broker.sms.receive(token, 'Me', 'hello, no code here') == 'dropped'
    assert broker.sms_notifications.status(key)['state'] == 'subscribed'  # a dropped text wakes nobody
    assert broker.sms.receive(token, 'Google', TEXT) == 'kept'
    assert terminal(broker, key)['state'] == 'delivered'
    [(url, payload)] = sent
    message = broker.dispatch(dict(action='sms-wait', sms_protocol=1))['messages'][0]['id']
    assert url == URL and payload == dict(event='akdbx.sms-received', source='iphone', message_id=message,
                                          subscription_id=key, event_id=payload['event_id'])
    assert '482913' not in json.dumps(payload) and 'Google' not in json.dumps(payload)
    # One-shot: the next text sends nothing more.
    broker.sms.receive(token, 'Google', TEXT)
    assert len(sent) == 1


def test_source_filter_and_a_text_that_came_before_the_subscription(events):
    broker, sent = events
    phone = broker.sms.add_source('iphone', 'shortcut')
    twilio = broker.sms.add_source('twilio-us', 'twilio')
    key = broker.dispatch(request(source='twilio-us'))['subscription_id']
    broker.sms.receive(phone, 'Google', TEXT)
    assert broker.sms_notifications.status(key)['state'] == 'subscribed'
    broker.sms.receive(twilio, 'Bank', 'Your code is 771122')
    assert terminal(broker, key)['source'] == 'twilio-us'
    # since: a text already received sends the event at once.
    early = broker.dispatch(request(url=URL + '-2', source='iphone', since=0))
    assert early['state'] in {'pending', 'sending', 'delivered'} and early['message_id']
    assert terminal(broker, early['subscription_id'])['state'] == 'delivered'
    assert [p['source'] for _, p in sent] == ['twilio-us', 'iphone']


def test_bad_requests_are_refused_and_cancel_works(events):
    broker, _ = events
    for bad in (request(source='Not A Name'), request(since='yesterday'), request(extra=1)):
        assert broker.dispatch(bad) == dict(ok=False, error='sms notification protocol 1 and a valid source name '
                                                            'or none required')
    key = broker.dispatch(request())['subscription_id']
    assert broker.dispatch(dict(action='unsubscribe-sms', sms_protocol=1, subscription_id=key))['state'] == 'cancelled'


def test_waiting_subscriptions_survive_a_restart_and_wait_for_the_next_text(tmp_path):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    first = SmsNotifications(sender=lambda *args: None, state_path=state / 'notify.sms')
    key = first.subscribe_text(request(source='iphone'), received=lambda *a: None)['subscription_id']
    first.close()
    sent = []
    second = SmsNotifications(sender=lambda *args: sent.append(args), state_path=state / 'notify.sms')
    try:
        assert second.status(key)['state'] == 'subscribed' and second.status(key)['source'] == 'iphone'
        second.publish_text('iphone', 'a' * 32)
        wait_for(lambda: sent)
        assert sent[0][1]['message_id'] == 'a' * 32
    finally:
        second.close()


def test_cli_receipts_are_strict():
    args = SimpleNamespace(command='subscribe-sms')
    good = dict(ok=True, subscription_id='b' * 32, state='subscribed', attempts=0, source='iphone', message_id=None,
                expires_in=None)
    assert sms_cli.valid_receipt(args, good)
    assert not sms_cli.valid_receipt(args, dict(good, code='482913'))
    assert not sms_cli.valid_receipt(args, dict(good, message_id='482913'))


def test_same_url_waits_again_after_an_unrelated_text(events):
    # Another site's code spends the one-shot wait; registering again with the
    # same URL must start a new wait, not return the delivered one.
    broker, sent = events
    token = broker.sms.add_source('iphone', 'shortcut')
    first = broker.dispatch(request(source='iphone'))['subscription_id']
    broker.sms.receive(token, 'Other', 'Your Other code is 112233')
    assert terminal(broker, first)['state'] == 'delivered'
    again = broker.dispatch(request(source='iphone'))
    assert again['subscription_id'] != first and again['state'] == 'subscribed' and again['message_id'] is None
    broker.sms.receive(token, 'Google', TEXT)
    assert terminal(broker, again['subscription_id'])['state'] == 'delivered'
    assert len(sent) == 2 and sent[0][1]['message_id'] != sent[1][1]['message_id']


def test_cli_shows_the_locked_receipt_for_subscriptions():
    locked = dict(ok=False, error='vault locked', unlock_url='https://box.example.test/?token=' + 'a' * 43)
    for command in ('subscribe-sms', 'sms-subscription-status', 'unsubscribe-sms'):
        assert sms_cli.valid_receipt(SimpleNamespace(command=command), locked)
