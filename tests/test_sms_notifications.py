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
    broker.sms.on_any_text = broker.sms_notifications.publish_any
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


def test_any_text_wait_for_a_setup_page_wakes_on_a_text_without_a_code(events):
    broker, sent = events
    # Registered before the source exists: the setup page cannot race it.
    receipt = broker.dispatch(request(source='iphone', any_text=True))
    key = receipt['subscription_id']
    assert receipt == dict(ok=True, subscription_id=key, state='subscribed', attempts=0, source='iphone',
                           message_id=None, any_text=True, result=None, expires_in=None)
    code_wait = broker.dispatch(request(URL + '-code', source='iphone'))['subscription_id']
    token = broker.sms.add_source('iphone', 'shortcut')
    other = broker.sms.add_source('ipad', 'shortcut')
    assert broker.sms.receive(other, 'Me', 'setup test from another phone') == 'dropped'
    assert broker.sms_notifications.status(key)['state'] == 'subscribed'  # another source wakes nothing
    assert broker.sms.receive(token, 'Me', 'Shortcut setup test 2026') == 'dropped'
    status = terminal(broker, key)
    assert status['state'] == 'delivered' and status['result'] == 'no-code-word' and status['message_id'] is None
    [(url, payload)] = sent
    assert url == URL and payload == dict(event='akdbx.sms-received', source='iphone', message_id=None,
                                          result='no-code-word', subscription_id=key, event_id=payload['event_id'])
    assert 'Shortcut' not in json.dumps(payload) and '2026' not in json.dumps(payload)
    # A dropped text never wakes an ordinary code wait.
    assert broker.sms_notifications.status(code_wait)['state'] == 'subscribed'


def test_any_text_wait_reports_a_kept_code_with_its_message_id(events):
    broker, sent = events
    token = broker.sms.add_source('iphone', 'shortcut')
    key = broker.dispatch(request(source='iphone', any_text=True))['subscription_id']
    assert broker.sms.receive(token, 'Google', TEXT) == 'kept'
    status = terminal(broker, key)
    message = broker.dispatch(dict(action='sms-wait', sms_protocol=1))['messages'][0]['id']
    assert status['result'] == 'code' and status['message_id'] == message
    assert sent[0][1]['result'] == 'code' and '482913' not in json.dumps(sent)


@pytest.mark.parametrize('extra', [dict(any_text=True), dict(any_text=True, source='iphone', since=1.0),
                                   dict(any_text='yes', source='iphone')])
def test_any_text_needs_one_source_and_no_since(events, extra):
    broker, _ = events
    assert broker.dispatch(request(**extra)) == dict(
        ok=False, error='an any-text sms subscription needs one source and no since time')


def test_any_text_wait_survives_a_restart(tmp_path):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    first = SmsNotifications(sender=lambda *args: None, state_path=state / 'notify.sms')
    key = first.subscribe_text(dict(request(source='iphone'), any_text=True), received=lambda *a: None)['subscription_id']
    first.close()
    assert json.loads((state / 'notify.sms').read_text())[0]['any_text'] is True
    sent = []
    second = SmsNotifications(sender=lambda *args: sent.append(args), state_path=state / 'notify.sms')
    try:
        assert second.status(key)['any_text'] is True and second.status(key)['source'] == 'iphone'
        second.publish_text('iphone', 'a' * 32)  # a code wait's event does not reach it
        assert second.status(key)['state'] == 'subscribed'
        second.publish_any('iphone', None, 'empty')
        wait_for(lambda: sent)
        assert sent[0][1]['result'] == 'empty' and sent[0][1]['message_id'] is None
    finally:
        second.close()


def test_any_text_cli_receipts_are_strict():
    args = SimpleNamespace(command='subscribe-sms', any_text=True)
    good = dict(ok=True, subscription_id='b' * 32, state='subscribed', attempts=0, source='iphone', message_id=None,
                any_text=True, result=None, expires_in=None)
    assert sms_cli.valid_receipt(args, good)
    assert sms_cli.valid_receipt(SimpleNamespace(command='sms-subscription-status'),
                                 {k: v for k, v in dict(good, result='no-code').items() if k != 'expires_in'})
    assert not sms_cli.valid_receipt(args, dict(good, result='482913'))
    assert not sms_cli.valid_receipt(args, {k: v for k, v in good.items() if k not in {'any_text', 'result'}})
    assert not sms_cli.valid_receipt(SimpleNamespace(command='subscribe-sms', any_text=False), good)


def test_any_text_cli_needs_a_source_and_a_new_broker(monkeypatch, capsys, tmp_path):
    from akdbx import cli
    file = tmp_path / 'callback'
    file.write_text(URL)
    file.chmod(0o600)
    calls = []
    caps = dict(ok=True, sms_protocol=1, sms_notifications_supported=True, sms_notifications_protocol=1)

    def broker(_, payload, **kwargs):
        calls.append(payload)
        if payload['action'] == 'ping':
            return caps
        return dict(ok=True, subscription_id='c' * 32, state='subscribed', attempts=0, source='iphone',
                    message_id=None, any_text=True, result=None, expires_in=None)
    monkeypatch.setattr(cli, 'request', broker)
    for argv in (['subscribe-sms', '--any-text', '--webhook-url-file', str(file)],
                 ['subscribe-sms', '--source', 'iphone', '--any-text', '--webhook-url-file', str(file)]):
        assert cli.main(argv) == 1
        assert 'subscription request not sent' in capsys.readouterr().out
    assert [c['action'] for c in calls] == ['ping', 'ping']
    caps['sms_notifications_any_text'] = True
    assert cli.main(['subscribe-sms', '--source', 'iphone', '--any-text', '--webhook-url-file', str(file)]) == 0
    captured = capsys.readouterr()
    assert URL not in captured.out + captured.err and json.loads(captured.out)['any_text'] is True
    assert calls[-1]['any_text'] is True and calls[-1]['source'] == 'iphone' and 'since' not in calls[-1]
