"""Extension pairing: one-shot webhooks, reconnects and the pairing page. Synthetic keys and values only."""
import hashlib
import json
import socket
import threading

import pytest

from akdbx import cli, extension_route as route
from akdbx.pairing_notifications import PairingNotifications
from akdbx.protocol import receive_message
from test_broker import running_broker
from test_extension_route import KEY, EXTENSION_PUBLIC, PageHandler, attach, make_broker, new_key
from test_web_unlock import wait_for

URL = 'https://callback.example/private-pairing-token'
DIGEST = hashlib.sha256(EXTENSION_PUBLIC).digest()
CODE = route.pairing_code(DIGEST)


def request(url=URL, **extra):
    return dict(action='subscribe-pairing', notification_protocol=1, webhook_url=url, **extra)


@pytest.fixture
def events():
    sent = []
    broker = make_broker()
    broker.pairing_notifications.close()
    broker.pairing_notifications = PairingNotifications(sender=lambda *args: sent.append(args))
    try:
        yield broker, sent
    finally:
        broker.pairing_notifications.close()


def terminal(broker, key):
    manager = broker.pairing_notifications
    wait_for(lambda: manager.status(key).get('state') in {'delivered', 'failed', 'cancelled'})
    return manager.status(key)


def token_for(broker, digest=DIGEST):
    return broker.extension._pairing_info(digest)['url'].split('token=')[1]


def other_key():
    _, public = new_key()
    return public


def test_pairing_sends_one_event_with_only_the_browser_name(events):
    broker, sent = events
    channel, _ = attach(broker, {}, paired=False)
    receipt = broker.dispatch(request())
    assert receipt == dict(ok=True, subscription_id=receipt['subscription_id'], state='subscribed', attempts=0,
                           code=None, browser=None, expires_in=None)
    token = token_for(broker)
    assert broker.extension.approve(token) is True
    key = receipt['subscription_id']
    assert terminal(broker, key)['state'] == 'delivered'
    [(url, payload)] = sent
    assert url == URL
    assert payload == dict(event='akdbx.extension-paired', browser='helium', subscription_id=key,
                           event_id=payload['event_id'])
    assert token not in json.dumps(payload) and CODE not in json.dumps(payload)
    # One-shot: a second pairing sends nothing more.
    second = route.Channel(broker.extension, None, 'chrome', other_key())
    broker.extension.channels[second.id] = second
    assert broker.extension.approve(token_for(broker, second.digest)) is True
    assert len(sent) == 1


def test_a_code_waits_for_its_own_browser_key_only(events):
    broker, sent = events
    attach(broker, {}, paired=False)
    other = route.Channel(broker.extension, None, 'chrome', other_key())
    broker.extension.channels[other.id] = other
    receipt = broker.dispatch(request(code=CODE))
    assert receipt['state'] == 'subscribed' and receipt['code'] == CODE
    assert broker.extension.approve(token_for(broker, other.digest)) is True
    assert broker.pairing_notifications.status(receipt['subscription_id'])['state'] == 'subscribed' and not sent
    assert broker.extension.approve(token_for(broker)) is True
    assert terminal(broker, receipt['subscription_id'])['browser'] == 'helium'
    assert [payload['browser'] for _, payload in sent] == ['helium']


def test_a_browser_paired_before_registration_is_reported_at_once(events):
    broker, sent = events
    attach(broker, {}, paired=True)
    any_browser = broker.dispatch(request())
    own = broker.dispatch(request('https://callback.example/second', code=CODE))
    for receipt in (any_browser, own):
        assert terminal(broker, receipt['subscription_id'])['state'] == 'delivered'
    assert sorted(payload['browser'] for _, payload in sent) == ['helium', 'helium']
    # Another code is not paired yet: it waits.
    waiting = broker.dispatch(request('https://callback.example/third', code='ABCD-EFGH'))
    assert waiting['state'] == 'subscribed'


@pytest.mark.parametrize('already_paired', [False, True])
def test_firefox_pairing_wakes_waits_and_has_a_valid_cli_receipt(events, already_paired):
    from akdbx.pairing_cli import valid_receipt
    broker, sent = events
    channel, _ = attach(broker, {}, paired=False)
    channel.browser = 'firefox'
    if already_paired:
        assert broker.extension.approve(token_for(broker))
    receipt = broker.dispatch(request())
    assert valid_receipt('subscribe-pairing', receipt)
    if not already_paired:
        assert broker.extension.approve(token_for(broker))
    final = terminal(broker, receipt['subscription_id'])
    assert final['state'] == 'delivered' and final['browser'] == 'firefox'
    assert valid_receipt('pairing-subscription-status', final)
    assert [payload['browser'] for _, payload in sent] == ['firefox']


@pytest.mark.parametrize('extra', [dict(code='abcd-efgh'), dict(code='ABCD-EFG1'), dict(code=5), dict(other=True)])
def test_malformed_pairing_subscriptions_are_refused(events, extra):
    broker, _ = events
    receipt = broker.dispatch(request(**extra))
    assert receipt == dict(ok=False, error='pairing notification protocol 1 and a valid pairing code or none required')


def test_waits_are_saved_and_survive_a_broker_restart(tmp_path):
    path = tmp_path / 'state' / 'notifications.json.pairings'
    path.parent.mkdir(mode=0o700)
    first = PairingNotifications(state_path=path, sender=lambda *args: None)
    receipt = first.subscribe_pairing(request(code=CODE), paired=lambda code: None)
    assert receipt['state'] == 'subscribed'
    rows = json.loads(path.read_text())
    assert rows == [dict(id=receipt['subscription_id'], url=URL, event_id=rows[0]['event_id'], attempts=0, code=CODE)]
    assert path.stat().st_mode & 0o777 == 0o600
    first.close()
    sent = []
    restored = PairingNotifications(state_path=path, sender=lambda *args: sent.append(args))
    try:
        key = receipt['subscription_id']
        # The pairing the old broker had is gone: the wait continues for the next one.
        assert restored.status(key)['state'] == 'subscribed' and not sent
        restored.publish_paired('ABCD-EFGH', 'chrome')
        assert restored.status(key)['state'] == 'subscribed'
        restored.publish_paired(CODE, 'chrome')
        wait_for(lambda: restored.status(key)['state'] == 'delivered')
        assert sent[0][1]['browser'] == 'chrome' and sent[0][1]['event_id'] == rows[0]['event_id']
        assert json.loads(path.read_text()) == []
    finally:
        restored.close()


def test_a_bad_saved_code_is_refused(tmp_path):
    path = tmp_path / 'state' / 'notifications.json.pairings'
    path.parent.mkdir(mode=0o700)
    path.write_text(json.dumps([dict(id='a' * 32, url=URL, event_id='b' * 32, attempts=0, code='bad')]))
    path.chmod(0o600)
    with pytest.raises(ValueError):
        PairingNotifications(state_path=path)


def test_cli_registers_shows_and_cancels_and_refuses_an_old_broker(events, tmp_path, capsys, monkeypatch):
    broker, _ = events
    file = tmp_path / 'callback'
    file.write_text(URL)
    file.chmod(0o600)
    sock = tmp_path / 'rpc' / 'broker.sock'
    prefix = ['--socket', str(sock)]
    with running_broker(sock, broker):
        assert cli.main([*prefix, 'subscribe-pairing', '--webhook-url-file', str(file), '--code', CODE]) == 0
        output = capsys.readouterr().out
        receipt = json.loads(output)
        assert URL not in output and receipt['expires_in'] is None and receipt['code'] == CODE
        for command, expected in [('pairing-subscription-status', 'subscribed'), ('unsubscribe-pairing', 'cancelled')]:
            assert cli.main([*prefix, command, receipt['subscription_id']]) == 0
            assert json.loads(capsys.readouterr().out)['state'] == expected
        assert cli.main([*prefix, 'subscribe-pairing', '--webhook-url-file', str(file), '--code', 'nope']) == 2
        assert 'subscription not sent' in capsys.readouterr().out
    calls = []

    def old(*args, **kwargs):
        calls.append(args[1])
        return dict(ok=True, unlock_notifications_supported=True, unlock_notifications_protocol=1)
    monkeypatch.setattr(cli, 'request', old)
    assert cli.main(['subscribe-pairing', '--webhook-url-file', '/absent']) == 1
    assert calls == [dict(action='ping')]
    assert 'require broker 0.33.0 or newer' in capsys.readouterr().out


# ----- reconnects: the pairing belongs to the key, not to one host connection --------
@pytest.fixture
def host(monkeypatch):
    import select as select_module
    monkeypatch.setattr(route, '_wait_readable',
                        lambda connection, timeout: bool(select_module.select([connection], [], [], timeout)[0]))
    opened = []

    def connect(broker, browser='chrome'):
        """One native-host connection, as the extension makes after its service worker starts."""
        broker_side, host_side = socket.socketpair()
        opened.extend([broker_side, host_side])
        hello = dict(action='extension-attach', extension_protocol=1, extension_id=route.EXTENSION_ID,
                     browser=browser, public_key=KEY)
        worker = threading.Thread(target=broker.extension.attach, args=(broker_side, hello), daemon=True)
        worker.start()
        attached = receive_message(host_side)
        assert attached['type'] == 'attached'

        def drop():
            # The service worker went idle and Chrome closed its native port.
            host_side.close()
            worker.join(5)
            assert not worker.is_alive()
        return attached, drop
    yield connect
    for item in opened:
        item.close()


def test_a_pending_link_survives_a_reconnect_of_the_same_key(host, events):
    broker, sent = events
    first, drop = host(broker)
    link = first['pairing']['url']
    status = broker.dispatch(dict(action='ping'))
    assert status['extension_pairing'] == [dict(browser='chrome', code=CODE, url=link)]
    receipt = broker.dispatch(request(code=CODE))
    drop()
    status = broker.dispatch(dict(action='ping'))
    assert status['extension_connected'] is False and 'extension_pairing' not in status
    # While the extension is away, the link it showed still opens the page with the same code.
    token = link.split('token=')[1]
    assert broker.extension.pairing_code(token) == CODE
    again, drop_again = host(broker)
    assert again['pairing'] == first['pairing'] and again['paired'] is False
    drop_again()
    # The user pairs while the worker sleeps; the next connection is paired.
    page = PageHandler('/extension/pair?token=' + token, 'POST', b'password=synthetic+master&confirmed=yes')
    from akdbx.extension_web import handle_pairing
    from akdbx.web_unlock import UnlockState
    from types import SimpleNamespace
    broker.vault = SimpleNamespace(entries=[], password='synthetic master')
    assert handle_pairing(page, UnlockState(broker, None, None)) and page.sent[0][0] == 200
    # No event yet: the browser cannot fill until it reconnects.
    assert broker.pairing_notifications.status(receipt['subscription_id'])['state'] == 'subscribed' and not sent
    paired, drop_paired = host(broker)
    assert paired['paired'] is True and 'pairing' not in paired
    assert terminal(broker, receipt['subscription_id'])['browser'] == 'chrome'
    assert broker.dispatch(dict(action='ping'))['extension_paired'] is True
    # An established pairing survives the next idle reconnect too.
    drop_paired()
    later, _ = host(broker)
    assert later['paired'] is True and broker.dispatch(dict(action='ping'))['extension_paired'] is True


def test_a_wait_made_while_a_paired_browser_is_away_fires_when_it_returns(host, events):
    broker, sent = events
    first, drop = host(broker)
    assert broker.extension.approve(first['pairing']['url'].split('token=')[1]) is True
    drop()
    # Paired but not attached: nothing can fill yet, so both waits stay open.
    any_browser = broker.dispatch(request())
    own = broker.dispatch(request('https://callback.example/second', code=CODE))
    assert any_browser['state'] == own['state'] == 'subscribed' and not sent
    host(broker)
    for receipt in (any_browser, own):
        assert terminal(broker, receipt['subscription_id'])['browser'] == 'chrome'
    assert len(sent) == 2


def test_a_new_browser_key_gets_a_new_code_and_link(host, events):
    """A browser restart makes a new key: the old link stays tied to the old key."""
    broker, _ = events
    first, drop = host(broker)
    drop()
    other = route.Channel(broker.extension, None, 'chrome', other_key())
    info = broker.extension._pairing_info(other.digest)
    assert info['code'] != first['pairing']['code'] and info['url'] != first['pairing']['url']
    assert broker.extension.approve(info['url'].split('token=')[1]) is True
    assert DIGEST not in broker.extension.approved


# ----- the pairing page ---------------------------------------------------------
def test_pairing_page_uses_the_unlock_button_and_a_success_title():
    from akdbx.extension_web import handle_pairing
    from akdbx.web_unlock import UnlockState
    from types import SimpleNamespace
    broker = make_broker()
    broker.vault = SimpleNamespace(entries=[], password='synthetic master')
    attach(broker, {}, paired=False)
    path = '/extension/pair?token=' + token_for(broker)
    state = UnlockState(broker, None, None)
    form = PageHandler(path)
    handle_pairing(form, state)
    status, body = form.sent[0]
    assert status == 200 and '<title>AKDBX: Pair the akdbx extension</title>' in body
    assert '<h1 id="portal-title">Pair the akdbx extension</h1>' in body
    # The same busy button as the unlock and save pages, driven by the same script.
    assert '<form data-unlock-form data-wait-text="Pairing the extension. Please wait."' in body
    assert ('<button type="submit" class="portal-submit" data-idle-label="Pair the extension" '
            'data-busy-label="Pairing the extension…"><span class="button-label">Pair the extension</span>'
            '<span class="portal-progress" role="progressbar" aria-label="Pairing the extension" hidden></span>'
            '</button>') in body
    assert '<p id="unlock-status" class="portal-status unlock-status" role="status" aria-live="polite"></p>' in body
    done = PageHandler(path, 'POST', b'password=synthetic+master&confirmed=yes')
    handle_pairing(done, state)
    status, body = done.sent[0]
    assert status == 200 and '<title>AKDBX: Successfully paired</title>' in body
    assert '<h1 id="portal-title">Successfully paired</h1>' in body and 'Pair the akdbx extension' not in body
    assert ('The extension is paired with akdbx until the browser or the broker restarts. '
            'You may close this page.') in body
