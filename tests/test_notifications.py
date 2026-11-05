from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import pytest

from akdbx import cli, notifications
from akdbx.broker import Broker
from akdbx.web_unlock import start_unlock_server
from test_broker import RecordingTyper, Vault, Entry, SECRET, running_broker
from test_web_unlock import call, wait_for


CALLBACK = "https://callback.example/hooks/private-bearer-token"


def registration(url=CALLBACK, **fields):
    return {"action": "subscribe-unlock", "notification_protocol": 1,
            "webhook_url": url, **fields}


@pytest.fixture
def notifier():
    sent = []
    manager = notifications.UnlockNotifications(sender=lambda url, payload: sent.append((url, payload)))
    yield manager, sent
    manager.close()


def terminal(manager, key):
    wait_for(lambda: manager.status(key).get("state") in {"delivered", "failed", "cancelled"})
    return manager.status(key)


def test_unlock_publishes_once_and_late_registration_cannot_miss_event(notifier):
    manager, sent = notifier
    broker = Broker(None, RecordingTyper())
    broker.unlock_notifications = manager
    receipt = broker.dispatch(registration())
    assert receipt["state"] == "subscribed" and not sent
    assert CALLBACK not in json.dumps(receipt)
    assert broker.unlock(Vault([Entry()]))
    assert not broker.unlock(Vault([]))
    assert terminal(manager, receipt["subscription_id"])["attempts"] == 1
    assert sent == [(CALLBACK, {
        "event": "akdbx.unlocked", "locked": False,
        "subscription_id": receipt["subscription_id"], "event_id": sent[0][1]["event_id"],
    })]
    assert SECRET not in json.dumps(sent)
    # A lost receipt retry does not send a second notification, even after success.
    assert broker.dispatch(registration())["subscription_id"] == receipt["subscription_id"]
    assert len(sent) == 1
    late = broker.dispatch(registration(CALLBACK + "-late"))
    assert terminal(manager, late["subscription_id"])["state"] == "delivered"
    assert len(sent) == 2 and not broker.typer.events


def test_real_private_unlock_triggers_event_without_agent_wait(tmp_path, notifier):
    manager, sent = notifier
    broker = Broker(None, RecordingTyper())
    broker.unlock_notifications = manager

    def opener(_database, password, _keyfile):
        if password != "synthetic master":
            raise ValueError("wrong password")
        return Vault([Entry()])

    server, url = start_unlock_server(
        broker, tmp_path / "synthetic.kdbx", None, tmp_path / "web" / "unlock.sock",
        "https://node.example:9443", opener=opener,
    )
    try:
        receipt = broker.dispatch(registration())
        parts = urlsplit(url)
        path = parts.path + "?" + parts.query
        assert call(server.server_address, "POST", path, urlencode({"password": "wrong"}))[0] == 401
        assert broker.locked and not sent
        assert call(server.server_address, "POST", path, urlencode({"password": "synthetic master"}))[0] == 200
        assert terminal(manager, receipt["subscription_id"])["state"] == "delivered"
        assert len(sent) == 1 and not broker.locked and not broker.typer.events
        assert url not in json.dumps(sent) and "synthetic master" not in json.dumps(sent)
    finally:
        server.shutdown()
        server.server_close()


def test_register_unlock_race_never_loses_callback():
    for _ in range(10):
        sent = threading.Event()
        manager = notifications.UnlockNotifications(sender=lambda *_: sent.set())
        broker = Broker(None, RecordingTyper())
        broker.unlock_notifications = manager
        barrier = threading.Barrier(2)

        def subscribe():
            barrier.wait(timeout=2)
            return broker.dispatch(registration())

        def unlock():
            barrier.wait(timeout=2)
            return broker.unlock(Vault([]))

        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                registered = pool.submit(subscribe)
                unlocked = pool.submit(unlock)
                assert registered.result(timeout=3)["ok"]
                assert unlocked.result(timeout=3)
            assert sent.wait(2)
        finally:
            manager.close()


def test_slow_delivery_does_not_delay_unlock_and_cancel_stops_queued_callback():
    started, release = threading.Event(), threading.Event()
    sent = []

    def sender(url, payload):
        sent.append(url)
        started.set()
        assert release.wait(3)

    manager = notifications.UnlockNotifications(sender=sender)
    broker = Broker(None, RecordingTyper())
    broker.unlock_notifications = manager
    first = broker.dispatch(registration())
    second = broker.dispatch(registration(CALLBACK + "-second"))
    try:
        assert broker.unlock(Vault([]))  # Returns while the sender is still blocked.
        assert started.wait(2)
        assert manager.status(first["subscription_id"])["state"] == "sending"
        assert broker.dispatch({"action": "unsubscribe-unlock",
                                "subscription_id": second["subscription_id"]})["state"] == "cancelled"
        release.set()
        assert terminal(manager, first["subscription_id"])["state"] == "delivered"
        assert sent == [CALLBACK]
    finally:
        release.set()
        manager.close()


def test_retry_is_bounded_and_reuses_event_id_without_secret_logs(monkeypatch, capsys, caplog):
    sent = []

    def sender(url, payload):
        sent.append(payload)
        raise OSError(url + " " + SECRET)

    manager = notifications.UnlockNotifications(sender=sender)
    monkeypatch.setattr(manager._stop, "wait", lambda _: False)
    try:
        receipt = manager.subscribe(registration(), unlocked=True)
        status = terminal(manager, receipt["subscription_id"])
        assert status["state"] == "failed" and status["attempts"] == 3
        assert sent[0] == sent[1] == sent[2]
        assert capsys.readouterr() == ("", "") and not caplog.records
        assert CALLBACK not in json.dumps(status) and SECRET not in json.dumps(status)
    finally:
        manager.close()


def test_retry_can_recover(monkeypatch):
    sent = []

    def sender(url, payload):
        sent.append(payload)
        if len(sent) == 1:
            raise OSError

    manager = notifications.UnlockNotifications(sender=sender)
    monkeypatch.setattr(manager._stop, "wait", lambda _: False)
    try:
        receipt = manager.subscribe(registration(), unlocked=True)
        status = terminal(manager, receipt["subscription_id"])
        assert status["state"] == "delivered" and status["attempts"] == 2
        assert sent[0] == sent[1]
    finally:
        manager.close()


def test_expiry_and_storage_budget(monkeypatch):
    now = [0]
    sent = []
    manager = notifications.UnlockNotifications(sender=lambda *a: sent.append(a), clock=lambda: now[0])
    monkeypatch.setattr(notifications, "MAX_SUBSCRIPTIONS", 2)
    try:
        receipt = manager.subscribe(registration(ttl=60), unlocked=False)
        manager.subscribe(registration(CALLBACK + "-2", ttl=60), unlocked=False)
        assert manager.subscribe(registration(CALLBACK + "-3"), unlocked=False)["ok"] is False
        now[0] = 61
        manager.publish()
        assert not sent
        assert manager.status(receipt["subscription_id"])["ok"] is False
        assert manager.subscribe(registration(CALLBACK + "-3"), unlocked=False)["ok"]
    finally:
        manager.close()


@pytest.mark.parametrize("url", [None, "http://callback.example/", "https://user:pass@callback.example/",
    "https://callback.example/#fragment", "https://callback.example:0/", "https://callback.example:99999/",
    "https://callback.example/\nsecret", "https://", "https://callback.example/" + "a" * 4096])
def test_invalid_callback_refused_without_echo(url, notifier):
    manager, sent = notifier
    result = manager.subscribe(registration(url), unlocked=False)
    assert not result["ok"] and not sent
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("ttl", [0, 59, 3601, True, 60.5, "600"])
def test_invalid_ttl_refused(ttl, notifier):
    manager, sent = notifier
    assert not manager.subscribe(registration(ttl=ttl), unlocked=False)["ok"]
    assert not sent


def test_cli_registration_status_cancel_and_private_file(tmp_path, notifier, capsys):
    manager, sent = notifier
    broker = Broker(None, RecordingTyper())
    broker.unlock_notifications = manager
    broker.unlock_url = "https://node.example:9443/?token=synthetic"
    url_file = tmp_path / "url"
    url_file.write_text(CALLBACK)
    url_file.chmod(0o600)
    socket_path = tmp_path / "rpc" / "broker.sock"
    prefix = ["--socket", str(socket_path), "--unlock-origin", "https://node.example:9443"]
    with running_broker(socket_path, broker):
        assert cli.main([*prefix, "subscribe-unlock", "--webhook-url-file", str(url_file)]) == 0
        result = capsys.readouterr()
        receipt = json.loads(result.out)
        assert receipt["state"] == "subscribed" and not result.err
        assert CALLBACK not in result.out
        key = receipt["subscription_id"]
        assert cli.main([*prefix, "unlock-subscription-status", key]) == 0
        assert json.loads(capsys.readouterr().out)["state"] == "subscribed"
        assert cli.main([*prefix, "unsubscribe-unlock", key]) == 0
        assert json.loads(capsys.readouterr().out)["state"] == "cancelled"
        assert broker.unlock(Vault([])) and not sent


def test_cli_refuses_old_broker_without_reading_or_registering(monkeypatch, capsys):
    calls = []

    def request(_socket, payload, **kwargs):
        calls.append(payload)
        return {"ok": True, "locked": True}

    monkeypatch.setattr(cli, "request", request)
    assert cli.main(["subscribe-unlock", "--webhook-url-file", "/absent"]) == 1
    assert calls == [{"action": "ping"}]
    assert "subscription not sent" in capsys.readouterr().out


def test_cli_refuses_public_or_symlinked_callback_file(tmp_path):
    url_file = tmp_path / "url"
    url_file.write_text(CALLBACK)
    url_file.chmod(0o644)
    with pytest.raises(ValueError, match="mode-0600"):
        cli._read_webhook_url(url_file)
    url_file.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(url_file)
    with pytest.raises(OSError):
        cli._read_webhook_url(link)


def test_notification_shutdown_releases_pending_work(notifier):
    manager, sent = notifier
    receipt = manager.subscribe(registration(), unlocked=False)
    manager.close()
    manager.publish()
    assert manager.status(receipt["subscription_id"])["state"] == "cancelled"
    assert not manager.subscribe(registration(CALLBACK + "-new"), unlocked=True)["ok"]
    assert not sent
