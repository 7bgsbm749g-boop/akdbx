from __future__ import annotations

import json
from http.client import HTTPConnection
from urllib.parse import urlencode, urlsplit

import pytest

from agentic_kdbx.broker import Broker
from agentic_kdbx.web_unlock import start_unlock_server
from test_broker import Entry, RecordingTyper, Vault, SECRET


def call(port, method, path, body=None, identity=True, timeout=2):
    connection = HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if identity:
        headers["Tailscale-User-Login"] = "owner@example.test"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, response.headers, data


@pytest.mark.parametrize("action", ["search", "fill", "unlock"])
def test_locked_broker_returns_only_unlock_url_and_types_nothing(action):
    typer = RecordingTyper()
    broker = Broker(None, typer)
    broker.unlock_url = "https://node.example/?token=opaque"
    response = broker.dispatch({"action": action, "query": "site"})
    assert response == {"ok": False, "error": "vault locked", "unlock_url": broker.unlock_url}
    assert SECRET not in json.dumps(response)
    assert broker.dispatch({"action": "ping"}) == {
        "ok": True, "locked": True, "unlock_url": broker.unlock_url,
    }
    assert typer.events == []


def test_tailscale_identity_and_one_time_web_unlock(tmp_path):
    def opener(database, password, keyfile):
        if password != "right master":
            raise ValueError("bad credentials")
        return Vault([Entry()])

    broker = Broker(None, RecordingTyper())
    server, url = start_unlock_server(
        broker, tmp_path / "vault.kdbx", None, "127.0.0.1", 0,
        "https://node.example:9443", opener=opener,
    )
    try:
        port = server.server_address[1]
        path = urlsplit(url).path + "?" + urlsplit(url).query
        status, _, _ = call(port, "GET", path, identity=False)
        assert status == 404
        status, _, _ = call(port, "POST", path, urlencode({"password": "right master"}), identity=False)
        assert status == 404
        assert broker.locked
        status, _, _ = call(port, "POST", "/?token=invalid", urlencode({"password": "right master"}))
        assert status == 404
        assert broker.locked
        status, headers, page = call(port, "GET", path)
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert b"right master" not in page

        status, _, page = call(port, "POST", path, urlencode({"password": "wrong"}))
        assert status == 401
        assert broker.locked
        assert b"wrong" not in page

        status, _, page = call(port, "POST", path, urlencode({"password": "right master"}))
        assert status == 200
        assert not broker.locked
        assert b"right master" not in page
        assert SECRET not in json.dumps(broker.dispatch({"action": "search", "query": "example"}))

        status, _, _ = call(port, "GET", path)
        assert status == 404  # original URL is invalidated after success
    finally:
        server.shutdown()
        server.server_close()


def test_web_unlock_refuses_non_loopback_listener(tmp_path):
    broker = Broker(None, RecordingTyper())
    try:
        start_unlock_server(broker, tmp_path / "vault.kdbx", None, "0.0.0.0", 0, "https://node")
    except ValueError as exc:
        assert "localhost" in str(exc)
    else:
        raise AssertionError("non-loopback listener accepted")
