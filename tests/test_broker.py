from __future__ import annotations

import json
import os
import socket
import stat
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from types import ModuleType, SimpleNamespace

import pytest

from agentic_kdbx.broker import Broker, PynputTyper, serve
from agentic_kdbx.protocol import receive_message, send_message


SECRET = "correct horse battery staple"


@dataclass
class Entry:
    uuid: str = "db-internal-uuid"
    title: str = "Example"
    username: str = "alice@example.com"
    password: str = SECRET
    url: str = "https://example.com/login"
    path: tuple[str, ...] = ("Root", "Web", "Example")


@dataclass
class Vault:
    entries: list


class RecordingTyper:
    def __init__(self):
        self.events = []

    def type_text(self, text):
        self.events.append(("type", text))

    def press_tab(self):
        self.events.append(("key", "tab"))


def make_broker(clock=lambda: 10):
    typer = RecordingTyper()
    return Broker(Vault([Entry()]), typer, clock=clock), typer


def test_search_response_never_contains_password_or_internal_uuid():
    broker, _ = make_broker()
    response = broker.dispatch({"action": "search", "query": "example"})
    serialized = json.dumps(response)
    assert response["ok"]
    assert SECRET not in serialized
    assert "db-internal-uuid" not in serialized
    assert response["entries"][0]["username"] == "alice@example.com"


def test_status_is_secret_free():
    broker, _ = make_broker()
    assert broker.dispatch({"action": "ping"}) == {"ok": True, "locked": False}


@pytest.mark.parametrize("mode, expected", [
    ("login", [("type", Entry.username), ("key", "tab"), ("type", SECRET)]),
    ("username", [("type", Entry.username)]),
    ("password", [("type", SECRET)]),
])
def test_fill_without_terminal_returns_only_receipt_and_consumes_handle(mode, expected, capsys, caplog):
    broker, typer = make_broker()
    handle = broker.dispatch({"action": "search", "query": "Example"})["entries"][0]["handle"]
    assert typer.events == []
    response = broker.dispatch({"action": "fill", "handle": handle, "mode": mode})
    assert response == {"ok": True, "filled": mode}
    assert SECRET not in json.dumps(response)
    assert typer.events == expected
    assert broker.dispatch({"action": "fill", "handle": handle})["ok"] is False
    assert typer.events == expected
    assert capsys.readouterr() == ("", "")
    assert not caplog.records


@pytest.mark.parametrize("mode", ["invalid", None, {}, []])
def test_invalid_mode_types_nothing_and_consumes_handle(mode):
    broker, typer = make_broker()
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    assert broker.dispatch({"action": "fill", "handle": handle, "mode": mode}) == {
        "ok": False, "error": "mode must be login, username, or password",
    }
    assert typer.events == []
    assert broker.dispatch({"action": "fill", "handle": handle})["ok"] is False


@pytest.mark.parametrize("elapsed", [300, 301])
def test_expired_handle_is_rejected_and_consumed(elapsed):
    now = [10]
    broker, typer = make_broker(clock=lambda: now[0])
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    now[0] += elapsed
    assert broker.dispatch({"action": "fill", "handle": handle})["ok"] is False
    now[0] = 10
    assert broker.dispatch({"action": "fill", "handle": handle})["ok"] is False
    assert typer.events == []


@pytest.mark.parametrize("handle", [None, 123, {}, [], "fabricated"])
def test_invalid_or_unknown_handle_types_nothing(handle):
    broker, typer = make_broker()
    assert broker.dispatch({"action": "fill", "handle": handle})["ok"] is False
    assert typer.events == []


def test_handles_cannot_be_used_by_another_broker():
    first, _ = make_broker()
    second, typer = make_broker()
    handle = first.dispatch({"action": "search"})["entries"][0]["handle"]
    assert second.dispatch({"action": "fill", "handle": handle})["ok"] is False
    assert typer.events == []


@pytest.mark.parametrize("error", [ValueError, RuntimeError])
def test_keyboard_failure_withholds_error_text_and_consumes_handle(error, capsys, caplog):
    class FailingTyper(RecordingTyper):
        def type_text(self, text):
            raise error(text)

    typer = FailingTyper()
    broker = Broker(Vault([Entry()]), typer)
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    assert broker.dispatch({"action": "fill", "handle": handle, "mode": "password"}) == {
        "ok": False, "error": "autofill failed",
    }
    assert broker.dispatch({"action": "fill", "handle": handle})["ok"] is False
    assert capsys.readouterr() == ("", "")
    assert not caplog.records


def test_metadata_operations_and_unsupported_actions_do_not_type():
    broker, typer = make_broker()
    assert broker.dispatch({"action": "search", "query": SECRET}) == {"ok": True, "entries": []}
    for action in ("ping", "search", "reveal", "clipboard", "export", "unlock"):
        response = broker.dispatch({"action": action})
        assert SECRET not in json.dumps(response)
    assert typer.events == []


def test_pynput_delivers_literal_text_and_tab_only_through_keyboard(monkeypatch):
    events = []

    class Keyboard:
        def type(self, text):
            events.append(("type", text))

        def press(self, key):
            events.append(("press", key))

        def release(self, key):
            events.append(("release", key))

    # Replace the native module before import: never connect to a desktop.
    keyboard = ModuleType("pynput.keyboard")
    keyboard.Controller = Keyboard
    keyboard.Key = SimpleNamespace(tab=object())
    monkeypatch.setitem(sys.modules, "pynput.keyboard", keyboard)
    literal = "synthetic ' $() ` ; \\ unicode: é"
    broker = Broker(Vault([Entry(password=literal)]), PynputTyper())
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    assert broker.dispatch({"action": "fill", "handle": handle}) == {"ok": True, "filled": "login"}
    assert events == [
        ("type", Entry.username), ("press", keyboard.Key.tab),
        ("release", keyboard.Key.tab), ("type", literal),
    ]


@contextmanager
def running_broker(socket_path, broker):
    stop = threading.Event()
    thread = threading.Thread(target=serve, args=(socket_path, broker, stop), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 2
        while not socket_path.exists() or stat.S_IMODE(socket_path.stat().st_mode) != 0o600:
            assert thread.is_alive() and time.monotonic() < deadline
            time.sleep(0.005)
        yield
    finally:
        stop.set()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_unix_socket_permissions_and_wire_response_have_no_secret(tmp_path):
    broker, _ = make_broker()
    socket_path = tmp_path / "private" / "broker.sock"
    with running_broker(socket_path, broker):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(socket_path))
            send_message(client, {"action": "search", "query": "example"})
            response = receive_message(client)
        assert SECRET not in json.dumps(response)
        assert stat.S_IMODE(os.stat(socket_path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(socket_path.parent).st_mode) == 0o700


def test_real_encrypted_kdbx_round_trip_never_returns_secret(tmp_path):
    from pykeepass import PyKeePass, create_database

    database = tmp_path / "test.kdbx"
    create_database(str(database), password="vault-master-password")
    writable = PyKeePass(str(database), password="vault-master-password")
    writable.add_entry(writable.root_group, "Real Site", "real-user", SECRET, url="https://real.example")
    writable.save()

    reopened = PyKeePass(str(database), password="vault-master-password")
    typer = RecordingTyper()
    broker = Broker(reopened, typer)
    search = broker.dispatch({"action": "search", "query": "real.example"})
    assert SECRET not in json.dumps(search)
    fill = broker.dispatch({"action": "fill", "handle": search["entries"][0]["handle"], "mode": "password"})
    assert fill == {"ok": True, "filled": "password"}
    assert typer.events == [("type", SECRET)]
