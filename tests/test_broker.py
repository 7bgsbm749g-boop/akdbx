from __future__ import annotations

import json
import os
import socket
import stat
import struct
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from types import ModuleType, SimpleNamespace

import pytest

import agentic_kdbx.broker as broker_module
from agentic_kdbx.broker import (
    Broker,
    MAX_CREDENTIAL_BYTES,
    MAX_CREDENTIAL_CHARACTERS,
    MAX_METADATA_BYTES,
    MAX_OUTSTANDING_HANDLES,
    PynputTyper,
    _serve_connection,
    serve,
)
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
    assert broker.dispatch({"action": "ping"}) == {"ok": True, "locked": False, "version": "0.6.0", "writes_available": False, "recovery_required": False, **expected_merge_capabilities()}


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


def test_handle_issuance_prunes_all_expired_handles():
    now = [10]
    broker, typer = make_broker(clock=lambda: now[0])
    expired = broker.dispatch({"action": "search"})["entries"][0]["handle"]

    now[0] += 300
    current = broker.dispatch({"action": "search"})["entries"][0]["handle"]

    assert list(broker._handles) == [current]
    assert broker.dispatch({"action": "fill", "handle": expired})["ok"] is False
    assert typer.events == []


def test_handle_resolution_prunes_other_expired_handles():
    now = [10]
    broker, _ = make_broker(clock=lambda: now[0])
    expired = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    now[0] += 100
    current = broker.dispatch({"action": "search"})["entries"][0]["handle"]

    now[0] += 200
    assert broker.dispatch({"action": "fill", "handle": current}) == {
        "ok": True, "filled": "login",
    }
    assert expired not in broker._handles


def test_outstanding_handles_are_bounded_by_evicting_oldest():
    broker, typer = make_broker()
    issued = [
        broker.dispatch({"action": "search"})["entries"][0]["handle"]
        for _ in range(MAX_OUTSTANDING_HANDLES + 1)
    ]

    assert len(broker._handles) == MAX_OUTSTANDING_HANDLES
    assert broker.dispatch({"action": "fill", "handle": issued[0]})["ok"] is False
    assert typer.events == []
    assert broker.dispatch({"action": "fill", "handle": issued[-1]}) == {
        "ok": True, "filled": "login",
    }


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


def test_pynput_delivers_safe_literal_text_and_tab_only_through_keyboard(monkeypatch):
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


@pytest.mark.parametrize(("mode", "username", "password"), [
    ("login", "unsafe\nusername", SECRET),
    ("login", Entry.username, "unsafe\tpassword"),
    ("username", "unsafe\rusername", SECRET),
    ("password", Entry.username, "unsafe\x00password"),
    ("password", Entry.username, "unsafe\x1bpassword"),
    ("password", Entry.username, "unsafe\x7fpassword"),
    ("password", Entry.username, "unsafe\x85password"),
])
def test_pynput_rejects_credential_controls_before_any_key_event(
    monkeypatch, mode, username, password,
):
    # Exercise the installed Controller.type conversion layer with its non-GUI
    # backend. In particular, a bad password in login mode must be found before
    # the safe username or the broker's intentional Tab is delivered.
    monkeypatch.setenv("PYNPUT_BACKEND", "dummy")
    from pynput import keyboard

    typer = PynputTyper()
    events = []
    monkeypatch.setattr(typer._keyboard, "press", lambda key: events.append(("press", key)))
    monkeypatch.setattr(typer._keyboard, "release", lambda key: events.append(("release", key)))
    broker = Broker(Vault([Entry(username=username, password=password)]), typer)
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]

    assert broker.dispatch({"action": "fill", "handle": handle, "mode": mode}) == {
        "ok": False, "error": "autofill failed",
    }
    assert events == []
    assert broker.dispatch({"action": "fill", "handle": handle})["ok"] is False


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


def test_second_broker_refuses_live_socket_without_disrupting_first(tmp_path):
    socket_path = tmp_path / "private" / "broker.sock"
    first, _ = make_broker()
    with running_broker(socket_path, first):
        with pytest.raises(RuntimeError, match="already managed|live endpoint"):
            serve(socket_path, Broker(None, RecordingTyper()), threading.Event())

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(socket_path))
            send_message(client, {"action": "ping"})
            assert receive_message(client) == {"ok": True, "locked": False, "version": "0.6.0", "writes_available": False, "recovery_required": False, **expected_merge_capabilities()}


def test_serve_rejects_unsafe_custom_runtime_directory_without_chmod(tmp_path):
    runtime = tmp_path / "shared"
    runtime.mkdir(mode=0o777)
    runtime.chmod(0o777)

    with pytest.raises(RuntimeError, match="mode 0700"):
        serve(runtime / "broker.sock", Broker(None, RecordingTyper()), threading.Event())

    assert stat.S_IMODE(runtime.stat().st_mode) == 0o777
    assert not (runtime / "broker.sock").exists()


def test_serve_supports_new_custom_private_runtime_directory(tmp_path):
    socket_path = tmp_path / "custom-runtime" / "custom.sock"
    with running_broker(socket_path, Broker(None, RecordingTyper())):
        assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600


def test_serve_rejects_private_leaf_below_replaceable_ancestor(tmp_path):
    replaceable = tmp_path / "replaceable"
    replaceable.mkdir(mode=0o777)
    replaceable.chmod(0o777)
    private = replaceable / "private"
    private.mkdir(mode=0o700)

    with pytest.raises(RuntimeError, match="replaceable"):
        serve(private / "broker.sock", Broker(None, RecordingTyper()), threading.Event())


def test_serve_reclaims_owned_stale_socket(tmp_path):
    socket_path = tmp_path / "private" / "broker.sock"
    socket_path.parent.mkdir(mode=0o700)
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(socket_path))
    stale.close()
    stale_identity = (socket_path.stat().st_dev, socket_path.stat().st_ino)

    with running_broker(socket_path, Broker(None, RecordingTyper())):
        current = socket_path.stat()
        assert (current.st_dev, current.st_ino) != stale_identity


def test_shutdown_does_not_unlink_replacement_socket(tmp_path):
    socket_path = tmp_path / "private" / "broker.sock"
    broker, _ = make_broker()
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with running_broker(socket_path, broker):
        original_inode = socket_path.stat().st_ino
        socket_path.unlink()
        replacement.bind(str(socket_path))
        assert socket_path.stat().st_ino != original_inode
    try:
        assert socket_path.exists()
        assert stat.S_ISSOCK(socket_path.stat().st_mode)
    finally:
        replacement.close()
        socket_path.unlink()


def test_idle_unix_client_does_not_block_other_requests(tmp_path):
    broker, _ = make_broker()
    socket_path = tmp_path / "private" / "broker.sock"
    with running_broker(socket_path, broker):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as idle:
            idle.connect(str(socket_path))
            idle.sendall(b"\x00")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(0.5)
                client.connect(str(socket_path))
                send_message(client, {"action": "ping"})
                assert receive_message(client) == {"ok": True, "locked": False, "version": "0.6.0", "writes_available": False, "recovery_required": False, **expected_merge_capabilities()}


def test_rpc_worker_admission_is_bounded_and_recovers(tmp_path, monkeypatch):
    monkeypatch.setattr(broker_module, "MAX_RPC_WORKERS", 2)
    original_serve_connection = broker_module._serve_connection
    release = threading.Event()
    both_started = threading.Event()
    counts_lock = threading.Lock()
    started = 0
    active = 0
    max_active = 0

    def blocking_serve_connection(connection, broker):
        nonlocal started, active, max_active
        with counts_lock:
            started += 1
            active += 1
            max_active = max(max_active, active)
            if started == 2:
                both_started.set()
        try:
            assert release.wait(2)
            original_serve_connection(connection, broker)
        finally:
            with counts_lock:
                active -= 1

    monkeypatch.setattr(
        broker_module, "_serve_connection", blocking_serve_connection,
    )
    socket_path = tmp_path / "private" / "broker.sock"
    held = [socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) for _ in range(2)]
    rejected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with running_broker(socket_path, Broker(None, RecordingTyper())):
            for client in held:
                client.connect(str(socket_path))
            assert both_started.wait(1)

            rejected.settimeout(1)
            rejected.connect(str(socket_path))
            assert rejected.recv(1) == b""
            with counts_lock:
                assert started == 2
                assert active == 2
                assert max_active == 2

            for client in held:
                client.close()
            release.set()

            deadline = time.monotonic() + 2
            while True:
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.settimeout(0.5)
                        client.connect(str(socket_path))
                        send_message(client, {"action": "ping"})
                        assert receive_message(client) == {"ok": True, "locked": True, "version": "0.6.0", "writes_available": False, "recovery_required": False, **expected_merge_capabilities()}
                    break
                except (ConnectionError, TimeoutError):
                    assert time.monotonic() < deadline
                    time.sleep(0.01)
    finally:
        release.set()
        for client in held:
            client.close()
        rejected.close()


def test_rpc_absolute_frame_deadline_stops_header_drip_and_recovers(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(broker_module, "CONNECTION_TIMEOUT", 0.2)
    socket_path = tmp_path / "private" / "broker.sock"
    with running_broker(socket_path, Broker(None, RecordingTyper())):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as drip:
            drip.settimeout(1)
            drip.connect(str(socket_path))
            started = time.monotonic()
            disconnected = False
            while time.monotonic() - started < 0.8:
                try:
                    drip.sendall(b"\x00")
                except (BrokenPipeError, ConnectionResetError):
                    disconnected = True
                    break
                time.sleep(0.04)  # shorter than the old per-read idle timeout
            if not disconnected:
                try:
                    disconnected = drip.recv(1) == b""
                except ConnectionResetError:
                    disconnected = True
            assert disconnected
            assert time.monotonic() - started < 0.8

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            client.connect(str(socket_path))
            send_message(client, {"action": "ping"})
            assert receive_message(client) == {"ok": True, "locked": True, "version": "0.6.0", "writes_available": False, "recovery_required": False, **expected_merge_capabilities()}


def test_rpc_worker_start_failure_is_local_and_cleanup_still_completes(
    tmp_path, monkeypatch,
):
    socket_path = tmp_path / "private" / "broker.sock"
    original_start = threading.Thread.start
    injected = threading.Event()

    def fail_once(worker):
        if not injected.is_set():
            injected.set()
            raise RuntimeError("synthetic worker start failure")
        return original_start(worker)

    with running_broker(socket_path, Broker(None, RecordingTyper())):
        monkeypatch.setattr(threading.Thread, "start", fail_once)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as failed_client:
            failed_client.settimeout(1)
            failed_client.connect(str(socket_path))
            assert injected.wait(1)
            assert failed_client.recv(1) == b""
        monkeypatch.setattr(threading.Thread, "start", original_start)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            client.connect(str(socket_path))
            send_message(client, {"action": "ping"})
            assert receive_message(client) == {"ok": True, "locked": True, "version": "0.6.0", "writes_available": False, "recovery_required": False, **expected_merge_capabilities()}

    assert not socket_path.exists()
    with running_broker(socket_path, Broker(None, RecordingTyper())):
        assert socket_path.is_socket()


def test_disconnected_unix_client_does_not_stop_broker(tmp_path):
    broker, _ = make_broker()
    socket_path = tmp_path / "private" / "broker.sock"
    with running_broker(socket_path, broker):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(socket_path))
        client.close()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            client.connect(str(socket_path))
            send_message(client, {"action": "ping"})
            assert receive_message(client) == {"ok": True, "locked": False, "version": "0.6.0", "writes_available": False, "recovery_required": False, **expected_merge_capabilities()}


def test_oversized_metadata_returns_generic_error_and_broker_stays_up(tmp_path):
    entry = Entry(title="x" * (MAX_METADATA_BYTES + 1))
    broker = Broker(Vault([entry]), RecordingTyper())
    socket_path = tmp_path / "private" / "broker.sock"
    with running_broker(socket_path, broker):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(socket_path))
            send_message(client, {"action": "search"})
            assert receive_message(client) == {"ok": False, "error": "search failed"}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(socket_path))
            send_message(client, {"action": "ping"})
            assert receive_message(client) == {"ok": True, "locked": False, "version": "0.6.0", "writes_available": False, "recovery_required": False, **expected_merge_capabilities()}


def test_unrelated_oversized_metadata_does_not_block_matching_entry():
    oversized = Entry(uuid="oversized", title="x" * (MAX_METADATA_BYTES + 1))
    target = Entry(uuid="target", title="Good", url="https://good.example")
    broker = Broker(Vault([oversized, target]), RecordingTyper())

    response = broker.dispatch({"action": "search", "query": "Good"})

    assert response["ok"] is True
    assert [entry["title"] for entry in response["entries"]] == ["Good"]


def test_total_search_response_budget_returns_generic_error():
    entries = [
        Entry(uuid=str(index), title=str(index) + "x" * 3000)
        for index in range(20)
    ]
    broker = Broker(Vault(entries), RecordingTyper())
    assert broker.dispatch({"action": "search"}) == {
        "ok": False,
        "error": "search failed",
    }


def test_concurrent_fills_do_not_interleave_keyboard_operations():
    first_started = threading.Event()
    release_first = threading.Event()

    class BlockingTyper(RecordingTyper):
        def type_text(self, text):
            self.events.append(("type", text))
            if text == "first-user":
                first_started.set()
                assert release_first.wait(1)

    typer = BlockingTyper()
    vault = Vault([
        Entry(uuid="first", title="First", username="first-user", password="first-pass"),
        Entry(uuid="second", title="Second", username="second-user", password="second-pass"),
    ])
    broker = Broker(vault, typer)
    first = broker.dispatch({"action": "search", "query": "First"})["entries"][0]["handle"]
    second = broker.dispatch({"action": "search", "query": "Second"})["entries"][0]["handle"]
    one = threading.Thread(target=broker.dispatch, args=({"action": "fill", "handle": first},))
    two = threading.Thread(target=broker.dispatch, args=({"action": "fill", "handle": second},))
    one.start()
    assert first_started.wait(1)
    two.start()
    time.sleep(0.05)
    assert typer.events == [("type", "first-user")]
    release_first.set()
    one.join(1)
    two.join(1)
    assert typer.events == [
        ("type", "first-user"), ("key", "tab"), ("type", "first-pass"),
        ("type", "second-user"), ("key", "tab"), ("type", "second-pass"),
    ]


def test_timed_out_queued_fill_never_starts_after_caller_disconnects(tmp_path):
    first_started = threading.Event()
    release_first = threading.Event()

    class BlockingTyper(RecordingTyper):
        def type_text(self, text):
            self.events.append(("type", text))
            if text == "first-user":
                first_started.set()
                assert release_first.wait(2)

    typer = BlockingTyper()
    broker = Broker(Vault([
        Entry(uuid="first", title="First", username="first-user", password="first-pass"),
        Entry(uuid="abandoned", title="Abandoned", username="abandoned-user", password="abandoned-pass"),
    ]), typer)
    first = broker.dispatch({"action": "search", "query": "First"})["entries"][0]["handle"]
    abandoned = broker.dispatch({"action": "search", "query": "Abandoned"})["entries"][0]["handle"]
    active = threading.Thread(
        target=broker.dispatch,
        args=({"action": "fill", "handle": first},),
    )
    active.start()
    assert first_started.wait(1)

    socket_path = tmp_path / "private" / "broker.sock"
    with running_broker(socket_path, broker):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.05)
            client.connect(str(socket_path))
            send_message(client, {
                "action": "fill",
                "handle": abandoned,
                "mode": "login",
                "start_deadline": time.monotonic() + 0.15,
            })
            with pytest.raises(TimeoutError):
                receive_message(client)

        # Let the caller's start deadline expire while the request remains
        # queued, then unblock the active fill. The abandoned credentials must
        # never reach the keyboard backend.
        time.sleep(0.15)
        release_first.set()
        active.join(1)
        assert not active.is_alive()
        time.sleep(0.05)
        assert all("abandoned" not in value for kind, value in typer.events if kind == "type")


def test_deadline_expiring_during_credential_preflight_types_nothing():
    now = [10.0]

    class ExpiringEntry:
        uuid = "expiring"

        @property
        def password(self):
            now[0] = 10.1
            return SECRET

    typer = RecordingTyper()
    broker = Broker(Vault([]), typer, clock=lambda: now[0])
    handle = broker._new_handle(ExpiringEntry())

    assert broker.dispatch({
        "action": "fill", "handle": handle, "mode": "password",
        "start_deadline": 10.05,
    }) == {"ok": False, "error": "autofill not started: request expired"}
    assert typer.events == []


def test_disconnect_during_credential_preflight_types_nothing():
    connected = [True]

    class DisconnectingEntry:
        uuid = "disconnecting"

        @property
        def password(self):
            connected[0] = False
            return SECRET

    typer = RecordingTyper()
    broker = Broker(Vault([]), typer, clock=lambda: 10.0)
    handle = broker._new_handle(DisconnectingEntry())

    assert broker.dispatch(
        {
            "action": "fill", "handle": handle, "mode": "password",
            "start_deadline": 11.0,
        },
        delivery_ready=lambda: connected[0],
    ) == {"ok": False, "error": "autofill not started: caller disconnected"}
    assert typer.events == []


@pytest.mark.parametrize("value", [
    "x" * (MAX_CREDENTIAL_CHARACTERS + 1),
    "\U0001f600" * (MAX_CREDENTIAL_BYTES // 4 + 1),
])
def test_oversized_credential_preflight_types_nothing(value):
    typer = RecordingTyper()
    broker = Broker(Vault([Entry(password=value)]), typer)
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]

    assert broker.dispatch({
        "action": "fill", "handle": handle, "mode": "password",
    }) == {"ok": False, "error": "autofill failed"}
    assert typer.events == []


@pytest.mark.parametrize("trailing", [b"", b"unexpected trailing data"])
def test_unexpired_fill_from_closed_caller_types_nothing(trailing):
    broker, typer = make_broker(clock=time.monotonic)
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    server_side, client_side = socket.socketpair()
    try:
        send_message(client_side, {
            "action": "fill", "handle": handle, "mode": "password",
            "start_deadline": time.monotonic() + 1,
        })
        client_side.sendall(trailing)
        client_side.close()
        _serve_connection(server_side, broker)
    finally:
        server_side.close()
        client_side.close()

    assert typer.events == []


def test_open_caller_with_trailing_protocol_data_is_rejected_before_typing():
    broker, typer = make_broker(clock=time.monotonic)
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    server_side, client_side = socket.socketpair()
    worker = threading.Thread(target=_serve_connection, args=(server_side, broker))
    try:
        send_message(client_side, {
            "action": "fill", "handle": handle, "mode": "password",
            "start_deadline": time.monotonic() + 1,
        })
        client_side.sendall(b"unexpected trailing data")
        worker.start()
        assert receive_message(client_side) == {
            "ok": False,
            "error": "autofill not started: caller disconnected",
        }
        worker.join(1)
        assert not worker.is_alive()
    finally:
        client_side.close()
        server_side.close()

    assert typer.events == []


def test_wire_fill_without_start_deadline_is_not_started(tmp_path):
    broker, typer = make_broker(clock=time.monotonic)
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    socket_path = tmp_path / "private" / "broker.sock"
    with running_broker(socket_path, broker):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(socket_path))
            send_message(client, {"action": "fill", "handle": handle})
            assert receive_message(client) == {
                "ok": False,
                "error": "autofill not started: invalid deadline",
            }
    assert typer.events == []


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


def expected_merge_capabilities(available=False):
    from agentic_kdbx.merge import engine_version
    version = engine_version()
    return {"merge_available": bool(available and version), "merge_engine": "keepassxc-cli " + version if version else None, "merge_same_credentials_only": True, "merge_protocol": 1, "merge_refresh_target_supported": True, "merge_preserve_conflicts_supported": True, "merge_preservation_policy": "capsule-v1", "merge_active_verification": "semantic-v1", "merge_diagnostics": "categories-v1"}
