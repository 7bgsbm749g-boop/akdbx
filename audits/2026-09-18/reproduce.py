"""Bounded reproductions of the audited behavior, using synthetic data only.

Run: .venv/bin/pytest -q audits/2026-09-18/reproduce.py
These assertions confirm vulnerabilities/limitations, not fixed behavior.
Never connects to the live broker, Tailscale proxy, vault, or desktop.
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.client import HTTPConnection
from urllib.parse import urlencode, urlsplit

import pytest

from akdbx.broker import Broker, PynputTyper, serve
from akdbx.cli import request
from akdbx.protocol import receive_message, send_message
from akdbx.web_unlock import start_unlock_server


@dataclass
class Entry:
    uuid: str = "synthetic-uuid"
    title: str = "Synthetic"
    username: str = "synthetic-user"
    password: str = "synthetic-password"
    url: str = "https://example.invalid"
    path: list[str] = field(default_factory=lambda: ["Root", "Synthetic"])


@dataclass
class Vault:
    entries: list = field(default_factory=lambda: [Entry()])


class Recorder:
    def __init__(self):
        self.events = []

    def type_text(self, text):
        self.events.append(("text", text))

    def press_tab(self):
        self.events.append(("tab", None))


def wait_for(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "bounded wait expired"
        time.sleep(0.005)


@contextmanager
def unix_server(path, broker, stop=None):
    stop = stop or threading.Event()
    errors = []

    def run():
        try:
            serve(path, broker, stop)
        except Exception as exc:
            errors.append(type(exc).__name__)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    wait_for(lambda: path.exists() or errors)
    assert not errors
    try:
        yield thread, errors
    finally:
        stop.set()
        thread.join(3)
        assert not thread.is_alive(), "test left an isolated broker running"


@contextmanager
def web_server(tmp_path, opener):
    server, url = start_unlock_server(
        Broker(None, Recorder()), tmp_path / "synthetic.kdbx", None,
        "127.0.0.1", 0, "https://example.invalid", opener=opener,
    )
    try:
        yield server, urlsplit(url).path + "?" + urlsplit(url).query
    finally:
        server.shutdown()
        server.server_close()


def post(server, path):
    client = HTTPConnection("127.0.0.1", server.server_port, timeout=8)
    try:
        client.request("POST", path, urlencode({"password": "synthetic-wrong"}), {
            "Content-Type": "application/x-www-form-urlencoded",
            "Tailscale-User-Login": "synthetic@example.invalid",
        })
        response = client.getresponse()
        response.read()
        return response.status
    finally:
        client.close()


def test_credential_control_characters_generate_enter_and_tab(monkeypatch):
    # Import the real installed Controller.type with its non-GUI dummy backend.
    monkeypatch.setenv("PYNPUT_BACKEND", "dummy")
    from pynput import keyboard

    typer = PynputTyper()
    events = []
    monkeypatch.setattr(typer._keyboard, "press", events.append)
    monkeypatch.setattr(typer._keyboard, "release", lambda key: None)
    broker = Broker(Vault([Entry(password="x\ny\tz\r")]), typer)
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    assert broker.dispatch({"action": "fill", "handle": handle, "mode": "password"})["ok"]
    assert events == ["x", keyboard.Key.enter, "y", keyboard.Key.tab, "z", keyboard.Key.enter]
    assert all(not isinstance(events[i], str) for i in (1, 3, 5))


def test_parallel_unlock_attempts_exceed_five(tmp_path):
    entered = []
    lock = threading.Lock()
    release = threading.Event()

    def opener(*args):
        with lock:
            entered.append(1)
        assert release.wait(5)
        raise ValueError("synthetic failure")

    with web_server(tmp_path, opener) as (server, path):
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(post, server, path) for _ in range(8)]
            try:
                wait_for(lambda: len(entered) == 8)
            finally:
                release.set()
            assert [f.result() for f in futures] == [401] * 8
        assert post(server, path) == 429
    assert len(entered) == 8


def test_unauthenticated_incomplete_http_headers_hold_threads(tmp_path):
    with web_server(tmp_path, lambda *args: Vault()) as (server, _):
        accepted = []
        original = server.finish_request

        def finish(sock, address):
            accepted.append(sock)
            original(sock, address)

        server.finish_request = finish
        clients = [socket.create_connection(server.server_address, timeout=1) for _ in range(6)]
        try:
            for client in clients:
                client.sendall(b"GET / HTTP/1.1\r\nHost: example.invalid\r\n")
            wait_for(lambda: len(accepted) == 6)
            assert all(sock.gettimeout() is None for sock in accepted)
            assert all(sock.fileno() >= 0 for sock in accepted)
        finally:
            for client in clients:
                client.shutdown(socket.SHUT_WR)
                while client.recv(8192):
                    pass
                client.close()


def test_idle_unix_client_blocks_other_clients(tmp_path):
    path = tmp_path / "private" / "broker.sock"
    with unix_server(path, Broker(Vault(), Recorder())):
        with socket.socket(socket.AF_UNIX) as idle, socket.socket(socket.AF_UNIX) as other:
            idle.connect(str(path))
            idle.sendall(b"\x00")  # incomplete frame header
            other.connect(str(path))
            other.settimeout(0.15)
            send_message(other, {"action": "ping"})
            with pytest.raises(TimeoutError):
                receive_message(other)
            idle.sendall(b"\x00\x00\x11" + b'{"action":"ping"}')
            assert receive_message(idle)["ok"]
            other.settimeout(2)
            assert receive_message(other)["ok"]


def test_disconnected_client_terminates_broker(tmp_path):
    path = tmp_path / "private" / "broker.sock"
    with unix_server(path, Broker(Vault(), Recorder())) as (thread, errors):
        client = socket.socket(socket.AF_UNIX)
        client.connect(str(path))
        client.close()
        thread.join(2)
        assert not thread.is_alive()
        assert errors == ["BrokenPipeError"]
        assert not path.exists()


def test_large_entry_metadata_terminates_broker(tmp_path):
    path = tmp_path / "private" / "broker.sock"
    broker = Broker(Vault([Entry(title="X" * 65536)]), Recorder())
    with unix_server(path, broker) as (thread, errors):
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(path))
            send_message(client, {"action": "search"})
            thread.join(2)
        assert not thread.is_alive()
        assert errors == ["ProtocolError"]


def test_expired_handles_are_retained(tmp_path):
    now = [0]
    broker = Broker(Vault(), Recorder(), clock=lambda: now[0])
    for _ in range(1000):
        broker.dispatch({"action": "search"})
        now[0] += 301
    assert len(broker._handles) == 1000
    assert all(handle.expires_at <= now[0] for handle in broker._handles.values())


def test_second_broker_replaces_live_socket_and_old_cleanup_removes_it(tmp_path):
    path = tmp_path / "private" / "broker.sock"
    old_stop = threading.Event()
    with unix_server(path, Broker(Vault(), Recorder()), old_stop) as (old_thread, _):
        old_inode = path.stat().st_ino
        with unix_server(path, Broker(None, Recorder())) as (new_thread, _):
            wait_for(lambda: path.stat().st_ino != old_inode)
            assert request(path, {"action": "ping"})["locked"]
            old_stop.set()
            old_thread.join(2)
            assert not old_thread.is_alive()
            assert new_thread.is_alive()
            assert not path.exists()


def test_client_trusts_writable_fake_socket_and_arbitrary_unlock_url(tmp_path):
    directory = tmp_path / "untrusted"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    path = directory / "broker.sock"
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    path.chmod(0o777)
    server.listen(1)
    server.settimeout(3)
    errors = []

    def fake():
        try:
            client, _ = server.accept()
            with client:
                receive_message(client)
                send_message(client, {"ok": True, "locked": True,
                                      "unlock_url": "https://phishing.example.invalid/"})
        except Exception as exc:
            errors.append(type(exc).__name__)

    thread = threading.Thread(target=fake, daemon=True)
    thread.start()
    try:
        response = request(path, {"action": "ping"})
        assert response["unlock_url"] == "https://phishing.example.invalid/"
    finally:
        thread.join(3)
        server.close()
    assert not thread.is_alive() and not errors


def test_arbitrary_direct_identity_header_is_accepted(tmp_path):
    with web_server(tmp_path, lambda *args: Vault()) as (server, path):
        assert post(server, path) == 200


def test_pykeepass_retains_master_password_after_broker_unlock(tmp_path):
    from pykeepass import create_database
    from akdbx.broker import open_vault_with_password

    path = tmp_path / "synthetic.kdbx"
    create_database(str(path), password="synthetic-master")
    broker = Broker(None, Recorder())
    broker.unlock(open_vault_with_password(path, "synthetic-master"))
    assert broker.vault.password == "synthetic-master"


def test_protected_metadata_is_returned_and_recycled_entries_are_searchable(tmp_path):
    from pykeepass import PyKeePass, create_database

    path = tmp_path / "synthetic.kdbx"
    vault = create_database(str(path), password="synthetic-master")
    entry = vault.add_entry(vault.root_group, "Synthetic", "synthetic-user", "synthetic-password")
    value = entry._element.find("String[Key='Title']/Value")
    value.set("Protected", "True")
    value.text = "synthetic-sensitive-title"
    vault.trash_entry(entry)
    vault.save()
    vault = PyKeePass(str(path), password="synthetic-master")
    broker = Broker(vault, Recorder())
    matches = broker.dispatch({"action": "search", "query": "synthetic-sensitive-title"})["entries"]
    assert len(matches) == 1
    assert matches[0]["title"] == "synthetic-sensitive-title"
    assert "Recycle Bin" in matches[0]["group"]


def test_queued_fill_executes_after_caller_times_out_and_disconnects(tmp_path):
    path = tmp_path / "private" / "broker.sock"
    recorder = Recorder()
    broker = Broker(Vault(), recorder)
    handle = broker.dispatch({"action": "search"})["entries"][0]["handle"]
    with unix_server(path, broker) as (thread, errors):
        with socket.socket(socket.AF_UNIX) as blocker:
            blocker.connect(str(path))
            blocker.sendall(b"\x00")
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(path))
                client.settimeout(0.15)  # shortened reproduction of CLI's 5 seconds
                send_message(client, {"action": "fill", "handle": handle, "mode": "password"})
                with pytest.raises(TimeoutError):
                    receive_message(client)
                assert recorder.events == []
            blocker.sendall(b"\x00\x00\x11" + b'{"action":"ping"}')
            assert receive_message(blocker)["ok"]
            wait_for(lambda: bool(recorder.events))
            assert recorder.events == [("text", "synthetic-password")]
        thread.join(2)
        assert errors == ["BrokenPipeError"]
