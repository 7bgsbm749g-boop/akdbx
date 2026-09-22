from __future__ import annotations

import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from urllib.parse import urlencode, urlsplit

import pytest

import agentic_kdbx.web_unlock as web_unlock
from agentic_kdbx.broker import Broker
from agentic_kdbx.web_unlock import start_unlock_server
from test_broker import Entry, RecordingTyper, Vault, SECRET


class UnixHTTPConnection(HTTPConnection):
    def __init__(self, socket_path, timeout=2):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = str(socket_path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def call(socket_path, method, path, body=None, identity=True, timeout=2):
    connection = UnixHTTPConnection(socket_path, timeout=timeout)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if identity:
        headers["Tailscale-User-Login"] = (
            identity if isinstance(identity, str) else "owner@example.test"
        )
    try:
        connection.request(method, path, body=body, headers=headers)
    except BrokenPipeError:
        # The handler intentionally rejects invalid identity/token headers
        # without waiting for the client to finish streaming a form body.
        pass
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, response.headers, data


def wait_for(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert predicate()


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
    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(
        broker, tmp_path / "vault.kdbx", None, socket_path,
        "https://node.example:9443", opener=opener,
    )
    try:
        path = urlsplit(url).path + "?" + urlsplit(url).query
        status, _, _ = call(socket_path, "GET", path, identity=False)
        assert status == 404
        status, _, _ = call(socket_path, "POST", path, urlencode({"password": "right master"}), identity=False)
        assert status == 404
        assert broker.locked
        status, _, _ = call(socket_path, "POST", "/?token=invalid", urlencode({"password": "right master"}))
        assert status == 404
        assert broker.locked
        status, headers, page = call(socket_path, "GET", path)
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert b"right master" not in page

        status, _, page = call(socket_path, "POST", path, urlencode({"password": "wrong"}))
        assert status == 401
        assert broker.locked
        assert b"wrong" not in page

        status, _, page = call(socket_path, "POST", path, urlencode({"password": "right master"}))
        assert status == 200
        assert not broker.locked
        assert b"right master" not in page
        assert SECRET not in json.dumps(broker.dispatch({"action": "search", "query": "example"}))

        status, _, _ = call(socket_path, "GET", path)
        assert status == 404  # original URL is invalidated after success
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("distinct_identities", [False, True])
def test_parallel_unlock_attempts_are_reserved_and_serialized(tmp_path, distinct_identities):
    entered = 0
    active = 0
    max_active = 0
    opener_lock = threading.Lock()
    release = threading.Event()
    completed = []

    def opener(*_args):
        nonlocal entered, active, max_active
        with opener_lock:
            entered += 1
            active += 1
            max_active = max(max_active, active)
        try:
            if entered == 1:
                assert release.wait(5)
            raise ValueError("synthetic failure")
        finally:
            with opener_lock:
                active -= 1

    broker = Broker(None, RecordingTyper())
    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(
        broker, tmp_path / "vault.kdbx", None, socket_path,
        "https://node.example:9443", opener=opener,
    )
    path = urlsplit(url).path + "?" + urlsplit(url).query

    def post(index):
        identity = f"owner-{index}@example.test" if distinct_identities else True
        result = call(
            socket_path, "POST", path, urlencode({"password": "wrong"}), identity=identity,
        )[0]
        with opener_lock:
            completed.append(result)
        return result

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(post, index) for index in range(8)]
            deadline = time.monotonic() + 5
            while len(completed) < 3 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert completed == [429] * 3
            assert entered == 1
            release.set()
            statuses = [future.result() for future in futures]

        assert statuses.count(401) == 5
        assert statuses.count(429) == 3
        assert entered == 5
        assert max_active == 1
        assert call(socket_path, "POST", path, urlencode({"password": "wrong"}))[0] == 429
    finally:
        release.set()
        server.shutdown()
        server.server_close()


def test_incomplete_requests_are_bounded_expire_and_release_capacity(tmp_path, monkeypatch):
    monkeypatch.setattr(web_unlock, "MAX_HTTP_CONNECTIONS", 2)
    monkeypatch.setattr(web_unlock, "REQUEST_IO_TIMEOUT", 0.15)
    monkeypatch.setattr(web_unlock, "CONNECTION_TIMEOUT", 0.5)
    opener_calls = 0

    def opener(*_args):
        nonlocal opener_calls
        opener_calls += 1
        raise AssertionError("an incomplete body must not reach the vault opener")

    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(
        Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
        socket_path, "https://node.example:9443", opener=opener,
    )
    path = urlsplit(url).path + "?" + urlsplit(url).query
    started = 0
    active = 0
    max_active = 0
    observed_lock = threading.Lock()
    original_finish_request = server.finish_request

    def observed_finish_request(request, client_address):
        nonlocal started, active, max_active
        with observed_lock:
            started += 1
            active += 1
            max_active = max(max_active, active)
        try:
            original_finish_request(request, client_address)
        finally:
            with observed_lock:
                active -= 1

    server.finish_request = observed_finish_request
    incomplete_header = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    incomplete_body = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        incomplete_header.connect(str(socket_path))
        incomplete_header.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        incomplete_body.connect(str(socket_path))
        incomplete_body.sendall(
            (
                f"POST {path} HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Tailscale-User-Login: owner@example.test\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 100\r\n\r\n"
                "password=x"
            ).encode()
        )
        wait_for(lambda: started == 2)

        with ThreadPoolExecutor(max_workers=1) as pool:
            queued = pool.submit(call, socket_path, "GET", path)
            time.sleep(0.05)
            assert not queued.done()
            assert started == 2
            assert queued.result(timeout=2)[0] == 200

        wait_for(lambda: active == 0)
        assert max_active == 2
        assert opener_calls == 0
        assert incomplete_header.recv(1) == b""
        assert incomplete_body.recv(1) == b""
    finally:
        incomplete_header.close()
        incomplete_body.close()
        server.shutdown()
        server.server_close()


def test_absolute_connection_deadline_stops_slow_header_drip(tmp_path, monkeypatch):
    monkeypatch.setattr(web_unlock, "REQUEST_IO_TIMEOUT", 0.2)
    monkeypatch.setattr(web_unlock, "CONNECTION_TIMEOUT", 0.35)
    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(
        Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
        socket_path, "https://node.example:9443",
    )
    path = urlsplit(url).path + "?" + urlsplit(url).query
    slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    slow.settimeout(1)
    try:
        slow.connect(str(socket_path))
        payload = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: "
        disconnected = False
        started = time.monotonic()
        while time.monotonic() - started < 0.8:
            try:
                slow.sendall(payload[:1])
            except (BrokenPipeError, ConnectionResetError):
                disconnected = True
                break
            payload = payload[1:] or b"x"
            time.sleep(0.04)  # frequent enough not to trigger the idle timeout
        if not disconnected:
            disconnected = slow.recv(1) == b""
        assert disconnected
        assert time.monotonic() - started < 0.8
        assert call(socket_path, "GET", path)[0] == 200
    finally:
        slow.close()
        server.shutdown()
        server.server_close()


def test_eof_short_body_is_rejected_before_unlock_admission(tmp_path, monkeypatch):
    monkeypatch.setattr(web_unlock, "REQUEST_IO_TIMEOUT", 1)
    monkeypatch.setattr(web_unlock, "CONNECTION_TIMEOUT", 1)
    opener_calls = []

    def opener(_database, password, _keyfile):
        opener_calls.append(password)
        raise AssertionError("a short body must not reach the vault opener")

    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(
        Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
        socket_path, "https://node.example:9443", opener=opener,
    )
    path = urlsplit(url).path + "?" + urlsplit(url).query
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    try:
        client.connect(str(socket_path))
        client.sendall(
            (
                f"POST {path} HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Tailscale-User-Login: owner@example.test\r\n"
                "Content-Length: 100\r\n\r\n"
                "password=synthetic"
            ).encode()
        )
        client.shutdown(socket.SHUT_WR)
        assert b" 400 " in client.recv(4096)
        assert opener_calls == []
        assert call(socket_path, "GET", path)[0] == 200
    finally:
        client.close()
        server.shutdown()
        server.server_close()


def test_absolute_expiry_during_body_never_reaches_opener(tmp_path, monkeypatch):
    monkeypatch.setattr(web_unlock, "REQUEST_IO_TIMEOUT", 1)
    monkeypatch.setattr(web_unlock, "CONNECTION_TIMEOUT", 0.15)
    opener_calls = []

    def opener(_database, password, _keyfile):
        opener_calls.append(password)
        raise AssertionError("an expired body must not reach the vault opener")

    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(
        Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
        socket_path, "https://node.example:9443", opener=opener,
    )
    path = urlsplit(url).path + "?" + urlsplit(url).query
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    try:
        client.connect(str(socket_path))
        client.sendall(
            (
                f"POST {path} HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Tailscale-User-Login: owner@example.test\r\n"
                "Content-Length: 100\r\n\r\n"
                "password=synthetic"
            ).encode()
        )
        assert client.recv(1) == b""
        assert opener_calls == []
        assert call(socket_path, "GET", path)[0] == 200
    finally:
        client.close()
        server.shutdown()
        server.server_close()


def test_request_expired_while_waiting_releases_unlock_reservation(tmp_path, monkeypatch):
    monkeypatch.setattr(web_unlock, "REQUEST_IO_TIMEOUT", 1)
    monkeypatch.setattr(web_unlock, "CONNECTION_TIMEOUT", 0.2)
    entered = threading.Event()
    release = threading.Event()
    victim_reserved = threading.Event()
    opener_calls = []
    original_reserve_attempt = web_unlock.UnlockState.reserve_attempt

    def observed_reserve_attempt(self, identity):
        attempt = original_reserve_attempt(self, identity)
        if identity == "victim@example.test" and attempt is not None:
            victim_reserved.set()
        return attempt

    monkeypatch.setattr(
        web_unlock.UnlockState, "reserve_attempt", observed_reserve_attempt,
    )

    def opener(_database, password, _keyfile):
        opener_calls.append(password)
        if password == "blocker":
            entered.set()
            assert release.wait(2)
        raise ValueError("synthetic failure")

    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(
        Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
        socket_path, "https://node.example:9443", opener=opener,
    )
    path = urlsplit(url).path + "?" + urlsplit(url).query

    def blocking_post():
        try:
            call(
                socket_path, "POST", path, urlencode({"password": "blocker"}),
                identity="blocker@example.test", timeout=1,
            )
        except (ConnectionError, OSError):
            pass

    victim = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    victim.settimeout(2)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            blocker = pool.submit(blocking_post)
            assert entered.wait(1)
            victim.connect(str(socket_path))
            body = "password=victim"
            victim.sendall(
                (
                    f"POST {path} HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Tailscale-User-Login: victim@example.test\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                    f"{body}"
                ).encode()
            )
            assert victim_reserved.wait(1)
            assert victim.recv(1) == b""
            release.set()
            blocker.result(timeout=2)

        assert opener_calls == ["blocker"]
        assert call(socket_path, "GET", path)[0] == 200

        # The blocker consumed one failure. The expired victim's reservation
        # must not consume another: all four remaining budget slots are usable.
        for index in range(4):
            status = call(
                socket_path, "POST", path,
                urlencode({"password": f"later-{index}"}),
                identity=f"later-{index}@example.test",
            )[0]
            assert status == 401
        assert call(
            socket_path, "POST", path, urlencode({"password": "over-limit"}),
        )[0] == 429
        assert "victim" not in opener_calls
    finally:
        release.set()
        victim.close()
        server.shutdown()
        server.server_close()


def test_web_unlock_requires_absolute_private_socket(tmp_path):
    broker = Broker(None, RecordingTyper())
    with pytest.raises(ValueError, match="absolute"):
        start_unlock_server(broker, tmp_path / "vault.kdbx", None, "unlock.sock", "https://node")

    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(RuntimeError, match="0700"):
        start_unlock_server(broker, tmp_path / "vault.kdbx", None, unsafe / "unlock.sock", "https://node")


def test_web_unlock_refuses_live_socket_and_removes_only_its_own(tmp_path):
    socket_path = tmp_path / "private" / "unlock.sock"
    broker = Broker(None, RecordingTyper())
    server, _ = start_unlock_server(
        broker, tmp_path / "vault.kdbx", None, socket_path, "https://node",
    )
    try:
        assert socket_path.is_socket()
        assert socket_path.stat().st_mode & 0o777 == 0o600
        with pytest.raises(RuntimeError, match="already managed"):
            start_unlock_server(
                broker, tmp_path / "vault.kdbx", None, socket_path, "https://node",
            )
    finally:
        server.shutdown()
        server.server_close()
    assert not socket_path.exists()


def test_web_unlock_replaces_owned_stale_socket(tmp_path):
    socket_path = tmp_path / "private" / "unlock.sock"
    socket_path.parent.mkdir(mode=0o700)
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(socket_path))
    stale.close()

    server, _ = start_unlock_server(
        Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
        socket_path, "https://node",
    )
    try:
        assert socket_path.is_socket()
    finally:
        server.shutdown()
        server.server_close()


def test_web_unlock_cleanup_does_not_unlink_replacement_socket(tmp_path):
    socket_path = tmp_path / "private" / "unlock.sock"
    server, _ = start_unlock_server(
        Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
        socket_path, "https://node",
    )
    server.shutdown()
    socket_path.unlink()
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    replacement.bind(str(socket_path))
    try:
        server.server_close()
        assert socket_path.is_socket()
    finally:
        replacement.close()
        socket_path.unlink()


def test_web_unlock_rejects_replaceable_ancestor_and_synthetic_replacement(tmp_path):
    replaceable = tmp_path / "replaceable"
    replaceable.mkdir(mode=0o777)
    replaceable.chmod(0o777)
    original = replaceable / "private"
    original.mkdir(mode=0o700)
    displaced = replaceable / "displaced"
    original.rename(displaced)
    original.mkdir(mode=0o700)
    fake_path = original / "unlock.sock"
    fake = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    fake.bind(str(fake_path))
    fake_identity = (fake_path.stat().st_dev, fake_path.stat().st_ino)
    try:
        with pytest.raises(RuntimeError, match="replaceable"):
            start_unlock_server(
                Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
                fake_path, "https://node",
            )
        current = fake_path.stat()
        assert (current.st_dev, current.st_ino) == fake_identity
    finally:
        fake.close()


def test_web_unlock_rejects_symlinked_ancestor(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(RuntimeError, match="unsafe or missing runtime ancestor"):
        start_unlock_server(
            Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
            alias / "private" / "unlock.sock", "https://node",
        )


def test_web_unlock_lifecycle_lock_closes_bind_listen_startup_race(tmp_path, monkeypatch):
    socket_path = tmp_path / "private" / "unlock.sock"
    entered = threading.Event()
    release = threading.Event()
    original_activate = web_unlock.ThreadingUnixHTTPServer.server_activate
    result = []

    def paused_activate(server):
        entered.set()
        assert release.wait(3)
        original_activate(server)

    monkeypatch.setattr(
        web_unlock.ThreadingUnixHTTPServer, "server_activate", paused_activate,
    )

    def first_start():
        try:
            result.append(start_unlock_server(
                Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
                socket_path, "https://node",
            ))
        except Exception as exc:
            result.append(exc)

    thread = threading.Thread(target=first_start)
    thread.start()
    assert entered.wait(2)
    try:
        with pytest.raises(RuntimeError, match="already managed"):
            start_unlock_server(
                Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
                socket_path, "https://node",
            )
    finally:
        release.set()
        thread.join(3)
    assert len(result) == 1 and not isinstance(result[0], Exception)
    server, _ = result[0]
    server.shutdown()
    server.server_close()


def test_web_unlock_bounded_probe_refuses_saturated_listener(tmp_path):
    socket_path = tmp_path / "private" / "unlock.sock"
    socket_path.parent.mkdir(mode=0o700)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    clients = []
    saturated = False
    try:
        for _ in range(32):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(0.03)
            try:
                client.connect(str(socket_path))
            except (TimeoutError, BlockingIOError):
                client.close()
                saturated = True
                break
            clients.append(client)
        assert saturated
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="cannot prove"):
            start_unlock_server(
                Broker(None, RecordingTyper()), tmp_path / "vault.kdbx", None,
                socket_path, "https://node",
            )
        assert time.monotonic() - started < 1
        assert socket_path.is_socket()
    finally:
        for client in clients:
            client.close()
        listener.close()
