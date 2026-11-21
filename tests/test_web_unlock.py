from __future__ import annotations

import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from urllib.parse import urlencode, urlsplit

import pytest

import akdbx.web_unlock as web_unlock
from akdbx.broker import Broker
from akdbx.web_unlock import start_unlock_server
from test_broker import target_capabilities, Entry, RecordingTyper, Vault, SECRET, expected_merge_capabilities, expected_sso_capabilities, expected_passwordless_capabilities, expected_extension_capabilities


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
        "version": "0.24.0", "unlock_notifications_supported": True, "unlock_notifications_protocol": 1, "unlock_notifications_until_unlock": True, "unlock_notifications_blocked_event": True, "unlock_link_protocol": 1, "unlock_link_max_failures": 3, "card_save_notifications_supported": True, "card_save_notifications_protocol": 1, "card_save_notifications_until_result": True, "writes_available": False, "recovery_required": False, **expected_merge_capabilities(), **expected_sso_capabilities(), **expected_passwordless_capabilities(), "cards_supported": True, "card_protocol": 1, "card_delivery": "cdp-card-element-v1", "card_browser_configured": False, "card_processor_frames_protocol": 1, "card_processors": ["adyen", "computop", "stripe"], "generated_entry_protocol": 1, "totp_supported": True, "totp_protocol": 1, "totp_import_supported": True, "totp_import_protocol": 1, **target_capabilities(), **expected_extension_capabilities(),
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


@pytest.mark.parametrize('encoding', ['%FF', '%C3'])
def test_unlock_rejects_lossy_percent_utf8_before_opening(tmp_path, encoding):
    attempts = []
    valid = 'synthetic-\ufffd-tail'

    def opener(database, password, keyfile):
        attempts.append(password)
        assert password == valid
        return Vault([Entry()])

    broker = Broker(None, RecordingTyper())
    socket_path = tmp_path / 'private' / 'unlock.sock'
    server, url = start_unlock_server(broker, tmp_path / 'vault.kdbx', None, socket_path,
                                      'https://node.example:9443', opener=opener)
    parts = urlsplit(url)
    route = parts.path + '?' + parts.query
    try:
        status, _, page = call(socket_path, 'POST', route, 'password=synthetic-' + encoding + '-tail')
        assert status == 401 and b'synthetic-' not in page
        assert broker.locked and not attempts
        assert call(socket_path, 'POST', route, urlencode(dict(password=valid)))[0] == 200
        assert attempts == [valid] and not broker.locked
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
            while len(completed) < 5 and time.monotonic() < deadline:
                time.sleep(0.01)
            # Three reservations are the link's whole budget: the other five
            # parallel guesses never reach the opener.
            assert completed == [429] * 5
            assert entered == 1
            release.set()
            statuses = [future.result() for future in futures]

        assert statuses.count(401) == 2
        assert statuses.count(403) == 1  # the third failure blocks the link
        assert statuses.count(429) == 5
        assert entered == 3
        assert max_active == 1
        assert call(socket_path, "POST", path, urlencode({"password": "wrong"}))[0] == 403
        assert entered == 3 and broker.unlock_blocked
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
        # must not consume another: both remaining attempts are usable.
        statuses = [call(
            socket_path, "POST", path,
            urlencode({"password": f"later-{index}"}),
            identity=f"later-{index}@example.test",
        )[0] for index in range(2)]
        assert statuses == [401, 403]
        assert call(
            socket_path, "POST", path, urlencode({"password": "over-limit"}),
        )[0] == 403
        assert opener_calls == ["blocker", "later-0", "later-1"]
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


# Per-link block: three failed attempts in total, then the link stops working.

RIGHT = "right master"
WEBHOOK = "https://callback.example/hooks/private-bearer-token"


def blocking_server(tmp_path, opener_calls=None, *, broker=None):
    def opener(_database, password, _keyfile):
        if opener_calls is not None:
            opener_calls.append(password)
        if password != RIGHT:
            raise ValueError("synthetic failure")
        return Vault([Entry()])

    broker = broker or Broker(None, RecordingTyper())
    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(
        broker, tmp_path / "vault.kdbx", None, socket_path,
        "https://node.example:9443", opener=opener,
    )
    return broker, server, socket_path, url


def route(url):
    parts = urlsplit(url)
    return parts.path + "?" + parts.query


def fail(socket_path, url, count):
    return [call(socket_path, "POST", route(url), urlencode({"password": f"wrong-{index}"}))[0]
            for index in range(count)]


def test_third_failure_blocks_link_and_correct_password_then_fails(tmp_path):
    attempts = []
    broker, server, socket_path, url = blocking_server(tmp_path, attempts)
    try:
        assert fail(socket_path, url, 2) == [401, 401]
        assert not broker.unlock_blocked
        status, _, page = call(socket_path, "POST", route(url), urlencode({"password": "wrong-2"}))
        assert status == 403 and b"Unlock link blocked" in page
        assert b"Ask your agent for a new unlock link" in page
        assert broker.unlock_blocked
        # The token stops working at once, even with the right password.
        status, _, page = call(socket_path, "POST", route(url), urlencode({"password": RIGHT}))
        assert status == 403 and b"<form" not in page
        assert call(socket_path, "GET", route(url))[0] == 403
        assert broker.locked and attempts == ["wrong-0", "wrong-1", "wrong-2"]

        # Blocked responses report the state and never carry an unlock URL.
        ping = broker.dispatch({"action": "ping"})
        assert ping["locked"] is True and ping["unlock_blocked"] is True and "unlock_url" not in ping
        assert broker.dispatch({"action": "search", "query": "example"}) == {
            "ok": False, "error": "vault locked", "unlock_blocked": True}
        assert url not in json.dumps(ping)
        # Another identity cannot get more attempts.
        status = call(socket_path, "POST", route(url), urlencode({"password": RIGHT}),
                      identity="other@example.test")[0]
        assert status == 403 and attempts == ["wrong-0", "wrong-1", "wrong-2"]
    finally:
        server.shutdown()
        server.server_close()


def test_failures_never_reset_or_expire_with_time(tmp_path, monkeypatch):
    assert not hasattr(web_unlock, "ATTEMPT_WINDOW") and not hasattr(web_unlock, "MAX_UNLOCK_ATTEMPTS")
    broker = Broker(None, RecordingTyper())
    state = web_unlock.UnlockState(broker, tmp_path / "vault.kdbx", None, public_base="https://node.example")
    now = [1000.0]
    monkeypatch.setattr(web_unlock.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(web_unlock.time, "time", lambda: now[0])
    token = state.token
    for _ in range(2):
        attempt = state.reserve_attempt("owner@example.test")
        assert attempt is not None and not state.record_failure(attempt)
    now[0] += 30 * 24 * 3600  # a month later
    # Time neither expires the link nor refunds its failed attempts.
    assert state.token_matches(token) and state.remaining() == 1
    attempt = state.reserve_attempt("other@example.test")
    assert state.record_failure(attempt) and state.blocked
    now[0] += 30 * 24 * 3600
    assert state.blocked and state.reserve_attempt("owner@example.test") is None


def test_parallel_wrong_attempts_cannot_exceed_three(tmp_path):
    calls = []
    calls_lock = threading.Lock()
    release = threading.Event()

    def opener(_database, password, _keyfile):
        with calls_lock:
            calls.append(password)
        assert release.wait(5)
        raise ValueError("synthetic failure")

    broker = Broker(None, RecordingTyper())
    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(broker, tmp_path / "vault.kdbx", None, socket_path,
                                      "https://node.example:9443", opener=opener)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(call, socket_path, "POST", route(url),
                                   urlencode({"password": f"guess-{index}"}),
                                   f"guess-{index}@example.test", 10) for index in range(8)]
            wait_for(lambda: len(calls) == 1)
            release.set()
            statuses = sorted(future.result()[0] for future in futures)
        # Requests that arrive after the block get 403 instead of 429.
        assert len(calls) == 3
        assert statuses.count(401) == 2 and statuses.count(403) >= 1
        assert statuses.count(403) + statuses.count(429) == 6
        assert fail(socket_path, url, 4) == [403] * 4 and len(calls) == 3
    finally:
        release.set()
        server.shutdown()
        server.server_close()


def test_new_unlock_link_only_while_blocked_and_with_confirmation(tmp_path):
    attempts = []
    broker, server, socket_path, url = blocking_server(tmp_path, attempts)
    try:
        new_link = {"action": "new-unlock-link", "user_confirmed": True}
        assert broker.dispatch(new_link) == {
            "ok": False, "error": "the current unlock link is not blocked; no link created"}
        assert broker.dispatch({"action": "ping"})["unlock_url"] == url
        assert fail(socket_path, url, 3) == [401, 401, 403]
        for refused in ({"action": "new-unlock-link"}, {"action": "new-unlock-link", "user_confirmed": "yes"},
                        {**new_link, "extra": 1}):
            assert broker.dispatch(refused)["ok"] is False
        assert broker.unlock_blocked

        receipt = broker.dispatch(new_link)
        assert receipt["ok"] is True and receipt["locked"] is True and set(receipt) == {"ok", "unlock_url", "locked"}
        fresh = receipt["unlock_url"]
        assert fresh != url and fresh.startswith("https://node.example:9443/?token=")
        assert not broker.unlock_blocked and broker.dispatch({"action": "ping"})["unlock_url"] == fresh
        # A second request does not replace the new, unblocked link.
        assert broker.dispatch(new_link)["ok"] is False
        assert call(socket_path, "GET", route(url))[0] == 404  # the old link stays dead
        assert call(socket_path, "GET", route(fresh))[0] == 200
        # The new link has its own three attempts.
        assert fail(socket_path, fresh, 2) == [401, 401]
        assert call(socket_path, "POST", route(fresh), urlencode({"password": RIGHT}))[0] == 200
        assert not broker.locked and attempts.count(RIGHT) == 1
    finally:
        server.shutdown()
        server.server_close()


def test_new_unlock_link_without_private_page_is_refused():
    broker = Broker(None, RecordingTyper())
    assert broker.dispatch({"action": "new-unlock-link", "user_confirmed": True}) == {
        "ok": False, "error": "this broker has no private unlock page; no link created"}


def test_blocked_event_wakes_subscriber_and_later_unlock_still_arrives(tmp_path):
    from akdbx.notifications import UnlockNotifications
    sent = []
    broker = Broker(None, RecordingTyper())
    broker.unlock_notifications = UnlockNotifications(sender=lambda url, payload: sent.append((url, payload)))
    broker, server, socket_path, url = blocking_server(tmp_path, broker=broker)
    try:
        receipt = broker.dispatch({"action": "subscribe-unlock", "notification_protocol": 1,
                                   "webhook_url": WEBHOOK})
        key = receipt["subscription_id"]
        assert receipt["state"] == "subscribed" and "unlock_blocked" not in receipt
        assert fail(socket_path, url, 3) == [401, 401, 403]
        wait_for(lambda: len(sent) == 1)
        blocked_url, blocked = sent[0]
        assert blocked_url == WEBHOOK
        assert blocked == {"event": "akdbx.unlock-blocked", "locked": True, "unlock_blocked": True,
                           "subscription_id": key, "event_id": blocked["event_id"],
                           "subscription_state": "subscribed"}
        assert urlsplit(url).query not in json.dumps(blocked)
        # The subscription keeps waiting for the real unlock.
        assert broker.dispatch({"action": "unlock-subscription-status", "subscription_id": key})["state"] == "subscribed"
        # A subscription made while blocked learns it from its receipt instead.
        late = broker.dispatch({"action": "subscribe-unlock", "notification_protocol": 1,
                                "webhook_url": WEBHOOK + "-late"})
        assert late["unlock_blocked"] is True and late["state"] == "subscribed"

        fresh = broker.dispatch({"action": "new-unlock-link", "user_confirmed": True})["unlock_url"]
        assert call(socket_path, "POST", route(fresh), urlencode({"password": RIGHT}))[0] == 200
        wait_for(lambda: len(sent) == 3)
        unlocked = {target: payload for target, payload in sent[1:]}
        assert unlocked[WEBHOOK] == {"event": "akdbx.unlocked", "locked": False, "subscription_id": key,
                                     "event_id": unlocked[WEBHOOK]["event_id"]}
        assert unlocked[WEBHOOK]["event_id"] != blocked["event_id"]
        assert unlocked[WEBHOOK + "-late"]["event"] == "akdbx.unlocked"
        wait_for(lambda: broker.dispatch({"action": "unlock-subscription-status",
                                          "subscription_id": key})["state"] == "delivered")
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()


def test_cli_new_unlock_link_requires_blocked_link_and_validates_origin(tmp_path, capsys):
    from akdbx import cli
    from test_broker import running_broker
    broker, server, socket_path, url = blocking_server(tmp_path)
    broker_socket = tmp_path / "private" / "broker.sock"
    prefix = ["--socket", str(broker_socket), "--unlock-origin", "https://node.example:9443"]

    def command(*args):
        code = cli.main([*prefix, *args])
        captured = capsys.readouterr()
        return code, captured

    try:
        with running_broker(broker_socket, broker):
            with pytest.raises(SystemExit):
                cli.main([*prefix, "new-unlock-link"])  # --user-confirmed is required
            capsys.readouterr()
            code, captured = command("new-unlock-link", "--user-confirmed")
            assert code == 1 and "not blocked" in json.loads(captured.out)["error"]
            assert not broker.unlock_blocked and broker.unlock_url == url

            assert fail(socket_path, url, 3) == [401, 401, 403]
            code, captured = command("status")
            status = json.loads(captured.out)
            assert status["unlock_blocked"] is True and "unlock_url" not in status
            code, captured = command("search", "example")
            assert code == 1 and json.loads(captured.out) == {
                "ok": False, "error": "vault locked", "unlock_blocked": True}

            code, captured = command("new-unlock-link", "--user-confirmed")
            receipt = json.loads(captured.out)
            assert code == 0 and receipt["ok"] is True and receipt["unlock_url"] == broker.unlock_url != url
            assert not broker.unlock_blocked
            code, captured = command("new-unlock-link", "--user-confirmed")
            assert code == 1 and "not blocked" in json.loads(captured.out)["error"]

            # A link on another origin never reaches the agent.
            assert fail(socket_path, broker.unlock_url, 3) == [401, 401, 403]
            code = cli.main(["--socket", str(broker_socket), "--unlock-origin", "https://other.example:9443",
                             "new-unlock-link", "--user-confirmed"])
            captured = capsys.readouterr()
            assert code != 0 and "token=" not in captured.out + captured.err
    finally:
        server.shutdown()
        server.server_close()
