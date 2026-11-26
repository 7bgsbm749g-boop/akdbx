from __future__ import annotations

import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from urllib.parse import urlencode, urlsplit

import pytest

from pykeepass.exceptions import CredentialsError
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
        "version": "0.50.0", "lock_timeout_seconds": 3600, "lock_event_sources": {}, "unlock_notifications_supported": True, "unlock_notifications_protocol": 1, "unlock_notifications_until_unlock": True, "unlock_notifications_blocked_event": True, "unlock_link_protocol": 1, "unlock_link_max_failures": 3, "card_save_notifications_supported": True, "card_save_notifications_protocol": 1, "card_save_notifications_until_result": True, "pairing_notifications_supported": True, "pairing_notifications_protocol": 1, "pairing_notifications_until_paired": True, "writes_available": False, "recovery_required": False, **expected_merge_capabilities(), **expected_sso_capabilities(), **expected_passwordless_capabilities(), "cards_supported": True, "card_protocol": 1, "card_delivery": "cdp-card-element-v1", "card_browser_configured": False, "card_processor_frames_protocol": 1, "card_processors": ["adyen", "computop", "stripe"], "stripe_card_element": True, "generated_entry_protocol": 1, "generated_single_field": True, "generated_additional_urls": True, "totp_supported": True, "totp_protocol": 1, "totp_import_supported": True, "totp_import_protocol": 1, **target_capabilities(), **expected_extension_capabilities(),
    }
    assert typer.events == []


def test_tailscale_identity_and_one_time_web_unlock(tmp_path):
    def opener(database, password, keyfile):
        if password != "right master":
            raise CredentialsError("bad credentials")
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


def test_tailscale_socket_serves_the_identity_statement_only_to_tailscale_serve(tmp_path):
    from akdbx import broker_identity
    from akdbx.extension_route import EXTENSION_ID
    broker = Broker(None, RecordingTyper())
    socket_path = tmp_path / "private" / "unlock.sock"
    server, _ = start_unlock_server(broker, tmp_path / "vault.kdbx", None, socket_path, "https://node.example:9443")
    path = "/.well-known/akdbx-identity"
    try:
        assert call(socket_path, "GET", path)[0] == 404  # No identity yet.
        identity = broker_identity.IdentityStore(tmp_path / "identity").announce("https://node.example:9443")
        broker.extension.set_identity(identity)
        status, headers, body = call(socket_path, "GET", path)
        assert status == 200 and headers["Content-Type"] == "application/json"
        assert headers["Cache-Control"] == "no-store"
        assert json.loads(body) == identity.message()
        connection = UnixHTTPConnection(socket_path)
        connection.request("GET", path, headers={"Tailscale-User-Login": "owner@example.test",
                                                 "Origin": "chrome-extension://" + EXTENSION_ID})
        assert connection.getresponse().status == 200
        connection.close()
        # Without Tailscale Serve's identity header, or from a web page on another origin: refused.
        assert call(socket_path, "GET", path, identity=False)[0] == 404
        connection = UnixHTTPConnection(socket_path)
        connection.request("GET", path, headers={"Tailscale-User-Login": "owner@example.test",
                                                 "Origin": "https://attacker.test"})
        assert connection.getresponse().status == 404
        connection.close()
        assert call(socket_path, "POST", path, "x=1")[0] == 405
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()


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
        # A malformed form is rejected before it reserves an attempt.
        assert status == 400 and b'synthetic-' not in page
        assert broker.locked and not attempts and broker.unlock_link.remaining() == 3
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
            raise CredentialsError("synthetic failure")
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
        raise CredentialsError("synthetic failure")

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
            raise CredentialsError("synthetic failure")
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
        raise CredentialsError("synthetic failure")

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
                                   "webhook_url": WEBHOOK, "blocked_events": True})
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
                                "webhook_url": WEBHOOK + "-late", "blocked_events": True})
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

            # A link on another origin never reaches the agent, and the check
            # runs before the broker replaces the link: it stays blocked.
            assert fail(socket_path, broker.unlock_url, 3) == [401, 401, 403]
            blocked_url = broker.unlock_url
            code, captured = command("status")
            assert json.loads(captured.out)["unlock_origin"] == "https://node.example:9443"
            code = cli.main(["--socket", str(broker_socket), "--unlock-origin", "https://other.example:9443",
                             "new-unlock-link", "--user-confirmed"])
            captured = capsys.readouterr()
            assert code != 0 and "token=" not in captured.out + captured.err
            assert broker.unlock_blocked and broker.unlock_url == blocked_url
    finally:
        server.shutdown()
        server.server_close()


def test_old_link_request_never_renders_the_replacement_token(tmp_path, monkeypatch):
    # F1: the link is blocked and replaced after this GET passed its check
    # but before its page was built. The page must keep the old token.
    broker, server, socket_path, url = blocking_server(tmp_path)
    state = broker.unlock_link
    replaced = []

    def rotate_once():
        if not replaced:
            for _ in range(3):
                state.record_failure(state.reserve_attempt())
            replaced.append(broker.dispatch({"action": "new-unlock-link", "user_confirmed": True})["unlock_url"])

    # Rotate right after the request's token check returns.
    for name in ("token_matches", "request_status"):
        real = getattr(state, name, None)
        if real is not None:
            def checked(token, _real=real):
                result = _real(token)
                rotate_once()
                return result
            monkeypatch.setattr(state, name, checked)
    try:
        status, _, page = call(socket_path, "GET", route(url))
        fresh_token = urlsplit(replaced[0]).query.split("token=", 1)[1]
        old_token = urlsplit(url).query.split("token=", 1)[1]
        assert status == 200 and fresh_token.encode() not in page and old_token.encode() in page
        # The stale form cannot reach the new link either.
        status, _, page = call(socket_path, "POST", route(url), urlencode({"password": RIGHT}))
        assert status == 404 and fresh_token.encode() not in page and broker.locked
    finally:
        server.shutdown()
        server.server_close()


def test_block_survives_a_broker_restart_until_a_confirmed_new_link(tmp_path):
    # F2: a restart must not clear the block or show a fresh link.
    notification_state = tmp_path / "state" / "unlock-notifications.json"
    flag = notification_state.with_name(notification_state.name + ".unlock-blocked")

    def start():
        broker = Broker(None, RecordingTyper(), notification_state_path=notification_state)
        return blocking_server(tmp_path, broker=broker)

    def stop(broker, server):
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()

    broker, server, socket_path, url = start()
    try:
        assert not flag.exists()
        assert fail(socket_path, url, 3) == [401, 401, 403]
    finally:
        stop(broker, server)
    assert flag.stat().st_mode & 0o777 == 0o600
    assert json.loads(flag.read_text()) == {"blocked": True}

    broker, server, socket_path, url = start()
    try:
        ping = broker.dispatch({"action": "ping"})
        assert ping["locked"] is True and ping["unlock_blocked"] is True and "unlock_url" not in ping
        assert broker.dispatch({"action": "search", "query": "x"}) == {
            "ok": False, "error": "vault locked", "unlock_blocked": True}
        status, _, page = call(socket_path, "POST", route(url), urlencode({"password": RIGHT}))
        assert status == 403 and broker.locked
        fresh = broker.dispatch({"action": "new-unlock-link", "user_confirmed": True})["unlock_url"]
        assert json.loads(flag.read_text()) == {"blocked": False}
    finally:
        stop(broker, server)

    broker, server, socket_path, url = start()
    try:
        ping = broker.dispatch({"action": "ping"})
        assert "unlock_blocked" not in ping and ping["unlock_url"] == url != fresh
        assert call(socket_path, "POST", route(url), urlencode({"password": RIGHT}))[0] == 200
    finally:
        stop(broker, server)


def test_untrusted_saved_block_fails_closed(tmp_path):
    notification_state = tmp_path / "state" / "unlock-notifications.json"
    notification_state.parent.mkdir(mode=0o700)
    flag = notification_state.with_name(notification_state.name + ".unlock-blocked")
    flag.write_text(json.dumps({"blocked": False}))
    flag.chmod(0o644)  # another user could have written it
    broker = Broker(None, RecordingTyper(), notification_state_path=notification_state)
    broker, server, socket_path, url = blocking_server(tmp_path, broker=broker)
    try:
        assert broker.unlock_blocked and "unlock_url" not in broker.dispatch({"action": "ping"})
        assert broker.dispatch({"action": "new-unlock-link", "user_confirmed": True})["ok"] is True
        assert flag.stat().st_mode & 0o777 == 0o600 and json.loads(flag.read_text()) == {"blocked": False}
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()


@pytest.mark.parametrize("body", ["", "password=", "other=value", "password=a&password=b", "password",
                                  # H5: parse_qs keeps an invalid escape as text; it must not count.
                                  "password=wrong%zz", "password=%", "password=wrong%4", "password=wrong%%41"])
def test_malformed_unlock_forms_are_rejected_without_an_attempt(tmp_path, body):
    # F6: only a real password check can use one of the three attempts.
    attempts = []
    broker, server, socket_path, url = blocking_server(tmp_path, attempts)
    try:
        for _ in range(4):
            assert call(socket_path, "POST", route(url), body)[0] == 400
        assert attempts == [] and broker.unlock_link.remaining() == 3 and not broker.unlock_blocked
        assert call(socket_path, "POST", route(url), urlencode({"password": RIGHT}))[0] == 200
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("error", [OSError("synthetic disk error"), RuntimeError("synthetic store error"),
                                   ValueError("synthetic parse error")])
def test_vault_store_errors_do_not_count_as_failed_attempts(tmp_path, error):
    # F6: a store or I/O error says nothing about the password.
    calls = []

    def opener(_database, password, _keyfile):
        calls.append(password)
        if len(calls) <= 4:
            raise error
        return Vault([Entry()])

    broker = Broker(None, RecordingTyper())
    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(broker, tmp_path / "vault.kdbx", None, socket_path,
                                      "https://node.example:9443", opener=opener)
    try:
        for _ in range(4):
            status, _, page = call(socket_path, "POST", route(url), urlencode({"password": RIGHT}))
            assert status == 503 and b"could not open the vault" in page and b"synthetic" not in page
        assert broker.unlock_link.remaining() == 3 and not broker.unlock_blocked and broker.locked
        assert call(socket_path, "POST", route(url), urlencode({"password": RIGHT}))[0] == 200
        assert not broker.locked
    finally:
        server.shutdown()
        server.server_close()


def test_unsaved_block_clear_keeps_the_link_blocked_and_refuses_a_new_link(tmp_path, monkeypatch, capsys):
    # H3: a restart must never undo a block whose clear was not saved.
    broker, server, socket_path, url = blocking_server(tmp_path)
    manager = broker.unlock_notifications
    saved = manager.save_unlock_blocked
    writes = []

    def broken(blocked):
        writes.append(blocked)
        raise OSError("synthetic disk full")

    new_link = {"action": "new-unlock-link", "user_confirmed": True}
    try:
        monkeypatch.setattr(manager, "save_unlock_blocked", broken)
        # Saving the block fails: it still holds in memory.
        assert fail(socket_path, url, 3) == [401, 401, 403] and writes == [True]
        assert broker.unlock_blocked
        # The operator and status both learn that a restart would undo it.
        err = capsys.readouterr().err
        assert "the block could not be saved" in err and "token=" not in err and "wrong-" not in err
        status = broker.dispatch({"action": "ping"})
        assert status["unlock_blocked"] is True and status["unlock_block_saved"] is False
        for _ in range(2):
            receipt = broker.dispatch(new_link)
            assert receipt["ok"] is False and receipt["unlock_blocked"] is True
            assert "could not be cleared" in receipt["error"] and "token=" not in json.dumps(receipt)
            assert broker.unlock_blocked and "unlock_url" not in broker.dispatch({"action": "ping"})
        assert writes == [True, False, False]
        assert call(socket_path, "POST", route(url), urlencode({"password": RIGHT}))[0] == 403
        assert broker.locked

        # Only a saved clear returns a replacement link.
        monkeypatch.setattr(manager, "save_unlock_blocked", saved)
        receipt = broker.dispatch(new_link)
        assert receipt["ok"] is True and not broker.unlock_blocked
        assert "unlock_block_saved" not in broker.dispatch({"action": "ping"})
        assert call(socket_path, "POST", route(receipt["unlock_url"]), urlencode({"password": RIGHT}))[0] == 200
    finally:
        server.shutdown()
        server.server_close()


def test_restored_block_resends_the_blocked_notice_to_opted_in_subscribers(tmp_path):
    # H4: a blocked notice queued before a restart is lost with it.
    from akdbx.notifications import UnlockNotifications
    state = tmp_path / "state" / "notifications.json"
    before = UnlockNotifications(sender=lambda *_: pytest.fail("no delivery before the restart"),
                                 state_path=state)
    register = {"notification_protocol": 1, "webhook_url": WEBHOOK}
    opted = before.subscribe({**register, "blocked_events": True}, unlocked=False)["subscription_id"]
    before.subscribe({**register, "webhook_url": WEBHOOK + "-legacy"}, unlocked=False)
    before.save_unlock_blocked(True)
    before.close()

    from test_broker import running_broker
    rpc_socket = tmp_path / "rpc" / "broker.sock"
    sent = []

    def sender(target, payload):
        # The consumer rechecks status on the event: the endpoint must listen.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(rpc_socket))
        sent.append((target, payload))

    broker = Broker(None, RecordingTyper())
    broker.unlock_notifications = UnlockNotifications(sender=sender, state_path=state)
    broker, server, socket_path, url = blocking_server(tmp_path, broker=broker)
    try:
        assert broker.unlock_blocked
        # Restoring the block sends nothing while the RPC endpoint is down.
        time.sleep(0.1)
        assert sent == [] and broker.unlock_notifications._worker is None
        with running_broker(rpc_socket, broker):
            wait_for(lambda: len(sent) == 1)
            wait_for(lambda: broker.unlock_notifications._worker is None)
            status = broker.dispatch({"action": "unlock-subscription-status", "subscription_id": opted})
            assert status["state"] == "subscribed"
        target, payload = sent[0]
        assert len(sent) == 1 and target == WEBHOOK  # the unlock-only subscription gets nothing
        assert payload["event"] == "akdbx.unlock-blocked" and payload["subscription_id"] == opted
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()


def test_unlock_page_names_the_computer_and_the_tailscale_login(tmp_path, monkeypatch):
    monkeypatch.setattr(web_unlock, "computer_name", lambda: "box<1>")
    broker = Broker(None, RecordingTyper())
    socket_path = tmp_path / "private" / "unlock.sock"
    server, url = start_unlock_server(broker, tmp_path / "vault.kdbx", None, socket_path, "https://node.example:9443")
    try:
        path = urlsplit(url).path + "?" + urlsplit(url).query
        status, _, page = call(socket_path, "GET", path, identity="owner<x>@example.test")
        assert status == 200
        assert (b"<p>Unlock AKDBX on <strong>box&lt;1&gt;</strong> as "
                b"<strong>owner&lt;x&gt;@example.test</strong>.</p>") in page
        assert b"Unlocking for" not in page and b"local user" not in page
        assert call(socket_path, "GET", path, identity=False)[0] == 404  # the identity check is unchanged
    finally:
        server.shutdown()
        server.server_close()


def test_computer_name_is_the_short_machine_name(monkeypatch):
    monkeypatch.setattr(web_unlock.socket, "gethostname", lambda: "Build-Box.example.lan")
    assert web_unlock.computer_name(windows=False) == "Build-Box"
    monkeypatch.setenv("COMPUTERNAME", "DESKTOP-AB12")
    assert web_unlock.computer_name(windows=True) == "DESKTOP-AB12"
    monkeypatch.delenv("COMPUTERNAME")
    monkeypatch.setattr(web_unlock.platform, "node", lambda: "desk-two")
    assert web_unlock.computer_name(windows=True) == "desk-two"
    monkeypatch.setattr(web_unlock.socket, "gethostname", lambda: "")
    assert web_unlock.computer_name(windows=False) == "this computer"
