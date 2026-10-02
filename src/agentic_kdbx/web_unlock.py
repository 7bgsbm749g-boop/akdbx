from __future__ import annotations

import html
import os
import secrets
import socket
import socketserver
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .broker import Broker, open_vault_with_password
from .runtime import (
    acquire_lifecycle_lock,
    prepare_private_runtime_directory,
    remove_stale_socket,
    unlink_socket_if_same,
)

MAX_BODY = 16 * 1024
MAX_UNLOCK_ATTEMPTS = 5
ATTEMPT_WINDOW = 60
MAX_HTTP_CONNECTIONS = 8
REQUEST_IO_TIMEOUT = 5.0
CONNECTION_TIMEOUT = 15.0


class ConnectionDeadline:
    """Absolute lifetime shared by a connection watchdog and its handler."""

    def __init__(self) -> None:
        self.expires_at = time.monotonic() + CONNECTION_TIMEOUT
        self.expired_event = threading.Event()

    def expire(self) -> None:
        self.expired_event.set()

    def expired(self) -> bool:
        return self.expired_event.is_set() or time.monotonic() >= self.expires_at


class ThreadingUnixHTTPServer(ThreadingHTTPServer):
    """HTTP over a filesystem-protected Unix socket for Tailscale Serve."""

    address_family = socket.AF_UNIX
    daemon_threads = True
    request_queue_size = MAX_HTTP_CONNECTIONS

    def __init__(
        self, server_address, *args, **kwargs,
    ) -> None:
        self._connection_slots = threading.BoundedSemaphore(MAX_HTTP_CONNECTIONS)
        self._deadline_lock = threading.Lock()
        self._deadlines: dict[socket.socket, ConnectionDeadline] = {}
        self._runtime_fd: int | None = None
        self._lifecycle_lock: int | None = None
        socket_path = Path(os.path.abspath(os.fspath(server_address)))
        runtime_path, self._runtime_fd = prepare_private_runtime_directory(
            socket_path.parent,
        )
        socket_path = runtime_path / socket_path.name
        self._socket_name = socket_path.name
        try:
            self._lifecycle_lock = acquire_lifecycle_lock(
                self._runtime_fd, self._socket_name,
            )
            remove_stale_socket(socket_path, self._runtime_fd, self._socket_name)
        except Exception:
            if self._lifecycle_lock is not None:
                os.close(self._lifecycle_lock)
                self._lifecycle_lock = None
            os.close(self._runtime_fd)
            self._runtime_fd = None
            raise
        super().__init__(str(socket_path), *args, **kwargs)

    def handle_error(self, request, client_address) -> None:
        # Unexpected exceptions may carry private form values. Never print a
        # traceback or exception message from a private HTTP worker.
        return

    def service_actions(self) -> None:
        # Expired staged secrets must be discarded even with no new requests.
        manager = getattr(self, 'write_manager', None)
        if manager is not None and manager.broker._vault_lock.acquire(blocking=False):
            try:
                manager._prune()
            finally:
                manager.broker._vault_lock.release()

    def get_request(self):
        # Reserve capacity before accept(), so no more than the bounded worker
        # count can become application-owned connections at once. Connections
        # beyond the cap remain in the kernel's bounded listen queue.
        self._connection_slots.acquire()
        try:
            request, client_address = super().get_request()
            request.settimeout(REQUEST_IO_TIMEOUT)
            return request, client_address
        except BaseException:
            self._connection_slots.release()
            raise

    @staticmethod
    def _expire_request(
        request: socket.socket, deadline: ConnectionDeadline,
    ) -> None:
        # The socket timeout above limits inactivity. This watchdog additionally
        # prevents a peer from extending a connection forever by slowly sending
        # bytes just before each inactivity deadline.
        deadline.expire()
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def request_expired(self, request: socket.socket) -> bool:
        with self._deadline_lock:
            deadline = self._deadlines.get(request)
        return deadline is None or deadline.expired()

    def process_request(self, request, client_address) -> None:
        try:
            super().process_request(request, client_address)
        except BaseException:
            # Thread creation can fail after get_request() reserved a slot.
            # Recover both the socket and capacity before propagating it.
            self.shutdown_request(request)
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        connection_deadline = ConnectionDeadline()
        with self._deadline_lock:
            self._deadlines[request] = connection_deadline
        deadline = threading.Timer(
            CONNECTION_TIMEOUT, self._expire_request,
            args=(request, connection_deadline),
        )
        deadline.daemon = True
        deadline_started = False
        try:
            deadline.start()
            deadline_started = True
            try:
                self.finish_request(request, client_address)
            except (TimeoutError, ConnectionError, OSError):
                # Expected for expired or client-abandoned requests. Do not log
                # request data or a traceback for an untrusted connection.
                pass
            except Exception:
                self.handle_error(request, client_address)
        finally:
            if deadline_started:
                deadline.cancel()
            with self._deadline_lock:
                self._deadlines.pop(request, None)
            self.shutdown_request(request)
            self._connection_slots.release()

    def server_bind(self) -> None:
        # HTTPServer.server_bind assumes an INET (host, port) address.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = None
        assert self._runtime_fd is not None
        os.chmod(self._socket_name, 0o600, dir_fd=self._runtime_fd)
        info = os.stat(
            self._socket_name, dir_fd=self._runtime_fd, follow_symlinks=False,
        )
        self._socket_identity = (info.st_dev, info.st_ino)

    def server_close(self) -> None:
        super().server_close()
        manager = getattr(self, 'write_manager', None)
        if manager is not None:
            with manager.broker._vault_lock:
                manager.public_base = None
                for op in manager.operations.values():
                    op.password = None
                    op.fill_refs.clear()
                    if op.state == 'pending':
                        op.state = 'cancelled'
        if self._runtime_fd is not None:
            unlink_socket_if_same(
                self._runtime_fd, self._socket_name,
                getattr(self, "_socket_identity", None),
            )
        if self._lifecycle_lock is not None:
            os.close(self._lifecycle_lock)
            self._lifecycle_lock = None
        if self._runtime_fd is not None:
            os.close(self._runtime_fd)
            self._runtime_fd = None


class UnlockState:
    def __init__(
        self,
        broker: Broker,
        database: Path,
        keyfile: Path | None,
        opener: Callable = open_vault_with_password,
    ) -> None:
        self.broker = broker
        self.database = database
        self.keyfile = keyfile
        self.opener = opener
        self.token = secrets.token_urlsafe(32)
        self.failures: list[float] = []
        self.identity_failures: dict[str, list[float]] = {}
        self.pending: dict[int, str] = {}
        self.next_attempt = 0
        self.lock = threading.Lock()
        self.unlock_lock = threading.Lock()

    def token_matches(self, token: str) -> bool:
        with self.lock:
            return secrets.compare_digest(token, self.token)

    def reserve_attempt(self, identity: str) -> int | None:
        """Atomically account for an attempt before expensive key derivation."""
        now = time.monotonic()
        with self.lock:
            self.failures = [stamp for stamp in self.failures if now - stamp < ATTEMPT_WINDOW]
            for key, stamps in list(self.identity_failures.items()):
                current = [stamp for stamp in stamps if now - stamp < ATTEMPT_WINDOW]
                if current:
                    self.identity_failures[key] = current
                else:
                    del self.identity_failures[key]

            pending_for_identity = sum(owner == identity for owner in self.pending.values())
            if len(self.failures) + len(self.pending) >= MAX_UNLOCK_ATTEMPTS:
                return None
            if len(self.identity_failures.get(identity, ())) + pending_for_identity >= MAX_UNLOCK_ATTEMPTS:
                return None

            self.next_attempt += 1
            self.pending[self.next_attempt] = identity
            return self.next_attempt

    def attempt_status(self, attempt: int, token: str) -> str:
        """Recheck mutable authorization state once this attempt reaches the opener."""
        with self.lock:
            if not self.broker.locked:
                self.pending.pop(attempt, None)
                return "unlocked"
            if not secrets.compare_digest(token, self.token):
                self.pending.pop(attempt, None)
                return "invalid"
            return "ready"

    def record_failure(self, attempt: int) -> None:
        with self.lock:
            identity = self.pending.pop(attempt, None)
            if identity is None:
                return
            now = time.monotonic()
            self.failures.append(now)
            self.identity_failures.setdefault(identity, []).append(now)

    def record_success(self, attempt: int) -> None:
        with self.lock:
            self.pending.pop(attempt, None)
            self.token = secrets.token_urlsafe(32)

    def cancel_attempt(self, attempt: int) -> None:
        """Release a reservation that did not reach an opener result."""
        with self.lock:
            self.pending.pop(attempt, None)


def _page(title: str, body: str) -> bytes:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta name="referrer" content="no-referrer"><title>{html.escape(title)}</title>
<style>body{{font:16px system-ui;max-width:28rem;margin:12vh auto;padding:1rem;background:#111;color:#eee}}
input,button{{box-sizing:border-box;width:100%;padding:.8rem;margin:.5rem 0;font:inherit}} .error{{color:#ff9b9b}}</style></head>
<body><h1>{html.escape(title)}</h1>{body}</body></html>""".encode("utf-8")


def handler_for(state: UnlockState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "agentic-kdbx"
        sys_version = ""

        def log_message(self, format, *args):
            return  # Never log URLs, identities, or form requests.

        def _identity_ok(self) -> bool:
            return bool(self.headers.get("Tailscale-User-Login"))

        def _token(self) -> str:
            return parse_qs(urlsplit(self.path).query).get("token", [""])[0]

        def _expired(self) -> bool:
            return self.server.request_expired(self.request)

        def _send(self, status: HTTPStatus, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _write_request(self) -> bool:
            if urlsplit(self.path).path != '/write':
                return False
            if not self._identity_ok():
                self._send(HTTPStatus.NOT_FOUND, _page('Not found', '<p>Invalid password request.</p>'))
                return True
            with state.broker._vault_lock:
                op = state.broker.writes.by_token(self._token())
                if op is None or op.password is not None:
                    self._send(HTTPStatus.NOT_FOUND, _page('Not found', '<p>Invalid or expired password request.</p>'))
                    return True
                if self.command == 'GET':
                    destination = ''.join(f'<dt>{html.escape(key)}</dt><dd>{html.escape(value)}</dd>' for key, value in op.values.items())
                    action = '/write?token=' + html.escape(op.token, quote=True)
                    body = f'<dl>{destination}</dl><p>Save only after the website has accepted this password. This changes KeePass only.</p><form method="post" action="{action}" autocomplete="off"><label>Chosen password</label><input name="password" type="password" required autocomplete="new-password"><label>Repeat password</label><input name="confirmation" type="password" required autocomplete="new-password"><label><input type="checkbox" name="confirmed" value="yes" required>I confirm this destination and password update</label><button>Save to KeePass</button></form>'
                    self._send(HTTPStatus.OK, _page('Confirm KeePass password', body))
                    return True
            # Read outside the vault lock so a stalled user cannot block fills.
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/x-www-form-urlencoded' or not 0 < length <= MAX_BODY:
                    raise ValueError
                raw = self.rfile.read(length)
                if len(raw) != length or self._expired():
                    return True
                values = parse_qs(raw.decode('utf-8'), strict_parsing=True)
                if any(len(v) != 1 for v in values.values()):
                    raise ValueError
            except Exception:
                self._send(HTTPStatus.BAD_REQUEST, _page('Invalid request', '<p>Request rejected.</p>'))
                return True
            with state.broker._vault_lock:
                # Cancellation/expiry may have happened during the private POST.
                op = state.broker.writes.by_token(self._token())
                if op is None or self._expired():
                    self._send(HTTPStatus.NOT_FOUND, _page('Not found', '<p>Invalid or expired password request.</p>'))
                    return True
                result = state.broker.writes.submit(op, values.get('password', [''])[0], values.get('confirmation', [''])[0], values.get('confirmed') == ['yes'])
            # No submitted fields, parser exceptions or secrets enter the page.
            body = '<p>Password saved to KeePass. You may close this page.</p>' if result['ok'] else '<p>' + html.escape(result['error']) + '</p>'
            self._send(HTTPStatus.OK if result['ok'] else HTTPStatus.CONFLICT, _page('KeePass save result', body))
            return True

        def do_GET(self) -> None:
            if self._write_request():
                return
            if not self._identity_ok() or not state.token_matches(self._token()):
                self._send(HTTPStatus.NOT_FOUND, _page("Not found", "<p>This unlock request is invalid.</p>"))
                return
            if not state.broker.locked:
                self._send(HTTPStatus.OK, _page("Vault unlocked", "<p>The KeePass broker is ready. You may close this page.</p>"))
                return
            action = "?token=" + html.escape(state.token, quote=True)
            login = html.escape(self.headers.get("Tailscale-User-Login", ""))
            body = f'<p>Unlocking for <strong>{login}</strong>.</p><form method="post" action="{action}" autocomplete="off"><label>Master password</label><input name="password" type="password" required autofocus autocomplete="current-password"><button type="submit">Unlock vault</button></form>'
            self._send(HTTPStatus.OK, _page("Unlock KeePass", body))

        def do_POST(self) -> None:
            if self._write_request():
                return
            identity = self.headers.get("Tailscale-User-Login", "")
            submitted_token = self._token()
            if not identity or not state.token_matches(submitted_token):
                self._send(HTTPStatus.NOT_FOUND, _page("Not found", "<p>This unlock request is invalid.</p>"))
                return
            if not state.broker.locked:
                self._send(HTTPStatus.OK, _page("Vault unlocked", "<p>The KeePass broker is ready. You may close this page.</p>"))
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                self._send(HTTPStatus.BAD_REQUEST, _page("Invalid request", "<p>The request was rejected.</p>"))
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                if not self._expired():
                    self._send(HTTPStatus.BAD_REQUEST, _page("Invalid request", "<p>The request was rejected.</p>"))
                return
            if self._expired():
                return
            attempt = state.reserve_attempt(identity)
            if attempt is None:
                self._send(HTTPStatus.TOO_MANY_REQUESTS, _page("Try later", "<p>Too many failed attempts. Wait one minute.</p>"))
                return

            try:
                if self._expired():
                    return
                with state.unlock_lock:
                    # Waiting behind another KDF may consume this request's
                    # entire network lifetime. Never begin new expensive work
                    # for a client whose absolute deadline has passed.
                    if self._expired():
                        return
                    status = state.attempt_status(attempt, submitted_token)
                    if status == "unlocked":
                        self._send(HTTPStatus.OK, _page("Vault unlocked", "<p>The KeePass broker is ready. You may close this page.</p>"))
                        return
                    if status == "invalid":
                        self._send(HTTPStatus.NOT_FOUND, _page("Not found", "<p>This unlock request is invalid.</p>"))
                        return
                    try:
                        values = parse_qs(raw.decode("utf-8"), strict_parsing=True)
                        password = values.get("password", [""])[0]
                        if not password:
                            raise ValueError
                        if self._expired():
                            return
                        vault = state.opener(state.database, password, state.keyfile)
                    except Exception:
                        password = ""
                        state.record_failure(attempt)
                        self._send(HTTPStatus.UNAUTHORIZED, _page("Unlock failed", '<p class="error">The database could not be unlocked.</p><p>Return to the agent-provided link and try again.</p>'))
                        return

                    password = ""
                    state.broker.unlock(vault)
                    state.record_success(attempt)  # invalidate the submitted URL
                    self._send(HTTPStatus.OK, _page("Vault unlocked", "<p>The KeePass broker is ready. You may close this page.</p>"))
            finally:
                state.cancel_attempt(attempt)

    return Handler


def start_unlock_server(
    broker: Broker,
    database: Path,
    keyfile: Path | None,
    socket_path: Path,
    public_base_url: str,
    opener: Callable = open_vault_with_password,
) -> tuple[ThreadingUnixHTTPServer, str]:
    socket_path = Path(socket_path).expanduser()
    if not socket_path.is_absolute():
        raise ValueError("unlock socket path must be absolute")
    state = UnlockState(broker, database, keyfile, opener)
    server = ThreadingUnixHTTPServer(str(socket_path), handler_for(state))
    url = public_base_url.rstrip("/") + "/?token=" + state.token
    broker.unlock_url = url
    broker.writes.public_base = public_base_url
    server.write_manager = broker.writes
    thread = threading.Thread(target=server.serve_forever, name="akdbx-web-unlock", daemon=True)
    thread.start()
    return server, url
