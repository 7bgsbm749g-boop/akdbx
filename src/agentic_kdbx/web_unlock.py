from __future__ import annotations

import html
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .broker import Broker, open_vault_with_password

MAX_BODY = 16 * 1024


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
        self.lock = threading.Lock()

    def allowed_attempt(self) -> bool:
        now = time.monotonic()
        with self.lock:
            self.failures = [stamp for stamp in self.failures if now - stamp < 60]
            return len(self.failures) < 5

    def record_failure(self) -> None:
        with self.lock:
            self.failures.append(time.monotonic())


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

        def do_GET(self) -> None:
            if not self._identity_ok() or not secrets.compare_digest(self._token(), state.token):
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
            if not self._identity_ok() or not secrets.compare_digest(self._token(), state.token):
                self._send(HTTPStatus.NOT_FOUND, _page("Not found", "<p>This unlock request is invalid.</p>"))
                return
            if not state.broker.locked:
                self._send(HTTPStatus.OK, _page("Vault unlocked", "<p>The KeePass broker is ready. You may close this page.</p>"))
                return
            if not state.allowed_attempt():
                self._send(HTTPStatus.TOO_MANY_REQUESTS, _page("Try later", "<p>Too many failed attempts. Wait one minute.</p>"))
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                self._send(HTTPStatus.BAD_REQUEST, _page("Invalid request", "<p>The request was rejected.</p>"))
                return
            raw = self.rfile.read(length)
            try:
                values = parse_qs(raw.decode("utf-8"), strict_parsing=True)
                password = values.get("password", [""])[0]
                if not password:
                    raise ValueError
                vault = state.opener(state.database, password, state.keyfile)
                password = ""
                state.broker.unlock(vault)
                state.token = secrets.token_urlsafe(32)  # invalidate the submitted URL
                self._send(HTTPStatus.OK, _page("Vault unlocked", "<p>The KeePass broker is ready. You may close this page.</p>"))
            except Exception:
                password = ""
                state.record_failure()
                self._send(HTTPStatus.UNAUTHORIZED, _page("Unlock failed", '<p class="error">The database could not be unlocked.</p><p>Return to the agent-provided link and try again.</p>'))

    return Handler


def start_unlock_server(
    broker: Broker,
    database: Path,
    keyfile: Path | None,
    host: str,
    port: int,
    public_base_url: str,
    opener: Callable = open_vault_with_password,
) -> tuple[ThreadingHTTPServer, str]:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("web unlock must listen on localhost")
    state = UnlockState(broker, database, keyfile, opener)
    server = ThreadingHTTPServer((host, port), handler_for(state))
    url = public_base_url.rstrip("/") + "/?token=" + state.token
    broker.unlock_url = url
    thread = threading.Thread(target=server.serve_forever, name="akdbx-web-unlock", daemon=True)
    thread.start()
    return server, url
