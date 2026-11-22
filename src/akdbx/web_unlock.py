from __future__ import annotations

import html
import os
import platform
import re
import secrets
import socket
import socketserver
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .broker import UNLOCK_LINK_MAX_FAILURES, Broker, is_wrong_credentials, open_vault_with_password
from .identities import FIELDS as IDENTITY_FIELDS, FIELD_LIMIT as IDENTITY_FIELD_LIMIT
from . import cards
from .portal import content_security_policy, field, render
from .writes import group_paths
from .runtime import (
    acquire_lifecycle_lock,
    prepare_private_runtime_directory,
    remove_stale_socket,
    unlink_socket_if_same,
)

MAX_BODY = 16 * 1024
# Failed master-password attempts allowed per unlock link, in total.
MAX_FAILED_ATTEMPTS = UNLOCK_LINK_MAX_FAILURES
MAX_HTTP_CONNECTIONS = 8
# A '%' must start a two-digit hex escape. parse_qs keeps any other '%' as
# text, so such a form would otherwise reach the password check.
_INVALID_ESCAPE = re.compile(rb'%(?![0-9A-Fa-f]{2})')


def parse_form(raw: bytes, **options) -> dict[str, list[str]]:
    """Strictly parse an urlencoded form; raise ValueError for any malformed byte or escape."""
    if _INVALID_ESCAPE.search(raw):
        raise ValueError('invalid percent escape')
    return parse_qs(raw.decode('utf-8'), strict_parsing=True, errors='strict', **options)
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

    # Windows CPython does not expose AF_UNIX. The loopback HTTPS subclass
    # supplies AF_INET and its own initializer; keep importing it safe.
    address_family = getattr(socket, 'AF_UNIX', None)
    daemon_threads = True
    request_queue_size = MAX_HTTP_CONNECTIONS

    def __init__(
        self, server_address, *args, **kwargs,
    ) -> None:
        if self.address_family is None:
            raise RuntimeError('Unix HTTP backend is unavailable on this platform')
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
                manager.broker.card_targets.prune()
                manager.broker.identity_targets.prune()
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
                manager.broker.card_targets.close()
                manager.broker.identity_targets.close()
                manager.public_base = None
                for op in manager.operations.values():
                    op.password = None
                    op.import_candidates = ()
                    op.import_nonce = None
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
    """One private unlock link and its total budget of failed attempts.

    A link allows ``MAX_FAILED_ATTEMPTS`` failed master-password attempts in
    total, not per minute. The failure that reaches the limit blocks the link
    at once: its token stops working and the broker alerts unlock-notification
    subscribers that asked for blocked events. Time never expires a link, and
    the block is saved next to the notification state, so a broker restart
    keeps it. Only ``new_link`` (the broker's ``new-unlock-link`` action,
    after the user confirms) makes a new token. Reservations count toward the
    budget, so parallel requests cannot run more than the limit through the
    vault opener. Only a wrong password or key file counts as a failure.
    """

    def __init__(
        self,
        broker: Broker,
        database: Path,
        keyfile: Path | None,
        opener: Callable = open_vault_with_password,
        public_base: str | None = None,
    ) -> None:
        self.broker = broker
        self.database = database
        self.keyfile = keyfile
        self.opener = opener
        self.public_base = public_base
        self.token = secrets.token_urlsafe(32)
        self.failures = 0
        self.blocked = False
        # False while the block holds only in memory (its save failed).
        self.block_saved = True
        self.pending: set[int] = set()
        self.next_attempt = 0
        self.lock = threading.Lock()
        self.unlock_lock = threading.Lock()
        # Restore a block from before a restart before the page serves.
        if self._saved_block():
            self.blocked = True
            self.failures = MAX_FAILED_ATTEMPTS

    def _saved_block(self) -> bool:
        try:
            return self.broker.unlock_notifications.load_unlock_blocked()
        except Exception:
            # An unreadable or untrusted saved block fails closed: the link
            # stays blocked until the user confirms a new one.
            return True

    def _save_block(self, blocked: bool) -> None:
        """Save the block flag; raise OSError when it cannot be saved."""
        try:
            self.broker.unlock_notifications.save_unlock_blocked(blocked)
        except Exception:
            raise OSError('unlock block state could not be saved') from None

    @property
    def url(self) -> str:
        assert self.public_base is not None
        return self.public_base.rstrip("/") + "/?token=" + self.token

    @property
    def origin(self) -> str | None:
        """The link's non-secret HTTPS origin, without its token."""
        if self.public_base is None:
            return None
        parts = urlsplit(self.public_base)
        return f"{parts.scheme}://{parts.netloc}"

    def _matches(self, token: object) -> bool:
        # Called under self.lock. Bytes avoid compare_digest's refusal of
        # non-ASCII text, so any submitted value is simply invalid.
        return isinstance(token, str) and secrets.compare_digest(
            token.encode("utf-8", "surrogatepass"), self.token.encode("ascii"))

    def token_matches(self, token: str) -> bool:
        with self.lock:
            return self._matches(token)

    def request_status(self, token: str) -> str:
        """Check one request's token, the block and the lock state together.

        The caller builds every response from the token it submitted, never
        from ``self.token``, so a request authorized by an old token cannot
        learn a replacement made after this check.
        """
        with self.lock:
            if not self._matches(token):
                return "invalid"
            if self.blocked:
                return "blocked"
            if not self.broker.locked:
                return "unlocked"
            return "ready"

    def remaining(self) -> int:
        with self.lock:
            return max(0, MAX_FAILED_ATTEMPTS - self.failures)

    def reserve_attempt(self, identity: str = "") -> int | None:
        """Atomically account for an attempt before expensive key derivation.

        The budget belongs to the link, not to an identity, so a stolen link
        cannot lock its owner out for a time window; it can only block itself.
        """
        with self.lock:
            if self.blocked or self.failures + len(self.pending) >= MAX_FAILED_ATTEMPTS:
                return None
            self.next_attempt += 1
            self.pending.add(self.next_attempt)
            return self.next_attempt

    def attempt_status(self, attempt: int, token: str) -> str:
        """Recheck mutable authorization state once this attempt reaches the opener."""
        with self.lock:
            if not self.broker.locked:
                self.pending.discard(attempt)
                return "unlocked"
            if self.blocked:
                self.pending.discard(attempt)
                return "blocked"
            if not self._matches(token):
                self.pending.discard(attempt)
                return "invalid"
            return "ready"

    def pairing_status(self, attempt: int, authorized: Callable[[], bool]) -> str:
        """Recheck a pairing attempt just before its password check.

        ``authorized`` reports whether the pairing token is still valid. A
        block revokes every pairing token, and the check runs under this
        link's lock, so a pairing token from before a block or a new link
        never gets a fresh budget.
        """
        with self.lock:
            if self.blocked:
                self.pending.discard(attempt)
                return "blocked"
            if attempt not in self.pending or not authorized():
                self.pending.discard(attempt)
                return "invalid"
            return "ready"

    def _revoke_pairings(self) -> None:
        # Called under self.lock. The hub lock never waits for this lock.
        extension = getattr(self.broker, "extension", None)
        if extension is not None:
            extension.revoke_pairings()

    def record_failure(self, attempt: int) -> bool:
        """Count one wrong password or key. Return True when it blocked the link."""
        with self.lock:
            if attempt not in self.pending:
                return False
            self.pending.discard(attempt)
            self.failures += 1
            if self.blocked or self.failures < MAX_FAILED_ATTEMPTS:
                return False
            # Block and alert under the broker's state lock, which also guards
            # subscribe-unlock: a subscriber either gets the blocked event or
            # sees unlock_blocked in its receipt, never neither.
            with self.broker._state_lock:
                self.blocked = True
                try:
                    self._save_block(True)
                except OSError:
                    # The block holds in memory; a restart would lose it.
                    self.block_saved = False
                    print("akdbx: the unlock link is blocked, but the block could not be saved; "
                          "a broker restart would undo it. Check the broker's state folder.",
                          file=sys.stderr, flush=True)
                self._revoke_pairings()
                self.broker.unlock_notifications.publish_blocked()
            return True

    def record_success(self, attempt: int) -> None:
        with self.lock:
            self.pending.discard(attempt)
            self.token = secrets.token_urlsafe(32)
            self.failures = 0
            try:
                self._save_block(False)
            except OSError:
                pass  # Only a confirmed new link clears a saved block.

    def cancel_attempt(self, attempt: int) -> None:
        """Release a reservation that did not reach a credential result."""
        with self.lock:
            self.pending.discard(attempt)

    def new_link(self) -> str | None:
        """Replace a blocked link with a fresh token and budget.

        Return the new private URL, or None when the current link is not
        blocked. Raise OSError, and keep the link blocked, when the cleared
        block cannot be saved: a restart must never undo a block silently.
        The broker cannot verify the user; the agent must have the user's
        confirmation before it asks for this.
        """
        with self.lock:
            if not self.blocked or self.public_base is None or self.pending:
                return None
            self._save_block(False)
            # Pairing links issued before now must not get the new budget.
            self._revoke_pairings()
            self.token = secrets.token_urlsafe(32)
            self.failures = 0
            self.block_saved = True
            with self.broker._state_lock:
                self.blocked = False
                self.broker.unlock_url = self.url
                return self.broker.unlock_url


BLOCKED_TITLE = "Unlock link blocked"
BLOCKED_BODY = (
    "<p>This unlock link is blocked after three failed master-password attempts. "
    "It cannot unlock AKDBX any more.</p>"
    "<p>Ask your agent for a new unlock link. If you did not make these attempts, "
    "tell your agent: someone else has this link.</p>"
)


OPEN_FAILED = ("AKDBX could not open the vault. This attempt did not count toward the link's limit. "
               "Check that the database file is available, then try again.")


def _page(title: str, body: str) -> bytes:
    return render(title, body)


CARD_FORM = {'name', 'number', 'month', 'year', 'csc', 'confirmed'}
CARD_GONE = dict(
    saved='This card was already saved. You may close this page.',
    cancelled='This card page was cancelled. Ask for a new card page.',
    stale=cards.STALE, failed=cards.FAILED, expired=cards.EXPIRED)


def _group_label(path: str) -> str:
    return path or 'Top level (no folder)'


# The same for password, authenticator and identity pages; {kind} is lower case.
GONE = dict(
    saved='This {kind} was already saved to vault. You may close this page.',
    cancelled='This page was cancelled. Ask for a new save page.',
    stale='The vault changed after this page opened, so nothing was saved. Ask for a new save page.',
    failed='The save could not be confirmed. Ask for the save status before you try again.',
    expired='This page has expired or is no longer valid. Ask for a new save page.')
TOO_LONG = 'The entered details are too long. Shorten them and try again.'


def _gone(kind: str, page_state: tuple) -> dict:
    """Result for a save page token that no longer opens a form."""
    reason, error = page_state
    if kind == 'card':
        message = CARD_GONE[reason]
    else:
        message = error if reason == 'failed' and error else GONE[reason].format(kind=SUBJECTS[kind].lower())
    return dict(ok=False, gone=True, reason=reason, error=message)


SUBJECTS = {'card': 'Card', 'identity': 'Identity', 'totp': 'Authenticator', 'password': 'Password'}


def _vault_text(message: str) -> str:
    """Save results name the vault, not the app."""
    return message.replace('AKDBX', 'vault')


def _save_result(kind: str, result: dict) -> tuple[str, str]:
    """The save result page title and body.

    ``data-save-result`` tells the page script the final state: saved,
    rejected (form still open), expired, stale, cancelled or failed.
    """
    reason = result['reason']
    # An earlier save that this page made is a success too.
    title = 'Success' if reason == 'saved' else 'Failure'
    if result['ok']:
        lines = [f'{SUBJECTS[kind]} saved to vault. You may close this page.']
        if kind == 'card':
            lines.append(f'Saved as \u201c{result["title"]}\u201d in {_group_label(result["group"])}.')
    else:
        lines = [_vault_text(result['error'])]
    role = 'status' if reason == 'saved' else 'alert'
    paragraphs = ''.join(f'<p>{html.escape(line)}</p>' for line in lines)
    return title, (f'<div id="save-result" data-save-result="{html.escape(reason, quote=True)}" '
                   f'role="{role}">{paragraphs}</div>')


def _result_page(kind: str, result: dict) -> bytes:
    return _page(*_save_result(kind, result))


def _save_reason(op, result: dict) -> dict:
    """Add the page state to a password, authenticator or identity result."""
    if result['ok']:
        return dict(result, reason='saved')
    # A correctable form error leaves the write pending.
    return dict(result, reason='rejected' if op.state == 'pending' else 'failed')


def _submit(label: str, busy: str) -> str:
    """The shared save button: busy bar while saving, then a final state."""
    return (f'<button type="submit" class="portal-submit" data-idle-label="{html.escape(label, quote=True)}" '
            f'data-busy-label="{html.escape(busy, quote=True)}"><span class="button-label">{html.escape(label)}</span>'
            f'<span class="portal-progress" role="progressbar" aria-label="{html.escape(busy.rstrip(chr(0x2026)), quote=True)}" hidden></span></button>')


def _save_form(action: str, inner: str, label: str, busy: str, *, card: bool = False) -> str:
    form = 'data-card-form ' if card else ''
    return (f'<form {form}data-save-form method="post" action="{action}" autocomplete="off">{inner}'
            f'{_submit(label, busy)}</form>'
            '<p id="save-status" class="portal-status" role="status" aria-live="polite"></p>')


def _card_form(op, action: str, groups: list) -> str:
    """Card save or update form. Title and group are non-secret and editable;
    an updated card keeps its group. Card values are never prefilled."""
    update = op.uuid is not None
    title = field('Title', 'title', kind='text', maxlength=4096, value=op.values['title'],
                  describedby='title-hint',
                  note='<p class="field-hint" id="title-hint">The name you and the agent see when choosing this card.</p>')
    current = op.values['group']
    options = [current] if update else groups
    choices = ''.join(f'<option value="{html.escape(path, quote=True)}"{" selected" if path == current else ""}>'
                      f'{html.escape(_group_label(path))}</option>' for path in options)
    hint = 'The vault folder this card is saved in.' + (' An updated card stays in its folder.' if update else '')
    # Not `required`: the top level has value "" and is the first option, which
    # HTML treats as a placeholder and would block the save. The broker checks it.
    control = 'disabled' if update else 'name="group"'
    group = (f'<div class="field"><label for="group">Group</label>'
             f'<select id="group" {control} aria-describedby="group-hint">{choices}</select>'
             f'<p class="field-hint" id="group-hint">{hint}</p></div>')
    fields = []
    for key, label, typ, limit, required, mode in (
            ('name', 'Cardholder name', 'text', 128, True, None),
            ('number', 'Card number', 'password', 32, True, 'numeric'),
            ('month', 'Expiry month (MM)', 'text', 2, True, 'numeric'),
            ('year', 'Expiry year (YYYY)', 'text', 4, True, 'numeric'),
            ('csc', 'Security code (optional)', 'password', 4, False, 'numeric')):
        note = f'<p class="field-error" id="{key}-error" hidden></p>'
        described = key + '-error'
        if key == 'number':
            # Only the detected brand is shown, never the number.
            note = '<p class="field-hint" id="card-brand" aria-live="polite"></p>' + note
            described += ' card-brand'
        fields.append(field(label, key, kind=typ, maxlength=limit, required=required, inputmode=mode,
                            describedby=described, note=note))
    label = 'Update card in AKDBX' if update else 'Save card to AKDBX'
    intro = ('<p>You are updating a saved card. Enter its current details.</p>' if update else
             '<p>Check the title and group, then enter the card details.</p>')
    inner = (f'{title}{group}{"".join(fields)}'
             '<label><input type="checkbox" name="confirmed" value="yes" required>I confirm this card and destination</label>')
    return intro + _save_form(action, inner, label, 'Saving card\u2026', card=True)


def computer_name(windows: bool | None = None) -> str:
    """The short name of this computer, for the page text only (never for a check).

    Windows: COMPUTERNAME, else ``platform.node()``. Linux: the host name before
    the first dot. The caller escapes it.
    """
    windows = os.name == 'nt' if windows is None else windows
    try:
        if windows:
            name = os.environ.get('COMPUTERNAME', '') or platform.node()
        else:
            name = socket.gethostname()
    except Exception:
        name = ''
    name = (name or '').strip().split('.', 1)[0][:63]
    return name or 'this computer'


def handler_for(state: UnlockState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "akdbx"
        sys_version = ""

        def log_message(self, format, *args):
            return  # Never log URLs, identities, or form requests.

        def _identity_ok(self) -> bool:
            return bool(self._identity())

        def _identity(self) -> str:
            # The loopback HTTPS listener (Linux and Windows) terminates TLS
            # itself; never accept a caller-supplied proxy identity there.
            # Its configured origin is loopback or, for unlock from another
            # device, the Tailscale Serve name that proxies to the listener.
            # Only the Linux Unix-socket backend, which Tailscale Serve alone
            # can reach, uses Tailscale's identity header.
            origin = getattr(self.server, 'local_origin', None)
            if origin is not None:
                expected = urlsplit(origin)
                if (self.headers.get_all('Host', []) != [expected.netloc]
                        or self.headers.get_all('Origin', []) not in ([], [origin])):
                    return ''
                return 'local user'
            return self.headers.get('Tailscale-User-Login', '')

        def _unlock_line(self) -> str:
            # Text only: _identity() still decides who may unlock. The loopback
            # HTTPS listener has no login to show; the legacy Tailscale socket
            # route shows the Tailscale login too.
            computer = html.escape(computer_name())
            if getattr(self.server, 'local_origin', None) is not None:
                return f'Unlock AKDBX on <strong>{computer}</strong>.'
            login = html.escape(self._identity())
            return f'Unlock AKDBX on <strong>{computer}</strong> as <strong>{login}</strong>.'

        def _token(self) -> str:
            return parse_qs(urlsplit(self.path).query).get("token", [""])[0]

        def _expired(self) -> bool:
            return self.server.request_expired(self.request)

        def _send(self, status: HTTPStatus, body: bytes, *, content_type='text/html; charset=utf-8', import_page=False) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", content_security_policy(import_page=import_page))
            self.send_header("X-Content-Type-Options", "nosniff")
            # same-origin, not no-referrer: under no-referrer, Chromium sends
            # Origin: null on a form POST, which the Origin checks refuse.
            # Cross-origin requests still get no referrer, so the token stays here.
            self.send_header("Referrer-Policy", "same-origin")
            self.end_headers()
            self.wfile.write(body)

        def _write_request(self) -> bool:
            from .import_web import handle_import
            from .extension_web import handle_pairing
            if handle_import(self, state) or handle_pairing(self, state):
                return True
            route = urlsplit(self.path).path
            kind = {'/write': 'password', '/totp': 'totp', '/card': 'card', '/identity': 'identity'}.get(route)
            if kind is None:
                return False
            if not self._identity_ok():
                self._send(HTTPStatus.NOT_FOUND, _page('Not found', '<p>Invalid password request.</p>'))
                return True
            with state.broker._vault_lock:
                op = state.broker.writes.by_token(self._token(), kind)
                if op is None and (kind == 'card' or self.command != 'GET'):
                    # Why the page no longer saves; a page script shows it on its button.
                    gone = _gone(kind, state.broker.writes.page_state(self._token(), kind))
                    self._send(HTTPStatus.NOT_FOUND, _result_page(kind, gone))
                    return True
                if op is None or op.password is not None:
                    self._send(HTTPStatus.NOT_FOUND, _page('Not found', '<p>Invalid or expired password request.</p>')
                               if self.command == 'GET' else
                               _result_page(kind, _gone(kind, ('expired', None))))
                    return True
                if self.command == 'GET':
                    destination = ''.join(f'<dt>{html.escape(key)}</dt><dd>{html.escape(value)}</dd>' for key, value in op.values.items())
                    action = route + '?token=' + html.escape(op.token, quote=True)
                    if kind == 'card':
                        body = _card_form(op, action, group_paths(state.broker.vault))
                    elif kind == 'identity':
                        # Only the fields the agent asked for; inputs are never prefilled.
                        fields = ''.join(field(IDENTITY_FIELDS[key], key, kind='text', maxlength=IDENTITY_FIELD_LIMIT,
                                               required=len(op.fields) == 1) for key in op.fields)
                        hint = 'Enter the detail you want to save.' if len(op.fields) == 1 else 'Enter only the details you want to save.'
                        inner = f'{fields}<label><input type="checkbox" name="confirmed" value="yes" required>I confirm this identity and destination</label>'
                        body = f'<dl>{destination}</dl><p>{hint}</p>' + _save_form(action, inner, 'Save identity to AKDBX', 'Saving identity\u2026')
                    elif kind == 'totp':
                        replacement = '<p>This replaces the saved authenticator key.</p>' if op.replace else ''
                        setup = field('Setup key or otpauth TOTP URI', 'setup', maxlength=4096)
                        body = f'<dl>{destination}</dl><p>Import the setup key or otpauth URI for this account. This saves an authenticator in AKDBX; it does not change the website. Keep a separate recovery method.</p>{replacement}' + _save_form(
                            action, f'{setup}<label><input type="checkbox" name="confirmed" value="yes" required>I confirm this account and authenticator key</label>',
                            'Save authenticator', 'Saving authenticator\u2026')
                        body += '<p><a href="/totp/import?token=' + html.escape(op.token, quote=True) + '">Import QR images / Google export, or review a browser capture</a></p>'
                    else:
                        password_fields = field('Chosen password', 'password', autocomplete='new-password') + field('Repeat password', 'confirmation', autocomplete='new-password')
                        body = f'<dl>{destination}</dl><p>Save only after the website has accepted this password. This changes AKDBX only.</p>' + _save_form(
                            action, f'{password_fields}<label><input type="checkbox" name="confirmed" value="yes" required>I confirm this destination and password update</label>',
                            'Save to AKDBX', 'Saving password\u2026')
                    title = {'card': 'Update AKDBX card' if op.uuid else 'Save AKDBX card', 'identity': 'Save AKDBX identity',
                             'totp': 'Confirm AKDBX authenticator', 'password': 'Confirm AKDBX password'}[kind]
                    self._send(HTTPStatus.OK, _page(title, body))
                    return True
            # Read outside the vault lock so a stalled user cannot block fills.
            too_long = False
            try:
                length = int(self.headers.get('Content-Length', '0'))
                # Each Unicode code point can use four percent-encoded UTF-8 bytes.
                # A card title and group can each be 4096 UTF-8 bytes.
                limit = 48 * 1024 if kind in {'identity', 'card'} else MAX_BODY
                too_long = length > limit
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/x-www-form-urlencoded' or not 0 < length <= limit:
                    raise ValueError
                raw = self.rfile.read(length)
                if len(raw) != length or self._expired():
                    return True
                values = parse_qs(raw.decode('utf-8'), strict_parsing=True, keep_blank_values=True, errors='strict')
                if any(len(v) != 1 for v in values.values()):
                    raise ValueError
                if kind == 'totp' and set(values) - {'setup', 'confirmed'}:
                    raise ValueError
                if kind == 'card' and not CARD_FORM <= set(values) <= CARD_FORM | {'title', 'group'}:
                    raise ValueError
                # The page shows only the fields this save asked for.
                if kind == 'identity' and set(values) != set(op.fields) | {'confirmed'}:
                    raise ValueError
            except Exception:
                # Too much text can be corrected on the open page; nothing was saved.
                self._send(HTTPStatus.BAD_REQUEST, _result_page(kind, dict(ok=False, reason='rejected', error=TOO_LONG))
                           if too_long else _page('Invalid request', '<p>Request rejected.</p>'))
                return True
            with state.broker._vault_lock:
                # Cancellation/expiry may have happened during the private POST.
                op = state.broker.writes.by_token(self._token(), kind)
                if op is None and not self._expired():
                    result = _gone(kind, state.broker.writes.page_state(self._token(), kind))
                elif op is None or self._expired():
                    self._send(HTTPStatus.NOT_FOUND, _result_page(kind, _gone(kind, ('expired', None))))
                    return True
                elif kind == 'card':
                    # The page may change the prepared title and group.
                    chosen = {key: values[key][0] for key in ('title', 'group') if key in values}
                    result = state.broker.cards.submit(op, {k: values[k][0] for k in ('name', 'number', 'month', 'year', 'csc')},
                                                       values.get('confirmed') == ['yes'], chosen)
                elif kind == 'identity':
                    result = state.broker.identities.submit(op, {key: values[key][0] for key in op.fields},
                                                            values['confirmed'] == ['yes'])
                elif kind == 'totp':
                    result = state.broker.writes.submit_totp(op, values.get('setup', [''])[0], values.get('confirmed') == ['yes'])
                else:
                    result = state.broker.writes.submit(op, values.get('password', [''])[0], values.get('confirmation', [''])[0], values.get('confirmed') == ['yes'])
            # No submitted fields, parser exceptions or secrets enter the page.
            if kind != 'card' and not result.get('gone'):
                result = _save_reason(op, result)
            status = (HTTPStatus.OK if result['ok'] else HTTPStatus.NOT_FOUND
                      if result.get('gone') or result['reason'] == 'expired' else HTTPStatus.CONFLICT)
            self._send(status, _result_page(kind, result))
            return True

        def do_GET(self) -> None:
            if self._write_request():
                return
            token = self._token()
            if not self._identity_ok():
                self._send_invalid()
                return
            if self._send_status(state.request_status(token)):
                return
            self._send(HTTPStatus.OK, self._unlock_page(token))

        def _send_invalid(self) -> None:
            self._send(HTTPStatus.NOT_FOUND, _page("Not found", "<p>This unlock request is invalid.</p>"))

        def _send_blocked(self) -> None:
            self._send(HTTPStatus.FORBIDDEN, _page(BLOCKED_TITLE, BLOCKED_BODY))

        def _send_status(self, status: str) -> bool:
            """Answer a request that cannot try a password; False when it can."""
            if status == "invalid":
                self._send_invalid()
            elif status == "blocked":
                self._send_blocked()
            elif status == "unlocked":
                self._send(HTTPStatus.OK, _page("Vault unlocked", "<p>The AKDBX broker is ready. You may close this page.</p>"))
            else:
                return False
            return True

        def _unlock_page(self, token: str, error: str = "") -> bytes:
            # Always the token that authorized this request, never state.token:
            # a caller with an old link must not see its replacement.
            action = "?token=" + html.escape(token, quote=True)
            password_field = field('Master password', 'password', autocomplete='current-password', autofocus=True)
            message = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ''
            body = (f'{message}<p>{self._unlock_line()}</p>'
                    f'<form data-unlock-form method="post" action="{action}" autocomplete="off">{password_field}'
                    '<button type="submit" class="portal-submit unlock-submit"'
                    ' data-idle-label="Unlock AKDBX" data-busy-label="Unlocking AKDBX\u2026">'
                    '<span class="button-label">Unlock AKDBX</span>'
                    '<span class="portal-progress unlock-progress" role="progressbar" aria-label="Unlocking AKDBX" hidden></span></button>'
                    '</form><p id="unlock-status" class="portal-status unlock-status" role="status" aria-live="polite"></p>')
            return _page("Unlock AKDBX", body)

        def _bad_request(self) -> None:
            self._send(HTTPStatus.BAD_REQUEST, _page("Invalid request", "<p>The request was rejected.</p>"))

        def do_POST(self) -> None:
            if self._write_request():
                return
            identity = self._identity()
            submitted_token = self._token()
            if not identity:
                self._send_invalid()
                return
            if self._send_status(state.request_status(submitted_token)):
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                self._bad_request()
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                if not self._expired():
                    self._bad_request()
                return
            if self._expired():
                return
            # Parse before reserving: a malformed or empty form is not an attempt.
            try:
                values = parse_form(raw)
                passwords = values.get("password", [])
                if len(passwords) != 1 or not passwords[0]:
                    raise ValueError
                password = passwords[0]
            except ValueError:
                self._bad_request()
                return
            finally:
                raw = b""
            attempt = state.reserve_attempt(identity)
            if attempt is None:
                password = ""
                if state.blocked:
                    self._send_blocked()
                else:
                    # Every remaining attempt of this link is already running.
                    self._send(HTTPStatus.TOO_MANY_REQUESTS, self._unlock_page(
                        submitted_token, "Another unlock attempt is in progress. Wait for its result."))
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
                    if self._send_status(state.attempt_status(attempt, submitted_token)):
                        return
                    try:
                        vault = state.opener(state.database, password, state.keyfile)
                    except Exception as exc:
                        password = ""
                        if not is_wrong_credentials(exc):
                            # A store or I/O error says nothing about the
                            # password: it never counts toward the block.
                            state.cancel_attempt(attempt)
                            self._send(HTTPStatus.SERVICE_UNAVAILABLE, self._unlock_page(
                                submitted_token, OPEN_FAILED))
                            return
                        if state.record_failure(attempt) or state.blocked:
                            self._send_blocked()
                            return
                        left = state.remaining()
                        self._send(HTTPStatus.UNAUTHORIZED, self._unlock_page(
                            submitted_token,
                            "AKDBX could not unlock the database. Check your master password and try again. "
                            + (f"{left} attempts left for this link." if left != 1 else
                               "1 attempt left for this link; another failure blocks it.")))
                        return
                    finally:
                        password = ""

                    state.broker.unlock(vault)
                    state.record_success(attempt)  # invalidate the submitted URL
                    self._send(HTTPStatus.OK, _page("Vault unlocked", "<p>The AKDBX broker is ready. You may close this page.</p>"))
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
    state = UnlockState(broker, database, keyfile, opener, public_base=public_base_url)
    server = ThreadingUnixHTTPServer(str(socket_path), handler_for(state))
    url = state.url
    broker.unlock_url = url
    broker.unlock_link = state
    broker.writes.public_base = public_base_url
    broker.merges.database = database
    server.write_manager = broker.writes
    thread = threading.Thread(target=server.serve_forever, name="akdbx-web-unlock", daemon=True)
    thread.start()
    return server, url
