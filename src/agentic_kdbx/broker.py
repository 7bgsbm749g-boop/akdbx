from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import select
import socket
import stat
import time
import threading
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Callable, Protocol

from .protocol import ProtocolError, receive_message, send_message
from .runtime import (
    acquire_lifecycle_lock,
    anchored_socket_path,
    prepare_private_runtime_directory,
    remove_stale_socket,
    unlink_socket_if_same,
)


CONNECTION_TIMEOUT = 1.0
MAX_RPC_WORKERS = 16
FILL_START_TIMEOUT = 4.0
MAX_CREDENTIAL_CHARACTERS = 64 * 1024
MAX_CREDENTIAL_BYTES = 64 * 1024
MAX_METADATA_BYTES = 4 * 1024
MAX_SEARCH_RESPONSE = 48 * 1024
MAX_OUTSTANDING_HANDLES = 1024
CONNECTION_ERROR = {"ok": False, "error": "request failed"}


class EntryLike(Protocol):
    uuid: object
    title: str | None
    username: str | None
    password: str | None
    url: str | None
    path: list[str]


class VaultLike(Protocol):
    entries: list[EntryLike]


class Typer(Protocol):
    def type_text(self, text: str) -> None: ...
    def press_tab(self) -> None: ...


class PynputTyper:
    def __init__(self) -> None:
        try:
            from pynput.keyboard import Controller, Key
        except Exception as exc:  # display backends may fail during import
            raise RuntimeError("keyboard backend unavailable; run inside a desktop session") from exc
        self._keyboard = Controller()
        self._tab = Key.tab

    def type_text(self, text: str) -> None:
        self._keyboard.type(text)

    def press_tab(self) -> None:
        self._keyboard.press(self._tab)
        self._keyboard.release(self._tab)


@dataclass
class Handle:
    entry: EntryLike
    expires_at: float


class Broker:
    """Transforms vault entries into secret-free responses and performs local fills."""

    def __init__(
        self,
        vault: VaultLike | None,
        typer: Typer,
        *,
        handle_ttl: float = 300,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.vault = vault
        self.typer = typer
        self.handle_ttl = handle_ttl
        self.clock = clock
        self._key = secrets.token_bytes(32)
        self._handles: dict[str, Handle] = {}
        self._state_lock = threading.Lock()
        self._keyboard_lock = threading.Lock()
        self.unlock_url: str | None = None

    @property
    def locked(self) -> bool:
        with self._state_lock:
            return self.vault is None

    def unlock(self, vault: VaultLike) -> bool:
        with self._state_lock:
            if self.vault is not None:
                return False
            self.vault = vault
            return True

    def _new_handle(self, entry: EntryLike) -> str:
        nonce = secrets.token_bytes(16)
        tag = hmac.new(self._key, nonce + str(entry.uuid).encode(), hashlib.sha256).digest()[:16]
        handle = (nonce + tag).hex()
        now = self.clock()
        with self._state_lock:
            self._prune_expired_handles(now)
            # dicts retain insertion order, so this evicts the oldest issued
            # live authorization rather than allowing retained state to grow.
            while len(self._handles) >= MAX_OUTSTANDING_HANDLES:
                self._handles.pop(next(iter(self._handles)))
            self._handles[handle] = Handle(entry, now + self.handle_ttl)
        return handle

    def _prune_expired_handles(self, now: float) -> None:
        """Remove expired handles while the caller holds ``_state_lock``."""
        for handle, item in list(self._handles.items()):
            if item.expires_at <= now:
                self._handles.pop(handle, None)

    def _resolve(self, handle: object) -> EntryLike:
        if not isinstance(handle, str):
            raise ValueError("invalid handle")
        now = self.clock()
        with self._state_lock:
            self._prune_expired_handles(now)
            item = self._handles.pop(handle, None)  # one use, successful or not
        if item is None:
            raise ValueError("unknown or expired handle; search again")
        return item.entry

    @staticmethod
    def _validate_credential_text(*values: str) -> None:
        """Bound preflight and reject text a keyboard backend may interpret as controls."""
        for value in values:
            if not isinstance(value, str):
                raise ValueError("invalid credential text")
            # Bound both the Unicode scan and the eventual keyboard operation.
            # The byte cap also catches compact character counts with unusually
            # large UTF-8 representations.
            if (
                len(value) > MAX_CREDENTIAL_CHARACTERS
                or len(value.encode("utf-8")) > MAX_CREDENTIAL_BYTES
            ):
                raise ValueError("credential text exceeds delivery budget")
            if any(unicodedata.category(character) == "Cc" for character in value):
                raise ValueError("unsafe credential text")

    def dispatch(
        self,
        request: dict,
        *,
        delivery_ready: Callable[[], bool] | None = None,
    ) -> dict:
        internal_dispatch = delivery_ready is None
        if delivery_ready is None:
            delivery_ready = lambda: True
        action = request.get("action")
        if action == "ping":
            return {"ok": True, "locked": self.locked, **({"unlock_url": self.unlock_url} if self.locked and self.unlock_url else {})}
        if self.locked:
            return {"ok": False, "error": "vault locked", **({"unlock_url": self.unlock_url} if self.unlock_url else {})}
        if action == "search":
            query = request.get("query", "")
            if not isinstance(query, str) or len(query) > 500:
                return {"ok": False, "error": "invalid query"}
            needle = query.casefold()
            matches = []
            try:
                with self._state_lock:
                    vault = self.vault
                assert vault is not None
                for entry in vault.entries:
                    try:
                        title = entry.title or ""
                        username = entry.username or ""
                        url = entry.url or ""
                        path = entry.path
                        if (
                            not all(isinstance(value, str) for value in (title, username, url))
                            or not isinstance(path, (list, tuple))
                            or not all(isinstance(value, str) for value in path)
                        ):
                            continue
                        group = "/".join(path[:-1]) if path else ""
                        metadata = (title, username, url, group)
                        is_match = not needle or any(needle in value.casefold() for value in metadata)
                    except Exception:
                        # A malformed/inaccessible entry must not disable
                        # searches for other entries.
                        continue
                    if not is_match:
                        continue
                    if any(len(value.encode("utf-8")) > MAX_METADATA_BYTES for value in metadata):
                        raise ValueError("metadata exceeds response budget")
                    candidate = {
                        "handle": "0" * 64,
                        "title": title,
                        "username": username,
                        "url": url,
                        "group": group,
                    }
                    projected = {
                        "ok": True,
                        "entries": [*(item for item, _entry in matches), candidate],
                    }
                    encoded_size = len(json.dumps(projected, separators=(",", ":")).encode("utf-8"))
                    if encoded_size > MAX_SEARCH_RESPONSE:
                        raise ValueError("search response exceeds budget")
                    matches.append((candidate, entry))
                    if len(matches) == 20:
                        break
            except Exception:
                return {"ok": False, "error": "search failed"}
            entries = []
            for candidate, entry in matches:
                candidate["handle"] = self._new_handle(entry)
                entries.append(candidate)
            return {"ok": True, "entries": entries}
        if action == "fill":
            try:
                entry = self._resolve(request.get("handle"))
                mode = request.get("mode", "login")
                if mode not in ("login", "username", "password"):
                    raise ValueError("mode must be login, username, or password")
                start_deadline = request.get("start_deadline")
                if start_deadline is None and internal_dispatch:
                    start_deadline = self.clock() + FILL_START_TIMEOUT
                if (
                    isinstance(start_deadline, bool)
                    or not isinstance(start_deadline, (int, float))
                    or not math.isfinite(start_deadline)
                ):
                    raise ValueError("autofill not started: invalid deadline")
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
            # Once credentials are accessed, backend errors must never reach RPC
            # responses: exception messages can contain the text being typed.
            try:
                remaining = min(start_deadline - self.clock(), FILL_START_TIMEOUT)
                if remaining <= 0 or not self._keyboard_lock.acquire(timeout=remaining):
                    return {"ok": False, "error": "autofill not started: request expired"}
                try:
                    # This lock is the fill queue boundary. Avoid credential
                    # access for requests already known to be abandoned.
                    if self.clock() >= start_deadline:
                        return {"ok": False, "error": "autofill not started: request expired"}
                    if not delivery_ready():
                        return {"ok": False, "error": "autofill not started: caller disconnected"}

                    # Materialize and validate every value needed by this mode
                    # before emitting any event. Entry access and validation
                    # may take time, so neither is itself the delivery boundary.
                    if mode == "login":
                        username, password = entry.username or "", entry.password or ""
                        self._validate_credential_text(username, password)
                    elif mode == "username":
                        username = entry.username or ""
                        self._validate_credential_text(username)
                    else:
                        password = entry.password or ""
                        self._validate_credential_text(password)

                    # This is the delivery boundary: re-authorize immediately
                    # before the first keyboard call, after all preflight work.
                    if self.clock() >= start_deadline:
                        return {"ok": False, "error": "autofill not started: request expired"}
                    if not delivery_ready():
                        return {"ok": False, "error": "autofill not started: caller disconnected"}

                    if mode == "login":
                        self.typer.type_text(username)
                        self.typer.press_tab()
                        self.typer.type_text(password)
                    elif mode == "username":
                        self.typer.type_text(username)
                    else:
                        self.typer.type_text(password)
                    return {"ok": True, "filled": mode}
                finally:
                    self._keyboard_lock.release()
            except Exception:
                return {"ok": False, "error": "autofill failed"}
        return {"ok": False, "error": "unknown action"}


def open_vault_with_password(database: Path, password: str, keyfile: Path | None = None):
    from pykeepass import PyKeePass
    return PyKeePass(str(database), password=password, keyfile=str(keyfile) if keyfile else None)


def _serve_connection(connection: socket.socket, broker: Broker) -> None:
    """Handle one bounded RPC without allowing its failure to stop the listener."""
    with connection:
        connection.settimeout(CONNECTION_TIMEOUT)
        try:
            request = receive_message(
                connection,
                deadline=time.monotonic() + CONNECTION_TIMEOUT,
            )
            response = broker.dispatch(
                request,
                delivery_ready=lambda: _connection_is_alive(connection),
            )
        except (ProtocolError, TimeoutError, OSError):
            response = CONNECTION_ERROR
        except Exception:
            response = CONNECTION_ERROR
        try:
            send_message(connection, response)
        except ProtocolError:
            try:
                send_message(connection, CONNECTION_ERROR)
            except (ProtocolError, TimeoutError, OSError):
                pass
        except (TimeoutError, OSError):
            pass


def _connection_is_alive(connection: socket.socket) -> bool:
    """Check that a one-request RPC has neither EOF nor trailing input pending."""
    try:
        readable, _, _ = select.select([connection], [], [], 0)
        # After receive_message consumed the one permitted request, readability
        # means either EOF or unexpected trailing protocol bytes. Neither state
        # is authorized to start credential delivery.
        return not readable
    except OSError:
        return False


def serve(socket_path: Path, broker: Broker, stop: Event | None = None) -> None:
    socket_path = Path(os.path.abspath(os.fspath(socket_path)))
    runtime_path, runtime_fd = prepare_private_runtime_directory(socket_path.parent)
    socket_path = runtime_path / socket_path.name
    lifecycle_lock: int | None = None
    server: socket.socket | None = None
    socket_identity: tuple[int, int] | None = None
    workers: set[threading.Thread] = set()
    workers_lock = threading.Lock()
    try:
        lifecycle_lock = acquire_lifecycle_lock(runtime_fd, socket_path.name)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        remove_stale_socket(socket_path, runtime_fd, socket_path.name)
        server.bind(anchored_socket_path(runtime_fd, socket_path.name))
        os.chmod(socket_path.name, 0o600, dir_fd=runtime_fd)
        socket_info = os.stat(socket_path.name, dir_fd=runtime_fd, follow_symlinks=False)
        socket_identity = (socket_info.st_dev, socket_info.st_ino)
        server.listen(8)
        server.settimeout(0.2 if stop else None)
        admission = threading.BoundedSemaphore(MAX_RPC_WORKERS)

        def run_connection(connection: socket.socket) -> None:
            try:
                _serve_connection(connection, broker)
            finally:
                with workers_lock:
                    workers.discard(threading.current_thread())
                admission.release()

        while stop is None or not stop.is_set():
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            if not admission.acquire(blocking=False):
                connection.close()
                continue
            worker: threading.Thread | None = None
            try:
                worker = threading.Thread(
                    target=run_connection, args=(connection,), daemon=True,
                )
                with workers_lock:
                    workers.add(worker)
                worker.start()
            except Exception:
                with workers_lock:
                    if worker is not None:
                        workers.discard(worker)
                try:
                    connection.close()
                finally:
                    admission.release()
                continue
    finally:
        try:
            if server is not None:
                server.close()
            with workers_lock:
                pending = list(workers)
            join_deadline = time.monotonic() + CONNECTION_TIMEOUT + 0.2
            for worker in pending:
                worker.join(max(0, join_deadline - time.monotonic()))
        finally:
            try:
                unlink_socket_if_same(
                    runtime_fd, socket_path.name, socket_identity,
                )
            finally:
                try:
                    if lifecycle_lock is not None:
                        os.close(lifecycle_lock)
                finally:
                    os.close(runtime_fd)
