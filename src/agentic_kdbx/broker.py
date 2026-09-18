from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import socket
import stat
import time
import threading
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Callable, Protocol

from .protocol import ProtocolError, receive_message, send_message


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
        self._handles[handle] = Handle(entry, self.clock() + self.handle_ttl)
        return handle

    def _resolve(self, handle: object) -> EntryLike:
        if not isinstance(handle, str):
            raise ValueError("invalid handle")
        item = self._handles.pop(handle, None)  # one use, successful or not
        if item is None or item.expires_at <= self.clock():
            raise ValueError("unknown or expired handle; search again")
        return item.entry

    def dispatch(self, request: dict) -> dict:
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
            assert self.vault is not None
            for entry in self.vault.entries:
                title, username, url = entry.title or "", entry.username or "", entry.url or ""
                group = "/".join(entry.path[:-1]) if entry.path else ""
                if needle and needle not in "\n".join((title, username, url, group)).casefold():
                    continue
                matches.append({
                    "handle": self._new_handle(entry),
                    "title": title,
                    "username": username,
                    "url": url,
                    "group": group,
                })
                if len(matches) == 20:
                    break
            return {"ok": True, "entries": matches}
        if action == "fill":
            try:
                entry = self._resolve(request.get("handle"))
                mode = request.get("mode", "login")
                if mode not in ("login", "username", "password"):
                    raise ValueError("mode must be login, username, or password")
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
            # Once credentials are accessed, backend errors must never reach RPC
            # responses: exception messages can contain the text being typed.
            try:
                username, password = entry.username or "", entry.password or ""
                if mode == "login":
                    self.typer.type_text(username)
                    self.typer.press_tab()
                    self.typer.type_text(password)
                elif mode == "username":
                    self.typer.type_text(username)
                else:
                    self.typer.type_text(password)
                return {"ok": True, "filled": mode}
            except Exception:
                return {"ok": False, "error": "autofill failed"}
        return {"ok": False, "error": "unknown action"}


def open_vault_with_password(database: Path, password: str, keyfile: Path | None = None):
    from pykeepass import PyKeePass
    return PyKeePass(str(database), password=password, keyfile=str(keyfile) if keyfile else None)


def serve(socket_path: Path, broker: Broker, stop: Event | None = None) -> None:
    socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(socket_path.parent, 0o700)
    if socket_path.exists() or socket_path.is_symlink():
        mode = socket_path.lstat().st_mode
        if not stat.S_ISSOCK(mode):
            raise RuntimeError(f"refusing to replace non-socket: {socket_path}")
        socket_path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        server.listen(8)
        server.settimeout(0.2 if stop else None)
        while stop is None or not stop.is_set():
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            with connection:
                try:
                    request = receive_message(connection)
                    response = broker.dispatch(request)
                except ProtocolError as exc:
                    response = {"ok": False, "error": str(exc)}
                send_message(connection, response)
    finally:
        server.close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
