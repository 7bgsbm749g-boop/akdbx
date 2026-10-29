from __future__ import annotations

import json
import socket
import struct
import time
from typing import Any

MAX_MESSAGE = 64 * 1024


class ProtocolError(Exception):
    pass


def send_message(sock: socket.socket, value: dict[str, Any]) -> None:
    data = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_MESSAGE:
        raise ProtocolError("message too large")
    sock.sendall(struct.pack("!I", len(data)) + data)


def _read_exact(sock: socket.socket, size: int, deadline: float | None = None) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        if deadline is not None:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise TimeoutError("message deadline exceeded")
            sock.settimeout(timeout)
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_message(sock: socket.socket, *, deadline: float | None = None) -> dict[str, Any]:
    size = struct.unpack("!I", _read_exact(sock, 4, deadline))[0]
    if size > MAX_MESSAGE:
        raise ProtocolError("message too large")
    try:
        value = json.loads(_read_exact(sock, size, deadline))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("request must be an object")
    return value
