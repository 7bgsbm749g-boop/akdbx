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
    """Send a UTF-8 JSON object with a four-byte network-order length prefix.

    Reject encoded payloads above MAX_MESSAGE with ProtocolError before sending.
    Serialization and socket errors propagate; callers must sanitize failures.
    """
    data = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_MESSAGE:
        raise ProtocolError("message too large")
    sock.sendall(struct.pack("!I", len(data)) + data)


def _read_exact(sock: socket.socket, size: int, deadline: float | None = None) -> bytes:
    """Receive exactly size bytes, rejecting early EOF with ProtocolError.

    An absolute monotonic deadline bounds all reads and changes the socket
    timeout to the remaining budget; timeout and socket errors propagate.
    """
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
    """Read one bounded length-prefixed JSON object from the socket.

    Apply the same absolute monotonic deadline to header and body. Reject
    oversize, malformed or non-object messages with ProtocolError. Leave
    trailing data unread for the caller to reject; no peer authentication here.
    """
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
