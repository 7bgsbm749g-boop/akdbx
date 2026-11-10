"""Bounded, one-shot unlock webhooks. No vault data crosses this boundary."""
from __future__ import annotations

import json
import hashlib
import os
import stat
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


MAX_SUBSCRIPTIONS = 64
DELIVERY_TIMEOUT = 4
MAX_ATTEMPTS = 3
MAX_DELIVERY_INPUT = 16 * 1024


def capabilities() -> dict:
    return {"unlock_notifications_supported": True, "unlock_notifications_protocol": 1,
            "unlock_notifications_until_unlock": True}


def validate_webhook_url(value: object) -> str:
    try:
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ValueError
        if any(ord(c) <= 32 or ord(c) >= 127 for c in value):
            raise ValueError
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.fragment or parts.port == 0):
            raise ValueError
        return value
    except ValueError:
        raise ValueError("webhook must be an HTTPS URL without credentials or fragment") from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post_event(url: str, payload: dict) -> None:
    # urllib's timeout limits socket inactivity, not DNS or the total time to
    # receive headers. Isolate one attempt so even those operations can be
    # killed and reaped at the absolute deadline. No URL/token enters argv,
    # the environment, an exception receipt, or a child output stream.
    try:
        data = json.dumps({'url': url, 'payload': payload}).encode('utf-8')
        if len(data) > MAX_DELIVERY_INPUT:
            raise ValueError
        subprocess.run([sys.executable, '-I', str(Path(__file__).resolve())],
                       input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=DELIVERY_TIMEOUT, check=True)
    except Exception:
        raise OSError('notification delivery failed') from None


def _post_event(url: str, payload: dict) -> None:
    # Do not forward a private webhook token through redirects or env proxies.
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    request = Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                      headers={"Content-Type": "application/json",
                               "User-Agent": "akdbx-unlock-notifier/1"})
    with opener.open(request, timeout=DELIVERY_TIMEOUT) as response:
        if not 200 <= response.status < 300:
            raise OSError("notification delivery failed")
        # The response body is irrelevant and may contain untrusted data.


@dataclass
class Subscription:
    url: str = field(repr=False)
    expires_at: float | None
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    state: str = "subscribed"
    attempts: int = 0
    url_hash: bytes = field(init=False, repr=False)

    def __post_init__(self):
        self.url_hash = hashlib.sha256(self.url.encode()).digest()


class UnlockNotifications:
    def __init__(self, *, sender=post_event, clock=time.monotonic, state_path=None):
        self._sender = sender
        self._clock = clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._items: dict[str, Subscription] = {}
        self._worker: threading.Thread | None = None
        self._state_path = Path(state_path) if state_path is not None else None
        self._restore()

    def _directory(self):
        from .runtime import prepare_private_runtime_directory
        if not self._state_path.is_absolute() or self._state_path.name in {'', '.', '..'}:
            raise ValueError('invalid notification state path')
        return prepare_private_runtime_directory(self._state_path.parent)[1]

    def _restore(self):
        if self._state_path is None:
            return
        directory = self._directory()
        try:
            try:
                fd = os.open(self._state_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
            except FileNotFoundError:
                return
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 512 * 1024):
                    raise ValueError('invalid notification state')
                data = json.loads(os.read(fd, 512 * 1024 + 1))
            finally:
                os.close(fd)
            if not isinstance(data, list) or len(data) > MAX_SUBSCRIPTIONS:
                raise ValueError('invalid notification state')
            for row in data:
                key, event, attempts = row['id'], row['event_id'], row['attempts']
                if (not isinstance(key, str) or len(key) != 32 or any(c not in '0123456789abcdef' for c in key)
                        or not isinstance(event, str) or len(event) != 32 or any(c not in '0123456789abcdef' for c in event)
                        or type(attempts) is not int or not 0 <= attempts <= MAX_ATTEMPTS):
                    raise ValueError('invalid notification state')
                item = Subscription(validate_webhook_url(row['url']), None, event_id=event,
                                    attempts=attempts)
                if attempts < MAX_ATTEMPTS:
                    self._items[key] = item
        except (KeyError, TypeError, json.JSONDecodeError):
            raise ValueError('invalid notification state') from None
        finally:
            os.close(directory)

    def _persist(self):
        if self._state_path is None or self._stop.is_set():
            return
        # Only waiting subscriptions need durable storage. Never persist vault
        # contents, unlock tokens or credentials. Callback URLs stay mode 0600.
        rows = [{'id': key, 'url': item.url, 'event_id': item.event_id, 'attempts': item.attempts}
                for key, item in self._items.items() if item.expires_at is None and
                item.state in {'subscribed', 'pending', 'sending'}]
        directory = self._directory()
        name = '.unlock-notifications-' + uuid.uuid4().hex
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(json.dumps(rows).encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self._state_path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)

    def _prune(self):
        now = self._clock()
        for key, item in list(self._items.items()):
            if item.expires_at is not None and item.expires_at <= now and item.state != "sending":
                del self._items[key]

    @staticmethod
    def _receipt(key, item):
        return {"ok": True, "subscription_id": key, "state": item.state,
                "attempts": item.attempts}

    def subscribe(self, request: dict, *, unlocked: bool) -> dict:
        if type(request.get("notification_protocol")) is not int or request["notification_protocol"] != 1:
            return {"ok": False, "error": "unlock notification protocol 1 required"}
        try:
            url = validate_webhook_url(request.get("webhook_url"))
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        ttl = request.get("ttl", 0)
        if type(ttl) is not int or not (ttl == 0 or 60 <= ttl <= 3600):
            return {"ok": False, "error": "subscription TTL must be 0 (until unlock/cancel) or 60–3600 seconds"}
        with self._lock:
            self._prune()
            if self._stop.is_set():
                return {"ok": False, "error": "unlock notifications stopped"}
            # A retry after a lost receipt reuses the existing subscription.
            url_hash = hashlib.sha256(url.encode()).digest()
            for key, item in self._items.items():
                if item.url_hash == url_hash:
                    remaining = None if item.expires_at is None else max(0, int(item.expires_at - self._clock()))
                    return {**self._receipt(key, item), "expires_in": remaining}
            if len(self._items) >= MAX_SUBSCRIPTIONS:
                terminal = next((key for key, item in self._items.items()
                                 if item.state in {'delivered', 'failed', 'cancelled', 'expired'}), None)
                if terminal is None:
                    return {"ok": False, "error": "unlock subscription limit reached"}
                del self._items[terminal]
            key = uuid.uuid4().hex
            item = Subscription(url, self._clock() + ttl if ttl else None,
                                state="pending" if unlocked else "subscribed")
            self._items[key] = item
            try:
                self._persist()
            except OSError:
                del self._items[key]
                return {"ok": False, "error": "notification could not be saved; subscription not registered"}
            self._start_worker()
            return {**self._receipt(key, item), "expires_in": ttl or None}

    def publish(self) -> None:
        with self._lock:
            self._prune()
            for item in self._items.values():
                if item.state == "subscribed":
                    item.state = "pending"
            self._start_worker()

    def status(self, key: object, *, cancel=False) -> dict:
        with self._lock:
            self._prune()
            item = self._items.get(key) if isinstance(key, str) else None
            if item is None:
                return {"ok": False, "error": "unknown or expired unlock subscription"}
            if cancel and item.state in {"subscribed", "pending", "sending"}:
                item.state = "cancelled"
                item.url = ""
                self._persist()
            return self._receipt(key, item)

    def _start_worker(self):
        # Called under _lock. At most one sender, and no idle listener process.
        if self._worker is not None or not any(i.state == "pending" for i in self._items.values()):
            return
        try:
            self._worker = threading.Thread(target=self._deliver, name="akdbx-unlock-events", daemon=True)
            self._worker.start()
        except Exception:
            self._worker = None
            for item in self._items.values():
                if item.state == "pending":
                    item.state, item.url = "failed", ""

    def _deliver(self):
        while not self._stop.is_set():
            with self._lock:
                self._prune()
                next_item = next(((k, i) for k, i in self._items.items() if i.state == "pending"), None)
                if next_item is None:
                    self._worker = None
                    return
                key, item = next_item
                item.state = "sending"
            for attempt in range(item.attempts, MAX_ATTEMPTS):
                with self._lock:
                    if item.state == "cancelled" or self._stop.is_set():
                        break
                    if item.expires_at is not None and item.expires_at <= self._clock():
                        item.state, item.url = "expired", ""
                        break
                    item.attempts += 1
                    try:
                        self._persist()
                    except OSError:
                        item.state, item.url = "failed", ""
                        break
                    url = item.url
                try:
                    self._sender(url, {"event": "akdbx.unlocked", "locked": False,
                                       "subscription_id": key, "event_id": item.event_id})
                except Exception:
                    # Never log the callback URL, its token, or exception text.
                    if attempt + 1 < MAX_ATTEMPTS and not self._stop.wait(1 << attempt):
                        continue
                    with self._lock:
                        if item.state != "cancelled":
                            item.state, item.url = "failed", ""
                        self._persist()
                    break
                else:
                    with self._lock:
                        if item.state != "cancelled":
                            item.state, item.url = "delivered", ""
                        self._persist()
                    break
        with self._lock:
            self._worker = None

    def close(self):
        with self._lock:
            self._persist()
            self._stop.set()
            for item in self._items.values():
                if item.state in {"subscribed", "pending", "sending"}:
                    item.state, item.url = "cancelled", ""
            worker = self._worker
        if worker is not None:
            worker.join(timeout=DELIVERY_TIMEOUT + 0.5)


if __name__ == '__main__':
    # Private one-attempt helper. Standalone execution avoids importing the
    # broker (or inheriting its decrypted vault via fork-only execution).
    try:
        raw = sys.stdin.buffer.read(MAX_DELIVERY_INPUT + 1)
        if len(raw) > MAX_DELIVERY_INPUT:
            raise ValueError
        value = json.loads(raw)
        _post_event(validate_webhook_url(value['url']), value['payload'])
    except Exception:
        sys.exit(1)
