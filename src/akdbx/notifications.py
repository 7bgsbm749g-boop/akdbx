"""Bounded, one-shot unlock webhooks. No vault data crosses this boundary."""
from __future__ import annotations

import json
import hashlib
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
    return {"unlock_notifications_supported": True, "unlock_notifications_protocol": 1}


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
    expires_at: float
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    state: str = "subscribed"
    attempts: int = 0
    url_hash: bytes = field(init=False, repr=False)

    def __post_init__(self):
        self.url_hash = hashlib.sha256(self.url.encode()).digest()


class UnlockNotifications:
    def __init__(self, *, sender=post_event, clock=time.monotonic):
        self._sender = sender
        self._clock = clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._items: dict[str, Subscription] = {}
        self._worker: threading.Thread | None = None

    def _prune(self):
        now = self._clock()
        for key, item in list(self._items.items()):
            if item.expires_at <= now and item.state != "sending":
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
        ttl = request.get("ttl", 1800)
        if type(ttl) is not int or not 60 <= ttl <= 3600:
            return {"ok": False, "error": "subscription TTL must be 60–3600 seconds"}
        with self._lock:
            self._prune()
            if self._stop.is_set():
                return {"ok": False, "error": "unlock notifications stopped"}
            # A retry after a lost receipt reuses the existing subscription.
            url_hash = hashlib.sha256(url.encode()).digest()
            for key, item in self._items.items():
                if item.url_hash == url_hash:
                    return self._receipt(key, item)
            if len(self._items) >= MAX_SUBSCRIPTIONS:
                return {"ok": False, "error": "unlock subscription limit reached"}
            key = uuid.uuid4().hex
            item = Subscription(url, self._clock() + ttl,
                                state="pending" if unlocked else "subscribed")
            self._items[key] = item
            self._start_worker()
            return {**self._receipt(key, item), "expires_in": ttl}

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
            for attempt in range(MAX_ATTEMPTS):
                with self._lock:
                    if item.state == "cancelled" or self._stop.is_set():
                        break
                    if item.expires_at <= self._clock():
                        item.state, item.url = "expired", ""
                        break
                    item.attempts += 1
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
                    break
                else:
                    with self._lock:
                        if item.state != "cancelled":
                            item.state, item.url = "delivered", ""
                    break
        with self._lock:
            self._worker = None

    def close(self):
        self._stop.set()
        with self._lock:
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
