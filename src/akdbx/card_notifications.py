"""One-shot card-save results; callbacks contain no card or entry metadata."""
from __future__ import annotations

import hashlib
import re
import threading

from .notifications import UnlockNotifications

RESULTS = {'saved', 'failed', 'cancelled', 'expired', 'interrupted'}


def capabilities():
    return dict(card_save_notifications_supported=True, card_save_notifications_protocol=1,
                card_save_notifications_until_result=True)


class CardSaveNotifications(UnlockNotifications):
    _label = 'card-save'
    def __init__(self, *, expire_handler, **kwargs):
        self._timers = {}
        self._expire_handler = expire_handler
        super().__init__(**kwargs)

    def resume(self):
        """Deliver restored results only after the broker socket is ready."""
        with self._lock:
            self._start_worker()

    @staticmethod
    def _subject(handle):
        return hashlib.sha256(handle.encode()).hexdigest()

    def _restore_item(self, row, item):
        subject, result = row.get('subject'), row.get('result')
        if (not isinstance(subject, str) or not re.fullmatch('[a-f0-9]{64}', subject)
                or result is not None and result not in RESULTS):
            raise ValueError('invalid card notification state')
        # Private forms are intentionally not restored. Report interruption,
        # never claim a save from a lost in-memory write operation.
        item.subject, item.result = subject, result or 'interrupted'
        item.state = 'pending'

    def _row(self, key, item):
        return dict(super()._row(key, item), subject=item.subject, result=item.result)

    def _payload(self, key, item):
        return dict(event='akdbx.card-save', state=item.result,
                    subscription_id=key, event_id=item.event_id)

    @staticmethod
    def _receipt(key, item):
        return dict(UnlockNotifications._receipt(key, item), result=item.result)

    def subscribe_save(self, request, *, state, expires):
        handle = request.get('write_handle')
        if (set(request) != {'action', 'notification_protocol', 'webhook_url', 'write_handle'}
                or type(request.get('notification_protocol')) is not int
                or request['notification_protocol'] != 1
                or not isinstance(handle, str) or not re.fullmatch('[a-f0-9]{64}', handle)):
            return dict(ok=False, error='card-save notification protocol 1 and exact write handle required')
        subject = self._subject(handle)
        receipt = super().subscribe(request, unlocked=state != 'pending', subject=subject,
                                    result=None if state == 'pending' else state)
        if receipt.get('state') == 'subscribed':
            # One deadline event for the existing form, never a polling timer or
            # subscription TTL. A save/cancel result cancels this deadline.
            with self._lock:
                if subject not in self._timers and not self._stop.is_set():
                    timer = threading.Timer(max(0, expires - self._clock()), self._expire_handler,
                                            args=(handle,))
                    timer.daemon = True
                    self._timers[subject] = timer
                    timer.start()
        return receipt

    def publish_save(self, handle, state):
        if state not in RESULTS:
            return
        subject = self._subject(handle)
        with self._lock:
            timer = self._timers.pop(subject, None)
            if timer is not None:
                timer.cancel()
        super().publish(subject=subject, result=state)

    def status(self, key, *, cancel=False):
        receipt = super().status(key, cancel=cancel)
        if cancel and receipt.get('ok'):
            with self._lock:
                item = self._items.get(key)
                if item is None:
                    return receipt
                if not any(other.subject == item.subject and other.state == 'subscribed'
                           for other in self._items.values()):
                    timer = self._timers.pop(item.subject, None)
                    if timer is not None:
                        timer.cancel()
        return receipt

    def close(self):
        with self._lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()
        super().close()
