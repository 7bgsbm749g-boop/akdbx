"""One-shot SMS webhooks (0.40.0); callbacks carry only the source and message id.

An agent that lets a site send a verification text registers a webhook and
ends its turn. When the next text with a code arrives (from one source, or
from any), the broker posts one ``akdbx.sms-received`` event with the source
name and the message id for ``fill-sms-code``. The event never carries the
code, the text or the sender.

A subscription can give ``since`` (Unix seconds): a text already received at
or after that time sends the event at once, so a text that arrives between
``sms-wait`` and the subscription is not missed. Waiting subscriptions are
saved like unlock subscriptions. A broker restart loses the texts, so a
restored subscription waits for the next one.

An ``any_text`` subscription (0.53.0) is for a source's setup or test page:
it wakes on the next text that one source forwards, with or without a code.
Its event adds ``result`` (``code``, ``no-code-word``, ``no-code``,
``several-codes`` or ``empty``) and has a message id only when a code was kept.
"""
from __future__ import annotations

import hashlib

from .notifications import UnlockNotifications
from .sms import MESSAGE_ID, NAME, RESULTS


FINISHED = {'delivered', 'failed', 'cancelled', 'expired'}
# The subject suffix of an any_text subscription; NAME never has a space.
ANY_TEXT = ' any-text'


def capabilities():
    return dict(sms_notifications_supported=True, sms_notifications_protocol=1, sms_notifications_any_text=True)


def _split(subject):
    """(source, any_text) of a subscription subject."""
    if isinstance(subject, str) and subject.endswith(ANY_TEXT):
        return subject[:-len(ANY_TEXT)], True
    return subject, False


class SmsNotifications(UnlockNotifications):
    _label = 'sms'

    def _restore_item(self, row, item):
        source, any_text = row.get('source'), row.get('any_text', False)
        if (source is not None and (not isinstance(source, str) or not NAME.fullmatch(source))
                or type(any_text) is not bool or any_text and source is None):
            raise ValueError('invalid sms notification state')
        item.subject = source + ANY_TEXT if any_text else source

    def _row(self, key, item):
        source, any_text = _split(item.subject)
        return dict(super()._row(key, item), source=source, **({'any_text': True} if any_text else {}))

    @staticmethod
    def _message(item):
        """(source, message id, result) of the text that woke the subscription."""
        # result is "SOURCE MESSAGE_ID" once a text with a code arrived, or
        # "SOURCE MESSAGE_ID|- RESULT" for an any_text subscription.
        parts = (item.result or '').split(' ')
        if len(parts) == 2 and NAME.fullmatch(parts[0]) and MESSAGE_ID.fullmatch(parts[1]):
            return parts[0], parts[1], None
        if (len(parts) == 3 and NAME.fullmatch(parts[0]) and parts[2] in RESULTS
                and (parts[1] == '-' or MESSAGE_ID.fullmatch(parts[1]))):
            return parts[0], None if parts[1] == '-' else parts[1], parts[2]
        return None, None, None

    def _payload(self, key, item):
        source, message, result = self._message(item)
        payload = dict(event='akdbx.sms-received', source=source, message_id=message,
                       subscription_id=key, event_id=item.event_id)
        if _split(item.subject)[1]:
            payload['result'] = result
        return payload

    @classmethod
    def _receipt(cls, key, item):
        source, message, result = cls._message(item)
        subject, any_text = _split(item.subject)
        receipt = dict(UnlockNotifications._receipt(key, item), source=subject or source, message_id=message)
        if any_text:
            receipt.update(any_text=True, result=result)
        return receipt

    def subscribe_text(self, request, *, received):
        """Register a wait; ``received(source, since)`` returns an already received text, or None."""
        source, since = request.get('source'), request.get('since')
        any_text = request.get('any_text', False)
        if (not set(request) <= {'action', 'sms_protocol', 'notification_protocol', 'webhook_url', 'ttl', 'source',
                                 'since', 'any_text'}
                or source is not None and (not isinstance(source, str) or not NAME.fullmatch(source))
                or since is not None and (type(since) not in (int, float) or not 0 <= since < 2 ** 34)):
            return dict(ok=False, error='sms notification protocol 1 and a valid source name or none required')
        if type(any_text) is not bool or any_text and (source is None or since is not None):
            return dict(ok=False, error='an any-text sms subscription needs one source and no since time')
        payload = {k: v for k, v in request.items() if k not in {'sms_protocol', 'source', 'since', 'any_text'}}
        if any_text:
            # The setup test waits for the next text from this source only.
            source += ANY_TEXT
        if isinstance(payload.get('webhook_url'), str):
            # One-shot: after an event (or a cancel) the same URL and source
            # start a new wait instead of returning the finished one.
            url_hash = hashlib.sha256(payload['webhook_url'].encode()).digest()
            with self._lock:
                for key in [key for key, item in self._items.items()
                            if item.url_hash == url_hash and item.subject == source and item.state in FINISHED]:
                    del self._items[key]
        found = received(source, since) if since is not None else None
        result = f'{found[0]} {found[1]}' if found else None
        return self.subscribe(payload, unlocked=found is not None, subject=source, result=result)

    def publish_text(self, source, message_id):
        """A text with a code arrived: wake the waits for its source and the waits for any source."""
        if not NAME.fullmatch(source) or not MESSAGE_ID.fullmatch(message_id):
            return
        for subject in (source, None):
            self.publish(subject=subject, result=f'{source} {message_id}')

    def publish_any(self, source, message_id, result):
        """A source forwarded a text (kept or dropped): wake its any_text waits."""
        if (not NAME.fullmatch(source) or result not in RESULTS
                or message_id is not None and not MESSAGE_ID.fullmatch(message_id)):
            return
        self.publish(subject=source + ANY_TEXT, result=f'{source} {message_id or "-"} {result}')
