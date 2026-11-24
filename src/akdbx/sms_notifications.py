"""One-shot SMS webhooks (0.37.0); callbacks carry only the source and message id.

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
"""
from __future__ import annotations

from .notifications import UnlockNotifications
from .sms import MESSAGE_ID, NAME


def capabilities():
    return dict(sms_notifications_supported=True, sms_notifications_protocol=1)


class SmsNotifications(UnlockNotifications):
    _label = 'sms'

    def _restore_item(self, row, item):
        source = row.get('source')
        if source is not None and (not isinstance(source, str) or not NAME.fullmatch(source)):
            raise ValueError('invalid sms notification state')
        item.subject = source

    def _row(self, key, item):
        return dict(super()._row(key, item), source=item.subject)

    @staticmethod
    def _message(item):
        # result is "SOURCE MESSAGE_ID" once a text arrived.
        source, _, message = (item.result or '').partition(' ')
        return (source, message) if NAME.fullmatch(source) and MESSAGE_ID.fullmatch(message) else (None, None)

    def _payload(self, key, item):
        source, message = self._message(item)
        return dict(event='akdbx.sms-received', source=source, message_id=message,
                    subscription_id=key, event_id=item.event_id)

    @classmethod
    def _receipt(cls, key, item):
        source, message = cls._message(item)
        return dict(UnlockNotifications._receipt(key, item), source=item.subject or source, message_id=message)

    def subscribe_text(self, request, *, received):
        """Register a wait; ``received(source, since)`` returns an already received text, or None."""
        source, since = request.get('source'), request.get('since')
        if (not set(request) <= {'action', 'sms_protocol', 'notification_protocol', 'webhook_url', 'ttl', 'source',
                                 'since'}
                or source is not None and (not isinstance(source, str) or not NAME.fullmatch(source))
                or since is not None and (type(since) not in (int, float) or not 0 <= since < 2 ** 34)):
            return dict(ok=False, error='sms notification protocol 1 and a valid source name or none required')
        payload = {k: v for k, v in request.items() if k not in {'sms_protocol', 'source', 'since'}}
        found = received(source, since) if since is not None else None
        result = f'{found[0]} {found[1]}' if found else None
        return self.subscribe(payload, unlocked=found is not None, subject=source, result=result)

    def publish_text(self, source, message_id):
        """A text with a code arrived: wake the waits for its source and the waits for any source."""
        if not NAME.fullmatch(source) or not MESSAGE_ID.fullmatch(message_id):
            return
        for subject in (source, None):
            self.publish(subject=subject, result=f'{source} {message_id}')
