"""One-shot extension-pairing webhooks (0.33.0); callbacks carry only the browser name.

An agent that gives the user a pairing link registers a webhook and ends its
turn. When a browser is paired and attached (it can fill now), the broker posts
one ``akdbx.extension-paired`` event. A pairing approved while the extension is
not connected sends the event when that key attaches again. A subscription can name the pairing code from
``status`` (``extension_pairing[].code``) to wait for that one browser key, or
name no code to wait for any browser. A code is not a secret: the popup and
the pairing page show it, and ``status`` returns it.

Waiting subscriptions are saved like unlock subscriptions. A broker restart
ends every pairing, so a restored subscription waits for the next pairing; the
extension keeps its key, and so its code, until the browser restarts.
"""
from __future__ import annotations

import re

from .notifications import UnlockNotifications
from .extension_route import BROWSERS

CODE = re.compile(r'[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}')


def capabilities():
    return dict(pairing_notifications_supported=True, pairing_notifications_protocol=1,
                pairing_notifications_until_paired=True)


class PairingNotifications(UnlockNotifications):
    _label = 'pairing'

    def _restore_item(self, row, item):
        code = row.get('code')
        if code is not None and (not isinstance(code, str) or not CODE.fullmatch(code)):
            raise ValueError('invalid pairing notification state')
        # The pairing the broker had is gone: wait for the next one.
        item.subject = code

    def _row(self, key, item):
        return dict(super()._row(key, item), code=item.subject)

    def _payload(self, key, item):
        return dict(event='akdbx.extension-paired', browser=item.result,
                    subscription_id=key, event_id=item.event_id)

    @staticmethod
    def _receipt(key, item):
        return dict(UnlockNotifications._receipt(key, item), code=item.subject, browser=item.result)

    def subscribe_pairing(self, request, *, paired):
        """Register a wait; ``paired(code)`` returns the browser already paired for it, or None."""
        code = request.get('code')
        if (not set(request) <= {'action', 'notification_protocol', 'webhook_url', 'ttl', 'code'}
                or code is not None and (not isinstance(code, str) or not CODE.fullmatch(code))):
            return dict(ok=False, error='pairing notification protocol 1 and a valid pairing code or none required')
        browser = paired(code)
        # Already paired (a race with the user): queue the event at once.
        return self.subscribe(dict(request), unlocked=browser is not None, subject=code, result=browser)

    def publish_paired(self, code, browser):
        """A browser key became paired: wake the waits for its code and the waits for any browser."""
        if browser not in BROWSERS:
            return
        for subject in (code, None):
            self.publish(subject=subject, result=browser)
