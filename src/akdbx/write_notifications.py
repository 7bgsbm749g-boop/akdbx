"""One-shot results of every private save page (0.53.0), keyed by write handle.

A private save page waits for the user: a chosen password (``create-entry``,
``update-password``), an authenticator key or private import
(``setup-totp``), identity details (``create-identity``, ``update-identity``)
or a card (``create-card``, ``update-card``). An agent registers a webhook for
the page's write handle and ends its turn. When the page reaches a result
(saved, failed, cancelled, expired, or interrupted by a broker restart), the
broker posts one ``akdbx.write-result`` event.

The design is the card-save notification's (``card_notifications``), for every
page kind: the event carries only the result state and two random ids, never
a value, entry metadata, write handle or page URL. The state file holds the
callback URL (mode 0600) and only a SHA-256 hash of the write handle.
Generated-password writes have no page, so they cannot be subscribed.
"""
from __future__ import annotations

from .card_notifications import RESULTS, CardSaveNotifications

PROTOCOL = 1
# The write kinds whose private page a subscription can follow.
KINDS = ('password', 'totp', 'identity', 'card')
COMMANDS = ('subscribe-write', 'write-subscription-status', 'unsubscribe-write')

__all__ = ['COMMANDS', 'KINDS', 'PROTOCOL', 'RESULTS', 'WriteNotifications', 'capabilities']


def capabilities():
    return dict(write_notifications_supported=True, write_notifications_protocol=PROTOCOL,
                write_notifications_until_result=True, write_notification_kinds=list(KINDS))


class WriteNotifications(CardSaveNotifications):
    _label = 'write'
    _event = 'akdbx.write-result'
    _protocol_error = 'write notification protocol 1 and exact write handle required'
