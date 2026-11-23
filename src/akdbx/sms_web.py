"""HTTPS routes for phone verification texts.

``POST /sms/in/<token>`` takes one forwarded text from a configured source:
JSON (``{"text": ..., "from": ...}``, as an iOS Shortcuts automation sends
it) or a form (``Body`` and ``From``, as Twilio sends it). The token in the
path is the only credential; it is never logged. The answer says only that
the request was accepted, never whether the text held a code.

``GET /sms/setup?token=...`` is the private setup page: it shows the source's
webhook URL and the steps for that source, for SETUP_TTL seconds.
"""
from __future__ import annotations

import html
import json
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from .sms import ROUTE_IN, ROUTE_SETUP, SETUP_TTL, webhook_url

MAX_BODY = 16 * 1024
TWIML = b'<?xml version="1.0" encoding="UTF-8"?><Response></Response>'
NOT_FOUND = b'{"ok":false}'
ACCEPTED = b'{"ok":true}'
TEXT_FIELDS = ('text', 'body', 'Body', 'message', 'content')
SENDER_FIELDS = ('from', 'From', 'sender')


def handle_sms(handler, state) -> bool:
    path = urlsplit(handler.path).path
    if path.startswith(ROUTE_IN):
        _inbound(handler, state, path[len(ROUTE_IN):])
        return True
    if path == ROUTE_SETUP:
        _setup(handler, state)
        return True
    return False


def _json(handler, status, body=NOT_FOUND):
    handler._send(status, body, content_type='application/json')


def _value(values: dict, names) -> str | None:
    for name in names:
        value = values.get(name)
        if isinstance(value, list):
            value = value[0] if len(value) == 1 else None
        if isinstance(value, str):
            return value
    return None


def _inbound(handler, state, token: str) -> None:
    inbox = state.broker.sms
    handler.close_connection = True
    if handler.command != 'POST':
        _json(handler, HTTPStatus.NOT_FOUND)
        return
    # A browser page on another origin must not post texts: senders here are
    # servers and phone automations, which send no Origin header.
    if not handler._identity_ok() or handler.headers.get_all('Origin', []):
        _json(handler, HTTPStatus.NOT_FOUND)
        return
    source = inbox.source_for(token)
    if source is None:
        _json(handler, HTTPStatus.NOT_FOUND)
        return
    try:
        length = int(handler.headers.get('Content-Length', '0'))
        if not 0 < length <= MAX_BODY:
            raise ValueError
        raw = handler.rfile.read(length)
        if len(raw) != length or handler._expired():
            return
        kind = handler.headers.get('Content-Type', '').split(';')[0].strip().lower()
        if kind == 'application/json':
            values = json.loads(raw.decode('utf-8'))
            if not isinstance(values, dict):
                raise ValueError
        elif kind == 'application/x-www-form-urlencoded':
            values = parse_qs(raw.decode('utf-8'), keep_blank_values=True, errors='strict')
        else:
            raise ValueError
        text = _value(values, TEXT_FIELDS)
        if text is None:
            raise ValueError
        sender = _value(values, SENDER_FIELDS) or ''
    except Exception:
        _json(handler, HTTPStatus.BAD_REQUEST)
        return
    finally:
        raw = b''
    result = inbox.receive(token, sender, text)
    text = ''
    if result == 'unknown':
        _json(handler, HTTPStatus.NOT_FOUND)
    elif result == 'limited':
        _json(handler, HTTPStatus.TOO_MANY_REQUESTS)
    elif source.kind == 'twilio':
        # Empty TwiML: Twilio sends no reply text.
        handler._send(HTTPStatus.OK, TWIML, content_type='text/xml')
    else:
        _json(handler, HTTPStatus.OK, ACCEPTED)


SHORTCUT_STEPS = (
    'On the iPhone, open <strong>Shortcuts</strong>, then <strong>Automation</strong>, then <strong>+</strong>.',
    'Choose <strong>Message</strong>. Set <strong>Message Contains</strong> to <code>code</code> '
    '(or leave it empty to send every text; akdbx keeps only texts with a verification code).',
    'Select <strong>Run Immediately</strong> and turn off <strong>Notify When Run</strong>. Tap <strong>Next</strong>, '
    'then <strong>New Blank Automation</strong>.',
    'Add the action <strong>Get Contents of URL</strong>. Paste the webhook URL below.',
    'Tap the arrow to show more. Set <strong>Method</strong> to <strong>POST</strong> and <strong>Request Body</strong> '
    'to <strong>JSON</strong>.',
    'Add a text field <code>text</code> with the value <strong>Shortcut Input</strong> (tap it and choose '
    '<strong>Content</strong>). Add a text field <code>from</code> with the value <strong>Shortcut Input</strong> '
    '(choose <strong>Sender</strong>). Tap <strong>Done</strong>.',
)
TWILIO_STEPS = (
    'In the Twilio Console, open <strong>Phone Numbers</strong>, <strong>Manage</strong>, '
    '<strong>Active numbers</strong> and select the number.',
    'Under <strong>Messaging Configuration</strong>, set <strong>A message comes in</strong> to '
    '<strong>Webhook</strong>, paste the webhook URL below and choose <strong>HTTP POST</strong>.',
    'Save the configuration.',
)
WEBHOOK_STEPS = (
    'Configure the service to send an HTTPS POST for each received text to the webhook URL below.',
    'Send JSON <code>{"text": "...", "from": "..."}</code>, or a form with <code>Body</code> and <code>From</code>.',
)


def _setup(handler, state) -> None:
    from .portal import field
    from .web_unlock import _page
    origin = getattr(state, 'origin', None)
    token = parse_qs(urlsplit(handler.path).query).get('token', [''])[0]
    setup = state.broker.sms.setup(token) if handler._identity_ok() and handler.command == 'GET' else None
    if setup is None or not isinstance(origin, str):
        handler._send(HTTPStatus.NOT_FOUND, _page('Not found', '<p>This SMS setup link is not valid any more. '
                                                  'Ask your agent for a new one.</p>'))
        return
    steps = {'shortcut': SHORTCUT_STEPS, 'twilio': TWILIO_STEPS}.get(setup.kind, WEBHOOK_STEPS)
    url = webhook_url(origin, setup.token)
    items = ''.join(f'<li>{step}</li>' for step in steps)
    body = (f'<p>Set up the SMS source <strong>{html.escape(setup.source)}</strong>. Texts it forwards reach only '
            'this AKDBX broker. AKDBX keeps the verification code for ten minutes and never shows it to the agent.</p>'
            f'<ol>{items}</ol>'
            + field('Webhook URL (keep it private)', 'webhook', kind='text', value=url, submitted=False,
                    required=False)
            + f'<p>Anyone with this URL can send texts to AKDBX. This page closes in {SETUP_TTL // 60} minutes. '
              'Ask your agent to replace the source if the URL leaks.</p>')
    handler._send(HTTPStatus.OK, _page('Set up SMS verification', body))
