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
import re
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


COPY_STEP = 'Tap the <strong>Webhook URL</strong> box above. It copies the URL.'
URL_STEP = ('Tap the grey <strong>URL</strong> in the action and paste. The action now shows the '
            '<code>https://</code> address.')
TEST_STEP = ('Test it: ask someone to text you <code>Your test code is 482913</code>, or send it to yourself. '
             'The first time, iOS can ask for permission: tap <strong>Allow</strong>, then '
             '<strong>Always Allow</strong>.')


def _variable_steps(variable: str, where: str) -> tuple:
    return (
        'Tap <strong>Add new field</strong> and choose <strong>Text</strong>. Type <code>text</code> on the left.',
        f'In that row, tap the grey <strong>Text</strong> on the right. {where} The row now shows <code>text</code> '
        f'and a blue <strong>{variable}</strong>. That sends the text of the message.',
        'Optional, so the agent sees who sent the text: tap <strong>Add new field</strong>, choose '
        f'<strong>Text</strong> and type <code>from</code>. Fill its value the same way. Then tap the blue '
        f'<strong>{variable}</strong> in the <code>from</code> row and choose <strong>Sender</strong>.',
    )


# Each group: (id, label, steps). The page opens the group that matches the
# iPhone's iOS version (from the User-Agent) and offers the others in a list.
SHORTCUT_GROUPS = (
    ('ios27', 'iOS 27 and later', (
        COPY_STEP,
        'Open the <strong>Shortcuts</strong> app. Tap <strong>+</strong> to make a new shortcut. (If it shows '
        '<strong>Describe a shortcut</strong>, tap <strong>Edit</strong>.)',
        'In the list at the bottom, tap <strong>Automation</strong>, then <strong>Message</strong>. A box '
        '<strong>When I receive a message</strong> appears at the top.',
        'In that box, tap the arrow next to <strong>where</strong>. Set the filter to <strong>Message</strong> '
        'contains <code>code</code>. (If the filter starts with <strong>Sender</strong>, tap it and choose '
        '<strong>Message</strong>.)',
        'Keep <strong>Automation</strong> on and <strong>Confirm Before Run</strong> off.',
        'In the <strong>Search</strong> bar at the bottom, type <code>Get Contents of URL</code> and tap it. A second '
        'box <strong>Get contents of URL</strong> appears.',
        URL_STEP,
        'Tap the round arrow after the address. Set <strong>Method</strong> to <strong>POST</strong>. Keep '
        '<strong>Request Body</strong> as <strong>JSON</strong> (the default).',
        *_variable_steps('Message', 'Above the keyboard, tap <strong>Select Variable</strong>. Then tap the blue '
                                    '<strong>Message</strong> that shows between the two boxes.'),
        'Tap the back arrow at the top left. Shortcuts saves the automation.',
        TEST_STEP,
    )),
    ('ios17', 'iOS 17 to iOS 26', (
        COPY_STEP,
        'Open the <strong>Shortcuts</strong> app. Tap the <strong>Automation</strong> tab at the bottom, then '
        '<strong>+</strong> (or <strong>New Automation</strong>).',
        'Scroll the list and tap <strong>Message</strong>.',
        'Tap <strong>Message Contains</strong>, type <code>code</code> and tap <strong>Done</strong>. Do not choose '
        'a sender.',
        'Select <strong>Run Immediately</strong>. If you see <strong>Notify When Run</strong>, turn it off. Tap '
        '<strong>Next</strong>.',
        'Tap <strong>New Blank Automation</strong> (on some versions: <strong>Create New Shortcut</strong>).',
        'Tap <strong>Add Action</strong> or the <strong>Search</strong> bar, type <code>Get Contents of URL</code> '
        'and tap it.',
        URL_STEP,
        'Tap the arrow in the action to show more. Set <strong>Method</strong> to <strong>POST</strong>. Keep '
        '<strong>Request Body</strong> as <strong>JSON</strong> (the default).',
        *_variable_steps('Shortcut Input', 'Above the keyboard, tap <strong>Shortcut Input</strong>.'),
        'Tap <strong>Done</strong> at the top right.',
        TEST_STEP,
    )),
    ('ios16', 'iOS 16 and earlier', (
        'On iOS 16 and earlier, iOS can ask you to confirm each time a message automation runs. Then a text is '
        'forwarded only after you tap the notification. Update to iOS 17 or later if you can.',
        COPY_STEP,
        'Open the <strong>Shortcuts</strong> app. Tap the <strong>Automation</strong> tab at the bottom, then '
        '<strong>Create Personal Automation</strong> (or <strong>+</strong> first).',
        'Scroll the list and tap <strong>Message</strong>.',
        'Tap <strong>Message Contains</strong>, type <code>code</code> and tap <strong>Done</strong>. Tap '
        '<strong>Next</strong>.',
        'Tap <strong>Add Action</strong>, type <code>Get Contents of URL</code> in the search bar and tap it.',
        URL_STEP,
        'Tap <strong>Show More</strong> in the action. Set <strong>Method</strong> to <strong>POST</strong>. Keep '
        '<strong>Request Body</strong> as <strong>JSON</strong> (the default).',
        *_variable_steps('Shortcut Input', 'Above the keyboard, tap <strong>Shortcut Input</strong>.'),
        'Tap <strong>Next</strong>. Turn off <strong>Ask Before Running</strong> and tap <strong>Don\'t Ask</strong>. '
        'Tap <strong>Done</strong>.',
        TEST_STEP,
    )),
)


def ios_major(user_agent: str) -> int | None:
    """The iOS major version from a User-Agent, or None if it is not an iPhone or iPad.

    Safari 26 and later freezes the OS token (``iPhone OS 18_6``) but its
    ``Version/`` token follows iOS. Chrome, Firefox and Edge on iOS have no
    ``Version/`` token and send the real OS version.
    """
    if not re.search(r'\b(iPhone|iPad|iPod)\b', user_agent):
        return None
    version = re.search(r'\bVersion/(\d+)', user_agent)
    if version and not re.search(r'\b(CriOS|FxiOS|EdgiOS)/', user_agent):
        return int(version.group(1))
    os_version = re.search(r'\bOS (\d+)_', user_agent)
    return int(os_version.group(1)) if os_version else None


def shortcut_group(major: int | None) -> str:
    if major is None or major >= 27:
        return 'ios27'
    return 'ios17' if major >= 17 else 'ios16'


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


def _copy_box(label: str, text: str) -> str:
    """A tap-to-copy box: the portal script copies data-copy and says so in the box's label."""
    quoted, label = html.escape(text, quote=True), html.escape(label, quote=True)
    return (f'<button type="button" class="copy-field" data-copy="{quoted}">'
            f'<span class="copy-label" data-idle="{label}" aria-live="polite">{label}</span>'
            f'<span class="copy-text">{quoted}</span></button>')


def _shortcut_steps(major: int | None) -> str:
    """A version list (opened at the detected iOS version) and one step list per group."""
    chosen = shortcut_group(major)
    detected = (f'This iPhone seems to run iOS {major}. ' if major is not None else '') + 'Choose another version if needed.'
    options = ''.join(f'<option data-show="{key}"{" selected" if key == chosen else ""}>{label}</option>'
                      for key, label, _ in SHORTCUT_GROUPS)
    lists = ''.join(f'<ol data-variant="{key}" data-variant-group="ios-steps"{"" if key == chosen else " hidden"}>'
                    + ''.join(f'<li>{step}</li>' for step in steps) + '</ol>'
                    for key, _, steps in SHORTCUT_GROUPS)
    return (f'<div class="field variant-field"><label for="ios-version">iOS version</label>'
            f'<select id="ios-version" data-variant-select="ios-steps" aria-describedby="ios-detected">{options}'
            f'</select></div><p id="ios-detected" class="field-hint">{detected}</p>{lists}')


def _setup(handler, state) -> None:
    from .web_unlock import _page
    origin = getattr(state, 'origin', None)
    token = parse_qs(urlsplit(handler.path).query).get('token', [''])[0]
    setup = state.broker.sms.setup(token) if handler._identity_ok() and handler.command == 'GET' else None
    if setup is None or not isinstance(origin, str):
        handler._send(HTTPStatus.NOT_FOUND, _page('Not found', '<p>This SMS setup link is not valid any more. '
                                                  'Ask your agent for a new one.</p>'))
        return
    url = webhook_url(origin, setup.token)
    if setup.kind == 'shortcut':
        instructions = _shortcut_steps(ios_major(handler.headers.get('User-Agent', '')))
    else:
        steps = TWILIO_STEPS if setup.kind == 'twilio' else WEBHOOK_STEPS
        instructions = '<ol>' + ''.join(f'<li>{step}</li>' for step in steps) + '</ol>'
    body = (f'<p>Set up the SMS source <strong>{html.escape(setup.source)}</strong>. Texts it forwards reach only '
            'this AKDBX broker. AKDBX keeps the verification code for ten minutes and never shows it to the agent.</p>'
            + _copy_box('Webhook URL (keep it private). Tap to copy.', url)
            + instructions
            + f'<p>Anyone with this URL can send texts to AKDBX. This page closes {SETUP_TTL // 3600} hour after it was '
              'made. Ask your agent to replace the source if the URL leaks.</p>')
    handler._send(HTTPStatus.OK, _page('Set up SMS verification', body))
