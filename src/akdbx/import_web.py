"""Private import UI and local native-host ingestion. No keys in receipts."""
from __future__ import annotations

import html
import json
import os
from http import HTTPStatus
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from .portal import field
from .totp import https_origin

MAX_IMPORT_BODY = 64 * 1024
ROUTES = {'/totp/import', '/totp/review', '/totp/capture',
          '/totp/assets/jsQR.js', '/totp/assets/import.js'}


def handle_import(handler, state):
    from .web_unlock import _page
    parsed = urlsplit(handler.path)
    route = parsed.path
    if route not in ROUTES:
        return False

    def send(status, body):
        handler._send(status, _page('Private authenticator import', body), import_page=True)

    try:
        query = parse_qs(parsed.query, strict_parsing=True)
        if set(query) != {'token'} or len(query['token']) != 1 or len(query['token'][0]) > 128:
            raise ValueError
        token = query['token'][0]
        native = route == '/totp/capture'
        if native:
            from .cli import _peer_credentials
            # A separate, deliberately local-only ingestion path. It never
            # pretends to be a Tailscale user or accepts unlock credentials.
            if (_peer_credentials(handler.request)[1] != os.getuid()
                    or handler.command != 'POST' or handler.headers.get('Origin') is not None
                    or handler.headers.get('Tailscale-User-Login') is not None):
                raise ValueError
        elif not handler._identity_ok():
            raise ValueError
        if not native and handler.command == 'POST':
            origin = handler.headers.get('Origin')
            if not isinstance(origin, str):
                raise ValueError
            origin_parts = urlsplit(origin)
            if (origin_parts.path not in {'', '/'} or origin_parts.query or origin_parts.fragment
                    or https_origin(origin) != https_origin(state.broker.writes.public_base)):
                raise ValueError
        with state.broker._vault_lock:
            op = state.broker.writes.by_token(token, 'totp')
            if op is None or not state.broker.writes.available():
                raise ValueError
            if handler.command == 'GET' and route.startswith('/totp/assets/'):
                name = route.rsplit('/', 1)[1]
                body = files('akdbx').joinpath('import_assets', name).read_bytes()
                handler._send(HTTPStatus.OK, body, content_type='application/javascript', import_page=True)
                return True
            if handler.command == 'GET' and route == '/totp/import' and not op.import_candidates:
                suffix = '?token=' + html.escape(token, quote=True)
                body = ('<p>Copy an existing key. This does not reset the website or remove phone codes.</p>'
                        '<p>Select QR images (up to 8 files, 4 MiB each, 4096 pixels per side), or enter a setup key/URI. '
                        'Google multi-part exports need every part. Images are decoded on this device; only decoded data is submitted.</p>'
                        '<form method="post" action="/totp/import' + suffix + '" autocomplete="off">'
                        '<label>QR images <input id="images" type="file" accept="image/png,image/jpeg,image/webp" multiple></label>'
                        '<label>Or take a QR photo <input id="camera" type="file" accept="image/*" capture="environment"></label>'
                        + field('Or setup key / URI', 'manual', maxlength=8192, required=False, submitted=False) +
                        '<input id="payloads" name="payloads" type="hidden"><p id="message" role="status"></p>'
                        '<button id="decode" type="button">Read QR images</button><button>Review accounts</button></form>'
                        '<script src="/totp/assets/jsQR.js' + suffix + '"></script>'
                        '<script src="/totp/assets/import.js' + suffix + '"></script>')
                send(HTTPStatus.OK, body)
                return True
            if handler.command == 'GET':
                _review(send, op, token)
                return True
        length = int(handler.headers.get('Content-Length', '0'))
        content_type = handler.headers.get('Content-Type', '').split(';')[0]
        if not 0 < length <= MAX_IMPORT_BODY or content_type != ('application/json' if native else 'application/x-www-form-urlencoded'):
            raise ValueError
        raw = handler.rfile.read(length)
        if len(raw) != length or handler._expired():
            raise ValueError
        if native:
            values = json.loads(raw)
            if not isinstance(values, dict) or set(values) != {'payloads', 'source_url'} or not isinstance(values['source_url'], str):
                raise ValueError
        else:
            values = parse_qs(raw.decode('utf-8'), strict_parsing=True)
            if any(len(v) != 1 for v in values.values()):
                raise ValueError
        with state.broker._vault_lock:
            op = state.broker.writes.by_token(token, 'totp')
            if op is None or handler._expired():
                raise ValueError
            if route in {'/totp/import', '/totp/capture'}:
                if native:
                    source, payloads = values['source_url'], values['payloads']
                    _check_capture(source, payloads)
                else:
                    if set(values) != {'payloads'}:
                        raise ValueError
                    source, payloads = '', json.loads(values['payloads'][0])
                state.broker.writes.stage_totp_import(op, payloads, source)
                if native:
                    handler._send(HTTPStatus.OK, b'{"ok":true,"state":"awaiting-private-confirmation"}', content_type='application/json')
                else:
                    _review(send, op, token)
            elif route == '/totp/review':
                if set(values) != {'choice', 'nonce', 'confirmed'} or not values['choice'][0].isascii() or not values['choice'][0].isdigit():
                    raise ValueError
                result = state.broker.writes.confirm_totp_import(op, int(values['choice'][0]), values['nonce'][0], values['confirmed'] == ['yes'])
                # The same Success or Failure result page as the other saves.
                handler._send(HTTPStatus.OK if result['ok'] else HTTPStatus.CONFLICT, _page(
                    'Success', '<p>Authenticator saved to vault. You may close this page.</p>'
                    '<p>Website acceptance is not confirmed by this save.</p>') if result['ok'] else _page(
                    'Failure', '<p>Import not saved. Check status before starting again.</p>'), import_page=True)
            else:
                raise ValueError
    except Exception:
        # Decoder/JSON/transport diagnostics can contain submitted keys. The
        # same fixed result is used even for deep or otherwise hostile input.
        send(HTTPStatus.BAD_REQUEST, '<p>Import rejected, expired or unavailable. Use a complete supported export and a fresh request.</p>')
    return True


def _check_capture(source, payloads):
    """One browser-captured TOTP setup URI from a named HTTPS page."""
    if (not isinstance(source, str) or not source or not isinstance(payloads, list) or len(payloads) != 1
            or not isinstance(payloads[0], str) or not payloads[0].startswith('otpauth://totp/')):
        raise ValueError


def serve_capture_connection(connection, broker, deadline):
    """Answer one Windows capture-pipe request from the browser native host.

    The pipe is separate from the agent RPC endpoint and accepts one message
    type. The caller has verified that the peer runs as this user in this
    session, as the Linux route checks the peer UID. The answer is the fixed
    receipt or a fixed failure; neither holds a key or the reason.
    """
    import time
    from .protocol import receive_message, send_message
    result = {'ok': False}
    try:
        message = receive_message(connection, deadline=deadline)
        if (set(message) != {'type', 'token', 'source_url', 'payloads'} or message['type'] != 'totp-capture'
                or not isinstance(message['token'], str) or not 0 < len(message['token']) <= 128):
            raise ValueError
        _check_capture(message['source_url'], message['payloads'])
        with broker._vault_lock:
            op = broker.writes.by_token(message['token'], 'totp')
            if op is None or not broker.writes.available() or time.monotonic() > deadline:
                raise ValueError
            broker.writes.stage_totp_import(op, message['payloads'], message['source_url'])
        result = {'ok': True, 'state': 'awaiting-private-confirmation'}
    except Exception:
        pass  # Decoder and transport errors can contain submitted keys.
    try:
        send_message(connection, result)
    except Exception:
        pass


def _review(send, op, token):
    if not op.import_candidates:
        send(HTTPStatus.CONFLICT, '<p>No captured import. Open the import page first.</p>')
        return
    destination = ''.join('<dt>' + html.escape(k) + '</dt><dd>' + html.escape(v) + '</dd>' for k, v in op.values.items())
    options = ''.join('<label><input type="radio" name="choice" value="' + str(i) + '" required>'
                      + html.escape(c.issuer + ' — ' + c.label) + '</label>' for i, c in enumerate(op.import_candidates))
    warning = '<p>This explicitly replaces the saved key in this vault entry.</p>' if op.replace else ''
    send(HTTPStatus.OK, '<dl>' + destination + '</dl><p>Source: ' + html.escape(op.import_source) + '</p>' + warning
         + '<p>Choose exactly one account for this destination. Labels are supplied by the import and do not prove account ownership. '
         'Other imported accounts will be discarded. Your phone setup is not changed.</p>'
         + '<form method="post" action="/totp/review?token=' + html.escape(token, quote=True) + '">' + options
         + '<input type="hidden" name="nonce" value="' + html.escape(op.import_nonce, quote=True) + '">'
         + '<label><input type="checkbox" name="confirmed" value="yes" required>I confirm this account and vault destination</label>'
         + '<button>Save selected authenticator</button></form>')
