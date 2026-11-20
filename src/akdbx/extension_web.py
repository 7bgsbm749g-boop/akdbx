"""Private HTTPS page that pairs a browser extension key with the broker.

The extension shows a code; this page shows the same code and asks for the
master password. A locked broker unlocks with the same entry. The password is
checked against the one the broker holds and is never stored or returned.
Failed attempts share the unlock page's rate limit.
"""
from __future__ import annotations

import hmac
import html
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from .portal import field

ROUTE = '/extension/pair'
MAX_BODY = 4096


def handle_pairing(handler, state):
    from .totp import https_origin
    from .web_unlock import _page
    if urlsplit(handler.path).path != ROUTE:
        return False
    broker = state.broker
    hub = broker.extension

    def send(status, body):
        handler._send(status, _page('Pair the akdbx extension', body))

    identity = handler._identity()
    token = handler._token()
    code = hub.pairing_code(token)
    if not identity or code is None or handler.command not in {'GET', 'POST'}:
        send(HTTPStatus.NOT_FOUND, '<p>This pairing link is not valid any more. A link expires after ten minutes '
                                   'or when the broker restarts.</p><p>Click the akdbx extension button again, then '
                                   'choose <strong>Open the pairing page</strong> for a new link.</p>')
        return True

    def form(error=''):
        action = ROUTE + '?token=' + html.escape(token, quote=True)
        message = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ''
        unlock = '<p>The vault is locked: this also unlocks it.</p>' if broker.locked else ''
        return (f'{message}<p>A browser extension asks to fill from akdbx. Continue only if the akdbx '
                f'extension popup on this computer shows this code:</p><p><strong>{html.escape(code)}</strong></p>'
                f'{unlock}<form method="post" action="{action}" autocomplete="off">'
                + field('Master password', 'password', autocomplete='current-password', autofocus=True) +
                '<label><input type="checkbox" name="confirmed" value="yes" required>'
                'The extension shows this code</label><button>Pair the extension</button></form>')

    if handler.command == 'GET':
        send(HTTPStatus.OK, form())
        return True
    try:
        origin = handler.headers.get('Origin')
        base = getattr(broker.writes, 'public_base', None)
        if not isinstance(origin, str) or not isinstance(base, str) or https_origin(origin) != https_origin(base):
            raise ValueError
        length = int(handler.headers.get('Content-Length', '0'))
        if (handler.headers.get('Content-Type', '').split(';')[0] != 'application/x-www-form-urlencoded'
                or not 0 < length <= MAX_BODY):
            raise ValueError
        raw = handler.rfile.read(length)
        if len(raw) != length:
            raise ValueError
        values = parse_qs(raw.decode('utf-8'), strict_parsing=True, errors='strict')
        if set(values) != {'password', 'confirmed'} or any(len(v) != 1 for v in values.values()) \
                or values['confirmed'] != ['yes'] or not values['password'][0]:
            raise ValueError
        password = values['password'][0]
    except Exception:
        send(HTTPStatus.BAD_REQUEST, '<p>Request rejected.</p>')
        return True
    if handler._expired():
        return True
    attempt = state.reserve_attempt(identity)
    if attempt is None:
        send(HTTPStatus.TOO_MANY_REQUESTS, form('Too many failed attempts. Wait one minute before trying again.'))
        return True
    try:
        with state.unlock_lock:
            if handler._expired():
                return True
            ok = False
            if broker.locked:
                try:
                    vault = state.opener(state.database, password, state.keyfile)
                    ok = broker.unlock(vault) or not broker.locked
                except Exception:
                    ok = False
                if ok:
                    state.record_success(attempt)
            else:
                held = getattr(broker.vault, 'password', None)
                ok = isinstance(held, str) and bool(held) and hmac.compare_digest(
                    password.encode('utf-8'), held.encode('utf-8'))
            password = ''
            if not ok:
                state.record_failure(attempt)
                send(HTTPStatus.UNAUTHORIZED, form('The master password is not correct.'))
                return True
        if not hub.approve(token):
            send(HTTPStatus.NOT_FOUND, '<p>This pairing request expired. Open akdbx in the browser again.</p>')
            return True
        send(HTTPStatus.OK, '<p>The extension is paired with akdbx until the browser or the broker restarts. '
                            'You may close this page.</p>')
        return True
    finally:
        state.cancel_attempt(attempt)
