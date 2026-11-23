"""Private HTTPS page that pairs a browser extension key with the broker.

The extension shows a code; this page shows the same code and asks for the
master password. A locked broker unlocks with the same entry. The password is
checked against the one the broker holds and is never stored or returned.
Failed attempts count toward the current unlock link's total of three: when
that link is blocked, this page refuses master-password attempts too, and a
block or a new link invalidates every pairing link issued before it. Only a
wrong password counts; a malformed form or a vault store error does not.
"""
from __future__ import annotations

import hmac
import html
from http import HTTPStatus
from urllib.parse import urlsplit

from .portal import field

ROUTE = '/extension/pair'
MAX_BODY = 4096
FORM_TITLE = 'Pair the akdbx extension'
SUCCESS_TITLE = 'Successfully paired'
# Status lines while the shared script posts the form (the unlock page has its own).
WAIT = 'Pairing the extension. Please wait.'
UNCONFIRMED = 'Pairing result not confirmed. Open the pairing page again from the akdbx extension.'


def handle_pairing(handler, state):
    from .broker import is_wrong_credentials
    from .totp import https_origin
    from .web_unlock import OPEN_FAILED, _page, _submit, parse_form
    if urlsplit(handler.path).path != ROUTE:
        return False
    broker = state.broker
    hub = broker.extension

    def send(status, body, title=FORM_TITLE):
        handler._send(status, _page(title, body))

    identity = handler._identity()
    token = handler._token()
    code = hub.pairing_code(token)
    if not identity or code is None or handler.command not in {'GET', 'POST'}:
        send(HTTPStatus.NOT_FOUND, '<p>This pairing link is not valid any more. A link expires after ten minutes '
                                   'or when the broker restarts, the unlock link is blocked or a new unlock link is made.</p><p>Click the akdbx extension button again, then '
                                   'choose <strong>Open the pairing page</strong> for a new link.</p>')
        return True

    def form(error=''):
        action = ROUTE + '?token=' + html.escape(token, quote=True)
        message = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ''
        unlock = '<p>The vault is locked: this also unlocks it.</p>' if broker.locked else ''
        # The unlock page's form and button: the shared script posts it, shows the busy
        # state and then replaces the sheet with the result page (success or error).
        return (f'{message}<p>A browser extension asks to fill from akdbx. Continue only if the akdbx '
                f'extension popup on this computer shows this code:</p><p><strong>{html.escape(code)}</strong></p>'
                f'{unlock}<form data-unlock-form data-wait-text="{WAIT}" data-unconfirmed-text="{UNCONFIRMED}" '
                f'method="post" action="{action}" autocomplete="off">'
                + field('Master password', 'password', autocomplete='current-password', autofocus=True) +
                '<label><input type="checkbox" name="confirmed" value="yes" required>'
                'The extension shows this code</label>' + _submit('Pair the extension', 'Pairing the extension\u2026') +
                '</form><p id="unlock-status" class="portal-status unlock-status" role="status" aria-live="polite"></p>')

    blocked = ('<p>Master-password attempts are blocked after three failures. Ask your agent for a new '
               'unlock link, then open the pairing page again. If you did not make these attempts, tell your '
               'agent: someone else has the link.</p>')
    if state.blocked:
        send(HTTPStatus.FORBIDDEN, blocked)
        return True
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
        values = parse_form(raw)
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
        if state.blocked:
            send(HTTPStatus.FORBIDDEN, blocked)
        else:
            send(HTTPStatus.TOO_MANY_REQUESTS, form('Another master-password attempt is in progress. Wait for its result.'))
        return True
    try:
        with state.unlock_lock:
            if handler._expired():
                return True
            # Recheck the pairing link and the block just before the password
            # check: either may have changed while this attempt waited.
            status = state.pairing_status(attempt, lambda: hub.pairing_code(token) is not None)
            if status != 'ready':
                password = ''
                if status == 'blocked':
                    send(HTTPStatus.FORBIDDEN, blocked)
                else:
                    send(HTTPStatus.NOT_FOUND, '<p>This pairing link is not valid any more. Click the akdbx '
                                               'extension button again for a new link.</p>')
                return True
            ok = False
            if broker.locked:
                try:
                    vault = state.opener(state.database, password, state.keyfile)
                except Exception as exc:
                    password = ''
                    if not is_wrong_credentials(exc):
                        # A store or I/O error is not a failed attempt.
                        state.cancel_attempt(attempt)
                        send(HTTPStatus.SERVICE_UNAVAILABLE, form(OPEN_FAILED))
                        return True
                else:
                    ok = broker.unlock(vault) or not broker.locked
                if ok:
                    state.record_success(attempt)
            else:
                held = getattr(broker.vault, 'password', None)
                ok = isinstance(held, str) and bool(held) and hmac.compare_digest(
                    password.encode('utf-8'), held.encode('utf-8'))
            password = ''
            if not ok:
                if state.record_failure(attempt) or state.blocked:
                    send(HTTPStatus.FORBIDDEN, blocked)
                    return True
                send(HTTPStatus.UNAUTHORIZED, form('The master password is not correct.'))
                return True
        if not hub.approve(token):
            send(HTTPStatus.NOT_FOUND, '<p>This pairing request expired. Open akdbx in the browser again.</p>')
            return True
        send(HTTPStatus.OK, '<p>The extension is paired with akdbx until the browser or the broker restarts. '
                            'You may close this page.</p>', SUCCESS_TITLE)
        return True
    finally:
        state.cancel_attempt(attempt)
