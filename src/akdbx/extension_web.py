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
    from .unlock_keys import ChallengeChanged
    from .hardware_key import TOUCH_TIMEOUT, HardwareKeyError
    from .web_unlock import (HARDWARE_CHANGED, KEY_FIELDS, OPEN_FAILED, _page, _submit, body_limit, call_opener,
                             computer_name, hardware_problem, is_multipart, keys_section, parse_unlock_body,
                             unlock_credentials)
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

    def form(error='', keys_open=False):
        action = ROUTE + '?token=' + html.escape(token, quote=True)
        message = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ''
        unlock = '<p>The vault is locked: this also unlocks it.</p>' if broker.locked else ''
        # Only an unlock can use a key file or hardware key; pairing an
        # unlocked broker checks the master password it holds.
        keys = keys_section(state, open_section=keys_open) if broker.locked else ''
        encoding = ' enctype="multipart/form-data"' if keys else ''
        # The unlock page's form and button: the shared script posts it, shows the busy
        # state and then replaces the sheet with the result page (success or error).
        return (f'{message}<p>A browser extension asks to fill from akdbx. Continue only if the akdbx '
                f'extension popup on this computer shows this code:</p><p><strong>{html.escape(code)}</strong></p>'
                f'{unlock}<form data-unlock-form data-wait-text="{WAIT}" data-unconfirmed-text="{UNCONFIRMED}" '
                f'method="post" action="{action}"{encoding} autocomplete="off">'
                + field('Master password', 'password', autocomplete='current-password', autofocus=True) + keys +
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
        if ((handler.headers.get('Content-Type', '').split(';')[0] != 'application/x-www-form-urlencoded'
                and not is_multipart(handler.headers))
                or not 0 < length <= body_limit(handler.headers, MAX_BODY)):
            raise ValueError
        raw = handler.rfile.read(length)
        if len(raw) != length:
            raise ValueError
        values = parse_unlock_body(handler.headers, raw)
        raw = b''
        if not {'password', 'confirmed'} <= set(values) <= {'password', 'confirmed'} | KEY_FIELDS \
                or values.pop('confirmed') != ['yes']:
            raise ValueError
        password, keys = unlock_credentials(values, state.keyfile)
        values = None
        if password is None and not broker.locked:
            raise ValueError  # Pairing an unlocked broker checks the master password it holds.
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
            keys_used = keys is not None
            if broker.locked:
                if keys is not None and keys.broker_key and hasattr(handler, 'server'):
                    handler.server.extend_request(handler.request, TOUCH_TIMEOUT + 5)
                try:
                    vault = call_opener(state, password, keys)
                except Exception as exc:
                    password = keys = None
                    if isinstance(exc, (ChallengeChanged, HardwareKeyError)):
                        # No response, or one for another challenge: not a failed attempt.
                        state.cancel_attempt(attempt)
                        send(HTTPStatus.CONFLICT, form(HARDWARE_CHANGED if isinstance(exc, ChallengeChanged)
                                                       else hardware_problem(exc, computer_name()), keys_open=True))
                        return True
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
                # Keys from a page that was opened while the vault was locked
                # are not checked: the held master password decides.
                held = getattr(broker.vault, 'password', None)
                ok = isinstance(held, str) and bool(held) and isinstance(password, str) and hmac.compare_digest(
                    password.encode('utf-8'), held.encode('utf-8'))
            password = keys = None
            if not ok:
                if state.record_failure(attempt) or state.blocked:
                    send(HTTPStatus.FORBIDDEN, blocked)
                    return True
                send(HTTPStatus.UNAUTHORIZED, form(
                    'AKDBX could not unlock the vault. Check the master password, key file and hardware '
                    'key.' if keys_used and broker.locked else 'The master password is not correct.',
                    keys_open=keys_used and broker.locked))
                return True
        if not hub.approve(token):
            send(HTTPStatus.NOT_FOUND, '<p>This pairing request expired. Open akdbx in the browser again.</p>')
            return True
        send(HTTPStatus.OK, '<p>The extension is paired with akdbx until the browser or the broker restarts. '
                            'You may close this page.</p>', SUCCESS_TITLE)
        return True
    finally:
        state.cancel_attempt(attempt)
