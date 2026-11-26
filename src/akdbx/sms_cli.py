"""SMS verification CLI: sources, waits and fills. It never prints a code or token."""
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import browser_slots, page_url
from .browser_card import TTL, failure
from .browser_code import DELIVERY, FIELDS
from .target import failure as x11_failure
from .sms import KINDS, MAX_WAIT, MESSAGE_ID, NAME, PROTOCOL, RESULTS, ROUTE_SETUP, TOKEN
from .target import DELIVERY as WINDOW_DELIVERY
from .native_fields import DELIVERY as NATIVE_DELIVERY

COMMANDS = {'sms-add-source', 'sms-remove-source', 'sms-sources', 'sms-wait', 'pin-code-target', 'fill-sms-code',
            'subscribe-sms', 'sms-subscription-status', 'unsubscribe-sms', 'sms-test-page'}
SUBSCRIPTION_STATES = {'subscribed', 'pending', 'sending', 'delivered', 'failed', 'cancelled', 'expired'}
SUBSCRIPTION_ERRORS = {'unknown or expired sms subscription',
                       'sms notification protocol 1 and a valid source name or none required',
                       'unlock notification protocol 1 required',
                       'webhook must be an HTTPS URL without credentials or fragment',
                       'subscription TTL must be 0 (until unlock/cancel) or 60–3600 seconds',
                       'sms notifications stopped', 'sms subscription limit reached',
                       'notification could not be saved; subscription not registered'}
PIN_ARGS = ('page_id', 'frame_id', 'top_url', 'frame_url', 'selector', 'field')
TARGET_REFUSED = failure(kind='code')
TARGET_UNCERTAIN = failure(True, kind='code')


def _name(text):
    import argparse
    if not NAME.fullmatch(text):
        raise argparse.ArgumentTypeError('use 1-32 lowercase letters, digits or hyphens')
    return text


def add_parsers(commands):
    p = commands.add_parser('sms-add-source', help='add a phone number that forwards verification texts; '
                                                   'returns a private setup page or fills the webhook URL')
    p.add_argument('name', type=_name, help='short label, for example iphone or twilio-us')
    p.add_argument('--kind', required=True, choices=KINDS,
                   help='shortcut: your own iPhone (iOS Shortcuts automation; recommended); '
                        'twilio: a Twilio virtual number; webhook: any other service that can POST')
    p.add_argument('--replace', action='store_true', help='issue a new webhook URL for an existing source')
    p.add_argument('--target', help='fresh pin-code-target token for a webhook-url field: type the URL there '
                                    'instead of returning a setup page (for example the Twilio Console)')
    p = commands.add_parser('sms-test-page', help='a private page that waits for a test text from a working source '
                                                  'and shows when its code arrives; the webhook URL stays the same')
    p.add_argument('name', type=_name)
    p = commands.add_parser('sms-remove-source', help='remove an SMS source; its webhook URL stops working')
    p.add_argument('name', type=_name)
    commands.add_parser('sms-sources', help='list SMS sources (names and kinds; never tokens)')
    p = commands.add_parser('sms-wait', help='list received verification texts (masked previews, no codes); '
                                             'optionally wait for the first one')
    since = p.add_mutually_exclusive_group()
    since.add_argument('--since', type=float, help='only texts received at or after this Unix time (seconds)')
    since.add_argument('--recent', type=int, metavar='SECONDS', help='only texts from the last SECONDS seconds')
    p.add_argument('--source', type=_name, help='only texts from this source')
    p.add_argument('--timeout', type=int, default=0,
                   help=f'wait up to this many seconds (0-{MAX_WAIT}) for the first matching text; default 0')
    p = commands.add_parser('pin-code-target', help='pin one focused HTTPS input for a verification code '
                                                    '(or a webhook URL); cdp route')
    for key in ('page_id', 'frame_id', 'selector'):
        p.add_argument('--' + key.replace('_', '-'), required=True)
    page_url.add(p, 'top-url', required=True, help='exact observed top-level page URL, query and fragment included')
    page_url.add(p, 'frame-url', required=True, help='exact frame URL (the top URL for a main-frame field)')
    p.add_argument('--field', choices=FIELDS, default='one-time-code')
    browser_slots.add_argument(p)
    p = commands.add_parser('fill-sms-code', help='fill the code of one received text; returns no code')
    p.add_argument('message', help='message id from sms-wait')
    p.add_argument('--target', required=True,
                   help='fresh pin-code-target, native code control, Android pin --mode sms, '
                        'or window pin-target token')
    page_url.add(p, 'target-url', required=False,
                 help='independently verified HTTPS challenge URL; required with an Android or window pin-target token')
    p = commands.add_parser('subscribe-sms', help='register a one-shot HTTPS webhook for the next verification text '
                                                  '(event akdbx.sms-received with the message id; never the code)')
    p.add_argument('--webhook-url-file', required=True, type=Path,
                   help='owned mode-0600 file containing the private callback URL')
    p.add_argument('--source', type=_name, help='only texts from this source; default: any source')
    since = p.add_mutually_exclusive_group()
    since.add_argument('--since', type=float, help='a text already received at or after this Unix time sends the '
                                                   'event at once')
    since.add_argument('--recent', type=int, metavar='SECONDS',
                       help='a text already received in the last SECONDS seconds sends the event at once')
    p.add_argument('--ttl', type=int, default=0,
                   help='0 waits until a text or cancel (default); 60–3600 seconds only for an explicitly '
                        'time-limited wait')
    for name in ('sms-subscription-status', 'unsubscribe-sms'):
        p = commands.add_parser(name, help='inspect/cancel a one-shot SMS subscription')
        p.add_argument('subscription_id')


def _token(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def _setup_url(value):
    if not isinstance(value, str):
        return False
    url = urlsplit(value)
    return url.path == ROUTE_SETUP and re.fullmatch(r'token=[A-Za-z0-9_-]{43}', url.query) is not None


def _iso(value):
    return isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value) is not None


def _failure_receipt(response):
    error = response.get('error')
    if response in (TARGET_REFUSED, TARGET_UNCERTAIN, x11_failure(False), x11_failure(True)):
        return True
    if not isinstance(error, str) or len(error) > 300:
        return False
    allowed = {'ok', 'error', 'unlock_url', 'unlock_blocked', 'unlock_origin'} if error == 'vault locked' else {'ok', 'error'}
    return set(response) <= allowed


def _subscription_receipt(args, response):
    if response.get('ok') is not True:
        if response.get('ok') is False and response.get('error') == 'vault locked':
            return _failure_receipt(response)  # keeps the private unlock link
        return (response.get('ok') is False and set(response) == {'ok', 'error'}
                and response['error'] in SUBSCRIPTION_ERRORS | {'SMS protocol 1 required', 'invalid SMS request'})
    keys = {'ok', 'subscription_id', 'state', 'attempts', 'source', 'message_id'}
    if args.command == 'subscribe-sms':
        keys.add('expires_in')
    return (set(response) == keys
            and isinstance(response['subscription_id'], str) and re.fullmatch('[a-f0-9]{32}', response['subscription_id'])
            and response['state'] in SUBSCRIPTION_STATES
            and type(response['attempts']) is int and 0 <= response['attempts'] <= 3
            and (response['source'] is None or isinstance(response['source'], str) and NAME.fullmatch(response['source']))
            and (response['message_id'] is None
                 or isinstance(response['message_id'], str) and MESSAGE_ID.fullmatch(response['message_id']))
            and (response.get('expires_in') is None
                 or type(response['expires_in']) is int and 0 <= response['expires_in'] <= 3600))


def valid_receipt(args, response):
    if args.command in {'subscribe-sms', 'sms-subscription-status', 'unsubscribe-sms'}:
        return _subscription_receipt(args, response)
    if response.get('ok') is not True:
        if response.get('ok') is not False:
            return False
        if args.command == 'sms-add-source' and {'name', 'kind'} <= set(response):
            # The source was saved but the webhook URL fill did not finish.
            rest = {k: v for k, v in response.items() if k not in {'name', 'kind', 'private_url'}}
            return response['name'] == args.name and _setup_url(response.get('private_url')) and _failure_receipt(rest)
        return _failure_receipt(response)
    if args.command == 'sms-add-source':
        base = {'ok', 'name', 'kind'}
        if response.get('name') != args.name or response.get('kind') != args.kind:
            return False
        if args.target is None:
            return set(response) == base | {'private_url'} and _setup_url(response['private_url'])
        return (set(response) == base | {'filled', 'code_delivery'} and response['filled'] == 'webhook-url'
                and response['code_delivery'] == DELIVERY)
    if args.command == 'sms-test-page':
        return (set(response) == {'ok', 'name', 'private_url'} and response['name'] == args.name
                and _setup_url(response['private_url']))
    if args.command == 'sms-remove-source':
        return set(response) == {'ok', 'removed'} and type(response['removed']) is bool
    if args.command == 'sms-sources':
        rows = response.get('sources')
        return (set(response) == {'ok', 'sources'} and isinstance(rows, list) and all(
            isinstance(r, dict) and {'name', 'kind', 'created'} <= set(r) <= {'name', 'kind', 'created', 'last_received',
                                                                         'last_result'}
            and NAME.fullmatch(str(r['name'])) and r['kind'] in KINDS
            and r.get('last_result', 'code') in RESULTS for r in rows))
    if args.command == 'sms-wait':
        rows = response.get('messages')
        keys = {'id', 'source', 'sender', 'preview', 'code_length', 'received_at', 'age_seconds'}
        return (set(response) == {'ok', 'messages'} and isinstance(rows, list) and all(
            isinstance(r, dict) and set(r) == keys and MESSAGE_ID.fullmatch(str(r['id']))
            and isinstance(r['sender'], str) and isinstance(r['preview'], str) and not re.search(r'\d', r['preview'])
            and type(r['code_length']) is int and 4 <= r['code_length'] <= 8 and _iso(r['received_at'])
            and type(r['age_seconds']) is int for r in rows))
    if args.command == 'pin-code-target':
        return (set(response) == {'ok', 'field', 'target', 'expires_in', 'code_delivery'}
                and response['field'] == args.field and _token(response['target'])
                and response['expires_in'] == TTL and response['code_delivery'] == DELIVERY)
    if args.command == 'fill-sms-code':
        from .android_route import CHROME_DELIVERY as ANDROID_CHROME, DELIVERY as ANDROID_APP
        return response in (dict(ok=True, filled='one-time-code', code_delivery=DELIVERY),
                            dict(ok=True, filled='one-time-code', code_delivery=NATIVE_DELIVERY),
                            dict(ok=True, filled='one-time-code', target_delivery=ANDROID_CHROME),
                            dict(ok=True, filled='one-time-code', target_delivery=ANDROID_APP),
                            dict(ok=True, filled='one-time-code', target_delivery=WINDOW_DELIVERY))
    return False


def run(args, request):
    try:
        caps = request({'action': 'ping'})
        if caps.get('ok') is not True or type(caps.get('sms_protocol')) is not int or caps['sms_protocol'] != PROTOCOL:
            print(json.dumps(dict(ok=False, error='broker lacks SMS protocol 1; request not sent')))
            return 1
        if args.command in {'subscribe-sms', 'sms-subscription-status', 'unsubscribe-sms'} and (
                caps.get('sms_notifications_supported') is not True
                or type(caps.get('sms_notifications_protocol')) is not int or caps['sms_notifications_protocol'] != 1):
            print(json.dumps(dict(ok=False, error='broker lacks SMS notification protocol 1; require broker 0.40.0 '
                                                  'or newer; subscription request not sent')))
            return 1
        payload = dict(action=args.command, sms_protocol=PROTOCOL)
        if args.command in {'sms-add-source', 'sms-remove-source', 'sms-test-page'}:
            payload['name'] = args.name
        if args.command == 'sms-add-source':
            payload['kind'] = args.kind
            if args.replace:
                payload['replace'] = True
            if args.target is not None:
                payload.update(target=args.target, target_protocol=1, start_deadline=time.monotonic() + 4)
        elif args.command == 'sms-wait':
            if not 0 <= args.timeout <= MAX_WAIT:
                print(json.dumps(dict(ok=False, error=f'--timeout must be 0-{MAX_WAIT}; request not sent')))
                return 1
            since = args.since if args.since is not None else (
                time.time() - args.recent if args.recent is not None else None)
            if since is not None:
                payload['since'] = since
            if args.source is not None:
                payload['source'] = args.source
            payload['timeout'] = args.timeout
        elif args.command == 'pin-code-target':
            if caps.get('locked') is False and caps.get('code_browser_configured') is not True:
                print(json.dumps(dict(ok=False, error='broker has no browser profile for code fills; request not sent')))
                return 1
            payload.update({key: getattr(args, key) for key in PIN_ARGS})
            slot, refusal = browser_slots.request_field(args, caps, 'cdp')
            if refusal is not None:
                print(json.dumps(dict(ok=False, error=refusal)))
                return 1
            payload.update(slot)
        elif args.command == 'subscribe-sms':
            from .cli import _read_webhook_url
            try:
                url = _read_webhook_url(args.webhook_url_file)
            except (OSError, ValueError):
                print('could not read private webhook URL file; subscription not sent', file=sys.stderr)
                return 2
            payload.update(notification_protocol=1, webhook_url=url, ttl=args.ttl)
            if args.source is not None:
                payload['source'] = args.source
            since = args.since if args.since is not None else (
                time.time() - args.recent if args.recent is not None else None)
            if since is not None:
                payload['since'] = since
        elif args.command in {'sms-subscription-status', 'unsubscribe-sms'}:
            payload['subscription_id'] = args.subscription_id
        elif args.command == 'fill-sms-code':
            # Android SMS pins are advertised by the Android capabilities, not in sms_fill_routes.
            modes = caps.get('android_fill_modes')
            android = caps.get('android_devices_configured') is True and isinstance(modes, list) and 'sms' in modes
            if caps.get('sms_fill_routes') == [] and not android:
                print(json.dumps(dict(ok=False, error='broker has no SMS fill route; request not sent')))
                return 1
            if not MESSAGE_ID.fullmatch(args.message):
                print(json.dumps(dict(ok=False, error='message id must be 32 lowercase hex characters; request not sent')))
                return 1
            payload.update(message=args.message, target=args.target, target_protocol=1,
                           start_deadline=time.monotonic() + 4)
            if args.target_url is not None:
                payload['target_url'] = args.target_url
        response = request(payload)
        if not valid_receipt(args, response):
            raise ValueError
    except Exception:
        print('SMS operation outcome unconfirmed; response withheld. Do not retry a fill automatically.', file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1


__all__ = ['COMMANDS', 'add_parsers', 'run', 'valid_receipt', 'TOKEN']
