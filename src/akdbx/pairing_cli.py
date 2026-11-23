"""Receipt-only CLI for extension-pairing webhooks (0.33.0)."""
import json
import re
import sys
from pathlib import Path

from .pairing_notifications import BROWSERS, CODE

COMMANDS = {'subscribe-pairing', 'pairing-subscription-status', 'unsubscribe-pairing'}
STATES = {'subscribed', 'pending', 'sending', 'delivered', 'failed', 'cancelled', 'expired'}
ERRORS = {'unknown or expired pairing subscription',
          'pairing notification protocol 1 and a valid pairing code or none required',
          'unlock notification protocol 1 required',
          'webhook must be an HTTPS URL without credentials or fragment',
          'subscription TTL must be 0 (until unlock/cancel) or 60–3600 seconds',
          'pairing notifications stopped', 'pairing subscription limit reached',
          'notification could not be saved; subscription not registered'}


def add_parsers(commands):
    p = commands.add_parser('subscribe-pairing',
                            help='register a one-shot HTTPS webhook for when a browser extension is paired and connected')
    p.add_argument('--webhook-url-file', required=True, type=Path,
                   help='owned mode-0600 file containing the private callback URL')
    p.add_argument('--code', help="wait for the browser with this pairing code (status 'extension_pairing'); "
                                  'default: any browser')
    p.add_argument('--ttl', type=int, default=0,
                   help='0 waits until a pairing or cancel (default); 60–3600 seconds only for an explicitly '
                        'time-limited wait')
    for name in ('pairing-subscription-status', 'unsubscribe-pairing'):
        p = commands.add_parser(name, help='inspect/cancel a one-shot pairing subscription')
        p.add_argument('subscription_id')


def valid_receipt(command, response):
    if response.get('ok') is not True:
        return response.get('ok') is False and set(response) == {'ok', 'error'} and response['error'] in ERRORS
    keys = {'ok', 'subscription_id', 'state', 'attempts', 'code', 'browser'}
    if command == 'subscribe-pairing':
        keys.add('expires_in')
    return (set(response) == keys
            and isinstance(response['subscription_id'], str) and re.fullmatch('[a-f0-9]{32}', response['subscription_id'])
            and response['state'] in STATES
            and type(response['attempts']) is int and 0 <= response['attempts'] <= 3
            and (response['code'] is None or isinstance(response['code'], str) and CODE.fullmatch(response['code']))
            and (response['browser'] is None or response['browser'] in BROWSERS)
            and (response.get('expires_in') is None
                 or type(response['expires_in']) is int and 0 <= response['expires_in'] <= 3600))


def run(args, request):
    if args.command == 'subscribe-pairing' and args.code is not None and not CODE.fullmatch(args.code):
        print(json.dumps(dict(ok=False, error='--code must be a pairing code such as ABCD-EFGH; subscription not sent')))
        return 2
    try:
        caps = request({'action': 'ping'})
        if (caps.get('ok') is not True or caps.get('pairing_notifications_supported') is not True
                or type(caps.get('pairing_notifications_protocol')) is not int
                or caps['pairing_notifications_protocol'] != 1
                or caps.get('pairing_notifications_until_paired') is not True):
            print(json.dumps(dict(ok=False, error='broker lacks pairing notification protocol 1; require broker '
                                                  '0.33.0 or newer; subscription request not sent')))
            return 1
        payload = dict(action=args.command)
        if args.command == 'subscribe-pairing':
            from .cli import _read_webhook_url
            try:
                url = _read_webhook_url(args.webhook_url_file)
            except (OSError, ValueError):
                print('could not read private webhook URL file; subscription not sent', file=sys.stderr)
                return 2
            payload.update(notification_protocol=1, webhook_url=url, ttl=args.ttl)
            if args.code is not None:
                payload['code'] = args.code
        else:
            payload['subscription_id'] = args.subscription_id
        response = request(payload)
        if not valid_receipt(args.command, response):
            raise ValueError
    except Exception:
        print('Pairing subscription outcome unconfirmed; response withheld.', file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1
