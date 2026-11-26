"""Receipt-only CLI for private save-page result webhooks (0.53.0)."""
import json
import re
import sys
from pathlib import Path

from .write_notifications import COMMANDS as _COMMANDS, PROTOCOL, RESULTS

COMMANDS = set(_COMMANDS)
STATES = {'subscribed', 'pending', 'sending', 'delivered', 'failed', 'cancelled', 'expired'}
ERRORS = {'unknown or expired private write', 'unknown or expired write subscription',
          'write notification protocol 1 and exact write handle required',
          'unlock notification protocol 1 required',
          'webhook must be an HTTPS URL without credentials or fragment',
          'write notifications stopped', 'write subscription limit reached',
          'notification could not be saved; subscription not registered'}


def add_parsers(commands):
    p = commands.add_parser('subscribe-write',
                            help='resume through a one-shot HTTPS webhook when a private save page '
                                 '(password, TOTP, identity or card) has a result')
    p.add_argument('write_handle')
    p.add_argument('--webhook-url-file', required=True, type=Path,
                   help='owned mode-0600 file containing the private callback URL')
    for name in ('write-subscription-status', 'unsubscribe-write'):
        p = commands.add_parser(name, help='inspect/cancel a one-shot save-page result subscription')
        p.add_argument('subscription_id')


def valid_receipt(command, response):
    if response.get('ok') is not True:
        return response.get('ok') is False and set(response) == {'ok', 'error'} and response['error'] in ERRORS
    keys = {'ok', 'subscription_id', 'state', 'attempts', 'result'}
    if command == 'subscribe-write':
        keys.add('expires_in')
    return (set(response) == keys
            and isinstance(response['subscription_id'], str) and re.fullmatch('[a-f0-9]{32}', response['subscription_id'])
            and response['state'] in STATES
            and type(response['attempts']) is int and 0 <= response['attempts'] <= 3
            and (response['result'] is None or response['result'] in RESULTS)
            and response.get('expires_in') is None)


def run(args, request):
    if args.command == 'subscribe-write' and not re.fullmatch('[a-f0-9]{64}', args.write_handle):
        print(json.dumps(dict(ok=False, error='write handle must be 64 hex characters; subscription not sent')))
        return 2
    try:
        caps = request({'action': 'ping'})
        if (caps.get('ok') is not True or caps.get('write_notifications_supported') is not True
                or type(caps.get('write_notifications_protocol')) is not int
                or caps['write_notifications_protocol'] != PROTOCOL
                or caps.get('write_notifications_until_result') is not True):
            print(json.dumps(dict(ok=False, error='broker lacks write notification protocol 1; require broker '
                                                  '0.53.0 or newer; subscription request not sent')))
            return 1
        payload = dict(action=args.command)
        if args.command == 'subscribe-write':
            from .cli import _read_webhook_url
            try:
                url = _read_webhook_url(args.webhook_url_file)
            except (OSError, ValueError):
                print('could not read private webhook URL file; subscription not sent', file=sys.stderr)
                return 2
            payload.update(write_handle=args.write_handle, notification_protocol=PROTOCOL, webhook_url=url)
        else:
            payload['subscription_id'] = args.subscription_id
        response = request(payload)
        if not valid_receipt(args.command, response):
            raise ValueError
    except Exception:
        print('Write subscription outcome unconfirmed; response withheld.', file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1
