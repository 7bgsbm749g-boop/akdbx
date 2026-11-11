"""Strict, receipt-only CLI for card operations; no secret arguments."""
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from .browser_card import DELIVERY, failure
from .cards import FILL_FIELDS
from .card_notifications import RESULTS

NOTIFICATIONS = {'subscribe-card-save', 'card-save-subscription-status', 'unsubscribe-card-save'}
COMMANDS = {'create-card', 'update-card', 'search-cards', 'pin-card-target', 'fill-card'} | NOTIFICATIONS
ERRORS = {'vault locked', 'save outcome uncertain; restart and unlock', 'request failed',
          'card operation refused; check selection and destination', 'card operation failed',
          failure()['error'], failure(True)['error']}
ERRORS |= {'unknown or expired card write', 'unknown or expired card-save subscription',
           'card-save notification protocol 1 and exact write handle required',
           'webhook must be an HTTPS URL without credentials or fragment',
           'card-save notifications stopped', 'card-save subscription limit reached',
           'notification could not be saved; subscription not registered'}


def add_parsers(commands):
    p = commands.add_parser('subscribe-card-save', help='resume through a one-shot HTTPS webhook after a private card save result')
    p.add_argument('write_handle')
    p.add_argument('--webhook-url-file', required=True, type=Path)
    for name in ('card-save-subscription-status', 'unsubscribe-card-save'):
        p = commands.add_parser(name, help='inspect/cancel a one-shot card-save subscription')
        p.add_argument('subscription_id')
    for name in ('create-card', 'update-card'):
        p = commands.add_parser(name, help='prepare a private card save page')
        if name == 'update-card':
            p.add_argument('handle')
        p.add_argument('--title', required=True)
        p.add_argument('--group', required=True)
    p = commands.add_parser('search-cards', help='find cards by non-secret label, brand or last four digits')
    p.add_argument('query', nargs='?', default='')
    p = commands.add_parser('pin-card-target', help='pin one exact HTTPS DOM payment field; no keyboard delivery')
    for name in ('page-id', 'frame-id', 'top-url', 'frame-url', 'selector'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--field', required=True, choices=FILL_FIELDS)
    p = commands.add_parser('fill-card', help='fill only the pinned card field; never types keys or submits')
    p.add_argument('handle')
    p.add_argument('--target', required=True)
    p.add_argument('--field', required=True, choices=FILL_FIELDS)
    p.add_argument('--format', choices=('MM/YY', 'MM/YYYY', 'YY', 'YYYY'))


def valid_receipt(command, response, args):
    if response.get('ok') is not True:
        return (response.get('ok') is False and response.get('error') in ERRORS
                and set(response) <= {'ok', 'error', 'unlock_url', 'delivery'}
                and response.get('delivery', 'not-started') in {'not-started', 'uncertain'})
    if command in NOTIFICATIONS:
        keys = {'ok', 'subscription_id', 'state', 'attempts', 'result'}
        if command == 'subscribe-card-save':
            keys.add('expires_in')
        return (set(response) == keys
                and isinstance(response.get('subscription_id'), str)
                and re.fullmatch('[a-f0-9]{32}', response['subscription_id'])
                and response.get('state') in {'subscribed', 'pending', 'sending', 'delivered', 'failed', 'cancelled', 'expired'}
                and type(response.get('attempts')) is int and 0 <= response['attempts'] <= 3
                and (response.get('result') is None or response['result'] in RESULTS)
                and response.get('expires_in') is None)
    if command in {'create-card', 'update-card'}:
        return (set(response) == {'ok', 'state', 'write_handle', 'private_url'} and response.get('state') == 'pending'
                and isinstance(response.get('write_handle'), str) and re.fullmatch('[a-f0-9]{64}', response['write_handle'])
                and urlsplit(response.get('private_url', '')).path == '/card')
    if command == 'fill-card':
        return (set(response) == {'ok', 'filled', 'card_delivery'}
                and response.get('card_delivery') == DELIVERY and response.get('filled') == args.field)
    if command == 'pin-card-target':
        return (set(response) == {'ok', 'target', 'expires_in', 'field', 'card_delivery'}
                and isinstance(response.get('target'), str) and re.fullmatch('[a-f0-9]{64}', response['target'])
                and type(response.get('expires_in')) is int and response['expires_in'] == 30
                and response.get('field') == args.field and response.get('card_delivery') == DELIVERY)
    if set(response) != {'ok', 'entries'} or not isinstance(response['entries'], list) or len(response['entries']) > 20:
        return False
    for entry in response['entries']:
        if (not isinstance(entry, dict) or set(entry) != {'handle', 'title', 'group', 'brand', 'last_four'}
                or any(not isinstance(v, str) or len(v.encode()) > 4096 for v in entry.values())
                or not re.fullmatch('[a-f0-9]{64}', entry['handle'])
                or not re.fullmatch('[0-9]{4}', entry['last_four']) or entry['brand'] not in {'visa', 'mastercard', 'amex', 'other'}):
            return False
    return True


def run(args, request):
    try:
        caps = request({'action': 'ping'})
        if args.command in NOTIFICATIONS:
            if (caps.get('ok') is not True or caps.get('card_save_notifications_supported') is not True
                    or type(caps.get('card_save_notifications_protocol')) is not int
                    or caps['card_save_notifications_protocol'] != 1
                    or caps.get('card_save_notifications_until_result') is not True):
                print(json.dumps(dict(ok=False, error='broker lacks card-save notification protocol 1; subscription request not sent')))
                return 1
            payload = dict(action=args.command)
            if args.command == 'subscribe-card-save':
                from .cli import _read_webhook_url
                payload.update(write_handle=args.write_handle, notification_protocol=1,
                               webhook_url=_read_webhook_url(args.webhook_url_file))
            else:
                payload['subscription_id'] = args.subscription_id
            response = request(payload)
            if not valid_receipt(args.command, response, args):
                raise ValueError
            print(json.dumps(response, indent=2))
            return 0 if response['ok'] else 1
        if (caps.get('ok') is not True or caps.get('cards_supported') is not True
                or type(caps.get('card_protocol')) is not int or caps['card_protocol'] != 1
                or caps.get('card_delivery') != DELIVERY):
            print(json.dumps(dict(ok=False, error='broker lacks card protocol 1; card request not sent')))
            return 1
        payload = dict(action=args.command, card_protocol=1)
        if args.command in {'create-card', 'update-card'}:
            payload['metadata'] = dict(title=args.title, group=args.group)
            if args.command == 'update-card':
                payload['handle'] = args.handle
        elif args.command == 'search-cards':
            payload['query'] = args.query
        elif args.command == 'pin-card-target':
            payload.update({k: getattr(args, k) for k in ('page_id', 'frame_id', 'top_url', 'frame_url', 'selector', 'field')})
        else:
            payload.update(handle=args.handle, target=args.target, field=args.field, start_deadline=time.monotonic() + 4)
            if args.format is not None:
                payload['format'] = args.format
        response = request(payload)
        if not valid_receipt(args.command, response, args):
            raise ValueError
    except Exception:
        print('Card operation outcome unconfirmed; response withheld. Do not retry a fill automatically.', file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1
