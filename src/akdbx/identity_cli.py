"""Identity CLI accepts labels and targets, never personal values."""
import json
import re
import sys
import time
from urllib.parse import urlsplit

from .browser_card import TTL, failure
from .browser_identity import DELIVERY
from .identities import COMMANDS, FAILED, FILL_FIELDS, REFUSED

PIN_ARGS = ('page_id', 'frame_id', 'top_url', 'frame_url', 'selector', 'field')
ERRORS = {'vault locked', 'save outcome uncertain; restart and unlock', 'request failed',
          REFUSED, FAILED, failure(kind='identity')['error'], failure(True, kind='identity')['error']}


def add_parsers(commands):
    p = commands.add_parser('create-identity', help='prepare a private identity and address save page')
    p.add_argument('--title', required=True, help='non-secret label')
    p.add_argument('--group', required=True, help='existing group path')
    p = commands.add_parser('search-identities', help='find identities by non-secret label')
    p.add_argument('query')
    p = commands.add_parser('pin-identity-target', help='pin one focused HTTPS identity field')
    for key in PIN_ARGS[:-1]:
        p.add_argument('--' + key.replace('_', '-'), required=True)
    p.add_argument('--field', required=True, choices=FILL_FIELDS)
    p = commands.add_parser('fill-identity', help='fill the pinned DOM field without sending keys or submitting')
    p.add_argument('handle')
    p.add_argument('--target', required=True)
    p.add_argument('--field', required=True, choices=FILL_FIELDS)


def _token(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def valid_receipt(args, response):
    if response.get('ok') is not True:
        return (response.get('ok') is False and response.get('error') in ERRORS
                and set(response) <= {'ok', 'error', 'unlock_url', 'delivery'}
                and response.get('delivery', 'not-started') in {'not-started', 'uncertain'})
    if args.command == 'create-identity':
        return (set(response) == {'ok', 'state', 'write_handle', 'private_url'}
                and response['state'] == 'pending' and _token(response['write_handle'])
                and urlsplit(response['private_url']).path == '/identity')
    if args.command == 'pin-identity-target':
        return (set(response) == {'ok', 'field', 'target', 'expires_in', 'identity_delivery'}
                and response['field'] == args.field and _token(response['target'])
                and type(response['expires_in']) is int and response['expires_in'] == TTL
                and response['identity_delivery'] == DELIVERY)
    if args.command == 'fill-identity':
        return response == dict(ok=True, filled=args.field, identity_delivery=DELIVERY)
    if set(response) != {'ok', 'entries'} or not isinstance(response['entries'], list) or len(response['entries']) > 20:
        return False
    return all(isinstance(entry, dict) and set(entry) == {'handle', 'title', 'group'}
               and _token(entry['handle']) and all(isinstance(entry[k], str) and len(entry[k].encode()) <= 4096
                                                 for k in ('title', 'group'))
               for entry in response['entries'])


def run(args, request):
    try:
        caps = request({'action': 'ping'})
        if (caps.get('ok') is not True or type(caps.get('identity_protocol')) is not int
                or caps['identity_protocol'] != 1 or caps.get('identity_delivery') != DELIVERY):
            print(json.dumps(dict(ok=False, error='broker lacks identity protocol 1; request not sent')))
            return 1
        if (caps.get('locked') is False and args.command in {'pin-identity-target', 'fill-identity'}
                and caps.get('identity_browser_configured') is not True):
            print(json.dumps(dict(ok=False, error='broker has no identity browser profile; request not sent')))
            return 1
        payload = dict(action=args.command, identity_protocol=1)
        if args.command == 'create-identity':
            payload['metadata'] = dict(title=args.title, group=args.group)
        elif args.command == 'search-identities':
            payload['query'] = args.query
        elif args.command == 'pin-identity-target':
            payload.update({key: getattr(args, key) for key in PIN_ARGS})
        else:
            payload.update(handle=args.handle, target=args.target, field=args.field, start_deadline=time.monotonic() + 4)
        response = request(payload)
        if not valid_receipt(args, response):
            raise ValueError
    except Exception:
        print('Identity operation outcome unconfirmed; response withheld. Do not retry a fill automatically.', file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1
