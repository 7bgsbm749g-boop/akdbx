"""Identity CLI accepts labels and targets, never personal values."""
import json
import re
import sys
import time
from urllib.parse import urlsplit

from .browser_card import TTL, failure
from .browser_identity import DELIVERY
from .identities import COMMANDS, FAILED, FILL_FIELDS, REFUSED, label_matches
from .extension_route import DELIVERY as EXTENSION_DELIVERY, ROUTES

PIN_ARGS = ('page_id', 'frame_id', 'top_url', 'frame_url', 'selector', 'field')
ERRORS = {'vault locked', 'save outcome uncertain; restart and unlock', 'request failed', REFUSED, FAILED}
TARGET_REFUSED = failure(kind='identity')
TARGET_UNCERTAIN = failure(True, kind='identity')


def add_parsers(commands):
    p = commands.add_parser('create-identity', help='prepare a private identity and address save page')
    p.add_argument('--title', required=True, help='non-secret label')
    p.add_argument('--group', required=True, help='existing group path')
    p = commands.add_parser('search-identities', help='find identities by non-secret label')
    p.add_argument('query')
    p.add_argument('--group', help='limit matches to this exact group path')
    p.add_argument('--exact', action='store_true', help='match the entire label, including case')
    p = commands.add_parser('pin-identity-target', help='pin one focused HTTPS identity field')
    for key in PIN_ARGS[:-1]:
        p.add_argument('--' + key.replace('_', '-'), required=key != 'frame_url',
                       **({'help': 'exact frame URL; required on the cdp route, optional on the extension route'}
                          if key == 'frame_url' else {}))
    p.add_argument('--field', required=True, choices=FILL_FIELDS)
    p.add_argument('--route', choices=ROUTES, help="cdp (debugging port) or extension (paired browser extension); default: the broker's")
    p = commands.add_parser('fill-identity', help='fill the pinned DOM field without sending keys or submitting')
    p.add_argument('handle')
    p.add_argument('--target', required=True)
    p.add_argument('--field', required=True, choices=FILL_FIELDS)


def _token(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def valid_receipt(args, response):
    if response.get('ok') is not True:
        if response.get('ok') is not False:
            return False
        if args.command in {'pin-identity-target', 'fill-identity'} and response == TARGET_REFUSED:
            return True
        if args.command == 'fill-identity' and response == TARGET_UNCERTAIN:
            return True
        error = response.get('error')
        allowed = {'ok', 'error', 'unlock_url', 'unlock_blocked'} if error == 'vault locked' else {'ok', 'error'}
        return error in ERRORS and set(response) <= allowed
    if args.command == 'create-identity':
        if set(response) != {'ok', 'state', 'write_handle', 'private_url'}:
            return False
        url = urlsplit(response['private_url'])
        return (response['state'] == 'pending' and _token(response['write_handle'])
                and url.path == '/identity' and re.fullmatch(r'token=[A-Za-z0-9_-]{43}', url.query) is not None)
    if args.command == 'pin-identity-target':
        return (set(response) == {'ok', 'field', 'target', 'expires_in', 'identity_delivery'}
                and response['field'] == args.field and _token(response['target'])
                and type(response['expires_in']) is int and response['expires_in'] == TTL
                and response['identity_delivery'] == (EXTENSION_DELIVERY if getattr(args, 'resolved_route', 'cdp') == 'extension'
                                                      else DELIVERY))
    if args.command == 'fill-identity':
        return response in (dict(ok=True, filled=args.field, identity_delivery=DELIVERY),
                            dict(ok=True, filled=args.field, identity_delivery=EXTENSION_DELIVERY))
    if set(response) != {'ok', 'entries'} or not isinstance(response['entries'], list) or len(response['entries']) > 20:
        return False
    labels = set()
    handles = set()
    for entry in response['entries']:
        if (not isinstance(entry, dict) or set(entry) != {'handle', 'title', 'group'}
                or not _token(entry['handle'])
                or any(not isinstance(entry[k], str) or len(entry[k].encode()) > 4096 for k in ('title', 'group'))):
            return False
        label = (entry['title'], entry['group'])
        if (label in labels or entry['handle'] in handles
                or args.group is not None and entry['group'] != args.group
                or not label_matches(entry['title'], args.query, args.exact)):
            return False
        labels.add(label)
        handles.add(entry['handle'])
    return True


def run(args, request):
    try:
        caps = request({'action': 'ping'})
        if (caps.get('ok') is not True or type(caps.get('identity_protocol')) is not int
                or caps['identity_protocol'] != 1 or caps.get('identity_delivery') != DELIVERY):
            print(json.dumps(dict(ok=False, error='broker lacks identity protocol 1; request not sent')))
            return 1
        if args.command == 'pin-identity-target':
            args.resolved_route = args.route or caps.get('default_fill_route') or 'cdp'
            if args.resolved_route == 'extension' and (type(caps.get('extension_protocol')) is not int
                                                       or caps['extension_protocol'] != 1):
                print(json.dumps(dict(ok=False, error='broker lacks extension route protocol 1; request not sent')))
                return 1
            if args.resolved_route == 'cdp' and not args.frame_url:
                print(json.dumps(dict(ok=False, error='--frame-url is required on the cdp route; request not sent')))
                return 1
        extension_ready = (getattr(args, 'resolved_route', None) == 'extension' if args.command == 'pin-identity-target'
                           else caps.get('extension_paired') is True)
        if (caps.get('locked') is False and args.command in {'pin-identity-target', 'fill-identity'}
                and caps.get('identity_browser_configured') is not True and not extension_ready):
            print(json.dumps(dict(ok=False, error='broker has no identity browser profile; request not sent')))
            return 1
        payload = dict(action=args.command, identity_protocol=1)
        if args.command == 'create-identity':
            payload['metadata'] = dict(title=args.title, group=args.group)
        elif args.command == 'search-identities':
            payload['query'] = args.query
            if args.group is not None:
                payload['group'] = args.group
            if args.exact:
                payload['exact'] = True
        elif args.command == 'pin-identity-target':
            payload.update({key: getattr(args, key) for key in PIN_ARGS if getattr(args, key) is not None})
            if args.route is not None:
                payload['route'] = args.route
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
