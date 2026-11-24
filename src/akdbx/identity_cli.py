"""Identity CLI accepts labels and targets, never personal values."""
import json
import re
import sys
import time
from urllib.parse import urlsplit

from .browser_card import TTL, failure
from .browser_identity import DELIVERY
from . import browser_slots, page_url
from .identities import (COMMANDS, FAILED, FIELD_PURPOSE_PROTOCOL, FIELDS, FIELDS_PROTOCOL, FILL_FIELDS, REFUSED,
                         TEL_FORMATS, UPDATE_PROTOCOL, label_matches)
from .extension_route import DELIVERY as EXTENSION_DELIVERY, ROUTES

PIN_ARGS = ('page_id', 'frame_id', 'top_url', 'frame_url', 'selector', 'field')
ERRORS = {'vault locked', 'save outcome uncertain; restart and unlock', 'request failed', REFUSED, FAILED}
TARGET_REFUSED = failure(kind='identity')
TARGET_UNCERTAIN = failure(True, kind='identity')


def add_parsers(commands):
    p = commands.add_parser('create-identity', help='prepare a private identity and address save page')
    p.add_argument('--title', required=True, help='non-secret label')
    p.add_argument('--group', required=True, help='existing group path')
    p.add_argument('--fields', type=field_list, metavar='FIELD[,FIELD...]',
                   help='show only these fields on the page, for example tel or tel,email; default: all. '
                        'Fields: ' + ', '.join(FIELDS))
    p = commands.add_parser('update-identity', help='prepare a private page that adds or changes chosen fields of one identity')
    p.add_argument('handle', help='fresh handle from search-identities')
    p.add_argument('--title', required=True, help='exact title of the selected identity')
    p.add_argument('--group', required=True, help='exact group path of the selected identity')
    p.add_argument('--fields', required=True, type=field_list, metavar='FIELD[,FIELD...]',
                   help='the fields to add or change, for example tel. Fields: ' + ', '.join(FIELDS))
    p = commands.add_parser('search-identities', help='find identities by non-secret label')
    p.add_argument('query')
    p.add_argument('--group', help='limit matches to this exact group path')
    p.add_argument('--exact', action='store_true', help='match the entire label, including case')
    p = commands.add_parser('pin-identity-target', help='pin one focused HTTPS identity field')
    for key in ('page_id', 'frame_id', 'selector'):
        p.add_argument('--' + key.replace('_', '-'), required=True)
    page_url.add(p, 'top-url', required=True, help='exact observed top-level page URL, query and fragment included')
    page_url.add(p, 'frame-url', required=False,
                 help='exact frame URL; required on the cdp route, optional on the extension route')
    p.add_argument('--field', required=True, choices=FILL_FIELDS)
    p.add_argument('--field-purpose', choices=FILL_FIELDS, metavar='FIELD',
                   help='you verified on the page that the field takes this detail (the same value as --field); '
                        'accepts a field with no autocomplete token or only "on"; a token for another detail still refuses')
    p.add_argument('--allow-autocomplete-off', action='store_true',
                   help='with --field-purpose: also accept autocomplete="off"')
    p.add_argument('--route', choices=ROUTES, help="cdp (debugging port) or extension (paired browser extension); default: the broker's")
    browser_slots.add_argument(p)
    p = commands.add_parser('fill-identity', help='fill the pinned DOM field without sending keys or submitting')
    p.add_argument('handle')
    p.add_argument('--target', required=True)
    p.add_argument('--field', required=True, choices=FILL_FIELDS)
    p.add_argument('--format', choices=TEL_FORMATS,
                   help='tel only: national fills the national significant number (digits only: no +, calling code '
                        'or trunk 0); international fills + calling code and that number; the saved value stays as it is')
    p.add_argument('--calling-code', metavar='DIGITS',
                   help='with --format: the country calling code the page\'s country picker shows, for example 44 '
                        'for +44; refuse unless the saved number has it; required when the saved number is in '
                        'national form with a trunk 0 (07...), which only some countries allow')


def field_list(text):
    """Comma-separated identity field keys, each once."""
    import argparse
    fields = [part.strip() for part in text.split(',')]
    unknown = [f for f in fields if f not in FIELDS]
    if not text.strip() or unknown or len(set(fields)) != len(fields):
        raise argparse.ArgumentTypeError('use comma-separated fields from: ' + ', '.join(FIELDS))
    return fields


def _option_refusal(args, caps):
    """Why the CLI refuses the pin or fill options before sending, or None."""
    if args.command == 'pin-identity-target':
        if args.allow_autocomplete_off and args.field_purpose is None:
            return '--allow-autocomplete-off needs --field-purpose'
        if args.field_purpose is not None and args.field_purpose != args.field:
            return '--field-purpose must name the same detail as --field'
        if args.field_purpose is not None and (type(caps.get('identity_field_purpose_protocol')) is not int
                                               or caps['identity_field_purpose_protocol'] != FIELD_PURPOSE_PROTOCOL):
            return 'broker lacks identity field purpose protocol 1'
    if args.command == 'fill-identity':
        if args.calling_code is not None and (args.format is None or not re.fullmatch('[1-9][0-9]{0,2}', args.calling_code)):
            return '--calling-code needs --format and 1 to 3 digits without +'
        if args.format is not None and args.field != 'tel':
            return '--format applies only to --field tel'
        formats = caps.get('identity_tel_formats')
        if args.format is not None and (not isinstance(formats, list) or args.format not in formats):
            return f'broker lacks the {args.format} tel format'
    return None


def _token(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def valid_receipt(args, response):
    if response.get('ok') is not True:
        if response.get('ok') is not False:
            return False
        if args.command in {'pin-identity-target', 'fill-identity'} and response == TARGET_REFUSED:
            return True
        if (args.command == 'pin-identity-target' and set(response) == {'ok', 'error'}
                and browser_slots.valid_message(response['error'])):
            return True
        if args.command == 'fill-identity' and response == TARGET_UNCERTAIN:
            return True
        error = response.get('error')
        allowed = {'ok', 'error', 'unlock_url', 'unlock_blocked'} if error == 'vault locked' else {'ok', 'error'}
        return error in ERRORS and set(response) <= allowed
    if args.command in {'create-identity', 'update-identity'}:
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
        if getattr(args, 'fields', None) is not None and (
                type(caps.get('identity_fields_protocol')) is not int or caps['identity_fields_protocol'] != FIELDS_PROTOCOL):
            print(json.dumps(dict(ok=False, error='broker lacks identity fields protocol 1; request not sent')))
            return 1
        if args.command == 'update-identity' and (
                type(caps.get('identity_update_protocol')) is not int or caps['identity_update_protocol'] != UPDATE_PROTOCOL):
            print(json.dumps(dict(ok=False, error='broker lacks identity update protocol 1; request not sent')))
            return 1
        refusal = _option_refusal(args, caps)
        if refusal is not None:
            print(json.dumps(dict(ok=False, error=refusal + '; request not sent')))
            return 1
        if args.command == 'pin-identity-target':
            args.resolved_route = args.route or caps.get('default_fill_route') or 'cdp'
            if args.resolved_route == 'extension' and (type(caps.get('extension_protocol')) is not int
                                                       or caps['extension_protocol'] != 1):
                print(json.dumps(dict(ok=False, error='broker lacks extension route protocol 1; request not sent')))
                return 1
            if args.resolved_route == 'cdp' and not args.frame_url:
                print(json.dumps(dict(ok=False, error='--frame-url or --frame-url-file is required on the cdp route; request not sent')))
                return 1
        extension_ready = (getattr(args, 'resolved_route', None) == 'extension' if args.command == 'pin-identity-target'
                           else caps.get('extension_paired') is True)
        if (caps.get('locked') is False and args.command in {'pin-identity-target', 'fill-identity'}
                and caps.get('identity_browser_configured') is not True and not extension_ready):
            print(json.dumps(dict(ok=False, error='broker has no identity browser profile; request not sent')))
            return 1
        payload = dict(action=args.command, identity_protocol=1)
        if args.command in {'create-identity', 'update-identity'}:
            payload['metadata'] = dict(title=args.title, group=args.group)
            if args.fields is not None:
                payload['fields'] = args.fields
            if args.command == 'update-identity':
                payload['handle'] = args.handle
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
            if args.field_purpose is not None:
                payload['field_purpose'] = args.field_purpose
            if args.allow_autocomplete_off:
                payload['allow_autocomplete_off'] = True
            slot, refusal = browser_slots.request_field(args, caps, args.resolved_route)
            if refusal is not None:
                print(json.dumps(dict(ok=False, error=refusal)))
                return 1
            payload.update(slot)
        else:
            payload.update(handle=args.handle, target=args.target, field=args.field, start_deadline=time.monotonic() + 4)
            if args.format is not None:
                payload['format'] = args.format
            if args.calling_code is not None:
                payload['calling_code'] = args.calling_code
        response = request(payload)
        if not valid_receipt(args, response):
            raise ValueError
    except Exception:
        print('Identity operation outcome unconfirmed; response withheld. Do not retry a fill automatically.', file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1
