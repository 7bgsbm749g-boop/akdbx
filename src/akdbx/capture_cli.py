"""CLI for capture-secret and deliver-secret: names and receipts, never values."""
import json
import sys
import time

from .secrets_capture import CAPTURE_DELIVERY, CAPTURE_PROTOCOL, valid_field
from .sink_helper import PROTOCOL as SINK_PROTOCOL, SINK_NAME

COMMANDS = ('capture-secret', 'deliver-secret')
UNCONFIRMED = {
    'capture-secret': 'Secret capture outcome unconfirmed; response withheld. Search the entry before any retry; '
                      'do not generate another secret on the website automatically.',
    'deliver-secret': 'Secret delivery outcome unconfirmed; response withheld. Check the destination service before any retry.',
}


def add_parsers(commands):
    p = commands.add_parser('capture-secret', help='save the text of a pinned read target (pin-password-target --mode read) '
                            'as a protected field; returns only a receipt')
    p.add_argument('--target', required=True, help='fresh single-use read pin from pin-password-target --mode read')
    p.add_argument('--field', required=True, help='custom field name, for example client_secret')
    for name in ('title', 'username', 'url', 'group'):
        p.add_argument('--' + name, required=True, help='exact verified entry metadata')
    selection = p.add_mutually_exclusive_group(required=True)
    selection.add_argument('--handle', help='fresh search handle of the existing entry to update')
    selection.add_argument('--new', action='store_true', help='create a new secret record with this metadata')
    p.add_argument('--replace', action='store_true', help='explicitly replace an existing field of this name')
    p = commands.add_parser('deliver-secret', help='write a captured protected field to a sink configured at broker start; '
                            'returns only a receipt')
    p.add_argument('--sink', required=True, help='sink name listed in status secret_sinks')
    p.add_argument('--field', required=True, help='field name; must equal the sink definition')
    p.add_argument('handle', help='fresh search handle of the entry that holds the field')


def valid_receipt(args, response, payload):
    if not isinstance(response, dict):
        return False
    if response.get('ok') is False:
        error = response.get('error')
        allowed = {'ok', 'error', 'unlock_url'} if error == 'vault locked' else {'ok', 'error'}
        return isinstance(error, str) and len(error) <= 300 and set(response) <= allowed
    if response.get('ok') is not True:
        return False
    if args.command == 'capture-secret':
        return (set(response) == {'ok', 'state', 'created', 'field', 'length', 'metadata', 'capture_delivery'}
                and response['state'] == 'saved' and response['created'] is args.new
                and response['field'] == args.field and type(response['length']) is int and 0 < response['length'] <= 4096
                and response['metadata'] == payload['metadata'] and response['capture_delivery'] == CAPTURE_DELIVERY)
    return (set(response) == {'ok', 'state', 'sink', 'field', 'restarted'}
            and response['state'] == 'delivered' and response['sink'] == args.sink and response['field'] == args.field
            and response['restarted'] in (True, False, None))


def run(args, request):
    if args.command == 'capture-secret' and (not valid_field(args.field) or args.new and args.replace):
        print('invalid --field, or --replace with --new; request not sent', file=sys.stderr)
        return 2
    if args.command == 'deliver-secret' and (not SINK_NAME.fullmatch(args.sink) or not valid_field(args.field)):
        print('invalid --sink or --field; request not sent', file=sys.stderr)
        return 2
    try:
        caps = request({'action': 'ping'})
        if args.command == 'capture-secret' and (
                caps.get('ok') is not True or type(caps.get('secret_capture_protocol')) is not int
                or caps['secret_capture_protocol'] != CAPTURE_PROTOCOL or caps.get('secret_capture_delivery') != CAPTURE_DELIVERY):
            print(json.dumps(dict(ok=False, error='broker lacks secret capture protocol 1; require broker 0.20.0 or newer; request not sent')))
            return 1
        if args.command == 'deliver-secret' and (
                caps.get('ok') is not True or type(caps.get('secret_sink_protocol')) is not int
                or caps['secret_sink_protocol'] != SINK_PROTOCOL or not isinstance(caps.get('secret_sinks'), list)):
            print(json.dumps(dict(ok=False, error='broker lacks secret sink protocol 1; require broker 0.20.0 or newer; request not sent')))
            return 1
        if args.command == 'deliver-secret' and caps.get('locked') is False and args.sink not in caps['secret_sinks']:
            print(json.dumps(dict(ok=False, error='unknown sink; status secret_sinks lists the configured sinks; request not sent')))
            return 1
        metadata = dict(title=args.title, username=args.username, url=args.url, group=args.group) if args.command == 'capture-secret' else None
        if args.command == 'capture-secret':
            payload = dict(action='capture-secret', capture_protocol=CAPTURE_PROTOCOL, target=args.target, field=args.field,
                           metadata=metadata, start_deadline=time.monotonic() + 4)
            if args.new:
                payload['create'] = True
            else:
                payload['handle'] = args.handle
                if args.replace:
                    payload['replace'] = True
        else:
            payload = dict(action='deliver-secret', sink_protocol=SINK_PROTOCOL, sink=args.sink, field=args.field,
                           handle=args.handle)
        response = request(payload)
        if not valid_receipt(args, response, payload):
            raise ValueError
    except (FileNotFoundError, ConnectionRefusedError):
        print('broker is not running', file=sys.stderr)
        return 2
    except Exception:
        print(UNCONFIRMED[args.command], file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1
