"""CLI for capture-secret, deliver-secret, capture-totp and commit-totp: names and receipts, never values."""
import json
import sys
import time
from .android_route import READ_DELIVERY as ANDROID_READ_DELIVERY
from .native_fields import READ_DELIVERY as NATIVE_READ_DELIVERY

from .extension_route import CAPTURE_DELIVERY as EXTENSION_CAPTURE_DELIVERY
from .secrets_capture import CAPTURE_DELIVERY, CAPTURE_PROTOCOL, valid_field
from .sink_helper import PROTOCOL as SINK_PROTOCOL, SINK_NAME
from .totp_capture import OLD_BROKER as QR_CAPTURE_REFUSAL, PROTOCOL as TOTP_CAPTURE_PROTOCOL, QR_PROTOCOL

COMMANDS = ('capture-secret', 'deliver-secret', 'capture-totp', 'commit-totp')
UNCONFIRMED = {
    'capture-secret': 'Secret capture outcome unconfirmed; response withheld. Search the entry before any retry; '
                      'do not generate another secret on the website automatically.',
    'deliver-secret': 'Secret delivery outcome unconfirmed; response withheld. Check the destination service before any retry.',
    'capture-totp': 'Authenticator capture outcome unconfirmed; response withheld. Search the entry for totp_pending '
                    'before any retry; do not restart the website enrollment automatically.',
    'commit-totp': 'Authenticator save outcome unconfirmed; response withheld. Search the entry (totp_configured, '
                   'totp_pending) before any retry.',
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
    p = commands.add_parser('capture-totp', help='save the TOTP setup key or otpauth URI shown in a pinned read target '
                            '(pin-password-target --mode read) as the entry\'s pending authenticator; returns only a receipt')
    p.add_argument('--target', required=True, help='fresh single-use read pin on the element that shows the setup key')
    p.add_argument('--qr', action='store_true', help='the pin is a QR read pin (pin-password-target --mode read --qr): '
                   'the browser decodes the setup QR code, which must hold an otpauth://totp/ URI')
    p.add_argument('--handle', required=True, help='fresh search handle of the existing entry for this site and account')
    for name in ('title', 'username', 'url', 'group'):
        p.add_argument('--' + name, required=True, help='exact verified entry metadata')
    p = commands.add_parser('commit-totp', help='move the pending captured authenticator into the entry\'s otp field '
                            'after the website accepted its code, or discard it; returns only a receipt')
    p.add_argument('--handle', required=True, help='fresh search handle of the entry')
    for name in ('title', 'username', 'url', 'group'):
        p.add_argument('--' + name, required=True, help='exact verified entry metadata')
    decision = p.add_mutually_exclusive_group(required=True)
    decision.add_argument('--site-accepted', action='store_true', help='the website accepted a code of the pending key')
    decision.add_argument('--discard', action='store_true', help='remove the pending key; the otp field is unchanged')
    p.add_argument('--replace', action='store_true', help='explicitly replace an existing otp field (kept in history)')


def valid_receipt(args, response, payload):
    if not isinstance(response, dict):
        return False
    if response.get('ok') is False:
        error = response.get('error')
        allowed = {'ok', 'error', 'unlock_url', 'unlock_blocked'} if error == 'vault locked' else {'ok', 'error'}
        return isinstance(error, str) and len(error) <= 300 and set(response) <= allowed
    if response.get('ok') is not True:
        return False
    if args.command == 'capture-totp':
        return (set(response) == {'ok', 'state', 'totp_configured', 'metadata', 'capture_delivery'}
                and response['state'] == 'pending' and type(response['totp_configured']) is bool
                and response['metadata'] == payload['metadata']
                and response['capture_delivery'] in (ANDROID_READ_DELIVERY, CAPTURE_DELIVERY, EXTENSION_CAPTURE_DELIVERY))
    if args.command == 'commit-totp':
        if args.discard:
            return set(response) == {'ok', 'state', 'metadata'} and response['state'] == 'discarded' and response['metadata'] == payload['metadata']
        return (set(response) == {'ok', 'state', 'replaced', 'metadata'} and response['state'] == 'saved'
                and type(response['replaced']) is bool and (args.replace or response['replaced'] is False)
                and response['metadata'] == payload['metadata'])
    if args.command == 'capture-secret':
        return (set(response) == {'ok', 'state', 'created', 'field', 'length', 'metadata', 'capture_delivery'}
                and response['state'] == 'saved' and response['created'] is args.new
                and response['field'] == args.field and type(response['length']) is int and 0 < response['length'] <= 4096
                and response['metadata'] == payload['metadata']
                and response['capture_delivery'] in (ANDROID_READ_DELIVERY, CAPTURE_DELIVERY, EXTENSION_CAPTURE_DELIVERY, NATIVE_READ_DELIVERY))
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
    if args.command == 'commit-totp' and args.discard and args.replace:
        print('--replace applies only with --site-accepted; request not sent', file=sys.stderr)
        return 2
    try:
        caps = request({'action': 'ping'})
        if args.command == 'capture-secret' and (
                caps.get('ok') is not True or type(caps.get('secret_capture_protocol')) is not int
                or caps['secret_capture_protocol'] != CAPTURE_PROTOCOL or caps.get('secret_capture_delivery') != CAPTURE_DELIVERY):
            print(json.dumps(dict(ok=False, error='broker lacks secret capture protocol 1; require broker 0.20.0 or newer; request not sent')))
            return 1
        if args.command in {'capture-totp', 'commit-totp'} and (
                caps.get('ok') is not True or type(caps.get('totp_capture_protocol')) is not int
                or caps['totp_capture_protocol'] != TOTP_CAPTURE_PROTOCOL):
            print(json.dumps(dict(ok=False, error='broker lacks authenticator capture protocol 1; require broker 0.35.0 or newer; request not sent')))
            return 1
        if args.command == 'capture-totp' and args.qr and (
                type(caps.get('totp_qr_capture_protocol')) is not int or caps['totp_qr_capture_protocol'] != QR_PROTOCOL):
            print(json.dumps(dict(ok=False, error=QR_CAPTURE_REFUSAL + '; request not sent')))
            return 1
        if args.command == 'deliver-secret' and (
                caps.get('ok') is not True or type(caps.get('secret_sink_protocol')) is not int
                or caps['secret_sink_protocol'] != SINK_PROTOCOL or not isinstance(caps.get('secret_sinks'), list)):
            print(json.dumps(dict(ok=False, error='broker lacks secret sink protocol 1; require broker 0.20.0 or newer; request not sent')))
            return 1
        if args.command == 'deliver-secret' and caps.get('locked') is False and args.sink not in caps['secret_sinks']:
            print(json.dumps(dict(ok=False, error='unknown sink; status secret_sinks lists the configured sinks; request not sent')))
            return 1
        metadata = (dict(title=args.title, username=args.username, url=args.url, group=args.group)
                    if args.command != 'deliver-secret' else None)
        if args.command == 'capture-totp':
            payload = dict(action='capture-totp', totp_capture_protocol=TOTP_CAPTURE_PROTOCOL, target=args.target,
                           handle=args.handle, metadata=metadata, start_deadline=time.monotonic() + 4)
            if args.qr:
                payload['read_kind'] = 'qr'
        elif args.command == 'commit-totp':
            payload = dict(action='commit-totp', totp_capture_protocol=TOTP_CAPTURE_PROTOCOL, handle=args.handle,
                           metadata=metadata, decision='site-accepted' if args.site_accepted else 'discard')
            if args.replace:
                payload['replace'] = True
        elif args.command == 'capture-secret':
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
