"""Native control discovery and pinning. Only opaque IDs and flags leave here."""
import json
import re
import sys

from .native_fields import ACCESSIBILITY_ERROR, DELIVERY, MODES, PROTOCOL, TTL
from .target import failure

COMMANDS = {'list-native-fields', 'pin-native-target'}
TOKEN = re.compile('[a-f0-9]{64}')


def add_parsers(commands):
    command = commands.add_parser('list-native-fields', help='list opaque native window/control IDs; never reads values or labels')
    command.add_argument('--pid', type=int, required=True, help='independently verified native application process')
    command = commands.add_parser('pin-native-target', help='pin exact native controls; no Tab, global keyboard or clipboard')
    command.add_argument('--window', required=True, help='fresh opaque window token from list-native-fields')
    command.add_argument('--control', required=True, type=int, help='focused control index; for login, focus password after discovering username')
    command.add_argument('--username-control', type=int, help='index focused during discovery, required only for login')
    command.add_argument('--mode', choices=MODES, required=True)
    command.add_argument('--field', help='exact card or identity field purpose; required only for those modes')
    command.add_argument('--service-url', required=True,
                         help='caller-verified HTTPS service used by this native app; not browser URL attestation')


def valid(response, command, args):
    if response.get('ok') is not True:
        return (response.get('ok') is False and response.get('error') in {failure()['error'], 'vault locked', ACCESSIBILITY_ERROR}
                and set(response) <= {'ok', 'error', 'delivery', 'unlock_url', 'unlock_blocked'}
                and response.get('delivery', 'not-started') == 'not-started')
    if command == 'pin-native-target':
        return (set(response) == {'ok', 'target', 'expires_in', 'target_delivery'}
                and isinstance(response['target'], str) and TOKEN.fullmatch(response['target'])
                and type(response['expires_in']) is int and response['expires_in'] == TTL
                and response['target_delivery'] == DELIVERY)
    if (set(response) != {'ok', 'pid', 'windows', 'expires_in'} or type(response['pid']) is not int
            or response['pid'] != args.pid or type(response['expires_in']) is not int or response['expires_in'] != TTL
            or not isinstance(response['windows'], list) or not 1 <= len(response['windows']) <= 8):
        return False
    for window in response['windows']:
        if (not isinstance(window, dict) or set(window) != {'window', 'controls'}
                or not isinstance(window['window'], str) or not TOKEN.fullmatch(window['window'])
                or not isinstance(window['controls'], list) or not 1 <= len(window['controls']) <= 128):
            return False
        for index, field in enumerate(window['controls']):
            if (not isinstance(field, dict) or set(field) != {'control', 'password', 'readonly', 'focused'}
                    or type(field['control']) is not int or field['control'] != index
                    or type(field['password']) is not bool or type(field['readonly']) is not bool
                    or type(field['focused']) is not bool):
                return False
        if sum(f['focused'] for f in window['controls']) != 1:
            return False
    return True


def run(args, request):
    try:
        caps = request({'action': 'ping'})
        if (caps.get('ok') is not True or type(caps.get('native_field_protocol')) is not int
                or caps['native_field_protocol'] != PROTOCOL or caps.get('native_field_supported') is not True
                or caps.get('native_field_delivery') != DELIVERY):
            print(json.dumps(dict(ok=False, error='broker lacks native field protocol 1; request not sent')))
            return 1
        payload = dict(action=args.command, native_protocol=PROTOCOL)
        if args.command == 'list-native-fields':
            payload['pid'] = args.pid
        else:
            if args.mode == 'code' and 'code' not in caps.get('native_field_modes', []):
                print(json.dumps(dict(ok=False, error='broker lacks native SMS code mode; request not sent')))
                return 1
            if ((args.username_control is not None) != (args.mode == 'login')
                    or (args.field is not None) != (args.mode in {'card', 'identity'})):
                raise ValueError()
            payload.update(window=args.window, control=args.control, mode=args.mode, service_url=args.service_url)
            if args.username_control is not None:
                payload['username_control'] = args.username_control
            if args.field is not None:
                payload['field'] = args.field
        response = request(payload)
        if not isinstance(response, dict) or not valid(response, args.command, args):
            raise ValueError()
    except Exception:
        print('native target operation unconfirmed; check the app and use fresh IDs', file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1
