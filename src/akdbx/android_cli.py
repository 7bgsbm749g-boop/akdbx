"""`akdbx android`: fill a verified field on a configured Android device.

Commands take no secret argument. Fill commands print only a receipt.
"""
import contextlib
import json
import os
import subprocess
import re
import sys
import time

from . import android_lifecycle, android_setup
from .android_route import AndroidError, CHROME_DELIVERY, DELIVERY, MODES, PROTOCOL, load_devices

DELIVERIES = {DELIVERY, CHROME_DELIVERY}

COMMAND = 'android'
FILL_ERROR = re.compile(r"(autofill (not started|outcome uncertain|failed)|vault locked|identity record|card record"
                        r"|passwordless record|captured secret record|save outcome uncertain|request failed"
                        r"|mode must|unknown or expired handle|invalid handle)[^\n]{0,300}")
FILLS = {'fill', 'fill-totp', 'google-sign-in'}
# Response budgets in seconds. The fill-start deadline stays 4 seconds; a fill
# that started may take the helper's whole run.
TIMEOUTS = {'devices': 180, 'inspect': 60, 'pin': 60, 'fill': 60, 'fill-totp': 60, 'google-sign-in': 150}
TOKEN = re.compile(r'[0-9a-f]{64}')


def add_parser(commands):
    android = commands.add_parser(
        COMMAND, help='Android devices: inspect the focused app, pin a verified field, fill it (no secret output)',
        description=('Fill a login, password, username or authenticator code into one verified field of the '
                     'focused app on an Android device that the operator configured for the broker. '
                     'The value goes from the broker to an akdbx helper on the device over adb standard input; '
                     'it is never an argument, typed key, clipboard content or output.'))
    sub = android.add_subparsers(dest='android_command', required=True)
    android_setup.add_parsers(sub)
    sub.add_parser('devices', help='list configured devices and whether each is reachable')
    inspect = sub.add_parser('inspect', help='read-only: the focused app, its verified site and its text fields')
    inspect.add_argument('--device', required=True, help='device name from android devices')
    pin = sub.add_parser('pin', help='pin one field (two in login mode) for 30 seconds')
    pin.add_argument('--device', required=True)
    pin.add_argument('--mode', required=True, choices=MODES)
    pin.add_argument('--field', required=True,
                     help='a field value from android inspect: the password field (login, password), the username '
                          'field (username) or the code field (totp). A page field must be focused (tap it first)')
    pin.add_argument('--username-field', help='field value of the username field; login mode only')

    pin.add_argument('--app-site', help=('exact HTTPS origin whose Digital Asset Links name this app; needed for '
                                         'apps other than Chrome and Google account sign-in'))
    google = sub.add_parser('google-sign-in', help=(
        'open a new Google account sign-in, fill the entry\'s email, submit it, then fill the password (and with '
        '--code the authenticator code) on the pages Google shows next, in one run; @gmail.com accounts only'))
    google.add_argument('handle', help='fresh handle from akdbx search; its URL or an additional URL is https://accounts.google.com')
    google.add_argument('--device', required=True)
    google.add_argument('--code', action='store_true', help='also fill the entry\'s authenticator code if Google asks for it next')
    for name in ('fill', 'fill-totp'):
        fill = sub.add_parser(name, help=('fill the entry\'s login, username or password into the pinned field(s)'
                                          if name == 'fill' else 'fill the entry\'s current authenticator code'))
        fill.add_argument('handle', help='fresh handle from akdbx search')
        fill.add_argument('--target', required=True, help='token from android pin')
        if name == 'fill':
            fill.add_argument('--mode', required=True, choices=('login', 'username', 'password'),
                              help='must be the mode of the pin')


def _short(value, limit=300):
    return isinstance(value, str) and 0 < len(value) <= limit and '\n' not in value


def valid(command, response):
    if not isinstance(response, dict) or not isinstance(response.get('ok'), bool):
        return False
    if response['ok'] is False:
        keys = {'ok', 'error', 'delivery', 'retry_after', 'unlock_url', 'unlock_blocked'}
        if not set(response) <= keys or not _short(response.get('error')):
            return False
        if command in FILLS:
            return (FILL_ERROR.fullmatch(response['error']) is not None
                    and response.get('delivery', 'not-started') in {'not-started', 'uncertain'})
        return 'delivery' not in response
    if command == 'devices':
        return set(response) == {'ok', 'devices'} and isinstance(response['devices'], list)
    if command == 'inspect':
        return set(response) <= {'ok', 'device', 'app', 'speak_password', 'site', 'site_note', 'page_url', 'fields'}
    if command == 'pin':
        return (set(response) == {'ok', 'target', 'expires_in', 'android_delivery', 'mode', 'origin', 'site_source', 'package'}
                and isinstance(response['target'], str) and TOKEN.fullmatch(response['target']) is not None
                and response['android_delivery'] in DELIVERIES and response['expires_in'] == 30
                and response['mode'] in MODES and _short(response['origin']) and _short(response['package']))
    if command == 'google-sign-in':
        return (set(response) - {'stopped_at'} == {'ok', 'filled', 'target_delivery'}
                and response['target_delivery'] == DELIVERY and isinstance(response['filled'], list)
                and all(step in ('email', 'password', 'code') for step in response['filled'])
                and response.get('stopped_at', 'email') in ('email', 'password', 'code', 'submit'))
    return (set(response) == {'ok', 'filled', 'target_delivery'} and response['target_delivery'] in DELIVERIES
            and response['filled'] in MODES)


def run(args, request):
    command = args.android_command
    try:
        if command == 'setup':
            print(json.dumps(android_setup.setup(args)))
            return 0
        if command not in ('wake', 'run'):
            with contextlib.ExitStack() as leases:
                return _request(args, request, leases)
        device = load_devices(android_setup.config_path()).get(args.device)
        if device is None:
            raise AndroidError('device is not registered in the local Android configuration')
        if command == 'wake' and device.managed is None:
            raise AndroidError('attached devices remain under operator control')
        argv = getattr(args, 'argv', [])
        if argv[:1] == ['--']:
            argv = argv[1:]
        if command == 'run' and not argv:
            raise AndroidError('android run requires a program after --')
        with android_lifecycle.use(device) as lease:
            if command == 'wake':
                print(json.dumps({'ok': True, 'device': device.name, 'power_state': 'awake'}))
                return 0
            env = {k: v for k, v in os.environ.items() if not k.startswith(('ADB_', 'ANDROID_'))}
            env.update(ANDROID_SERIAL=device.serial, ANDROID_ADB_SERVER_PORT=str(device.port),
                       PATH=str(os.path.dirname(device.adb)) + os.pathsep + env.get('PATH', ''))
            return subprocess.run(argv, env=env, pass_fds=(lease.fileno(),) if lease else ()).returncode
    except (AndroidError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc) if isinstance(exc, AndroidError)
                          else 'local Android setup or lifecycle command failed'}))
        return 1


def _request(args, request, leases):
    command = args.android_command
    try:
        caps = request({'action': 'ping'})
        if (caps.get('ok') is not True or type(caps.get('android_fill_protocol')) is not int
                or caps['android_fill_protocol'] != PROTOCOL or caps.get('android_fill_delivery') != DELIVERY):
            print(json.dumps({'ok': False, 'error': 'broker lacks Android fill protocol 1; update akdbx; request not sent'}))
            return 1
        managed = caps.get('android_managed_devices', {}).get(getattr(args, 'device', None))
        if managed and (command == 'inspect' or not caps.get('locked')):
            device = load_devices(android_setup.config_path()).get(args.device)
            if not device or not device.managed or android_lifecycle.unit_name(device) != managed.get('unit'):
                raise AndroidError('use the broker host and its AKDBX_ANDROID_DEVICES file for managed Android')
            # Boot before starting the short fill deadline. The 30-second pin
            # and its 60-second fill fit within the minimum 120-second idle period.
            leases.enter_context(android_lifecycle.use(device))
        if command == 'devices':
            payload = {'action': 'android-devices'}
        elif command == 'inspect':
            payload = {'action': 'android-inspect', 'device': args.device}
        elif command == 'pin':
            if (args.username_field is None) == (args.mode == 'login'):
                print(json.dumps({'ok': False, 'error': '--username-field is required in login mode and only there; '
                                                        'request not sent'}))
                return 1
            payload = {'action': 'android-pin', 'android_protocol': PROTOCOL, 'device': args.device,
                       'mode': args.mode, 'field': args.field}
            if args.username_field is not None:
                payload['username_field'] = args.username_field
            if args.app_site is not None:
                payload['app_site'] = args.app_site

        elif command == 'google-sign-in':
            payload = {'action': 'android-google-sign-in', 'android_protocol': PROTOCOL, 'device': args.device,
                       'handle': args.handle, 'code': args.code, 'start_deadline': time.monotonic() + 4}
        else:
            payload = {'action': command, 'handle': args.handle, 'target': args.target, 'target_protocol': 1,
                       'start_deadline': time.monotonic() + 4}
            if command == 'fill':
                payload['mode'] = args.mode
        response = request(payload, timeout=TIMEOUTS[command])
        if not valid(command, response):
            raise ValueError
    except AndroidError:
        raise
    except Exception:
        if command in FILLS:
            print('autofill outcome unconfirmed: broker response rejected; do not retry automatically', file=sys.stderr)
        else:
            print('Android request failed; response withheld', file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1
