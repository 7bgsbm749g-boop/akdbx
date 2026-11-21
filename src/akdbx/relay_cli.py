"""`akdbx relay enable|status|disable`: set up the akdbx relay for the private pages.

Output is JSON on stdout. It never holds the relay secret or the private key.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

from . import relay as relay_module
from .relay import DEFAULT_RELAY, RelayBusy, RelayError, RelayStore, RelayStoreError

COMMAND = 'relay'
ORIGIN = re.compile(r'https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?')


def add_parser(commands):
    command = commands.add_parser(
        COMMAND, help='open the private pages from any device through the akdbx relay (no open port)',
        description='The akdbx relay forwards encrypted connections to this broker. TLS ends in the broker, '
                    'so the relay cannot read the master password. See docs/private-pages.md.')
    actions = command.add_subparsers(dest='relay_command', required=True)
    enable = actions.add_parser('enable', help='register this broker, get its certificate and use the relay')
    enable.add_argument('--relay', default=DEFAULT_RELAY, dest='relay_url',
                        help=f'relay control URL (default {DEFAULT_RELAY})')
    actions.add_parser('status', help='show the relay name, origin, certificate expiry and connection; no secret')
    disable = actions.add_parser('disable', help='stop using the relay at the next broker start')
    disable.add_argument('--forget', action='store_true',
                         help='also delete the saved name, secret, key and certificate')


def _print(result):
    print(json.dumps(result, indent=2))


def _fail(message, code=1):
    _print({'ok': False, 'error': message})
    return code


def _explicit_origin(args):
    """Why the CLI and `serve` would not use the relay origin, if they would not."""
    if getattr(args, 'unlock_origin_explicit', False):
        return '--unlock-origin or AKDBX_UNLOCK_ORIGIN is set: serve and the CLI use that origin, not the relay'
    return None


def run(args, broker_status, *, store=None, endpoint_factory=None, sleep=time.sleep):
    """``broker_status`` sends the peer-verified ``relay-status`` request to the running broker."""
    store = store or RelayStore()
    endpoint_factory = endpoint_factory or relay_module.endpoint
    try:
        if args.relay_command == 'enable':
            return _enable(args, store, endpoint_factory, sleep)
        if args.relay_command == 'disable':
            return _disable(args, store)
        return _status(args, store, broker_status)
    except RelayStoreError as exc:
        return _fail(f'the relay directory cannot be trusted: {exc}', 2)


def _enable(args, store, endpoint_factory, sleep):
    try:
        endpoint = endpoint_factory(args.relay_url)
    except ValueError as exc:
        return _fail(str(exc), 2)
    try:
        held = store.lock()
    except RelayBusy:
        config = store.load()
        if config is not None and config.enabled and config.relay == endpoint.url:
            result = {'ok': True, 'enabled': True, 'changed': False, 'name': config.name, 'origin': config.origin,
                      'relay': config.relay, 'next': 'A running broker already uses the relay.'}
            _print(result)
            return 0
        return _fail('another akdbx process (a running broker) uses the relay directory; stop it and run '
                     "'akdbx relay enable' again")
    with held:
        try:
            config, info, created = relay_module.enable(
                store, endpoint, sleep=sleep,
                notify=lambda text: print('akdbx relay: ' + text, file=sys.stderr, flush=True))
        except RelayError as exc:
            saved = None
            try:
                saved = store.load()
            except RelayStoreError:
                pass
            result = {'ok': False, 'error': str(exc)}
            if exc.retry_after is not None:
                result['retry_after'] = exc.retry_after
            if saved is not None:
                result['registered'] = True
                result['name'] = saved.name
                result['next'] = "The registration is saved; run 'akdbx relay enable' again to finish."
            _print(result)
            return 1
    result = {'ok': True, 'enabled': True, 'changed': True, 'registered_now': created, 'name': config.name,
              'origin': config.origin, 'relay': config.relay, **info.as_dict(), 'directory': str(store.directory),
              'next': ('Restart the broker with only the vault (no --unlock-origin, --tls-cert, --tls-key or '
                       f'--local-port): akdbx serve VAULT. Its private pages then open at {config.origin} on any '
                       'device, and every akdbx command uses that origin. The relay forwards encrypted traffic '
                       'and cannot read it. If you use the browser extension, run akdbx extension build again.')}
    warning = _explicit_origin(args)
    if warning:
        result['warning'] = warning + '; unset it to use the relay'
    _print(result)
    return 0


def _disable(args, store):
    if args.forget:
        # The repair for untrusted or malformed files: never read them. Only
        # the folder is checked; the fixed file names are deleted through it.
        if not store.exists():
            _print({'ok': True, 'enabled': False, 'registered': False})
            return 0
        try:
            held = store.lock()
        except RelayBusy:
            return _fail("a running broker uses the relay; stop it, then run 'akdbx relay disable --forget'")
        with held:
            store.forget()
        store.remove_folder()
        _print({'ok': True, 'enabled': False, 'registered': False, 'forgot': True,
                'next': "The name, secret, key and certificate are deleted. 'akdbx relay enable' registers a "
                        'new name. Restart a running broker to stop using the relay.'})
        return 0
    config = store.load()
    if config is None and not store.exists():
        _print({'ok': True, 'enabled': False, 'registered': False})
        return 0
    if config is not None and config.enabled:
        config.enabled = False
        store.save(config)
    _print({'ok': True, 'enabled': False, 'registered': config is not None,
            **({'name': config.name} if config is not None else {}),
            'next': ('The files are kept; \'akdbx relay enable\' uses the same name again. Restart a running '
                     'broker to stop using the relay.')})
    return 0


def _not_running(exc):
    """True when no broker listens; any other failure (a check that failed) leaves the state unknown."""
    if isinstance(exc, (FileNotFoundError, ConnectionRefusedError)):
        return True
    # Windows: the broker pipe does not exist (windows_rpc.connect raises a plain OSError).
    return os.name == 'nt' and type(exc) is OSError


def _broker_state(broker_status):
    try:
        response = broker_status()
    except Exception as exc:
        if _not_running(exc):
            return {'running': False}
        # The broker may run, but its socket or answer failed a check: never report it stopped.
        return {'running': 'unknown', 'error': f'the broker check failed ({type(exc).__name__})'}
    if not isinstance(response, dict) or response.get('ok') is not True:
        return {'running': True, 'uses_relay': 'unknown',
                'error': 'the broker did not report its relay state (an older version?)'}
    broker = {'running': True}
    state = response.get('relay')
    if isinstance(state, dict) and type(state.get('connected')) is bool:
        broker.update(uses_relay=True, connected=state['connected'])
        if isinstance(state.get('renewal_error'), str):
            broker['renewal_error'] = state['renewal_error'][:300]
    else:
        broker['uses_relay'] = False
    origin = response.get('active_origin')
    if isinstance(origin, str) and ORIGIN.fullmatch(origin):
        broker['origin'] = origin
    return broker


def _status(args, store, broker_status):
    config = store.load()
    if config is None:
        _print({'ok': True, 'registered': False, 'enabled': False,
                'next': "Run 'akdbx relay enable' to open the private pages from any device."})
        return 0
    result = {'ok': True, 'registered': True, 'enabled': config.enabled, 'name': config.name,
              'origin': config.origin, 'relay': config.relay, 'directory': str(store.directory)}
    info = store.certificate(config.name)
    if info is None:
        result['certificate'] = False
    else:
        result.update(info.as_dict())
        result['certificate_expired'] = info.not_after <= relay_module._utcnow()
    result['broker'] = broker = _broker_state(broker_status)
    if broker.get('uses_relay') is True and not config.enabled:
        result['next'] = 'The running broker still uses the relay until it restarts.'
    elif broker.get('uses_relay') is False and config.enabled and not _explicit_origin(args):
        result['next'] = 'Restart the broker to use the relay.'
    warning = _explicit_origin(args)
    if warning and config.enabled:
        result['warning'] = warning
    _print(result)
    return 0
