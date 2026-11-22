"""`akdbx relay enable|status|rotate|disable`: set up the akdbx relay for the private pages.

Output is JSON on stdout. It never holds the relay secret or the private key.
"""
from __future__ import annotations

import json
import re
import sys
import time

from . import relay as relay_module
from .relay import DEFAULT_RELAY, RelayBusy, RelayError, RelayStore, RelayStoreError

COMMAND = 'relay'
ORIGIN = re.compile(r'https://[a-z0-9.-]{1,253}(:[0-9]{1,5})?')
# What an origin change needs from a browser extension user, by extension version.
EXTENSION_FOLLOWS = ('A browser extension at version 0.3.0 or later follows the new origin by itself at its next '
                     'connection: no rebuild, no reload. An older extension needs akdbx extension build again '
                     'and a reload.')


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
    actions.add_parser('rotate', help='register a new relay name and certificate, and use them at the next broker '
                                      'start (stop the broker first)',
                       description='Registers a new name with the saved relay and gets its certificate. Each '
                                   'certificate is logged in public Certificate Transparency logs and counts '
                                   "toward the relay's weekly budget. The broker must be stopped; start it again "
                                   'and unlock the vault on the new origin.')
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
        if args.relay_command == 'rotate':
            return _rotate(args, store, endpoint_factory, sleep)
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
        if config is not None and config.enabled and relay_module.same_relay(config.relay, endpoint.url):
            result = {'ok': True, 'enabled': True, 'changed': False, 'name': config.name, 'origin': config.origin,
                      'relay': config.relay, 'next': 'A running broker already uses the relay.'}
            _print(result)
            return 0
        return _fail('another akdbx process (a running broker) uses the relay directory; stop it and run '
                     "'akdbx relay enable' again")
    refreshed = []
    with held:
        if store.load_rotation() is not None:
            return _fail("an earlier 'akdbx relay rotate' did not finish; run 'akdbx relay rotate' again")
        try:
            config, info, created = relay_module.enable(
                store, endpoint, sleep=sleep, endpoint_factory=endpoint_factory, refreshed=refreshed,
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
                       'and cannot read it. ' + EXTENSION_FOLLOWS)}
    warnings = [refresh.warning for refresh in refreshed if refresh.warning]
    changes = [change for refresh in refreshed for change in refresh.changes]
    if changes:
        result['moved'] = changes
        result['next'] += ' The origin changed: restart a running broker.'
    warning = _explicit_origin(args)
    if warning:
        warnings.append(warning + '; unset it to use the relay')
    if warnings:
        result['warning'] = '; '.join(warnings)
    _print(result)
    return 0


def _rotate(args, store, endpoint_factory, sleep):
    """Switch to a new relay name. Refuse while a broker holds the relay: it must restart to use the name."""
    try:
        held = store.lock()
    except RelayBusy:
        return _fail("a running broker uses the relay; stop it, run 'akdbx relay rotate' again, then start it")
    with held:
        try:
            rotation = relay_module.rotate(
                store, sleep=sleep, endpoint_factory=endpoint_factory,
                notify=lambda text: print('akdbx relay: ' + text, file=sys.stderr, flush=True))
        except RelayError as exc:
            result = {'ok': False, 'error': str(exc)}
            if exc.retry_after is not None:
                result['retry_after'] = exc.retry_after
            try:
                pending = store.load_rotation()
            except RelayStoreError:
                pending = None
            if pending is not None:
                result['registered'] = True
                result['next'] = ("The new name is saved; run 'akdbx relay rotate' again to finish. It registers "
                                  'no other name. The broker keeps the current name until then.')
            _print(result)
            return 1
    config = rotation.config
    result = {'ok': True, 'rotated': True, 'resumed': rotation.resumed, 'name': config.name,
              'origin': config.origin, 'previous_origin': rotation.previous.origin, 'relay': config.relay,
              'enabled': config.enabled, **rotation.certificate.as_dict(),
              'next': (f'Start the broker again (akdbx serve VAULT) and unlock the vault at {config.origin}. '
                       'The old name is no longer used. ' + EXTENSION_FOLLOWS)}
    warnings = []
    if not config.enabled:
        warnings.append("the relay is disabled: run 'akdbx relay enable' to use the new name")
    warning = _explicit_origin(args)
    if warning:
        warnings.append(warning + '; unset it to use the relay')
    if warnings:
        result['warning'] = '; '.join(warnings)
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
    """True when no broker listens; any other failure (a check that failed) leaves the state unknown.

    Windows raises FileNotFoundError for a missing broker pipe; a busy pipe or a
    pipe I/O failure is a plain OSError, so the state is unknown.
    """
    return isinstance(exc, (FileNotFoundError, ConnectionRefusedError))


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
    if isinstance(state, dict) and isinstance(state.get('moved'), list):
        moved = [item[:200] for item in state['moved'][:4] if isinstance(item, str)]
        if moved:
            broker['moved'] = moved
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
              'origin': config.origin, 'public_port': config.public_port, 'relay': config.relay,
              'directory': str(store.directory)}
    if store.load_rotation() is not None:
        result['rotation_pending'] = True
    info = store.certificate(config.name)
    if info is None:
        result['certificate'] = False
    else:
        result.update(info.as_dict())
        result['certificate_expired'] = info.not_after <= relay_module._utcnow()
    result['broker'] = broker = _broker_state(broker_status)
    if result.get('rotation_pending'):
        result['next'] = "An earlier 'akdbx relay rotate' did not finish: stop the broker and run it again."
    elif broker.get('uses_relay') is True and not config.enabled:
        result['next'] = 'The running broker still uses the relay until it restarts.'
    elif broker.get('uses_relay') is False and config.enabled and not _explicit_origin(args):
        result['next'] = 'Restart the broker to use the relay.'
    elif (broker.get('uses_relay') is True and isinstance(broker.get('origin'), str)
          and broker['origin'] != config.origin):
        result['next'] = (f"The running broker still uses {broker['origin']}; restart it to use {config.origin}. "
                          + EXTENSION_FOLLOWS)
    elif broker.get('moved'):
        result['next'] = 'The broker moved to this origin at its start. ' + EXTENSION_FOLLOWS
    warning = _explicit_origin(args)
    if warning and config.enabled:
        result['warning'] = warning
    _print(result)
    return 0
