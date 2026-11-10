from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import struct
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .broker import Broker, FILL_START_TIMEOUT, serve
from .protocol import ProtocolError, receive_message, send_message
from .target import X11Typer, DELIVERY
from .runtime import anchored_socket_path, open_private_runtime_directory
from .merge import ID_PATTERN
from .web_unlock import start_unlock_server
from .notifications import validate_webhook_url
from . import card_cli


# Reserved example domain: deployment addresses belong in local configuration.
DEFAULT_UNLOCK_ORIGIN = "https://unlock.example.invalid:9443"
IDENTITY_CREATES = ('create-sso-entry', 'create-passwordless-entry')


def default_socket() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = Path(runtime) / "akdbx" if runtime else Path(f"/tmp/akdbx-{os.getuid()}")
    canonical = base / "akdbx.sock"
    legacy_base = Path(runtime) / "agentic-kdbx" if runtime else base
    legacy = legacy_base / "agentic-kdbx.sock"
    # Keep existing unlocked brokers usable during an upgrade. All normal
    # ownership, symlink and peer checks still apply when connecting.
    for candidate in (canonical, legacy):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        return candidate
    return canonical


def _validate_socket_path(socket_path: Path, broker_uid: int) -> tuple[Path, int]:
    """Open a trusted runtime leaf and validate its socket relative to that fd."""
    socket_path = Path(os.path.abspath(os.fspath(socket_path)))
    try:
        runtime_path, runtime_fd = open_private_runtime_directory(
            socket_path.parent, owner_uid=broker_uid,
        )
    except RuntimeError as exc:
        raise PermissionError(str(exc)) from exc
    try:
        socket_info = os.stat(
            socket_path.name, dir_fd=runtime_fd, follow_symlinks=False,
        )
        if not stat.S_ISSOCK(socket_info.st_mode):
            raise PermissionError("broker path is not a Unix socket")
        if socket_info.st_uid != broker_uid:
            raise PermissionError("socket is not owned by the configured broker UID")
        if stat.S_IMODE(socket_info.st_mode) != 0o600:
            raise PermissionError("broker socket must have mode 0600")
        return runtime_path / socket_path.name, runtime_fd
    except Exception:
        os.close(runtime_fd)
        raise


def _peer_credentials(client: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("Unix peer credential verification is unavailable on this platform")
    size = struct.calcsize("3i")
    return struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))


def _validate_unlock_url(url: object, expected_origin: str) -> None:
    if not isinstance(url, str):
        raise ProtocolError("invalid unlock URL")
    expected = urlsplit(expected_origin)
    candidate = urlsplit(url)
    try:
        expected_port = expected.port
        candidate_port = candidate.port
    except ValueError as exc:
        raise ProtocolError("invalid unlock URL") from exc
    if (
        expected.scheme.lower() != "https"
        or not expected.hostname
        or expected.username is not None
        or expected.password is not None
        or expected.path not in {"", "/"}
        or expected.query
        or expected.fragment
    ):
        raise ValueError("configured unlock origin must be an HTTPS origin without path, query, or credentials")
    expected_identity = (
        expected.hostname.lower(), 443 if expected_port is None else expected_port,
    )
    candidate_identity = (
        candidate.hostname.lower(), 443 if candidate_port is None else candidate_port,
    ) if candidate.hostname else None
    try:
        token = parse_qs(candidate.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise ProtocolError("invalid unlock URL") from exc
    if (
        candidate.scheme.lower() != "https"
        or candidate.username is not None
        or candidate.password is not None
        or candidate_identity != expected_identity
        or candidate.fragment
        or set(token) != {"token"}
        or len(token["token"]) != 1
        or not token["token"][0]
    ):
        raise ProtocolError("broker returned an untrusted unlock URL")


def _validate_response(response: dict, expected_unlock_origin: str) -> dict:
    # Validate configuration even when an unlocked response has no URL.
    expected = urlsplit(expected_unlock_origin)
    try:
        expected.port
    except ValueError as exc:
        raise ValueError("configured unlock origin is invalid") from exc
    if (
        expected.scheme.lower() != "https"
        or not expected.hostname
        or expected.username is not None
        or expected.password is not None
        or expected.path not in {"", "/"}
        or expected.query
        or expected.fragment
    ):
        raise ValueError("configured unlock origin must be an HTTPS origin without path, query, or credentials")
    if type(response.get("ok")) is not bool:
        raise ProtocolError("invalid broker response")
    for capability in ('locked', 'writes_available', 'recovery_required', 'merge_available', 'merge_same_credentials_only', 'merge_refresh_target_supported', 'merge_preserve_conflicts_supported', 'admission_supported', 'sso_identity_supported', 'passwordless_identity_supported', 'target_fill_required', 'totp_supported'):
        if capability in response and type(response[capability]) is not bool:
            raise ProtocolError("invalid broker response")
    if 'version' in response and not isinstance(response['version'], str):
        raise ProtocolError("invalid broker response")
    if 'totp_import_supported' in response and type(response['totp_import_supported']) is not bool:
        raise ProtocolError("invalid importer capability")
    if 'totp_import_protocol' in response and (type(response['totp_import_protocol']) is not int or response['totp_import_protocol'] != 1):
        raise ProtocolError("unsupported importer protocol")
    if "error" in response and not isinstance(response["error"], str):
        raise ProtocolError("invalid broker response")
    if "private_url" in response:
        _validate_unlock_url(response["private_url"], expected_unlock_origin)
    if "unlock_url" in response:
        _validate_unlock_url(response["unlock_url"], expected_unlock_origin)
    return response


def request(
    socket_path: Path,
    payload: dict,
    *,
    broker_uid: int | None = None,
    expected_unlock_origin: str = DEFAULT_UNLOCK_ORIGIN,
) -> dict:
    broker_uid = os.getuid() if broker_uid is None else broker_uid
    socket_path, runtime_fd = _validate_socket_path(socket_path, broker_uid)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if payload.get('action') in {'merge', 'admit'}:
        timeout = 480 if payload.get('refresh_target') or payload.get('preserve_conflicts') else 240
    else:
        timeout = 240 if payload.get('action') in IDENTITY_CREATES else 15 if payload.get('action') == 'pin-card-target' else 5
    client.settimeout(timeout)
    try:
        client.connect(anchored_socket_path(runtime_fd, socket_path.name))
        _, peer_uid, _ = _peer_credentials(client)
        if peer_uid != broker_uid:
            raise PermissionError("broker peer UID does not match the configured broker UID")
        send_message(client, payload)
        return _validate_response(receive_message(client), expected_unlock_origin)
    finally:
        client.close()
        os.close(runtime_fd)


def _read_webhook_url(path: Path) -> str:
    """Read a private callback without placing its bearer token in argv/output."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096):
            raise ValueError("webhook URL file must be an owned mode-0600 regular file of at most 4096 bytes")
        return validate_webhook_url(source.read(4097).strip())


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="akdbx", description="Secret-withholding KeePass autofill broker")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--socket", type=Path, default=default_socket())
    result.add_argument(
        "--broker-uid", type=int, default=int(os.environ.get("AKDBX_BROKER_UID", os.getuid())),
        help="expected operating-system UID of the broker",
    )
    result.add_argument(
        "--unlock-origin", default=os.environ.get("AKDBX_UNLOCK_ORIGIN", DEFAULT_UNLOCK_ORIGIN),
        help="deployment HTTPS origin for private pages (or AKDBX_UNLOCK_ORIGIN); default is a non-routable example",
    )
    commands = result.add_subparsers(dest="command", required=True)
    card_cli.add_parsers(commands)
    start = commands.add_parser("serve", help="unlock a KDBX and run the local broker")
    start.add_argument("database", type=Path)
    start.add_argument('--card-browser-profile', type=Path, default=os.environ.get('AKDBX_CARD_BROWSER_PROFILE'),
                       help='existing private Chrome user-data directory with local CDP enabled; no browser is launched')
    start.add_argument("--keyfile", type=Path)
    start.add_argument("--yes-on-fill", action="store_true", help="deprecated no-op: fills no longer require terminal approval")
    start.add_argument("--web-unlock", action="store_true", help="compatibility flag: private web unlock is always enabled")
    start.add_argument("--unlock-socket", type=Path, help=argparse.SUPPRESS)
    start.add_argument("--unlock-url", help=argparse.SUPPRESS)
    start.add_argument("--notification-state", type=Path, help="private durable until-unlock subscription file; default beside broker socket")
    search = commands.add_parser("search", help="return matching non-secret login metadata")
    search.add_argument("query", nargs="?", default="")
    fill = commands.add_parser("fill", help="autofill using a handle returned by search")
    fill.add_argument("handle")
    fill.add_argument("--mode", choices=("login", "username", "password"), default="login")
    pin = commands.add_parser('pin-target', help='pin an independently verified local foreground PID/window and current input-focus window for 30 seconds')
    pin.add_argument('--pid', type=int, required=True)
    pin.add_argument('--window', type=lambda value: int(value, 0), required=True, help='verified X11 client window ID, decimal or 0x hex')
    for name in ('create-entry', 'generate-entry', *IDENTITY_CREATES, 'update-password', 'generate-password', 'setup-totp'):
        help_text = {
            'create-sso-entry': 'save a Google/GitHub SSO identity (no password form)',
            'create-passwordless-entry': 'save an email-code identity (no password or saved code)',
            'generate-password': 'stage a broker-generated password for an existing entry',
            'generate-entry': 'stage a broker-generated password for a new entry',
            'setup-totp': 'import an authenticator key through a private page for an existing entry; never pass keys on the command line',
        }.get(name, 'prepare a private password save')
        command = commands.add_parser(name, help=help_text, description=help_text)
        if name not in ('create-entry', 'generate-entry', *IDENTITY_CREATES):
            command.add_argument('handle')
        for field in ('title', 'username', 'url', 'group'):
            command.add_argument('--' + field, required=True, help='exact selected/destination metadata')
        if name == 'create-sso-entry':
            command.add_argument('--auth-method', required=True, choices=('google', 'github'), help='verified SSO provider; no separate site password')
        if name == 'create-passwordless-entry':
            command.add_argument('--auth-method', required=True, choices=('email_code',), help='verified native email-code sign-in; no separate site password; never save the code')
        if name in ('generate-password', 'generate-entry'):
            command.add_argument('--length', type=int, default=24)
            command.add_argument('--symbols', default='!@#$%*-_+=?', help='allowed ASCII punctuation; empty for letters and digits')
        if name == 'setup-totp':
            command.add_argument('--replace', action='store_true', help='explicitly permit replacing this entry\'s existing authenticator')
    for name in ('write-status', 'cancel-write', 'commit-password'):
        command = commands.add_parser(name, help='check/cancel a staged write' if name != 'commit-password' else 'save staged password after verified website acceptance')
        command.add_argument('write_handle')
        if name == 'commit-password':
            command.add_argument('--site-accepted', action='store_true', required=True)
    generated = commands.add_parser('fill-generated', help='fill a single-use generated password reference into a verified focused field')
    generated.add_argument('handle')
    generated.add_argument('--target-url', required=True, help='independently verified reset site URL')
    totp = commands.add_parser('fill-totp', help='generate and directly fill a saved TOTP code; returns no key or code')
    totp.add_argument('handle', help='fresh selected-entry handle from search')
    totp.add_argument('--target-url', required=True, help='independently verified HTTPS challenge URL; must match the entry origin')
    for command in (fill, generated, totp):
        command.add_argument('--target', required=True, help='fresh single-use pin-target token; no global fallback')
    commands.add_parser("status", help="check broker status")
    subscribe = commands.add_parser("subscribe-unlock", help="register a one-shot HTTPS unlock webhook; no active agent wait")
    subscribe.add_argument("--webhook-url-file", required=True, type=Path,
                           help="owned mode-0600 file containing the private callback URL")
    subscribe.add_argument("--ttl", type=int, default=0, help="0 waits until unlock/cancel (default); 60–3600 seconds only for an explicitly time-limited wait")
    for name in ("unlock-subscription-status", "unsubscribe-unlock"):
        command = commands.add_parser(name, help="inspect/cancel a one-shot unlock subscription")
        command.add_argument("subscription_id")
    merge = commands.add_parser('merge', help='merge another encrypted KDBX into the broker vault using held credentials')
    merge.add_argument('source', type=Path, help='source KDBX (unchanged); same password and key file as target')
    merge.add_argument('--check', action='store_true', help='verify a staged encrypted merge without replacing the target')
    merge.add_argument('--refresh-target', action='store_true', help='reconcile the verified broker state, current disk target and source using held credentials')
    merge.add_argument('--preserve-conflicts', action='store_true', help='keep every logical version in encrypted in-vault capsules; current target wins active timestamp ties')
    merge.add_argument('--operation-id', help='32 lowercase hex characters; reuse only to retrieve the same durable receipt')
    admit = commands.add_parser('admit', help='opt-in exact-byte conditional admission with external encrypted snapshots; policy review required',
                                description='Exact-byte snapshot-admission-v1; explicit group verification profiles require CLI and broker 0.8.0 or newer. Policy review required.')
    admit.add_argument('source', type=Path)
    admit.add_argument('--policy', required=True, choices=('snapshot-admission-v1',))
    admit.add_argument('--group-verification', default='group-semantic-v1', choices=('group-semantic-v1', 'group-tag-sequence-v1', 'native-group-selection-v1'), help='explicit group contract; extended profiles require exact KeePassXC 2.7.10')
    admit.add_argument('--snapshot-dir', required=True, type=Path, help='existing mode-0700 directory outside the synced vault; permanently bound for recovery')
    admit.add_argument('--if-match', help='optional current encrypted target SHA256; no quotes or wildcard')
    admit.add_argument('--check', action='store_true', help='read-only admission check; retain snapshots and receipt')
    admit.add_argument('--operation-id', help='32 lowercase hex; use merge-status to recover this same operation')
    merge_status = commands.add_parser('merge-status', help='read a durable merge receipt, including after restart')
    merge_status.add_argument('operation_id')
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "serve":
        database = args.database.expanduser()
        keyfile = args.keyfile.expanduser() if args.keyfile else None
        if args.yes_on_fill:
            print("Warning: --yes-on-fill is deprecated and has no effect; fills no longer require terminal approval.", file=sys.stderr)
        broker = Broker(None, X11Typer(), card_browser_profile=args.card_browser_profile,
                        notification_state_path=args.notification_state or args.socket.with_name(args.socket.name + '.unlock-notifications.json'))
        unlock_name = ("agentic-kdbx-unlock.sock"
                       if args.socket.name == "agentic-kdbx.sock"
                       else "akdbx-unlock.sock")
        unlock_socket = args.unlock_socket or args.socket.with_name(unlock_name)
        unlock_server, unlock_url = start_unlock_server(
            broker, database, keyfile, unlock_socket, args.unlock_url or args.unlock_origin,
        )
        print(f"Vault locked. Open over Tailscale: {unlock_url}", file=sys.stderr)
        print(f"Broker ready at {args.socket}; Ctrl-C locks it.", file=sys.stderr)
        try:
            serve(args.socket, broker)
        except KeyboardInterrupt:
            print("\nBroker locked.", file=sys.stderr)
        finally:
            unlock_server.shutdown()
            unlock_server.server_close()
        return 0
    if args.command in card_cli.COMMANDS:
        return card_cli.run(args, lambda payload: request(args.socket, payload, broker_uid=args.broker_uid,
                                                        expected_unlock_origin=args.unlock_origin))
    payload = {"action": "ping" if args.command == "status" else args.command}
    if args.command in {'unlock-subscription-status', 'unsubscribe-unlock'}:
        payload['subscription_id'] = args.subscription_id
    elif args.command == 'pin-target':
        payload.update(pid=args.pid, window=args.window, target_protocol=1)
    elif args.command == "search":
        payload["query"] = args.query
    elif args.command in {'merge', 'admit'}:
        payload.update(source=os.path.abspath(args.source.expanduser()), check=args.check,
                       operation_id=args.operation_id or uuid.uuid4().hex)
        if args.command == 'admit':
            payload.update(policy=args.policy, verification='native-containment-v1',
                           group_protocol=2, group_verification=args.group_verification,
                           snapshot_directory=os.path.abspath(args.snapshot_dir.expanduser()))
            if args.if_match is not None:
                payload['if_match'] = args.if_match
        if args.command == 'merge' and args.refresh_target:
            payload['refresh_target'] = True
        if args.command == 'merge' and args.preserve_conflicts:
            payload['preserve_conflicts'] = True
            payload['active_verification'] = 'semantic-v1'
        if not ID_PATTERN.fullmatch(payload['operation_id']):
            print('operation ID must be 32 lowercase hexadecimal characters', file=sys.stderr)
            return 2
        # Known before send: recover after a lost response without a new merge.
        print('Merge operation: ' + payload['operation_id'], file=sys.stderr)
    elif args.command == 'merge-status':
        payload['operation_id'] = args.operation_id
    elif args.command in ('create-entry', 'generate-entry', *IDENTITY_CREATES, 'update-password', 'generate-password', 'setup-totp'):
        payload['metadata'] = {field: getattr(args, field) for field in ('title', 'username', 'url', 'group')}
        if args.command not in ('create-entry', 'generate-entry', *IDENTITY_CREATES):
            payload['handle'] = args.handle
        if args.command in ('generate-password', 'generate-entry'):
            payload.update(length=args.length, symbols=args.symbols)
        if args.command in IDENTITY_CREATES:
            payload['auth_method'] = args.auth_method
        if args.command == 'setup-totp':
            payload['replace'] = args.replace
    elif args.command in {'write-status', 'cancel-write', 'commit-password'}:
        payload['write_handle'] = args.write_handle
        if args.command == 'commit-password':
            payload['site_accepted'] = args.site_accepted
    elif args.command in {'fill-generated', 'fill-totp'}:
        payload.update(handle=args.handle, target_url=args.target_url, start_deadline=time.monotonic() + FILL_START_TIMEOUT)
    elif args.command == "fill":
        payload.update(
            handle=args.handle,
            mode=args.mode,
            start_deadline=time.monotonic() + FILL_START_TIMEOUT,
        )
    if args.command in {'fill', 'fill-generated', 'fill-totp'}:
        payload.update(target=args.target, target_protocol=1)
    identity_kind = 'SSO' if args.command == 'create-sso-entry' else 'passwordless'
    try:
        if args.command == 'subscribe-unlock':
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True
                    or capabilities.get('unlock_notifications_supported') is not True
                    or type(capabilities.get('unlock_notifications_protocol')) is not int
                    or capabilities['unlock_notifications_protocol'] != 1):
                print(json.dumps({'ok': False, 'error': 'broker lacks unlock notification protocol 1; require broker 0.11.0 or newer; subscription not sent'}))
                return 1
            if args.ttl == 0 and capabilities.get('unlock_notifications_until_unlock') is not True:
                print(json.dumps({'ok': False, 'error': 'broker lacks an until-unlock subscription; subscription not sent'}))
                return 1
            payload.update(webhook_url=_read_webhook_url(args.webhook_url_file),
                           ttl=args.ttl, notification_protocol=1)
        if args.command in {'setup-totp', 'fill-totp'}:
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or capabilities.get('totp_supported') is not True
                    or type(capabilities.get('totp_protocol')) is not int or capabilities.get('totp_protocol') != 1):
                print(json.dumps({'ok': False, 'error': 'broker lacks TOTP protocol 1; require broker 0.10.0 or newer; TOTP request not sent'}))
                return 1
        if args.command == 'generate-entry':
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or type(capabilities.get('generated_entry_protocol')) is not int
                    or capabilities.get('generated_entry_protocol') != 1):
                print(json.dumps({'ok': False, 'error': 'broker lacks generated entry protocol 1; generation not sent'}))
                return 1
        if args.command in {'pin-target', 'fill', 'fill-generated', 'fill-totp'}:
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or capabilities.get('target_fill_required') is not True
                    or type(capabilities.get('target_fill_protocol')) is not int
                    or capabilities.get('target_fill_protocol') != 1
                    or capabilities.get('target_fill_delivery') != DELIVERY):
                print(json.dumps({'ok': False, 'error': 'broker lacks target fill protocol 1; require broker 0.9.0 or newer; target request not sent'}))
                return 1
            if args.command in {'fill', 'fill-generated', 'fill-totp'}:
                # Capability preflight does not use up the short start deadline.
                payload['start_deadline'] = time.monotonic() + FILL_START_TIMEOUT
        if args.command in IDENTITY_CREATES:
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            prefix = 'sso' if args.command == 'create-sso-entry' else 'passwordless'
            methods = capabilities.get(prefix + '_auth_methods')
            if (capabilities.get('ok') is not True or capabilities.get(prefix + '_identity_supported') is not True
                    or type(capabilities.get(prefix + '_identity_protocol')) is not int
                    or capabilities.get(prefix + '_identity_protocol') != 1
                    or not isinstance(methods, list) or not all(isinstance(method, str) for method in methods)
                    or args.auth_method not in methods):
                minimum = '0.8.1' if args.command == 'create-sso-entry' else '0.9.1'
                print(json.dumps({'ok': False, 'error': f'broker lacks {identity_kind} identity protocol 1 for the requested method; require broker {minimum} or newer; {identity_kind} creation not sent'}))
                return 1
        if args.command == 'admit':
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or capabilities.get('admission_supported') is not True
                    or type(capabilities.get('admission_protocol')) is not int
                    or capabilities.get('admission_protocol') != 1
                    or capabilities.get('admission_policy') != 'snapshot-admission-v1'
                    or capabilities.get('admission_verification') != 'native-containment-v1'
                    or capabilities.get('admission_group_verification') != 'group-semantic-v1'
                    or type(capabilities.get('admission_group_protocol')) is not int
                    or capabilities.get('admission_group_protocol') != 2
                    or not isinstance(capabilities.get('admission_group_verifiers'), list)
                    or args.group_verification not in capabilities['admission_group_verifiers']
                    or capabilities.get('admission_group_tags') != 'keepassium-2.5.171-sequence-v1'
                    or capabilities.get('admission_group_selection') != 'keepassxc-2.7.10-selection-v1'
                    or capabilities.get('admission_group_diagnostics') != 'group-categories-v1'):
                print(json.dumps({'ok': False, 'error': 'broker lacks exact requested group verification protocol 2; require broker 0.8.0 with the selected profile; admission not sent'}))
                return 1
        if args.command == 'merge' and (args.refresh_target or args.preserve_conflicts):
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if not capabilities.get('ok') or args.refresh_target and capabilities.get('merge_refresh_target_supported') is not True:
                print(json.dumps({'ok': False, 'error': 'broker does not support --refresh-target; require broker 0.4.0 or newer; merge not sent'}))
                return 1
            if args.preserve_conflicts and (capabilities.get('merge_preserve_conflicts_supported') is not True or capabilities.get('merge_preservation_policy') != 'capsule-v1' or capabilities.get('merge_active_verification') != 'semantic-v1'):
                print(json.dumps({'ok': False, 'error': 'broker does not support --preserve-conflicts capsule-v1/semantic-v1; require broker 0.6.0 or newer; merge not sent'}))
                return 1
        response = request(
            args.socket, payload, broker_uid=args.broker_uid,
            expected_unlock_origin=args.unlock_origin,
        )
    except (FileNotFoundError, ConnectionRefusedError):
        print("broker is not running", file=sys.stderr)
        return 2
    except (PermissionError, ProtocolError, RuntimeError, ValueError) as exc:
        if args.command in {'merge', 'admit'}:
            print('merge outcome unconfirmed: broker response rejected; use merge-status ' + payload['operation_id'] + '; do not retry with a new ID', file=sys.stderr)
        elif args.command in IDENTITY_CREATES:
            print(f'{identity_kind} save outcome unconfirmed: broker response rejected; check status and search before any retry', file=sys.stderr)
        else:
            print(f"refusing untrusted broker response: {exc}", file=sys.stderr)
        return 2
    except (TimeoutError, OSError):
        if args.command in {"fill", "fill-generated", "fill-totp"}:
            print(
                "autofill outcome uncertain: connection lost after request; do not retry automatically",
                file=sys.stderr,
            )
        elif args.command == 'commit-password':
            print('save outcome uncertain: check write-status before any retry; do not reset the site again', file=sys.stderr)
        elif args.command in IDENTITY_CREATES:
            print(f'{identity_kind} save outcome uncertain: check status and search before any retry; do not create another record automatically', file=sys.stderr)
        elif args.command in {'merge', 'admit'}:
            print('merge outcome uncertain: use merge-status ' + payload['operation_id'] + '; do not retry with a new ID', file=sys.stderr)
        else:
            print("broker request failed", file=sys.stderr)
        return 2
    if args.command in {'setup-totp', 'fill-totp'}:
        allowed = ({'ok', 'write_handle', 'private_url', 'state'} if args.command == 'setup-totp'
                   else {'ok', 'filled', 'target_delivery'}) if response.get('ok') else {'ok', 'error', 'retry_after', 'unlock_url', 'delivery'}
        invalid_delivery = 'delivery' in response and (
            args.command != 'fill-totp' or response['delivery'] not in ('not-started', 'uncertain'))
        invalid_retry = 'retry_after' in response and (
            type(response['retry_after']) is not int or not 1 <= response['retry_after'] <= 120)
        if set(response) - allowed or invalid_delivery or invalid_retry:
            print('TOTP operation outcome unconfirmed: receipt rejected; inspect status before any retry', file=sys.stderr)
            return 2
        if args.command == 'setup-totp' and response.get('ok') and (
                response.get('state') != 'pending' or not isinstance(response.get('write_handle'), str)
                or not response['write_handle'] or urlsplit(response.get('private_url', '')).path != '/totp'):
            print('TOTP setup outcome unconfirmed: receipt rejected; inspect status before any retry', file=sys.stderr)
            return 2
    if args.command in {'pin-target', 'fill', 'fill-generated', 'fill-totp'} and response.get('ok'):
        invalid_pin = args.command == 'pin-target' and (
            not isinstance(response.get('target'), str) or len(response['target']) != 64
            or any(c not in '0123456789abcdef' for c in response['target'])
            or type(response.get('pid')) is not int or response['pid'] != args.pid
            or type(response.get('window')) is not int or response['window'] != args.window
            or type(response.get('expires_in')) is not int or response['expires_in'] != 30)
        invalid_fill = args.command in {'fill', 'fill-generated', 'fill-totp'} and (
            response.get('filled') != (args.mode if args.command == 'fill' else 'totp' if args.command == 'fill-totp' else 'password'))
        if response.get('target_delivery') != DELIVERY or invalid_pin or invalid_fill:
            print('target operation outcome unconfirmed: receipt rejected; do not retry automatically', file=sys.stderr)
            return 2
    if args.command in {'merge', 'admit'} and response.get('error') == 'vault locked':
        response['continuation'] = 'Open unlock_url privately, then repeat the same command, policy and operation ID.'
        response['operation_id'] = payload['operation_id']
    if args.command in IDENTITY_CREATES and response.get('ok') and (
            response.get('state') != 'saved' or response.get('passwordless') is not True
            or response.get('auth_method') != args.auth_method or response.get('metadata') != payload['metadata']):
        print(f'{identity_kind} save outcome unconfirmed: receipt rejected; check status and search before any retry', file=sys.stderr)
        return 2
    if args.command == 'admit' and response.get('ok') and (
            response.get('mode') != 'admission' or response.get('policy') != 'snapshot-admission-v1'
            or response.get('verification') != 'native-containment-v1' or response.get('exact_bytes') is not True
            or response.get('group_verification') != args.group_verification
            or type(response.get('group_protocol')) is not int or response.get('group_protocol') != 2
            or response.get('group_tag_verification') != ('raw-v1' if args.group_verification == 'group-semantic-v1' else 'keepassium-2.5.171-sequence-v1')
            or response.get('group_selection') != ('keepassxc-2.7.10-selection-v1' if args.group_verification == 'native-group-selection-v1' else 'strict-v1')
            or response.get('operation_id') != payload['operation_id']
            or response.get('check') is not args.check
            or response.get('state') not in ({'checked'} if args.check else {'saved', 'unchanged'})):
        print('admission outcome unconfirmed: result policy rejected; use merge-status ' + payload['operation_id'], file=sys.stderr)
        return 2
    print(json.dumps(response, indent=2))
    return 0 if response.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
