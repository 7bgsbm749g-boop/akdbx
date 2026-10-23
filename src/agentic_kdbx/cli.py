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
from .broker import Broker, FILL_START_TIMEOUT, PynputTyper, serve
from .protocol import ProtocolError, receive_message, send_message
from .runtime import anchored_socket_path, open_private_runtime_directory
from .merge import ID_PATTERN
from .web_unlock import start_unlock_server


DEFAULT_UNLOCK_ORIGIN = "https://vps-3857965a.tailb80cc4.ts.net:9443"


def default_socket() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = Path(runtime) / "agentic-kdbx" if runtime else Path(f"/tmp/akdbx-{os.getuid()}")
    return base / "agentic-kdbx.sock"


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
    for capability in ('locked', 'writes_available', 'recovery_required', 'merge_available', 'merge_same_credentials_only', 'merge_refresh_target_supported', 'merge_preserve_conflicts_supported', 'admission_supported'):
        if capability in response and type(response[capability]) is not bool:
            raise ProtocolError("invalid broker response")
    if 'version' in response and not isinstance(response['version'], str):
        raise ProtocolError("invalid broker response")
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
    client.settimeout((480 if payload.get('refresh_target') or payload.get('preserve_conflicts') else 240) if payload.get('action') in {'merge', 'admit'} else 5)
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
        help="trusted HTTPS origin for broker-provided unlock links",
    )
    commands = result.add_subparsers(dest="command", required=True)
    start = commands.add_parser("serve", help="unlock a KDBX and run the local broker")
    start.add_argument("database", type=Path)
    start.add_argument("--keyfile", type=Path)
    start.add_argument("--yes-on-fill", action="store_true", help="deprecated no-op: fills no longer require terminal approval")
    start.add_argument("--web-unlock", action="store_true", help="compatibility flag: private web unlock is always enabled")
    start.add_argument("--unlock-socket", type=Path, help=argparse.SUPPRESS)
    start.add_argument("--unlock-url", default="https://vps-3857965a.tailb80cc4.ts.net:9443", help=argparse.SUPPRESS)
    search = commands.add_parser("search", help="return matching non-secret login metadata")
    search.add_argument("query", nargs="?", default="")
    fill = commands.add_parser("fill", help="autofill using a handle returned by search")
    fill.add_argument("handle")
    fill.add_argument("--mode", choices=("login", "username", "password"), default="login")
    for name in ('create-entry', 'update-password', 'generate-password'):
        command = commands.add_parser(name, help='prepare a private password save' if name != 'generate-password' else 'stage a broker-generated password for an existing entry')
        if name != 'create-entry':
            command.add_argument('handle')
        for field in ('title', 'username', 'url', 'group'):
            command.add_argument('--' + field, required=True, help='exact selected/destination metadata')
        if name == 'generate-password':
            command.add_argument('--length', type=int, default=24)
            command.add_argument('--symbols', default='!@#$%*-_+=?', help='allowed ASCII punctuation; empty for letters and digits')
    for name in ('write-status', 'cancel-write', 'commit-password'):
        command = commands.add_parser(name, help='check/cancel a staged write' if name != 'commit-password' else 'save staged password after verified website acceptance')
        command.add_argument('write_handle')
        if name == 'commit-password':
            command.add_argument('--site-accepted', action='store_true', required=True)
    generated = commands.add_parser('fill-generated', help='fill a single-use generated password reference into a verified focused field')
    generated.add_argument('handle')
    generated.add_argument('--target-url', required=True, help='independently verified reset site URL')
    commands.add_parser("status", help="check broker status")
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
        broker = Broker(None, PynputTyper())
        unlock_socket = args.unlock_socket or args.socket.with_name("agentic-kdbx-unlock.sock")
        unlock_server, unlock_url = start_unlock_server(broker, database, keyfile, unlock_socket, args.unlock_url)
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
    payload = {"action": "ping" if args.command == "status" else args.command}
    if args.command == "search":
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
    elif args.command in {'create-entry', 'update-password', 'generate-password'}:
        payload['metadata'] = {field: getattr(args, field) for field in ('title', 'username', 'url', 'group')}
        if args.command != 'create-entry':
            payload['handle'] = args.handle
        if args.command == 'generate-password':
            payload.update(length=args.length, symbols=args.symbols)
    elif args.command in {'write-status', 'cancel-write', 'commit-password'}:
        payload['write_handle'] = args.write_handle
        if args.command == 'commit-password':
            payload['site_accepted'] = args.site_accepted
    elif args.command == 'fill-generated':
        payload.update(handle=args.handle, target_url=args.target_url, start_deadline=time.monotonic() + FILL_START_TIMEOUT)
    elif args.command == "fill":
        payload.update(
            handle=args.handle,
            mode=args.mode,
            start_deadline=time.monotonic() + FILL_START_TIMEOUT,
        )
    try:
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
        else:
            print(f"refusing untrusted broker response: {exc}", file=sys.stderr)
        return 2
    except (TimeoutError, OSError):
        if args.command in {"fill", "fill-generated"}:
            print(
                "autofill outcome uncertain: connection lost after request; do not retry automatically",
                file=sys.stderr,
            )
        elif args.command == 'commit-password':
            print('save outcome uncertain: check write-status before any retry; do not reset the site again', file=sys.stderr)
        elif args.command in {'merge', 'admit'}:
            print('merge outcome uncertain: use merge-status ' + payload['operation_id'] + '; do not retry with a new ID', file=sys.stderr)
        else:
            print("broker request failed", file=sys.stderr)
        return 2
    if args.command in {'merge', 'admit'} and response.get('error') == 'vault locked':
        response['continuation'] = 'Open unlock_url privately, then repeat the same command, policy and operation ID.'
        response['operation_id'] = payload['operation_id']
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
