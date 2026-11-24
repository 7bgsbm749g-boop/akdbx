from __future__ import annotations

import argparse
import hashlib
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
from .browser_password import DELIVERY as PASSWORD_DELIVERY
from .runtime import anchored_socket_path, open_private_runtime_directory
from .merge import ID_PATTERN
from .web_unlock import start_unlock_server
from .local_https import is_loopback_origin, reload_certificate, start_local_unlock_server
from .notifications import validate_webhook_url
from . import capture_cli, card_cli, extension_host, identity_cli, pairing_cli, relay as relay_module, relay_cli, secret_cli, sms_cli
from . import android_cli, android_route, browser_slots, page_url, setup_cli
from .extension_route import DELIVERY as EXTENSION_DELIVERY, ROUTES as FILL_ROUTES
from .sink_helper import SinkError


# Reserved example domain: deployment addresses belong in local configuration.
DEFAULT_UNLOCK_ORIGIN = "https://unlock.example.invalid:9443"
IDENTITY_CREATES = ('create-sso-entry', 'create-passwordless-entry')
URL_CHANGES = ('add-url', 'remove-url')


# Where systemd-logind puts per-user runtime directories. A non-interactive
# SSH command often has no XDG_RUNTIME_DIR even though the user's broker runs
# under this directory.
SYSTEM_RUNTIME_ROOT = Path("/run/user")


def _socket_candidates(runtime: Path) -> tuple[Path, Path]:
    return runtime / "akdbx" / "akdbx.sock", runtime / "agentic-kdbx" / "agentic-kdbx.sock"


def _first_present(candidates) -> Path | None:
    # Keep existing unlocked brokers usable during an upgrade. All normal
    # ownership, symlink and peer checks still apply when connecting.
    for candidate in candidates:
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        return candidate
    return None


def _private_system_runtime() -> Path | None:
    """Return /run/user/<uid> only when it is this user's own private directory."""
    runtime = SYSTEM_RUNTIME_ROOT / str(os.getuid())
    try:
        info = runtime.lstat()
    except OSError:
        return None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022):
        return None
    return runtime


def default_socket() -> Path:
    if os.name == 'nt':
        from .windows_rpc import default_pipe
        return default_pipe()
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        canonical, legacy = _socket_candidates(Path(runtime))
        return _first_present((canonical, legacy)) or canonical
    # Without XDG_RUNTIME_DIR (for example `ssh host akdbx status`), use a
    # broker that already listens in the logind runtime directory before the
    # /tmp fallback. A new broker still defaults to the /tmp path.
    system_runtime = _private_system_runtime()
    if system_runtime is not None:
        # This location is a guess, so take only an actual socket and skip
        # unexpected entries instead of letting them hide a broker or the
        # old /tmp default.
        for candidate in _socket_candidates(system_runtime):
            try:
                if stat.S_ISSOCK(candidate.lstat().st_mode):
                    return candidate
            except OSError:
                continue
    base = Path(f"/tmp/akdbx-{os.getuid()}")
    canonical = base / "akdbx.sock"
    return _first_present((canonical, base / "agentic-kdbx.sock")) or canonical


def _validate_socket_path(socket_path: Path, broker_uid: int) -> tuple[Path, int]:
    """Open a trusted runtime leaf and validate its socket relative to that fd."""
    socket_path = Path(os.path.abspath(os.fspath(socket_path)))
    try:
        runtime_path, runtime_fd = open_private_runtime_directory(
            socket_path.parent, owner_uid=broker_uid,
        )
    except RuntimeError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            raise FileNotFoundError from exc
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


def _same_origin(first: str, second: str) -> bool:
    """True when two HTTPS origins name the same host and effective port, as client validation compares them."""
    def identity(value):
        parts = urlsplit(value)
        port = parts.port
        if (parts.scheme.lower() != 'https' or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.path not in {'', '/'} or parts.query or parts.fragment):
            return None
        return parts.hostname.lower(), 443 if port is None else port
    try:
        a, b = identity(first), identity(second)
    except ValueError:
        return False
    return a is not None and a == b


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
    for capability in ('locked', 'unlock_blocked', 'unlock_block_saved', 'writes_available', 'recovery_required', 'merge_available', 'merge_same_credentials_only', 'merge_refresh_target_supported', 'merge_preserve_conflicts_supported', 'admission_supported', 'sso_identity_supported', 'passwordless_identity_supported', 'target_fill_required', 'totp_supported'):
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
    if "unlock_origin" in response:
        # A blocked link's status has no URL, only its non-secret origin.
        origin = response["unlock_origin"]
        parts = urlsplit(origin) if isinstance(origin, str) else None
        if parts is None or parts.path or parts.query or parts.fragment:
            raise ProtocolError("invalid broker response")
        _validate_unlock_url(origin + "/?token=origin-check", expected_unlock_origin)
    pairing = response.get("extension_pairing")
    if pairing is not None:
        # Pairing links are private broker pages, like the unlock link.
        if not isinstance(pairing, list) or len(pairing) > 4:
            raise ProtocolError("invalid broker response")
        for item in pairing:
            if not isinstance(item, dict) or set(item) != {"browser", "code", "url"}:
                raise ProtocolError("invalid broker response")
            _validate_unlock_url(item["url"], expected_unlock_origin)
            if urlsplit(item["url"]).path != "/extension/pair":
                raise ProtocolError("invalid broker response")
    return response


def _extension_capture(capabilities):
    """The broker reads secrets through the extension (0.32.0+)."""
    return (type(capabilities.get('extension_capture_protocol')) is int and capabilities['extension_capture_protocol'] == 1
            and capabilities.get('extension_capture_delivery') == 'extension-dom-read-v1')


def _read_route(args, capabilities):
    """The route a read pin takes: --route, else the default route; an older broker reads only over CDP.

    The extension reads only in the top document, so a child-frame read pin without --route takes CDP.
    """
    if args.route is not None:
        return args.route
    if getattr(args, 'frame_origin', None) is not None:
        return 'cdp'
    default = capabilities.get('default_fill_route')
    return 'extension' if default == 'extension' and _extension_capture(capabilities) else 'cdp'


def _request_timeout(payload: dict) -> int:
    """One response budget for both transports; the broker bounds its own work."""
    action = payload.get('action')
    if action in {'merge', 'admit'}:
        return 480 if payload.get('refresh_target') or payload.get('preserve_conflicts') else 240
    # Frame routes resolve bounded out-of-process iframe targets first.
    slow = action in {'pin-card-target', 'pin-identity-target', 'list-password-frames'} or (
        action == 'pin-password-target' and ('frame_origin' in payload or payload.get('route') == 'extension'
                                             or payload.get('mode') == 'read'))
    if action == 'sms-wait':
        timeout = payload.get('timeout', 0)
        return (timeout if type(timeout) is int and 0 <= timeout <= 300 else 0) + 10
    slow = slow or action in {'pin-code-target', 'sms-add-source'}
    return 240 if action in (*IDENTITY_CREATES, *URL_CHANGES, 'commit-password', secret_cli.COMMAND, *capture_cli.COMMANDS) else 15 if slow else 5


def request(
    socket_path: Path,
    payload: dict,
    *,
    broker_uid: int | None = None,
    expected_unlock_origin: str = DEFAULT_UNLOCK_ORIGIN,
    before_send=None,
    timeout: int | None = None,
) -> dict:
    timeout = _request_timeout(payload) if timeout is None else timeout
    if os.name == 'nt':
        from .windows_rpc import connect
        if broker_uid is not None:
            raise ValueError('--broker-uid is a Linux option; Windows requires the same user/session')
        with connect(socket_path) as client:
            client.settimeout(timeout)
            send_message(client, payload, before_send=before_send)
            return _validate_response(receive_message(client), expected_unlock_origin)
    broker_uid = os.getuid() if broker_uid is None else broker_uid
    socket_path, runtime_fd = _validate_socket_path(socket_path, broker_uid)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(anchored_socket_path(runtime_fd, socket_path.name))
        _, peer_uid, _ = _peer_credentials(client)
        if peer_uid != broker_uid:
            raise PermissionError("broker peer UID does not match the configured broker UID")
        send_message(client, payload, before_send=before_send)
        return _validate_response(receive_message(client), expected_unlock_origin)
    finally:
        client.close()
        os.close(runtime_fd)


def _read_webhook_url(path: Path) -> str:
    """Read a private callback without placing its bearer token in argv/output."""
    if os.name == 'nt':
        from .windows_security import read_private
        try:
            data, _ = read_private(path, limit=4096)
            return validate_webhook_url(data.decode('utf-8').strip())
        except Exception:
            raise ValueError('could not read the private Windows webhook URL file') from None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 4096):
            raise ValueError("webhook URL file must be an owned mode-0600 regular file of at most 4096 bytes")
        return validate_webhook_url(source.read(4097).strip())


def _mutation_not_sent(command, error):
    """Describe pre-send failures using only local, fixed text."""
    if isinstance(error, PermissionError):
        reason = 'broker socket or peer identity check failed'
    elif isinstance(error, (ProtocolError, ValueError)):
        reason = 'broker capability or response validation failed'
    elif isinstance(error, RuntimeError):
        reason = 'broker peer verification unavailable'
    else:
        reason = 'broker connection or capability check failed'
    prefix = 'save' if command == 'commit-password' else 'autofill'
    message = f'{prefix} not started: {reason}; request not sent'
    if command == 'commit-password':
        message += '; check write-status before any retry; do not reset the site again'
    return message


def _socket_option(value: str) -> Path:
    """--socket: a Windows pipe name as given; on Linux one absolute path, with ~ expanded, for the broker
    connection and for every command that setup writes (they run from another folder)."""
    return Path(value) if os.name == 'nt' else Path(os.path.abspath(Path(value).expanduser()))


def parser() -> argparse.ArgumentParser:
    """Build command parsers for broker, vault, and target operations."""
    result = argparse.ArgumentParser(prog="akdbx", description="Secret-withholding AKDBX autofill broker")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--socket", type=_socket_option)
    result.add_argument(
        "--broker-uid", type=int, default=(None if os.name == 'nt' else os.environ.get("AKDBX_BROKER_UID", os.getuid())),
        help="expected operating-system UID of the broker",
    )
    result.add_argument(
        "--unlock-origin",
        help=("deployment HTTPS origin for private pages. Order: this option, then AKDBX_UNLOCK_ORIGIN, then the "
              "origin of an enabled akdbx relay ('akdbx relay enable'), then https://localhost:9443. "
              "'serve --relay' ignores AKDBX_UNLOCK_ORIGIN and refuses this option unless it is the relay origin"),
    )
    commands = result.add_subparsers(dest="command", required=True)
    card_cli.add_parsers(commands)
    pairing_cli.add_parsers(commands)
    identity_cli.add_parsers(commands)
    extension_host.add_parser(commands)
    secret_cli.add_parser(commands)
    capture_cli.add_parsers(commands)
    sms_cli.add_parsers(commands)
    relay_cli.add_parser(commands)
    setup_cli.add_parser(commands)
    android_cli.add_parser(commands)
    start = commands.add_parser("serve", help="unlock a KDBX and run the local broker")
    start.add_argument("database", type=Path)
    start.add_argument('--card-browser-profile', type=Path, default=os.environ.get('AKDBX_CARD_BROWSER_PROFILE'),
                       help='existing private Chrome user-data directory with local CDP enabled; no browser is launched')
    start.add_argument("--keyfile", type=Path)
    start.add_argument("--password-browser-profile", type=Path, default=os.environ.get("AKDBX_PASSWORD_BROWSER_PROFILE"),
                       help="operator-selected private Chrome user data directory with remote debugging enabled")
    start.add_argument('--browser-profile-root', type=Path, default=os.environ.get(browser_slots.ROOT_ENV) or None,
                       help=('private folder of agent desktop slots (env ' + browser_slots.ROOT_ENV + '): each slot '
                             'ROOT/slotN is one Chrome user-data directory with local CDP enabled. Password, card and '
                             'identity pins then name their slot (--browser-slot); replaces --password-browser-profile '
                             'and --card-browser-profile'))
    start.add_argument("--yes-on-fill", action="store_true", help="deprecated no-op: fills no longer require terminal approval")
    start.add_argument("--web-unlock", action="store_true", help="compatibility flag: private web unlock is always enabled")
    start.add_argument("--unlock-socket", type=Path, help=argparse.SUPPRESS)
    start.add_argument("--unlock-url", help=argparse.SUPPRESS)
    start.add_argument("--notification-state", type=Path, help="private durable until-unlock subscription file; default beside broker socket. Linux saves a blocked unlock link beside this file when it is given, otherwise in ${XDG_STATE_HOME:-~/.local/state}/akdbx")
    start.add_argument('--secret-sinks', type=Path, default=os.environ.get('AKDBX_SECRET_SINKS'),
                       help='operator sink configuration for deliver-secret (root- or broker-owned, not group/other writable)')
    start.add_argument('--sms-sources', type=Path,
                       help='private file of SMS verification sources (names, kinds and webhook token hashes); '
                            'default beside --notification-state, or in the per-user state folder')
    start.add_argument('--tls-cert', type=Path, help='trusted PEM certificate for the loopback HTTPS private page')
    start.add_argument('--tls-key', type=Path, help='private PEM certificate key (Linux: mode 0600; Windows: restrictive DACL)')
    start.add_argument('--local-port', type=int,
                       help='loopback HTTPS port when --unlock-origin is a remote (Tailscale Serve) origin')
    start.add_argument('--relay', action='store_true',
                       help=('require the saved akdbx relay (akdbx relay enable) and its origin; '
                             'AKDBX_UNLOCK_ORIGIN is then ignored. Without this flag, serve uses an enabled relay '
                             'unless --unlock-origin or AKDBX_UNLOCK_ORIGIN is set'))
    start.add_argument('--no-print-unlock-link', action='store_true',
                       help=('do not print the private unlock link at start; print only that the vault is locked '
                             "and to run 'akdbx status'. Recommended for a service or task, whose output a log "
                             'such as the systemd journal keeps'))
    start.add_argument('--default-fill-route', choices=FILL_ROUTES, default=os.environ.get('AKDBX_DEFAULT_FILL_ROUTE', 'cdp'),
                       help='route for pins that name none: cdp (debugging port) or extension (paired browser extension)')
    start.add_argument('--android-devices', type=Path,
                       default=os.environ.get(android_route.CONFIG_ENV) or android_route.default_config_path(),
                       help=('operator file naming Android devices for the android commands (env '
                             + android_route.CONFIG_ENV + '; default ' + str(android_route.default_config_path())
                             + '); read at each request, so a change needs no restart'))
    search = commands.add_parser("search", help="return matching non-secret login metadata")
    search.add_argument("query", nargs="?", default="")
    fill = commands.add_parser("fill", help="autofill using a handle returned by search")
    fill.add_argument("handle")
    fill.add_argument("--mode", choices=("login", "username", "password"), default="login")
    pin = commands.add_parser('pin-target', help='pin an independently verified local foreground PID/window and current input-focus window for 30 seconds')
    pin.add_argument('--pid', type=int, required=True)
    pin.add_argument('--window', type=lambda value: int(value, 0), required=True, help='verified X11 client window ID or Windows top-level HWND, decimal or 0x hex')
    pin.add_argument('--browser-slot', metavar='SLOT',
                     help='agent desktop slot whose Chrome owns the window (Linux, broker 0.35.3+): the broker pins it '
                          'on that slot\'s X display; --pid must be that Chrome. Not taken from $AGENT_DESKTOP_SLOT')
    password_pin = commands.add_parser('pin-password-target', help='pin an exact HTTPS main-frame or same-site child-frame password field; no keyboard fallback')
    for flag in ('page-id', 'frame-id', 'selector'):
        password_pin.add_argument('--' + flag, required=True)
    page_url.add(password_pin, 'top-url', required=True, help='exact observed top-level page URL, query and fragment included')
    password_pin.add_argument('--frame-origin', help='exact HTTPS origin of the child frame named by --frame-id (from list-password-frames); '
                              'the saved credential must match this origin; requires broker password_frame_protocol 1')
    password_pin.add_argument('--mode', choices=('password', 'username', 'login', 'read'), default='password',
                              help='read pins a focused element that shows a secret, for capture-secret or capture-totp; never select its text')
    password_pin.add_argument('--username-selector', help='required in login mode; no Tab traversal')
    password_pin.add_argument('--password-purpose', choices=('current-password', 'new-password'),
                              help='explicitly verified purpose for password-only fields with absent or on autocomplete')
    password_pin.add_argument('--allow-autocomplete-off', action='store_true',
                              help='allow a verified off password field; requires --password-purpose and broker capability')
    password_pin.add_argument('--route', choices=FILL_ROUTES,
                              help="cdp (debugging port) or extension (paired browser extension); default: the broker's")
    browser_slots.add_argument(password_pin)
    frames = commands.add_parser('list-password-frames', help='read-only: list frame ids, origins and visible field counts of one exact HTTPS page')
    page_url.add(frames, 'top-url', required=True, help='exact verified top-level page URL')
    frames.add_argument('--page-id', help='page target id; required only when several tabs show the same exact URL')
    frames.add_argument('--route', choices=FILL_ROUTES, help="cdp or extension; default: the broker's")
    browser_slots.add_argument(frames)
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
            command.add_argument('--single-field', action='store_true',
                                 help='the verified form has one new-password field and no confirmation field: '
                                      'return only a password fill reference; commit after that one fill')
        if name == 'setup-totp':
            command.add_argument('--replace', action='store_true', help='explicitly permit replacing this entry\'s existing authenticator')
    for name in URL_CHANGES:
        help_text = ('metadata-only: let a selected entry fill on one more exact HTTPS origin (KeePassXC Additional URL); '
                     'the origin must be on the same site (registrable domain) as the saved URL'
                     if name == 'add-url' else 'metadata-only: remove one additional exact HTTPS origin from a selected entry')
        command = commands.add_parser(name, help=help_text, description=help_text)
        command.add_argument('--url', required=True, help='exact HTTPS origin, for example https://login.example.com/')
        command.add_argument('handle', help='fresh selected-entry handle from search')
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
    totp.add_argument('--pending', action='store_true',
                      help='fill a code of the pending authenticator that capture-totp saved, to confirm a website enrollment')
    for command in (fill, generated, totp):
        command.add_argument('--target', required=True, help='fresh single-use pin-target token; no global fallback')
    commands.add_parser("status", help="check broker status")
    new_link = commands.add_parser(
        "new-unlock-link",
        help="replace a blocked unlock link; only after the user confirms the failed attempts were theirs",
        description="Works only while the current unlock link is blocked after three failed attempts. "
                    "The broker cannot verify the user: ask the user first whether they made the failed "
                    "attempts and want a new link. Never retry automatically.")
    new_link.add_argument("--user-confirmed", action="store_true", required=True,
                          help="the user said yes to both questions")
    subscribe = commands.add_parser("subscribe-unlock", help="register a one-shot HTTPS unlock webhook; no active agent wait")
    subscribe.add_argument("--webhook-url-file", required=True, type=Path,
                           help="owned mode-0600 file containing the private callback URL")
    subscribe.add_argument("--ttl", type=int, default=0, help="0 waits until unlock/cancel (default); 60–3600 seconds only for an explicitly time-limited wait")
    subscribe.add_argument("--blocked-events", action="store_true",
                           help="also send akdbx.unlock-blocked when the unlock link is blocked (broker 0.25.0+); "
                                "only for a consumer that rechecks status on every event")
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


def _valid_frame_list(response):
    """Accept only the fixed, value-free frame listing shape."""
    def text(value, limit=128):
        return isinstance(value, str) and 0 < len(value) <= limit
    frames = response.get('frames')
    extension = response.get('route') == 'extension'
    if (set(response) != {'ok', 'page_id', 'main_frame_id', 'frame_policy', 'frames', 'truncated'} | ({'route'} if extension else set())
            or not text(response['page_id']) or not text(response['main_frame_id'])
            or response['frame_policy'] != 'same-site-chain-v1' or type(response['truncated']) is not bool
            or not isinstance(frames, list) or len(frames) > 64):
        return False
    keys = {'frame_id', 'parent_frame_id', 'depth', 'origin', 'eligible', 'visible_fields'} | (
        set() if extension else {'out_of_process'})
    for frame in frames:
        fields = frame.get('visible_fields') if isinstance(frame, dict) else None
        if (not isinstance(frame, dict) or set(frame) != keys or not text(frame['frame_id'])
                or not (frame['parent_frame_id'] is None or text(frame['parent_frame_id']))
                or type(frame['depth']) is not int or not 0 <= frame['depth'] <= 64 or not text(frame['origin'], 512)
                or not extension and type(frame['out_of_process']) is not bool or type(frame['eligible']) is not bool
                or not (fields is None or isinstance(fields, dict) and set(fields) == {'password', 'text'}
                        and all(type(v) is int and 0 <= v <= 512 for v in fields.values()))):
            return False
    return True


# Windows only: `status` there must name exactly what the running broker can
# deliver, and the CLI refuses the rest before it sends a request. The Linux
# CLI keeps its established behaviour, where the broker itself refuses.
PASSWORD_BROWSER_REFUSAL = ('broker has no password browser profile (password_browser_configured is false); '
                            'the operator starts it with --password-browser-profile; target request not sent')
MERGE_UNAVAILABLE_REFUSAL = ('merge unavailable (merge_available is false); require a safe writable vault and '
                             'KeePassXC CLI >=2.7.10,<2.8 installed for all users; merge not sent')


def default_notification_state(socket_path: Path) -> Path:
    """Durable until-unlock subscriptions live beside the broker endpoint.

    A Windows named pipe has no directory, so its state file goes to a private
    per-user folder that the broker creates or verifies at startup.
    """
    name = socket_path.name + '.unlock-notifications.json'
    if os.name == 'nt':
        return Path(os.environ['LOCALAPPDATA']) / 'akdbx' / name
    return socket_path.with_name(name)


def default_unlock_block_state(socket_path: Path) -> Path:
    """Linux: where the broker saves a blocked unlock link by default.

    The runtime folder that holds the socket is cleared on reboot or logout,
    so the block lives in the persistent per-user state folder instead,
    keyed to the broker endpoint so two brokers never share one flag.
    """
    base = os.environ.get('XDG_STATE_HOME', '')
    root = Path(base) if os.path.isabs(base) else Path.home() / '.local' / 'state'
    key = hashlib.sha256(os.fsencode(os.path.realpath(socket_path))).hexdigest()
    return root / 'akdbx' / f'unlock-blocked-{key}.json'


def default_sms_sources(args, notification_state: Path | None = None) -> Path:
    """Where the broker keeps its SMS sources (names, kinds, token hashes).

    --sms-sources wins. Otherwise the file sits beside an explicit (or the
    Windows) notification state, or, on Linux, in the persistent per-user
    state folder keyed to the broker endpoint: the runtime folder that holds
    the socket is cleared on reboot.
    """
    if getattr(args, 'sms_sources', None) is not None:
        return args.sms_sources.expanduser()
    explicit = args.notification_state.expanduser() if args.notification_state is not None else notification_state
    if explicit is not None:
        return Path(str(explicit) + '.sms-sources')
    block = default_unlock_block_state(args.socket)
    return block.with_name(block.name.replace('unlock-blocked-', 'sms-sources-', 1))


def refuse_untrusted_unlock_block(broker) -> bool:
    """Return True, after it prints why, when `serve` must not start.

    A saved unlock-link block that cannot be trusted never starts a broker
    blocked with no way out, and never silently unblocks it.
    """
    manager = broker.unlock_notifications
    try:
        manager.load_unlock_blocked()
        return False
    except Exception as exc:
        path = manager._blocked_path()
        # A folder failure names the folder; a file failure has no detail.
        detail = f' ({exc})' if isinstance(exc, RuntimeError) else ''
    if os.name == 'nt':
        rules = (f'{path.parent} must be a folder that only this user, SYSTEM and administrators can access, '
                 'and the file must be private to this user')
    else:
        rules = (f'{path.parent} and each folder above it must be owned by you or root and not writable by '
                 f'group or others (for example: chmod 700 {path.parent}), and the file must be a regular file '
                 'you own with mode 0600')
    # Print first: the notifiers have not started work, and a failed state
    # write while closing them must not hide which permissions to fix.
    print(f'refusing to start: the saved unlock-link block {path} cannot be trusted{detail}. {rules}. '
          'Fix the permissions, or start with --notification-state FILE in a private folder.', file=sys.stderr)
    for notifier in (manager, broker.card_save_notifications, broker.pairing_notifications,
                     broker.sms_notifications):
        try:
            notifier.close()
        except Exception:
            pass
    return True


def resolve_unlock_origin(args) -> None:
    """Set ``args.unlock_origin``: the option, AKDBX_UNLOCK_ORIGIN, an enabled relay, then the default.

    `serve` and every other command resolve it the same way, so the CLI
    trusts the relay origin without the user copying it. A relay directory
    that fails the private-file checks gives no origin.
    """
    relay = args.command == 'serve' and getattr(args, 'relay', False)
    # `serve --relay` takes the relay origin: an inherited variable must not change it.
    explicit = args.unlock_origin or (None if relay else os.environ.get('AKDBX_UNLOCK_ORIGIN')) or None
    if args.command == 'serve' and getattr(args, 'unlock_url', None):
        explicit = explicit or args.unlock_url
    args.unlock_origin_explicit = explicit is not None
    args.unlock_origin = explicit or relay_module.saved_origin() or 'https://localhost:9443'


def _relay_for_serve(args):
    """Return ``(config, store)`` when `serve` uses the relay, ``(None, None)`` when not, or an exit code."""
    store = relay_module.RelayStore()
    if args.unlock_origin_explicit and not args.relay:
        return None, None
    try:
        config = store.load()
        certificate = store.certificate(config.name) if config is not None and config.enabled else None
    except relay_module.RelayStoreError as exc:
        if not args.relay and not store.exists():
            return None, None
        print(f'refusing to start: the saved relay configuration cannot be trusted ({exc}). Fix it, run '
              "'akdbx relay disable --forget', or start with --unlock-origin.", file=sys.stderr)
        return 2
    if config is None or not config.enabled:
        if args.relay:
            print("--relay needs an enabled relay: run 'akdbx relay enable' first", file=sys.stderr)
            return 2
        return None, None
    if args.unlock_origin_explicit and not _same_origin(args.unlock_origin, config.origin):
        print(f'--relay sets the origin itself ({config.origin}): remove --unlock-origin and --unlock-url',
              file=sys.stderr)
        return 2
    if args.tls_cert is not None or args.tls_key is not None or args.local_port is not None:
        print('the akdbx relay is enabled: it sets the origin, the certificate and the loopback port itself. '
              "Remove --tls-cert, --tls-key and --local-port, or run 'akdbx relay disable', or set "
              '--unlock-origin to serve without the relay', file=sys.stderr)
        return 2
    if certificate is None:
        try:
            rotating = store.load_rotation() is not None
        except relay_module.RelayStoreError:
            rotating = False
        print("the relay has no usable certificate yet: run 'akdbx relay "
              + ("rotate' again to finish the new name" if rotating else "enable' again"), file=sys.stderr)
        return 2
    return config, store


def _refresh_relay(args, config, store):
    """With the relay lock held: take the relay's current public port and control URL, then warn.

    A failed check keeps the saved values (one warning); it never stops the
    start. Return ``(config, changes)``.
    """
    result = relay_module.refresh(store, config)
    if result.warning:
        print('akdbx relay: warning: ' + result.warning, file=sys.stderr)
    for change in result.changes:
        print('akdbx relay: ' + change, file=sys.stderr)
    config = result.config
    if result.changes and args.unlock_origin_explicit and not _same_origin(args.unlock_origin, config.origin):
        print(f'warning: --unlock-origin names the old relay origin {args.unlock_origin}; this broker now '
              f'serves {config.origin}. Remove --unlock-origin.', file=sys.stderr)
    if result.changes:
        print(f'akdbx relay: the private pages moved to {config.origin}. ' + relay_cli.EXTENSION_FOLLOWS,
              file=sys.stderr)
    inherited = os.environ.get('AKDBX_UNLOCK_ORIGIN', '').strip().rstrip('/')
    if inherited and not _same_origin(inherited, config.origin):
        # serve --relay ignores the variable, but other akdbx commands in this environment still use it
        # and would refuse this broker's links as untrusted.
        print(f'warning: AKDBX_UNLOCK_ORIGIN is {inherited}, but this broker serves the relay origin '
              f'{config.origin}. Other akdbx commands with this variable will refuse its links: unset '
              'AKDBX_UNLOCK_ORIGIN or set it to the relay origin.', file=sys.stderr)
    return config, result.changes


def announce_identity(broker, socket_path, directory=None) -> None:
    """Sign the private pages' origin for the browser extension (see broker_identity).

    A failure never stops the broker: an extension then keeps the origin it
    trusts and opens no link on another one.
    """
    from . import broker_identity
    base = getattr(broker.writes, 'public_base', None)
    if not isinstance(base, str):
        return
    try:
        identity = broker_identity.IdentityStore.for_endpoint(socket_path, directory).announce(base)
    except broker_identity.IdentityError as exc:
        print(f'warning: the browser extension cannot follow an origin change: {exc}. Extensions keep the '
              'origin they trust.', file=sys.stderr)
        return
    except Exception as exc:
        print('warning: the browser extension cannot follow an origin change: the broker identity could not be '
              f'loaded or saved ({type(exc).__name__}). Extensions keep the origin they trust.', file=sys.stderr)
        return
    broker.extension.set_identity(identity)
    if identity.changed:
        print(f'Browser extension: this broker signed its origin {identity.origin} (sequence {identity.seq}). '
              'A paired extension at version 0.3.0 or later follows it at its next connection.', file=sys.stderr)


def _free_loopback_port() -> int:
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def main(argv: list[str] | None = None) -> int:
    """Run one CLI command and return its process exit status."""
    args = parser().parse_args(argv)
    url_error = page_url.resolve(args)
    if url_error is not None:
        print(url_error, file=sys.stderr)
        return 2
    if os.name == 'nt' and args.broker_uid is not None:
        print('--broker-uid applies only to Linux; Windows requires the same user/session', file=sys.stderr)
        return 2
    resolve_unlock_origin(args)
    if args.command == 'extension':
        return extension_host.run(args, args.socket, args.unlock_origin)
    # Setup passes --socket on to the commands it runs only when it was given.
    args.socket_explicit = args.socket is not None
    if args.socket is None:
        try:
            args.socket = default_socket()
        except OSError:
            print('could not locate default broker socket; use --socket', file=sys.stderr)
            return 2
    if args.command == setup_cli.COMMAND:
        return setup_cli.run(args, status=lambda origin: request(
            args.socket, {'action': 'ping'}, broker_uid=args.broker_uid, expected_unlock_origin=origin))
    if args.command == relay_cli.COMMAND:
        return relay_cli.run(args, lambda: request(args.socket, {'action': 'relay-status'},
                                                   broker_uid=args.broker_uid,
                                                   expected_unlock_origin=args.unlock_origin))
    if args.command == "serve":
        database = args.database.expanduser()
        keyfile = args.keyfile.expanduser() if args.keyfile else None
        relay_choice = _relay_for_serve(args)
        if isinstance(relay_choice, int):
            return relay_choice
        relay_config, relay_store = relay_choice
        relay_lock = None
        if relay_config is not None:
            try:
                relay_lock = relay_store.lock()
            except relay_module.RelayBusy:
                print('refusing to start: another akdbx broker uses the relay now', file=sys.stderr)
                return 2
            except relay_module.RelayStoreError as exc:
                print(f'refusing to start: the relay directory cannot be trusted ({exc}). Fix it, run '
                      "'akdbx relay disable --forget', or start with --unlock-origin.", file=sys.stderr)
                return 2
            try:
                relay_config, relay_moved = _refresh_relay(args, relay_config, relay_store)
            except BaseException:
                relay_lock.release()
                raise
            # The relay origin, the relay certificate and key (one private file),
            # and a free loopback port: the same loopback page as a Tailscale route.
            args.unlock_origin = relay_config.origin
            args.tls_cert = args.tls_key = relay_store.tls_path
            args.local_port = _free_loopback_port()
        else:
            relay_moved = ()
        try:
            return _serve(args, database, keyfile, relay_config, relay_store, relay_moved)
        finally:
            if relay_lock is not None:
                relay_lock.release()
    return _command(args)


def _serve(args, database, keyfile, relay_config, relay_store, relay_moved=()) -> int:
    if args.browser_profile_root is not None and (args.password_browser_profile is not None
                                                  or args.card_browser_profile is not None):
        print('--browser-profile-root replaces --password-browser-profile and --card-browser-profile '
              '(and their AKDBX_* variables): give only the root', file=sys.stderr)
        return 2
    if args.yes_on_fill:
        print("Warning: --yes-on-fill is deprecated and has no effect; fills no longer require terminal approval.", file=sys.stderr)
    if os.name == 'nt':
        import pywintypes
        from .windows_target import WindowsTyper
        from .windows_unlock import start_windows_unlock_server
        try:
            state = (args.notification_state.expanduser() if args.notification_state is not None
                     else default_notification_state(args.socket))
            broker = Broker(None, WindowsTyper(), card_browser_profile=args.card_browser_profile,
                            password_browser_profile=args.password_browser_profile,
                            browser_profile_root=args.browser_profile_root,
                            notification_state_path=state, secret_sinks_path=args.secret_sinks,
                            default_fill_route=args.default_fill_route,
                            sms_sources_path=default_sms_sources(args, state),
                            android_devices_path=args.android_devices)
        except SinkError as exc:
            print('secret sink configuration refused: ' + str(exc), file=sys.stderr)
            return 2
        except (OSError, ValueError, KeyError, RuntimeError, pywintypes.error):
            print('could not open the private notification state; use --notification-state with a file in a '
                  'folder that only this user, SYSTEM and administrators can access', file=sys.stderr)
            return 2
        if refuse_untrusted_unlock_block(broker):
            return 2
        try:
            from .windows_rpc import capture_pipe
            unlock_server, unlock_url = start_windows_unlock_server(
                broker, database, keyfile, args.unlock_origin, args.tls_cert, args.tls_key,
                local_port=args.local_port, capture_pipe=capture_pipe(args.socket))
        except (OSError, ValueError, pywintypes.error):
            broker.unlock_notifications.close()
            broker.card_save_notifications.close()
            broker.pairing_notifications.close()
            broker.sms_notifications.close()
            print('could not start Windows HTTPS unlock; check origin, local port, TLS files, permissions, '
                  'and that no other broker uses this pipe', file=sys.stderr)
            return 2
    else:
        # --tls-cert and --tls-key select the loopback HTTPS page, the same
        # page as on Windows. Without them, Linux keeps its Tailscale Serve
        # Unix-socket backend, which a loopback origin cannot reach.
        local_https = args.tls_cert is not None or args.tls_key is not None
        if local_https and args.unlock_url is not None:
            print('--unlock-url belongs to the Tailscale Serve socket route; '
                  'the HTTPS page uses --unlock-origin', file=sys.stderr)
            return 2
        if not local_https and (args.local_port is not None
                                or is_loopback_origin(args.unlock_url or args.unlock_origin)):
            print('a loopback unlock origin or --local-port needs --tls-cert and --tls-key', file=sys.stderr)
            return 2
        try:
            broker = Broker(None, X11Typer(), card_browser_profile=args.card_browser_profile,
                            password_browser_profile=args.password_browser_profile,
                            browser_profile_root=args.browser_profile_root,
                            notification_state_path=args.notification_state or default_notification_state(args.socket),
                            # An explicit --notification-state keeps the block beside it.
                            unlock_block_path=(None if args.notification_state
                                               else default_unlock_block_state(args.socket)),
                            secret_sinks_path=args.secret_sinks, default_fill_route=args.default_fill_route,
                            sms_sources_path=default_sms_sources(args),
                            android_devices_path=args.android_devices)
        except SinkError as exc:
            print('secret sink configuration refused: ' + str(exc), file=sys.stderr)
            return 2
        except (ValueError, OSError, RuntimeError):
            print('could not open the private SMS source state; fix or move it, or use --sms-sources', file=sys.stderr)
            return 2
        if refuse_untrusted_unlock_block(broker):
            return 2
    unlock_name = ("agentic-kdbx-unlock.sock"
                   if args.socket.name == "agentic-kdbx.sock"
                   else "akdbx-unlock.sock")
    unlock_socket = args.unlock_socket or args.socket.with_name(unlock_name)
    if os.name != 'nt' and local_https:
        try:
            # The unlock socket path then serves only the browser native
            # host's authenticator capture, as the capture pipe does on Windows.
            unlock_server, unlock_url = start_local_unlock_server(
                broker, database, keyfile, args.unlock_origin, args.tls_cert, args.tls_key,
                local_port=args.local_port, capture_socket=unlock_socket)
        except (OSError, ValueError, RuntimeError):
            broker.unlock_notifications.close()
            broker.card_save_notifications.close()
            broker.pairing_notifications.close()
            broker.sms_notifications.close()
            print('could not start HTTPS unlock; check origin, local port, TLS files and permissions '
                  '(key mode 0600), and that no other broker uses this port or socket', file=sys.stderr)
            return 2
    elif os.name != 'nt':
        unlock_server, unlock_url = start_unlock_server(
            broker, database, keyfile, unlock_socket, args.unlock_url or args.unlock_origin,
        )
    announce_identity(broker, args.socket)
    if broker.unlock_blocked:
        # A restored block: the link answers 403, so print no URL.
        print("Vault locked. The unlock link is blocked after three failed master-password attempts. "
              "Ask the user whether they made the failed attempts and want a new link; only after the "
              "user confirms, run: akdbx new-unlock-link --user-confirmed", file=sys.stderr)
    elif args.no_print_unlock_link:
        # A service log (journal, task output) must not keep the link's token.
        print("Vault locked. Run 'akdbx status' to get the private unlock link.", file=sys.stderr)
    else:
        print(f"Vault locked. Open the private HTTPS page: {unlock_url}", file=sys.stderr)
    relay_client = None
    if relay_config is not None:
        relay_client = relay_module.RelayClient(
            relay_module.endpoint(relay_config.relay), relay_config, relay_store, args.local_port,
            reload_tls=lambda path: reload_certificate(unlock_server, path, path), moved=relay_moved)
        broker.relay = relay_client.start()
        print(f"Relay: the private pages open at {relay_config.origin} on any device, through "
              f"{relay_config.relay}. TLS ends in this broker; the relay cannot read the traffic.",
              file=sys.stderr)
    print(f"Broker ready at {args.socket}; Ctrl-C locks it.", file=sys.stderr)
    try:
        serve(args.socket, broker)
    except KeyboardInterrupt:
        print("\nBroker locked.", file=sys.stderr)
    finally:
        if relay_client is not None:
            relay_client.stop()
        broker.passwords.close()
        unlock_server.shutdown()
        unlock_server.server_close()
    return 0


def _command(args) -> int:
    if args.command in card_cli.COMMANDS:
        return card_cli.run(args, lambda payload: request(args.socket, payload, broker_uid=args.broker_uid,
                                                        expected_unlock_origin=args.unlock_origin))
    if args.command in pairing_cli.COMMANDS:
        return pairing_cli.run(args, lambda payload: request(args.socket, payload, broker_uid=args.broker_uid,
                                                           expected_unlock_origin=args.unlock_origin))
    if args.command in identity_cli.COMMANDS:
        return identity_cli.run(args, lambda payload: request(args.socket, payload, broker_uid=args.broker_uid,
                                                            expected_unlock_origin=args.unlock_origin))
    if args.command == android_cli.COMMAND:
        return android_cli.run(args, lambda payload, **kwargs: request(
            args.socket, payload, broker_uid=args.broker_uid, expected_unlock_origin=args.unlock_origin, **kwargs))
    if args.command == secret_cli.COMMAND:
        return secret_cli.run(args, lambda payload, **kwargs: request(
            args.socket, payload, broker_uid=args.broker_uid, expected_unlock_origin=args.unlock_origin, **kwargs))
    if args.command in sms_cli.COMMANDS:
        return sms_cli.run(args, lambda payload: request(args.socket, payload, broker_uid=args.broker_uid,
                                                      expected_unlock_origin=args.unlock_origin))
    if args.command in capture_cli.COMMANDS:
        return capture_cli.run(args, lambda payload: request(args.socket, payload, broker_uid=args.broker_uid,
                                                          expected_unlock_origin=args.unlock_origin))
    payload = {"action": "ping" if args.command == "status" else args.command}
    if args.command in {'unlock-subscription-status', 'unsubscribe-unlock'}:
        payload['subscription_id'] = args.subscription_id
    elif args.command == 'new-unlock-link':
        payload['user_confirmed'] = args.user_confirmed is True
    elif args.command == 'pin-password-target':
        if args.mode == 'login' and not args.username_selector:
            print('--mode login requires --username-selector', file=sys.stderr)
            return 2
        if args.mode != 'login' and args.username_selector is not None:
            print('--username-selector is only valid with --mode login', file=sys.stderr)
            return 2
        if args.password_purpose is not None and args.mode != 'password':
            print('--password-purpose requires --mode password', file=sys.stderr)
            return 2
        if args.allow_autocomplete_off and (args.mode != 'password' or args.password_purpose is None):
            print('--allow-autocomplete-off requires --mode password and --password-purpose', file=sys.stderr)
            return 2
        payload.update(password_protocol=1, page_id=args.page_id, frame_id=args.frame_id, top_url=args.top_url,
                       selector=args.selector, mode=args.mode)
        if args.mode == 'read':
            payload['capture_protocol'] = 1
        if args.username_selector is not None:
            payload['username_selector'] = args.username_selector
        if args.password_purpose is not None:
            payload['password_purpose'] = args.password_purpose
        if args.allow_autocomplete_off:
            payload['allow_autocomplete_off'] = True
        if args.frame_origin is not None:
            payload.update(frame_protocol=1, frame_origin=args.frame_origin)
        if args.route is not None:
            payload['route'] = args.route
    elif args.command == 'list-password-frames':
        payload.update(password_protocol=1, frame_protocol=1, top_url=args.top_url)
        if args.page_id is not None:
            payload['page_id'] = args.page_id
        if args.route is not None:
            payload['route'] = args.route
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
            if args.single_field:
                # Older brokers never see the option unless they report it.
                payload['single_field'] = True
        if args.command in IDENTITY_CREATES:
            payload['auth_method'] = args.auth_method
        if args.command == 'setup-totp':
            payload['replace'] = args.replace
    elif args.command in URL_CHANGES:
        payload.update(handle=args.handle, url=args.url, additional_urls_protocol=1)
    elif args.command in {'write-status', 'cancel-write', 'commit-password'}:
        payload['write_handle'] = args.write_handle
        if args.command == 'commit-password':
            payload['site_accepted'] = args.site_accepted
    elif args.command in {'fill-generated', 'fill-totp'}:
        payload.update(handle=args.handle, target_url=args.target_url, start_deadline=time.monotonic() + FILL_START_TIMEOUT)
        if args.command == 'fill-totp' and args.pending:
            payload['pending'] = True
    elif args.command == "fill":
        payload.update(
            handle=args.handle,
            mode=args.mode,
            start_deadline=time.monotonic() + FILL_START_TIMEOUT,
        )
    if args.command in {'fill', 'fill-generated', 'fill-totp'}:
        payload.update(target=args.target, target_protocol=1)
    identity_kind = 'SSO' if args.command == 'create-sso-entry' else 'passwordless'
    track_send = args.command in {'fill', 'fill-generated', 'fill-totp', 'commit-password'}
    send_started = False

    def mark_send():
        nonlocal send_started
        send_started = True

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
            try:
                webhook_url = _read_webhook_url(args.webhook_url_file)
            except (OSError, ValueError):
                print('could not read private webhook URL file; subscription not sent', file=sys.stderr)
                return 2
            payload.update(webhook_url=webhook_url, ttl=args.ttl, notification_protocol=1)
            if args.blocked_events and capabilities.get('unlock_notifications_blocked_event') is True:
                # Opt in only on request: a consumer that removes its one-shot
                # trigger on any event must get only akdbx.unlocked. Older
                # brokers keep their unlock-only subscription.
                payload['blocked_events'] = True
        if args.command == 'new-unlock-link':
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or type(capabilities.get('unlock_link_protocol')) is not int
                    or capabilities['unlock_link_protocol'] != 1):
                print(json.dumps({'ok': False, 'error': 'broker lacks unlock link protocol 1; require broker 0.25.0 or newer; request not sent'}))
                return 1
            if capabilities.get('unlock_blocked') is not True:
                print(json.dumps({'ok': False, 'error': 'the current unlock link is not blocked; no link created; request not sent'}))
                return 1
            # The status request already checked this origin against the
            # configured one; without it the CLI cannot check before the
            # broker replaces the link.
            if not isinstance(capabilities.get('unlock_origin'), str):
                print(json.dumps({'ok': False, 'error': 'broker did not report its unlock origin; no link created; request not sent'}))
                return 1
        if args.command in {'setup-totp', 'fill-totp'}:
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or capabilities.get('totp_supported') is not True
                    or type(capabilities.get('totp_protocol')) is not int or capabilities.get('totp_protocol') != 1):
                print(json.dumps({'ok': False, 'error': 'broker lacks TOTP protocol 1; require broker 0.10.0 or newer; TOTP request not sent'}))
                return 1
            if args.command == 'fill-totp' and args.pending and (
                    type(capabilities.get('totp_capture_protocol')) is not int or capabilities['totp_capture_protocol'] != 1):
                print(json.dumps({'ok': False, 'error': 'broker lacks authenticator capture protocol 1; require broker 0.35.0 or newer; TOTP request not sent'}))
                return 1
        if args.command == 'generate-entry':
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or type(capabilities.get('generated_entry_protocol')) is not int
                    or capabilities.get('generated_entry_protocol') != 1):
                print(json.dumps({'ok': False, 'error': 'broker lacks generated entry protocol 1; generation not sent'}))
                return 1
        if args.command in {'generate-entry', 'generate-password'} and args.single_field:
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if capabilities.get('ok') is not True or capabilities.get('generated_single_field') is not True:
                print(json.dumps({'ok': False, 'error': 'broker lacks generated single-field support; require broker 0.31.0 or newer; generation not sent'}))
                return 1
        if args.command == 'list-password-frames' or args.command == 'pin-password-target' and args.frame_origin is not None:
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or type(capabilities.get('password_frame_protocol')) is not int
                    or capabilities['password_frame_protocol'] != 1 or capabilities.get('password_frame_policy') != 'same-site-chain-v1'):
                print(json.dumps({'ok': False, 'error': 'broker lacks password frame protocol 1; require broker 0.16.0 or newer; frame request not sent'}))
                return 1
        # A window pin takes a slot only when asked: from a slot shell it can also pin a native app on the broker's display.
        if (args.command in {'list-password-frames', 'pin-password-target'} and browser_slots.chosen(args) is not None
                or args.command == 'pin-target' and args.browser_slot is not None):
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            slot_route = ('cdp' if args.command == 'pin-target' else
                          _read_route(args, capabilities) if args.command == 'pin-password-target' and args.mode == 'read'
                          else args.route or capabilities.get('default_fill_route') or 'cdp')
            slot, refusal = browser_slots.request_field(args, capabilities, slot_route)
            if refusal is None and slot and args.command == 'pin-target' and (
                    type(capabilities.get('target_slot_protocol')) is not int or capabilities['target_slot_protocol'] != 1):
                refusal = 'broker lacks slot window pins (target_slot_protocol 1); require broker 0.35.3 or newer; request not sent'
            if refusal is not None:
                print(json.dumps({'ok': False, 'error': refusal}))
                return 1
            payload.update(slot)
        if getattr(args, 'route', None) == 'extension':
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or type(capabilities.get('extension_protocol')) is not int
                    or capabilities['extension_protocol'] != 1 or capabilities.get('extension_delivery') != EXTENSION_DELIVERY):
                print(json.dumps({'ok': False, 'error': 'broker lacks extension route protocol 1; require broker 0.21.0 or newer; request not sent'}))
                return 1
        if args.command in {'pin-password-target', 'pin-target', 'fill', 'fill-generated', 'fill-totp'}:
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            # A paired extension can deliver without a debugging-port profile.
            if args.command == 'pin-password-target' and args.mode == 'read':
                extension_route = _read_route(args, capabilities) == 'extension'
            elif args.command == 'pin-password-target':
                extension_route = (args.route or capabilities.get('default_fill_route')) == 'extension'
            else:
                extension_route = capabilities.get('extension_paired') is True
            if args.command in {'pin-password-target', 'fill-generated'} or args.command == 'fill' and args.mode != 'username':
                if (capabilities.get('ok') is not True or type(capabilities.get('password_fill_protocol')) is not int
                        or capabilities.get('password_fill_protocol') != 1
                        or capabilities.get('password_fill_delivery') != PASSWORD_DELIVERY):
                    print(json.dumps({'ok': False, 'error': 'broker lacks DOM password delivery; target request not sent'}))
                    return 1
                if os.name == 'nt' and capabilities.get('password_browser_configured') is False and not extension_route:
                    print(json.dumps({'ok': False, 'error': PASSWORD_BROWSER_REFUSAL}))
                    return 1
            if args.command == 'pin-password-target' and args.password_purpose is not None:
                if type(capabilities.get('password_purpose_protocol')) is not int or capabilities['password_purpose_protocol'] != 1:
                    print(json.dumps({'ok': False, 'error': 'broker lacks explicit password purpose protocol 1; target request not sent'}))
                    return 1
            if args.command == 'pin-password-target' and args.mode == 'read':
                if (type(capabilities.get('secret_capture_protocol')) is not int or capabilities['secret_capture_protocol'] != 1
                        or capabilities.get('secret_capture_delivery') != 'chromium-dom-read-v1'):
                    print(json.dumps({'ok': False, 'error': 'broker lacks secret capture protocol 1; require broker 0.20.0 or newer; target request not sent'}))
                    return 1
                if args.route == 'extension' and not _extension_capture(capabilities):
                    print(json.dumps({'ok': False, 'error': 'broker lacks extension secret capture protocol 1; '
                                      'require broker 0.32.0 or newer; target request not sent'}))
                    return 1
            if args.command == 'pin-password-target' and args.allow_autocomplete_off:
                if type(capabilities.get('password_autocomplete_off_protocol')) is not int or capabilities['password_autocomplete_off_protocol'] != 1:
                    print(json.dumps({'ok': False, 'error': 'broker lacks explicit autocomplete off protocol 1; target request not sent'}))
                    return 1
            if args.command != 'pin-password-target' and (capabilities.get('ok') is not True or capabilities.get('target_fill_required') is not True
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
        if args.command in URL_CHANGES:
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            if (capabilities.get('ok') is not True or type(capabilities.get('additional_urls_protocol')) is not int
                    or capabilities['additional_urls_protocol'] != 1
                    or capabilities.get('additional_urls_policy') != 'kp2a-exact-origin-v1'):
                print(json.dumps({'ok': False, 'error': 'broker lacks additional URL protocol 1; require broker 0.18.0 or newer; change not sent'}))
                return 1
        if os.name == 'nt' and args.command in {'merge', 'admit'}:
            capabilities = request(args.socket, {'action': 'ping'}, broker_uid=args.broker_uid,
                                   expected_unlock_origin=args.unlock_origin)
            # A locked broker still gets the request: its answer carries the
            # private unlock link and the repeat-command continuation.
            if capabilities.get('locked') is False and capabilities.get('merge_available') is False:
                print(json.dumps({'ok': False, 'error': MERGE_UNAVAILABLE_REFUSAL}))
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
            **({'before_send': mark_send} if track_send else {}),
        )
    except (FileNotFoundError, ConnectionRefusedError):
        print("broker is not running", file=sys.stderr)
        return 2
    except (PermissionError, ProtocolError, RuntimeError, ValueError) as exc:
        if track_send and not send_started:
            print(_mutation_not_sent(args.command, exc), file=sys.stderr)
        elif args.command in {'merge', 'admit'}:
            print('merge outcome unconfirmed: broker response rejected; use merge-status ' + payload['operation_id'] + '; do not retry with a new ID', file=sys.stderr)
        elif args.command in URL_CHANGES:
            print('additional URL save outcome unconfirmed: broker response rejected; search before any retry', file=sys.stderr)
        elif args.command in IDENTITY_CREATES:
            print(f'{identity_kind} save outcome unconfirmed: broker response rejected; check status and search before any retry', file=sys.stderr)
        elif args.command in {'fill', 'fill-generated', 'fill-totp'}:
            print('autofill outcome unconfirmed: broker response rejected; do not retry automatically', file=sys.stderr)
        elif args.command == 'commit-password':
            print('save outcome unconfirmed: broker response rejected; check write-status before any retry; do not reset the site again', file=sys.stderr)
        else:
            print(f"refusing untrusted broker response: {exc}", file=sys.stderr)
        return 2
    except (TimeoutError, OSError) as exc:
        if track_send and not send_started:
            print(_mutation_not_sent(args.command, exc), file=sys.stderr)
        elif args.command in {"fill", "fill-generated", "fill-totp"}:
            print(
                "autofill outcome uncertain: connection lost after request; do not retry automatically",
                file=sys.stderr,
            )
        elif args.command == 'commit-password':
            print('save outcome uncertain: check write-status before any retry; do not reset the site again', file=sys.stderr)
        elif args.command in URL_CHANGES:
            print('additional URL save outcome uncertain: search to check the entry before any retry', file=sys.stderr)
        elif args.command in IDENTITY_CREATES:
            print(f'{identity_kind} save outcome uncertain: check status and search before any retry; do not create another record automatically', file=sys.stderr)
        elif args.command in {'merge', 'admit'}:
            print('merge outcome uncertain: use merge-status ' + payload['operation_id'] + '; do not retry with a new ID', file=sys.stderr)
        else:
            print("broker request failed", file=sys.stderr)
        return 2
    if args.command in {'setup-totp', 'fill-totp'}:
        allowed = ({'ok', 'write_handle', 'private_url', 'state'} if args.command == 'setup-totp'
                   else {'ok', 'filled', 'target_delivery'}) if response.get('ok') else {'ok', 'error', 'retry_after', 'unlock_url', 'unlock_blocked', 'delivery'}
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
    if args.command in {'generate-entry', 'generate-password'} and response.get('ok'):
        references = response.get('fill_handles')
        modes = {'password'} if args.single_field else {'password', 'confirmation'}
        if (not isinstance(references, dict) or set(references) != modes
                or not all(isinstance(ref, str) and ref for ref in references.values())
                or len(set(references.values())) != len(modes)
                or response.get('single_field', False) is not args.single_field
                or not isinstance(response.get('write_handle'), str) or not response['write_handle']):
            # The staged write expires unused; a wrong fill count must not start.
            print('generated password receipt rejected: unexpected fill references; do not fill; '
                  'the staged write expires unused', file=sys.stderr)
            return 2
    if args.command == 'list-password-frames' and response.get('ok') and not _valid_frame_list(response):
        print('frame list rejected: unexpected broker response', file=sys.stderr)
        return 2
    if args.command == 'pin-password-target' and response.get('ok'):
        pin_route = (_read_route(args, capabilities) if args.mode == 'read' else
                     args.route or ('extension' if capabilities.get('default_fill_route') == 'extension' else 'cdp'))
        token = response.get('target')
        if (set(response) != {'ok', 'target', 'expires_in', 'target_delivery'} or not isinstance(token, str)
                or len(token) != 64 or any(c not in '0123456789abcdef' for c in token)
                or type(response.get('expires_in')) is not int or response['expires_in'] != 30
                or response.get('target_delivery') != (EXTENSION_DELIVERY if pin_route == 'extension' else PASSWORD_DELIVERY)):
            print('password pin outcome unconfirmed: receipt rejected', file=sys.stderr)
            return 2
    if args.command in {'pin-target', 'fill', 'fill-generated', 'fill-totp'} and response.get('ok'):
        invalid_pin = args.command == 'pin-target' and (
            not isinstance(response.get('target'), str) or len(response['target']) != 64
            or any(c not in '0123456789abcdef' for c in response['target'])
            or type(response.get('pid')) is not int or response['pid'] != args.pid
            or type(response.get('window')) is not int or response['window'] != args.window
            or type(response.get('expires_in')) is not int or response['expires_in'] != 30
            or response.get(browser_slots.FIELD) != payload.get(browser_slots.FIELD))
        invalid_fill = args.command in {'fill', 'fill-generated', 'fill-totp'} and (
            response.get('filled') != (args.mode if args.command == 'fill' else 'totp' if args.command == 'fill-totp' else 'password'))
        expected_delivery = PASSWORD_DELIVERY if args.command == 'fill-generated' or args.command == 'fill' and args.mode != 'username' else DELIVERY
        if args.command == 'fill' and args.mode == 'username' and response.get('target_delivery') == PASSWORD_DELIVERY:
            expected_delivery = PASSWORD_DELIVERY
        if args.command in {'fill', 'fill-generated'} and response.get('target_delivery') == EXTENSION_DELIVERY:
            expected_delivery = EXTENSION_DELIVERY
        if response.get('target_delivery') != expected_delivery or invalid_pin or invalid_fill:
            print('target operation outcome unconfirmed: receipt rejected; do not retry automatically', file=sys.stderr)
            return 2
    if args.command == 'new-unlock-link' and response.get('ok') and (
            set(response) != {'ok', 'unlock_url', 'locked'} or type(response['locked']) is not bool):
        print('new unlock link rejected: unexpected broker response; do not retry automatically', file=sys.stderr)
        return 2
    if args.command in {'merge', 'admit'} and response.get('error') == 'vault locked':
        response['continuation'] = ('The unlock link is blocked: follow the skill before any new-unlock-link, then repeat the same command, policy and operation ID.'
                                    if response.get('unlock_blocked') else
                                    'Open unlock_url privately, then repeat the same command, policy and operation ID.')
        response['operation_id'] = payload['operation_id']
    if args.command in URL_CHANGES and response.get('ok') and (
            set(response) != {'ok', 'state', 'metadata', 'additional_urls', 'changed', 'url'}
            or response.get('state') != 'saved'
            or response.get('changed') != ('added' if args.command == 'add-url' else 'removed')
            or response.get('url') != args.url.rstrip('/') + '/'
            or not isinstance(response.get('additional_urls'), list)
            or not all(isinstance(url, str) for url in response['additional_urls'])
            or (response['url'].rstrip('/') in response['additional_urls']) != (args.command == 'add-url')):
        print('additional URL save outcome unconfirmed: receipt rejected; search before any retry', file=sys.stderr)
        return 2
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
