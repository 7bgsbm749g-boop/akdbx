"""Browser native messaging host. Secret payloads never enter the agent RPC.

On the broker's machine only. Build/install commands are explicit; merely
importing this module does not touch Chrome, its profile, or the running broker.

* Linux and macOS: the host posts to the private pages' Unix socket and checks the
  broker's peer UID.
* Windows: the host writes one message to the broker's capture named pipe
  (the RPC pipe name plus ``-capture``). It checks that the pipe server runs as
  this user in this desktop session, as the CLI does for the RPC pipe. The
  install registers the host for one browser under ``HKEY_CURRENT_USER``.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import stat
import struct
import sys
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

MAX_NATIVE_MESSAGE = 48 * 1024
HOST_NAME = 'org.akdbx.private_import'
FIREFOX_ID = 'private-import@akdbx.org'
RECEIPT = {'ok': True, 'state': 'awaiting-private-confirmation'}


def config_path(browser='chrome'):
    filename = 'browser-import-firefox.json' if browser == 'firefox' else 'browser-import.json'
    if os.name == 'nt':
        return Path(os.environ['LOCALAPPDATA']) / 'akdbx' / filename
    return Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'akdbx' / filename


def _check_config(config):
    if set(config) != {'extension_id', 'origin', 'socket'} or not all(isinstance(v, str) for v in config.values()):
        raise ValueError
    if config['extension_id'] != FIREFOX_ID and not re.fullmatch('[a-p]{32}', config['extension_id']):
        raise ValueError
    if os.name == 'nt' and config['socket']:
        # An empty pipe means the default broker's capture pipe, resolved at
        # run time: its name holds the current desktop session ID.
        from .windows_rpc import CAPTURE_SUFFIX, pipe_name
        if not pipe_name(config['socket'], capture=True).endswith(CAPTURE_SUFFIX):
            raise ValueError
    return config


def load_config(path):
    if os.name == 'nt':
        from .windows_security import read_private
        # Same DACL and parent checks as the broker's own private files.
        return _check_config(json.loads(read_private(path, limit=4096)[0]))
    from .runtime import open_private_runtime_directory
    _, directory = open_private_runtime_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_size > 4096):
                raise ValueError
            if sys.platform == 'darwin':
                from .macos import require_private_acl
                require_private_acl(stream.fileno())
            config = json.loads(stream.read(4097))
        return _check_config(config)
    finally:
        os.close(directory)


def capture(message, config):
    """Only the native host calls this. Do not add an agent-facing equivalent."""
    from .cli import _validate_unlock_url
    if not isinstance(message, dict) or set(message) != {'private_url', 'source_url', 'payloads'}:
        raise ValueError
    private_url = message['private_url']
    _validate_unlock_url(private_url, config['origin'])
    parsed = urlsplit(private_url)
    if parsed.path != '/totp' or len(private_url) > 4096:
        raise ValueError
    if os.name == 'nt':
        return _capture_windows(message, config, parsed)
    from .cli import _validate_socket_path, _peer_credentials
    from .runtime import anchored_socket_path
    # HTTP is strictly over the configured UDS, never a URL chosen by a webpage.
    body = json.dumps({'source_url': message['source_url'], 'payloads': message['payloads']}, separators=(',', ':')).encode()
    if len(body) > MAX_NATIVE_MESSAGE:
        raise ValueError
    path, directory = _validate_socket_path(Path(config['socket']), os.getuid())
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(10)
        client.connect(anchored_socket_path(directory, path.name))
        if _peer_credentials(client)[1] != os.getuid():
            raise ValueError
        connection = http.client.HTTPConnection('localhost', timeout=10)
        connection.sock = client
        connection.request('POST', '/totp/capture?' + parsed.query, body,
                           {'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read(1025)
        if response.status != 200 or len(raw) > 1024 or json.loads(raw) != RECEIPT:
            raise ValueError
        return dict(RECEIPT)
    finally:
        client.close()
        os.close(directory)


def _capture_windows(message, config, parsed):
    """Send one capture to the broker's capture pipe, never a URL chosen by a webpage."""
    import time
    from urllib.parse import parse_qs
    from .protocol import receive_message, send_message
    from .windows_rpc import capture_pipe, connect, default_pipe
    query = parse_qs(parsed.query, strict_parsing=True)
    if set(query) != {'token'} or len(query['token']) != 1:
        raise ValueError
    request = dict(type='totp-capture', token=query['token'][0], source_url=message['source_url'],
                   payloads=message['payloads'])
    if len(json.dumps(request, separators=(',', ':')).encode()) > MAX_NATIVE_MESSAGE:
        raise ValueError
    # connect() refuses a pipe server of another user or desktop session.
    pipe = _check_config(config)['socket'] or capture_pipe(default_pipe())
    with connect(Path(pipe), capture=True) as connection:
        connection.settimeout(10)
        send_message(connection, request)
        if receive_message(connection, deadline=time.monotonic() + 10) != RECEIPT:
            raise ValueError
    return dict(RECEIPT)


def _read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise ValueError
        data.extend(chunk)
    return bytes(data)


def native_session(incoming, outgoing, config, caller):
    try:
        extension_id = config['extension_id']
        expected = FIREFOX_ID if extension_id == FIREFOX_ID else 'chrome-extension://' + extension_id + '/'
        if not extension_id or caller != expected:
            raise ValueError
        size = struct.unpack('<I', _read_exact(incoming, 4))[0]
        if not 0 < size <= MAX_NATIVE_MESSAGE:
            raise ValueError
        message = json.loads(_read_exact(incoming, size))
        result = capture(message, config)
    except Exception:
        result = {'ok': False, 'error': 'private capture not confirmed; check status and the private import page'}
    encoded = json.dumps(result, separators=(',', ':')).encode()
    outgoing.write(struct.pack('<I', len(encoded)) + encoded)
    outgoing.flush()


def build_extension(destination, browser='chrome'):
    # Never replace an existing profile or extension directory.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for item in files('akdbx').joinpath('browser_extension').iterdir():
        if item.is_file():
            (destination / item.name).write_bytes(item.read_bytes())
    if browser == 'firefox':
        path = destination / 'manifest.json'
        manifest = json.loads(path.read_bytes())
        manifest['browser_specific_settings'] = {'gecko': {
            'id': FIREFOX_ID, 'strict_min_version': '153.0',
            'data_collection_permissions': {'required': ['none']}}}
        path.write_text(json.dumps(manifest, indent=2))
    for name in ('jsQR.js', 'jsQR.LICENSE', 'VENDOR.txt'):
        (destination / name).write_bytes(files('akdbx').joinpath('import_assets', name).read_bytes())


def host_identity(args):
    if getattr(args, 'browser', 'chrome') == 'firefox':
        if args.extension_id not in (None, FIREFOX_ID):
            raise ValueError('incorrect Firefox add-on ID')
        return FIREFOX_ID, {'allowed_extensions': [FIREFOX_ID]}
    if not re.fullmatch('[a-p]{32}', args.extension_id or ''):
        raise ValueError('invalid Chromium extension ID')
    return args.extension_id, {'allowed_origins': ['chrome-extension://' + args.extension_id + '/']}


def install_host(args):
    """Register the invoked console script without selecting another PATH install."""
    import fcntl
    from .cli import _validate_unlock_url
    from .runtime import prepare_private_runtime_directory, prepare_registration_directory
    extension_id, allowed = host_identity(args)
    _validate_unlock_url(args.origin.rstrip('/') + '/totp?token=configuration-check', args.origin)
    executable = Path(sys.argv[0]).absolute()
    if (executable.name != 'akdbx-browser-import' or not executable.is_file()
            or not os.access(executable, os.X_OK)):
        raise ValueError('run the installed akdbx-browser-import console script')
    from .extension_host import linux_manifest_dir
    browser = getattr(args, 'browser', 'chrome')
    path = config_path(browser)
    manifest_dir = args.manifest_dir or linux_manifest_dir(browser)
    _, directory = prepare_private_runtime_directory(path.parent, create_ancestors=True)
    created = None
    manifest_created = None
    registration = None
    manifest = HOST_NAME + '.json'
    try:
        # Serialize installers sharing a config, including rollback after a failed manifest write.
        fcntl.flock(directory, fcntl.LOCK_EX)
        _, registration = prepare_registration_directory(manifest_dir, create_ancestors=args.manifest_dir is None)
        try:
            os.stat(manifest, dir_fd=registration, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('native manifest already exists')
        config = dict(extension_id=extension_id, origin=args.origin.rstrip('/'), socket=str(args.socket.absolute()))
        try:
            existing = load_config(path)
        except FileNotFoundError:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'w') as stream:
                created = os.fstat(stream.fileno())
                json.dump(config, stream)
        else:
            if existing != config:
                raise ValueError('a different private import configuration exists')
        # An explicit directory supports Chrome's existing custom user-data root.
        fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=registration)
        with os.fdopen(fd, 'w') as stream:
            manifest_created = os.fstat(stream.fileno())
            json.dump(dict(name=HOST_NAME, description='Private akdbx authenticator import',
                           path=str(Path(executable).absolute()), type='stdio',
                           **allowed), stream)
    except Exception:
        if manifest_created is not None:
            current_manifest = os.stat(manifest, dir_fd=registration, follow_symlinks=False)
            if (current_manifest.st_dev, current_manifest.st_ino) == (manifest_created.st_dev, manifest_created.st_ino):
                os.unlink(manifest, dir_fd=registration)
        if created is not None:
            current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                os.unlink(path.name, dir_fd=directory)
        raise
    finally:
        if registration is not None:
            os.close(registration)
        os.close(directory)


def windows_paths(browser):
    from .extension_host import WINDOWS_KEYS
    home = Path(os.environ['LOCALAPPDATA']) / 'akdbx' / 'browser-import'
    return dict(manifest=home / f'{HOST_NAME}.{browser}.json', key=WINDOWS_KEYS[browser] + '\\' + HOST_NAME)


def _registered(key):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
            return winreg.QueryValueEx(handle, '')[0]
    except OSError:
        return None


def host_executable():
    """The installed console script of this environment.

    The manifest names it directly: a batch launcher would be read by cmd.exe in
    the console code page, which breaks a non-ASCII interpreter path.
    """
    import sysconfig
    executable = Path(sysconfig.get_path('scripts')) / 'akdbx-browser-import.exe'
    if not executable.is_file():
        raise ValueError('install akdbx into this Python environment first')
    return executable.absolute()


def install_host_windows(args):
    """Register the host for one browser. Never replace another registration or file."""
    import winreg
    from .cli import _validate_unlock_url
    from .windows_security import ensure_private_directory, read_private_optional, write_new
    extension_id, allowed = host_identity(args)
    _validate_unlock_url(args.origin.rstrip('/') + '/totp?token=configuration-check', args.origin)
    config = _check_config(dict(extension_id=extension_id, origin=args.origin.rstrip('/'),
                                socket=str(args.socket or '')))
    executable = host_executable()
    where = windows_paths(args.browser)
    manifest, key = where['manifest'], where['key']
    path = config_path(args.browser)
    if _registered(key) is not None or manifest.exists():
        raise ValueError('a private import host is already registered for this browser')
    # Chromium browsers share the original config. Firefox has its own fixed ID.
    ensure_private_directory(path.parent)
    raw = read_private_optional(path, limit=4096)
    existing = None if raw is None else _check_config(json.loads(raw))
    if existing is not None and existing != config:
        raise ValueError('a different private import configuration exists')
    ensure_private_directory(manifest.parent)
    created = []
    try:
        if existing is None:
            write_new(path, json.dumps(config).encode())
            created.append(path)
        write_new(manifest, json.dumps(dict(name=HOST_NAME, description='Private akdbx authenticator import',
                                            path=str(executable), type='stdio',
                                            **allowed)).encode())
        created.append(manifest)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
            winreg.SetValueEx(handle, '', 0, winreg.REG_SZ, str(manifest))
    except BaseException:
        for item in reversed(created):
            try:
                item.unlink()
            except OSError:
                pass
        raise
    return where


def uninstall_host_windows(args):
    """Remove this browser's registration and manifest.

    The shared configuration goes with the last registration, so a new install
    can use another origin, extension ID or pipe.
    """
    import winreg
    from .extension_route import CHROMIUM_BROWSERS as BROWSERS
    where = windows_paths(args.browser)
    if _registered(where['key']) == str(where['manifest']):
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, where['key'])
    where['manifest'].unlink(missing_ok=True)
    if args.browser == 'firefox':
        if _registered(where['key']) is None:
            config_path('firefox').unlink(missing_ok=True)
        return
    if not any(windows_paths(b)['manifest'].exists() or _registered(windows_paths(b)['key']) is not None
               for b in BROWSERS):
        config_path().unlink(missing_ok=True)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    firefox = len(argv) >= 2 and Path(argv[0]).is_absolute()
    if firefox or not argv or argv[0].startswith('chrome-extension://'):
        # Chrome on Windows appends --parent-window=HWND; it is not used.
        from .extension_host import _binary_stdio
        incoming, outgoing = _binary_stdio()
        try:
            config = load_config(config_path('firefox' if firefox else 'chrome'))
        except Exception:
            config = {'extension_id': ''}
        caller = argv[1] if firefox else argv[0] if argv else ''
        native_session(incoming, outgoing, config, caller)
        return 0
    from .extension_route import BROWSERS
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build-extension')
    build.add_argument('destination', type=Path)
    build.add_argument('--browser', choices=BROWSERS, default='chrome')
    install = commands.add_parser('install-host')
    install.add_argument('--extension-id', help='required for Chromium browsers')
    install.add_argument('--origin', required=True)
    if os.name == 'nt':
        install.add_argument('--browser', required=True, choices=BROWSERS)
        install.add_argument('--socket', help='broker capture pipe; default: this user\'s broker pipe plus -capture')
        uninstall = commands.add_parser('uninstall-host')
        uninstall.add_argument('--browser', required=True, choices=BROWSERS)
    else:
        install.add_argument('--socket', required=True, type=Path)
        install.add_argument('--browser', choices=BROWSERS, default='chrome')
        install.add_argument('--manifest-dir', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'build-extension':
            build_extension(args.destination, args.browser)
        elif args.command == 'uninstall-host':
            uninstall_host_windows(args)
        elif os.name == 'nt':
            install_host_windows(args)
        else:
            install_host(args)
    except Exception:
        print('Installation not completed; check paths, permissions, and existing files. Existing files are never overwritten.', file=sys.stderr)
        return 1
    print('Completed. No vault or running browser was accessed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
