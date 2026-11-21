"""Chrome native messaging host. Secret payloads never enter the agent RPC.

On the broker's machine only. Build/install commands are explicit; merely
importing this module does not touch Chrome, its profile, or the running broker.

* Linux: the host posts to the private pages' Unix socket and checks the
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
RECEIPT = {'ok': True, 'state': 'awaiting-private-confirmation'}


def config_path():
    if os.name == 'nt':
        return Path(os.environ['LOCALAPPDATA']) / 'akdbx' / 'browser-import.json'
    return Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'akdbx' / 'browser-import.json'


def _check_config(config):
    if set(config) != {'extension_id', 'origin', 'socket'} or not all(isinstance(v, str) for v in config.values()):
        raise ValueError
    if not re.fullmatch('[a-p]{32}', config['extension_id']):
        raise ValueError
    if os.name == 'nt':
        from .windows_rpc import CAPTURE_SUFFIX, pipe_name
        if not pipe_name(config['socket']).endswith(CAPTURE_SUFFIX):
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
    from .windows_rpc import connect
    query = parse_qs(parsed.query, strict_parsing=True)
    if set(query) != {'token'} or len(query['token']) != 1:
        raise ValueError
    request = dict(type='totp-capture', token=query['token'][0], source_url=message['source_url'],
                   payloads=message['payloads'])
    if len(json.dumps(request, separators=(',', ':')).encode()) > MAX_NATIVE_MESSAGE:
        raise ValueError
    # connect() refuses a pipe server of another user or desktop session.
    with connect(Path(_check_config(config)['socket'])) as connection:
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
        if caller != 'chrome-extension://' + config['extension_id'] + '/':
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


def build_extension(destination):
    # Never replace an existing profile or extension directory.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for item in files('akdbx').joinpath('browser_extension').iterdir():
        if item.is_file():
            (destination / item.name).write_bytes(item.read_bytes())
    for name in ('jsQR.js', 'jsQR.LICENSE', 'VENDOR.txt'):
        (destination / name).write_bytes(files('akdbx').joinpath('import_assets', name).read_bytes())


def install_host(args):
    """Register the invoked console script without selecting another PATH install."""
    from .cli import _validate_unlock_url
    from .runtime import prepare_private_runtime_directory
    if not re.fullmatch('[a-p]{32}', args.extension_id):
        raise ValueError('invalid extension ID')
    _validate_unlock_url(args.origin.rstrip('/') + '/totp?token=configuration-check', args.origin)
    executable = Path(sys.argv[0]).absolute()
    if (executable.name != 'akdbx-browser-import' or not executable.is_file()
            or not os.access(executable, os.X_OK)):
        raise ValueError('run the installed akdbx-browser-import console script')
    path = config_path()
    args.manifest_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
    manifest = args.manifest_dir / (HOST_NAME + '.json')
    if os.path.lexists(manifest):
        raise ValueError('native manifest already exists')
    _, directory = prepare_private_runtime_directory(path.parent)
    created = None
    manifest_created = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'w') as stream:
            created = os.fstat(stream.fileno())
            json.dump(dict(extension_id=args.extension_id, origin=args.origin.rstrip('/'), socket=str(args.socket.absolute())), stream)
        # An explicit directory supports Chrome's existing custom user-data root.
        with manifest.open('x') as stream:
            manifest_created = os.fstat(stream.fileno())
            json.dump(dict(name=HOST_NAME, description='Private akdbx authenticator import',
                           path=str(Path(executable).absolute()), type='stdio',
                           allowed_origins=['chrome-extension://' + args.extension_id + '/']), stream)
    except Exception:
        if manifest_created is not None:
            current_manifest = manifest.lstat()
            if (current_manifest.st_dev, current_manifest.st_ino) == (manifest_created.st_dev, manifest_created.st_ino):
                manifest.unlink()
        if created is not None:
            current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                os.unlink(path.name, dir_fd=directory)
        raise
    finally:
        os.close(directory)


def windows_paths(browser):
    from .extension_host import WINDOWS_KEYS
    home = Path(os.environ['LOCALAPPDATA']) / 'akdbx' / 'browser-import'
    return dict(launcher=home / f'{browser}.cmd', manifest=home / f'{HOST_NAME}.{browser}.json',
                key=WINDOWS_KEYS[browser] + '\\' + HOST_NAME)


def _registered(key):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
            return winreg.QueryValueEx(handle, '')[0]
    except OSError:
        return None


def install_host_windows(args):
    """Register a launcher for one browser. Never replace another registration or file."""
    import winreg
    from .cli import _validate_unlock_url
    from .windows_rpc import capture_pipe, default_pipe
    from .windows_security import ensure_private_directory, read_private_optional, write_new
    if not re.fullmatch('[a-p]{32}', args.extension_id):
        raise ValueError('invalid extension ID')
    _validate_unlock_url(args.origin.rstrip('/') + '/totp?token=configuration-check', args.origin)
    socket_path = str(args.socket if args.socket is not None else capture_pipe(default_pipe()))
    config = _check_config(dict(extension_id=args.extension_id, origin=args.origin.rstrip('/'), socket=socket_path))
    python = str(Path(sys.executable).absolute())
    if any(c in python for c in '"%\r\n^&|<>'):
        raise ValueError('the Python path contains a character that a Windows launcher cannot quote')
    where = windows_paths(args.browser)
    launcher, manifest, key = where['launcher'], where['manifest'], where['key']
    path = config_path()
    if _registered(key) is not None or launcher.exists() or manifest.exists():
        raise ValueError('a private import host is already registered for this browser')
    # One configuration serves every browser; a second browser must match it.
    ensure_private_directory(path.parent)
    raw = read_private_optional(path, limit=4096)
    existing = None if raw is None else _check_config(json.loads(raw))
    if existing is not None and existing != config:
        raise ValueError('a different private import configuration exists')
    ensure_private_directory(launcher.parent)
    created = []
    try:
        if existing is None:
            write_new(path, json.dumps(config).encode())
            created.append(path)
        write_new(launcher, f'@echo off\r\n"{python}" -I -m akdbx.browser_import %*\r\n'.encode())
        created.append(launcher)
        write_new(manifest, json.dumps(dict(name=HOST_NAME, description='Private akdbx authenticator import',
                                            path=str(launcher), type='stdio',
                                            allowed_origins=['chrome-extension://' + args.extension_id + '/'])).encode())
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
    """Remove this browser's registration, launcher and manifest; keep the configuration."""
    import winreg
    where = windows_paths(args.browser)
    if _registered(where['key']) == str(where['manifest']):
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, where['key'])
    for name in ('manifest', 'launcher'):
        try:
            where[name].unlink()
        except FileNotFoundError:
            pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0].startswith('chrome-extension://'):
        # Chrome on Windows appends --parent-window=HWND; it is not used.
        from .extension_host import _binary_stdio
        incoming, outgoing = _binary_stdio()
        try:
            config = load_config(config_path())
        except Exception:
            config = {'extension_id': ''}
        native_session(incoming, outgoing, config, argv[0] if argv else '')
        return 0
    from .extension_route import BROWSERS
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build-extension')
    build.add_argument('destination', type=Path)
    install = commands.add_parser('install-host')
    install.add_argument('--extension-id', required=True)
    install.add_argument('--origin', required=True)
    if os.name == 'nt':
        install.add_argument('--browser', required=True, choices=BROWSERS)
        install.add_argument('--socket', help='broker capture pipe; default: this user\'s broker pipe plus -capture')
        uninstall = commands.add_parser('uninstall-host')
        uninstall.add_argument('--browser', required=True, choices=BROWSERS)
    else:
        install.add_argument('--socket', required=True, type=Path)
        install.add_argument('--manifest-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'build-extension':
            build_extension(args.destination)
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
