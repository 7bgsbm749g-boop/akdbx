"""Chrome native messaging host. Secret payloads never enter the agent RPC.

Linux, on the broker's machine only. Build/install commands are explicit; merely
importing this module does not touch Chrome, its profile, or the running broker.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import shutil
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
    return Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'akdbx' / 'browser-import.json'


def load_config(path):
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
        if set(config) != {'extension_id', 'origin', 'socket'} or not all(isinstance(v, str) for v in config.values()):
            raise ValueError
        if not re.fullmatch('[a-p]{32}', config['extension_id']):
            raise ValueError
        return config
    finally:
        os.close(directory)


def capture(message, config):
    """Only the native host calls this. Do not add an agent-facing equivalent."""
    from .cli import _validate_socket_path, _validate_unlock_url, _peer_credentials
    from .runtime import anchored_socket_path
    if not isinstance(message, dict) or set(message) != {'private_url', 'source_url', 'payloads'}:
        raise ValueError
    private_url = message['private_url']
    _validate_unlock_url(private_url, config['origin'])
    parsed = urlsplit(private_url)
    if parsed.path != '/totp' or len(private_url) > 4096:
        raise ValueError
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
    from .cli import _validate_unlock_url
    from .runtime import prepare_private_runtime_directory
    if not re.fullmatch('[a-p]{32}', args.extension_id):
        raise ValueError('invalid extension ID')
    _validate_unlock_url(args.origin.rstrip('/') + '/totp?token=configuration-check', args.origin)
    executable = shutil.which('akdbx-browser-import')
    if not executable:
        raise ValueError('install the akdbx package first')
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


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0].startswith('chrome-extension://'):
        try:
            config = load_config(config_path())
        except Exception:
            config = {'extension_id': ''}
        native_session(sys.stdin.buffer, sys.stdout.buffer, config, argv[0] if argv else '')
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build-extension')
    build.add_argument('destination', type=Path)
    install = commands.add_parser('install-host')
    install.add_argument('--extension-id', required=True)
    install.add_argument('--origin', required=True)
    install.add_argument('--socket', required=True, type=Path)
    install.add_argument('--manifest-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'build-extension':
            build_extension(args.destination)
        else:
            install_host(args)
    except Exception:
        print('Installation not completed; check paths, permissions, and existing files. Existing files are never overwritten.', file=sys.stderr)
        return 1
    print('Completed. No vault or running browser was accessed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
