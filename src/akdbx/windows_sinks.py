"""Same-user Windows sink helper. Only its private startup file selects destinations."""
import argparse
import json
import os
from pathlib import Path
import re
import time

import pywintypes
import win32con
import win32file

from .protocol import receive_message, send_message
from . import sink_helper as sinks, windows_rpc as rpc, windows_security as security


def local_path(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z]:\\[^\x00-\x1f<>:"|?*]+', value):
        raise sinks.SinkError('sink path must be a normalized local Windows path')
    path = Path(value)
    reserved = getattr(os.path, 'isreserved', lambda part: Path(part).is_reserved())
    if (str(path) != value or any(part == '..' or part.endswith((' ', '.')) or reserved(part)
                                  for part in path.parts[1:])):
        raise sinks.SinkError('sink path must be a normalized local Windows path')
    return path


def load_config(path):
    try:
        data, _ = security.read_private(local_path(str(path)), limit=sinks.MAX_CONFIG)
        raw = json.loads(data.decode('utf-8'))
        if (not isinstance(raw, dict) or set(raw) != {'version', 'helper_pipe', 'sinks'}
                or type(raw['version']) is not int or raw['version'] != 1
                or not isinstance(raw['sinks'], dict) or len(raw['sinks']) > sinks.MAX_SINKS):
            raise ValueError()
        pipe = rpc.pipe_name(raw['helper_pipe'])
        if not pipe.endswith('-sinks'):
            raise ValueError()
        definitions = {}
        for name, spec in raw['sinks'].items():
            if (not sinks.SINK_NAME.fullmatch(name) or not isinstance(spec, dict)
                    or set(spec) != {'entry_origin', 'field', 'path', 'key'}
                    or not sinks.valid_field(spec['field']) or not sinks.ORIGIN.fullmatch(spec['entry_origin'])
                    or not sinks.ENV_KEY.fullmatch(spec['key'])):
                raise ValueError()
            local_path(spec['path'])
            definitions[name] = dict(spec, name=name, writer='windows-pipe')
        return dict(helper_pipe=pipe, sinks=definitions)
    except Exception:
        raise sinks.SinkError('invalid or unreadable private Windows sink configuration') from None


def write(sink, value):
    sinks.validate_value(value)
    path = local_path(sink['path'])
    # Serialize across helpers and aliases in this directory. Opening the lock
    # and locking its first byte covers the complete read/modify/replace.
    with security.trusted_directory(path.parent), security.checked_handle(path.parent, directory=True):
        lock_path = path.parent / '.akdbx-sinks.lock'
        with security.checked_handle(lock_path, access=win32con.GENERIC_READ | win32con.GENERIC_WRITE |
                                     win32con.READ_CONTROL, creation=win32con.OPEN_ALWAYS) as lock:
            overlapped = pywintypes.OVERLAPPED()
            win32file.LockFileEx(lock, win32con.LOCKFILE_EXCLUSIVE_LOCK | win32con.LOCKFILE_FAIL_IMMEDIATELY,
                                 1, 0, overlapped)
            try:
                before = security.read_private_optional(path, limit=sinks.MAX_FILE)
                data = before or b''
                crlf = b'\r\n' in data
                if crlf:
                    if b'\n' in data.replace(b'\r\n', b''):
                        raise sinks.SinkError('mixed or unsupported sink file line endings')
                    data = data.replace(b'\r\n', b'\n')
                updated = sinks.render(data, sink['key'], value)
                if crlf:
                    updated = updated.replace(b'\n', b'\r\n')
                if len(updated) > sinks.MAX_FILE:
                    raise sinks.SinkError('sink file would be too large; not changed')
                if before != updated:
                    if before != security.read_private_optional(path, limit=sinks.MAX_FILE):
                        raise sinks.SinkError('sink file changed during the write; not changed')
                    security.replace_private(path, updated, replace_existing=before is not None)
            finally:
                win32file.UnlockFileEx(lock, 1, 0, overlapped)


def handle(connection, config):
    with connection:
        try:
            security.require_same_integrity(connection.peer)
            request = receive_message(connection, deadline=time.monotonic() + 5)
            if (not isinstance(request, dict) or set(request) != {'sink_protocol', 'sink', 'digest', 'value'}
                    or type(request['sink_protocol']) is not int or request['sink_protocol'] != sinks.PROTOCOL):
                raise ValueError()
            sink = config['sinks'][request['sink']]
            if request['digest'] != sinks.sink_digest(sink):
                raise ValueError()
            write(sink, request['value'])
            response = dict(ok=True)
        except Exception:
            response = dict(ok=False)
        connection.settimeout(5)
        send_message(connection, response)


def deliver(config, sink, value):
    with rpc.connect(config['helper_pipe']) as connection:
        security.require_same_integrity(connection.peer)
        send_message(connection, dict(sink_protocol=sinks.PROTOCOL, sink=sink['name'],
                                      digest=sinks.sink_digest(sink), value=value))
        reply = receive_message(connection, deadline=time.monotonic() + 5)
        if not isinstance(reply, dict) or set(reply) != {'ok'} or reply['ok'] is not True:
            raise sinks.SinkError('Windows sink delivery unconfirmed; check the sink before any retry')
    return dict(restarted=None)


def serve(config, stop=None):
    pipe = config['helper_pipe']
    rpc.accept_connections(pipe, rpc.new_pipe(pipe, first=True), lambda conn: handle(conn, config), stop)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config')
    try:
        serve(load_config(parser.parse_args().config))
    except (sinks.SinkError, OSError):
        parser.exit(1, 'Windows sink helper unavailable; check its private configuration and pipe\n')


if __name__ == '__main__':
    main()
