#!/usr/bin/python3 -I
"""Write one stored secret into a sink that the operator defined ahead of time.

A sink is a KEY=VALUE environment file with a fixed path, key, owner, group,
mode and optional fixed restart command. Callers choose only a sink name; they
never choose a path, key, owner or command. Writes keep every other line and
replace the file atomically (temporary file, fsync, rename, fsync directory).

The same code runs in two places:

* inside the broker, for a `"writer": "direct"` sink that the broker's own
  account owns (tests use these);
* as a root-owned, socket-activated helper for a `"writer": "root-helper"`
  sink that belongs to another account. Install a root-owned copy of this
  file (for example `/usr/local/libexec/akdbx-secret-sink`) and run it from a
  systemd socket with `Accept=yes`. It then reads only the root-owned
  configuration at `HELPER_CONFIG`, accepts only the broker UIDs that file
  lists and never imports code from a user-writable location.

This module uses only the standard library and imports nothing from akdbx,
so that the installed root copy is self-contained. No error, reply or log
line contains the value.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys

PROTOCOL = 1
HELPER_CONFIG = '/etc/akdbx/secret-sinks.json'
MAX_CONFIG = 64 * 1024
MAX_FILE = 1024 * 1024
MAX_REQUEST = 16 * 1024
MAX_SINKS = 32
MAX_VALUE = 4096
RESTART_TIMEOUT = 60
RUNUSER = '/usr/sbin/runuser'
SAFE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

SINK_NAME = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?')
FIELD_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}')
ENV_KEY = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}')
# Values are written unquoted. Allow only characters that systemd
# EnvironmentFile, POSIX shells and common dotenv parsers all read literally.
ENV_VALUE = re.compile(r'[A-Za-z0-9._+/=:@%,^-]{1,' + str(MAX_VALUE) + '}')  # No ~: shells expand it.
ACCOUNT = re.compile(r'[a-z_][a-z0-9_-]{0,31}')
ORIGIN = re.compile(r'https://[a-z0-9.-]{1,253}(?::[1-9][0-9]{0,4})?')
WRITERS = ('direct', 'root-helper')


class SinkError(Exception):
    """Fixed, value-free messages only."""


def _absolute(path):
    return (isinstance(path, str) and 0 < len(path) <= 4096 and '\0' not in path and path.startswith('/')
            and not path.endswith('/') and os.path.normpath(path) == path and not path.startswith('//'))


def _restart(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {'user', 'argv', 'env'} or 'argv' not in value:
        raise SinkError('invalid sink restart')
    argv, user, env = value['argv'], value.get('user'), value.get('env', {})
    if (not isinstance(argv, list) or not 0 < len(argv) <= 32 or not _absolute(argv[0])
            or not all(isinstance(a, str) and 0 < len(a) <= 1024 and '\0' not in a for a in argv)
            or user is not None and (not isinstance(user, str) or not ACCOUNT.fullmatch(user))
            or not isinstance(env, dict) or len(env) > 16
            or not all(isinstance(k, str) and ENV_KEY.fullmatch(k) and k != 'PATH' and isinstance(v, str)
                       and len(v) <= 1024 and '\0' not in v and '\n' not in v for k, v in env.items())):
        raise SinkError('invalid sink restart')
    return dict(argv=list(argv), user=user, env=dict(env))


def validate_sink(name, value):
    """Return a normalized sink definition or raise SinkError."""
    if not isinstance(name, str) or not SINK_NAME.fullmatch(name):
        raise SinkError('invalid sink name')
    required = {'writer', 'field', 'entry_origin', 'path', 'key', 'owner', 'group', 'mode'}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - {'restart'}:
        raise SinkError('invalid sink definition')
    mode = value['mode']
    if (value['writer'] not in WRITERS or not isinstance(value['field'], str) or not FIELD_NAME.fullmatch(value['field'])
            or not isinstance(value['entry_origin'], str) or not ORIGIN.fullmatch(value['entry_origin'])
            or not _absolute(value['path']) or not isinstance(value['key'], str) or not ENV_KEY.fullmatch(value['key'])
            or not all(isinstance(value[k], str) and ACCOUNT.fullmatch(value[k]) for k in ('owner', 'group'))
            or not isinstance(mode, str) or not re.fullmatch(r'0[0-7]{3}', mode)
            or int(mode, 8) & 0o022 or not int(mode, 8) & 0o600 == 0o600):
        raise SinkError('invalid sink definition')
    return dict(name=name, writer=value['writer'], field=value['field'], entry_origin=value['entry_origin'],
                path=value['path'], key=value['key'], owner=value['owner'], group=value['group'],
                mode=int(mode, 8), restart=_restart(value.get('restart')))


def sink_digest(sink):
    """Bind a helper request to the exact definition that the broker authorized."""
    import hashlib
    return hashlib.sha256(json.dumps(sink, sort_keys=True).encode('utf-8')).hexdigest()


def _trusted_file(path, trusted_uids):
    """Read a small regular file whose path no untrusted account can change."""
    if not _absolute(path):
        raise SinkError('sink configuration path must be absolute and normalized')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = path.strip('/').split('/')
        for part in parts[:-1]:
            info = os.fstat(directory)
            if info.st_uid not in trusted_uids | {0} or info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                raise SinkError('sink configuration directory is not trusted')
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        info = os.fstat(directory)
        if info.st_uid not in trusted_uids | {0} or info.st_mode & 0o022:
            raise SinkError('sink configuration directory is not trusted')
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except OSError:
        raise SinkError('sink configuration unavailable') from None
    finally:
        os.close(directory)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in trusted_uids or info.st_mode & 0o022
                or info.st_size > MAX_CONFIG):
            raise SinkError('sink configuration is not trusted')
        data = os.read(fd, MAX_CONFIG + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_CONFIG:
        raise SinkError('sink configuration is too large')
    return data


def load_config(path, trusted_uids):
    """Parse the operator's sink file: {"version": 1, "sinks": {NAME: {...}}, ...}."""
    try:
        raw = json.loads(_trusted_file(path, set(trusted_uids)).decode('utf-8'))
    except (UnicodeError, ValueError):
        raise SinkError('sink configuration is not valid JSON') from None
    if (not isinstance(raw, dict) or set(raw) - {'version', 'sinks', 'helper_socket', 'broker_uids'}
            or raw.get('version') != 1 or not isinstance(raw.get('sinks'), dict) or len(raw['sinks']) > MAX_SINKS):
        raise SinkError('unsupported sink configuration')
    helper, uids = raw.get('helper_socket'), raw.get('broker_uids', [])
    if helper is not None and not _absolute(helper):
        raise SinkError('invalid helper socket path')
    if not isinstance(uids, list) or not all(type(u) is int and 0 < u < 2 ** 31 for u in uids):
        raise SinkError('invalid broker UID list')
    sinks = {name: validate_sink(name, value) for name, value in raw['sinks'].items()}
    if helper is None and any(s['writer'] == 'root-helper' for s in sinks.values()):
        raise SinkError('root-helper sinks need helper_socket')
    return dict(sinks=sinks, helper_socket=helper, broker_uids=set(uids))


def validate_value(value):
    if not isinstance(value, str) or not ENV_VALUE.fullmatch(value):
        raise SinkError('value cannot be written to an environment file unquoted; nothing written')
    return value


def render(existing, key, value):
    """Set exactly one KEY=VALUE line; keep every other line byte for byte."""
    try:
        text = existing.decode('utf-8')
    except UnicodeError:
        raise SinkError('sink file is not UTF-8 text; not changed') from None
    # Line-wise editing is only safe when every assignment is one physical
    # line. Quotes and backslashes (also in comments) can join lines for some
    # parsers, so a file that has any of them is refused, not parsed.
    if any(c in text for c in '\0\r"\'\\'):
        raise SinkError('sink file has quotes, backslashes or unsupported characters; not changed')
    lines = text.splitlines(keepends=True)
    pattern = re.compile(r'[ \t]*(?:export[ \t]+)?' + re.escape(key) + r'[ \t]*=')
    found = [index for index, line in enumerate(lines) if pattern.match(line)]
    if len(found) > 1:
        raise SinkError('sink file sets the key more than once; not changed')
    line = key + '=' + value + '\n'
    if found:
        # Keep an existing `export` so a shell still passes the key on.
        prefix = re.match(r'[ \t]*(?:export[ \t]+)?', lines[found[0]]).group(0)
        lines[found[0]] = prefix + line
    else:
        if lines and not lines[-1].endswith('\n'):
            lines[-1] += '\n'
        lines.append(line)
    return ''.join(lines).encode('utf-8')


def _account_ids(sink):
    import grp
    import pwd
    try:
        return pwd.getpwnam(sink['owner']).pw_uid, grp.getgrnam(sink['group']).gr_gid
    except KeyError:
        raise SinkError('sink owner or group does not exist') from None


def _open_parent(path, owner_uid):
    """Walk every component without following symlinks; return (dir_fd, name)."""
    parts = path.strip('/').split('/')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)

    def trusted(final):
        # Every directory on the path belongs to root or the sink owner, and no
        # other account can rename entries in it (a root-owned sticky ancestor
        # such as /tmp is allowed; the final directory must not be shared).
        info = os.fstat(directory)
        shared = info.st_mode & 0o022 and not (not final and info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
        if info.st_uid not in {0, owner_uid} or shared:
            raise SinkError('sink directory path is not owned by the sink owner or root, or others can write it')
    try:
        for part in parts[:-1]:
            trusted(False)
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        trusted(True)
        return directory, parts[-1]
    except OSError:
        os.close(directory)
        raise SinkError('sink directory unavailable or not a plain directory path') from None
    except SinkError:
        os.close(directory)
        raise


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def write_sink(sink, value):
    """Atomically set the sink's key; return whether the file content changed."""
    validate_value(value)
    uid, gid = _account_ids(sink)
    if os.geteuid() != 0 and uid != os.geteuid():
        raise SinkError('direct sinks must belong to the broker account')
    directory, name = _open_parent(sink['path'], uid)
    staging = None
    try:
        # One writer at a time per directory, across helper processes and the
        # broker, for the whole read-modify-replace.
        import fcntl
        fcntl.flock(directory, fcntl.LOCK_EX)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            existing, before, attributes = b'', None, None
        except OSError:
            raise SinkError('sink file is not a regular file') from None
        else:
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid or info.st_size > MAX_FILE:
                    raise SinkError('sink file is not a single-link regular file of the sink owner')
                existing, before = os.read(fd, MAX_FILE + 1), _identity(info)
                attributes = info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)
            finally:
                os.close(fd)
        updated = render(existing, sink['key'], value)
        if len(updated) > MAX_FILE:
            raise SinkError('sink file would be too large; not changed')
        # Rewrite as well when only the owner, group or mode differ.
        changed = updated != existing or attributes != (uid, gid, sink['mode'])
        if changed:
            staging = '.' + name[:64] + '.akdbx-' + secrets.token_hex(8) + '.tmp'
            fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                os.fchown(stream.fileno(), uid, gid)
                os.fchmod(stream.fileno(), sink['mode'])
                stream.write(updated)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                current = _identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
            except FileNotFoundError:
                current = None
            if current != before:
                raise SinkError('sink file changed during the write; not changed')
            os.replace(staging, name, src_dir_fd=directory, dst_dir_fd=directory)
            staging = None
            os.fsync(directory)
        return changed
    except OSError:
        raise SinkError('sink write failed; check the sink file') from None
    finally:
        if staging is not None:
            try:
                os.unlink(staging, dir_fd=directory)
            except OSError:
                pass
        os.close(directory)


def restart_plan(sink):
    """Return the restart argv, or None; checked before anything is written."""
    import pwd
    spec = sink['restart']
    if spec is None:
        return None
    argv, user = list(spec['argv']), spec['user']
    if os.geteuid() == 0:
        # The root helper never runs a restart as root (or a UID 0 alias): by
        # default it runs as the sink owner.
        user = user or sink['owner']
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            raise SinkError('restart user does not exist') from None
        if uid == 0:
            raise SinkError('root-helper restart commands cannot run as root')
        return [RUNUSER, '-u', user, '--', *argv]
    if user is not None:
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            raise SinkError('restart user does not exist') from None
        if uid != os.geteuid():
            raise SinkError('restart user must be the broker account for direct sinks')
    return argv


def restart(sink, argv=None):
    """Run the fixed restart command, if any; return True, or None without one."""
    argv = restart_plan(sink) if argv is None else argv
    if argv is None:
        return None
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={'PATH': SAFE_PATH, **sink['restart']['env']}, cwd='/', timeout=RESTART_TIMEOUT, close_fds=True)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def deliver(sink, value):
    # The receipt never says whether the value was already present: that would
    # let a caller of the helper test a guessed value.
    argv = restart_plan(sink)
    write_sink(sink, value)
    return dict(restarted=restart(sink, argv))


def _peer_uid(connection):
    size = struct.calcsize('3i')
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))[1]


def _receive(connection):
    data = b''
    while b'\n' not in data:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_REQUEST:
            raise SinkError('request too large')
    line, _, rest = data.partition(b'\n')
    if rest.strip():
        raise SinkError('unexpected request data')
    return json.loads(line.decode('utf-8'))


def serve_connection(connection, config):
    """Handle one request on an accepted Unix connection; reply with a receipt only."""
    try:
        connection.settimeout(5)
        if _peer_uid(connection) not in config['broker_uids']:
            raise SinkError('caller is not an allowed broker')
        request = _receive(connection)
        if (not isinstance(request, dict) or set(request) != {'sink_protocol', 'sink', 'field', 'sink_digest', 'value'}
                or request['sink_protocol'] != PROTOCOL or type(request['sink_protocol']) is not int):
            raise SinkError('invalid request')
        sink = config['sinks'].get(request['sink']) if isinstance(request['sink'], str) else None
        if sink is None or sink['writer'] != 'root-helper':
            raise SinkError('unknown sink')
        if request['field'] != sink['field']:
            raise SinkError('field does not match the sink')
        if request['sink_digest'] != sink_digest(sink):
            raise SinkError('sink definition changed since the broker started; restart the broker')
        reply = dict(ok=True, **deliver(sink, request['value']))
    except SinkError as exc:
        reply = dict(ok=False, error=str(exc))
    except Exception:
        reply = dict(ok=False, error='sink helper failed; nothing confirmed')
    finally:
        request = None
    try:
        connection.settimeout(5)
        connection.sendall(json.dumps(reply).encode('utf-8') + b'\n')
    except OSError:
        pass


def main():
    """systemd `Accept=yes` entry point: the accepted connection is stdin."""
    if os.geteuid() != 0:
        print('akdbx secret sink helper must run as root from its socket unit', file=sys.stderr)
        return 2
    connection = socket.socket(fileno=os.dup(0))
    try:
        try:
            config = load_config(HELPER_CONFIG, {0})
        except SinkError as exc:
            connection.sendall(json.dumps(dict(ok=False, error=str(exc))).encode('utf-8') + b'\n')
            return 1
        serve_connection(connection, config)
    finally:
        connection.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
