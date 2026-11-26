"""Native-messaging host for the akdbx browser extension, and its installer.

The browser starts this host for the fixed extension ID only. The host connects
to the running broker's private endpoint (Unix socket or named pipe) with the
CLI's peer checks, then relays bounded JSON messages in both directions. It
keeps no state, writes no files and logs nothing. Values pass through it only
sealed to the paired extension's key (see ``extension_route``), so the host
never sees one in plain text.

Install commands write a small launcher and a host manifest in this user's
own folders and register the manifest for one browser:

* Windows (per user, ``HKEY_CURRENT_USER``): Chrome reads
  ``Software\\Google\\Chrome\\NativeMessagingHosts``; Edge reads
  ``Software\\Microsoft\\Edge\\NativeMessagingHosts``; Helium, a Chromium-branded
  build, reads ``Software\\Chromium\\NativeMessagingHosts`` and then Chrome's key.
* Linux: the host manifest goes in the browser's user-data folder:
  ``~/.config/google-chrome``, ``~/.config/microsoft-edge`` or
  ``~/.config/net.imput.helium`` (each under ``NativeMessagingHosts``).
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import struct
import sys
import tempfile
import threading
from importlib.resources import files

from .extension_route import (BROWSERS, FIREFOX_EXTENSION_ID, EXTENSION_ID, EXTENSION_ORIGIN, EXTENSION_VERSION, HOST_NAME, PUBLIC_KEY,
                              PROTOCOL, valid_extension_version)
from .protocol import MAX_MESSAGE, ProtocolError, receive_message, send_message

MAX_FRAME = MAX_MESSAGE
FROM_BROKER = {'attached', 'state', 'call', 'response', 'error'}
FROM_EXTENSION = {'reply', 'request'}
EXTENSION_KEY = ('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxc7bzfI9oXFOvC2UNIVQYcoX5EZ++4YevmQbMTCKPJYgDb91uJ80Z3Kd'
                 'AOlAyV2inpkrCPI2LMaJuhex3+cep32fMlPDdVyMf/Q/bp0jND91nrxT1C3ZHiM52GrKBDWnjR+E8gQ1q/nQM+7g22VY53oPfae'
                 'hsdiTXfZxHcsz4SUkdA4efd/CZX2XXofRB1mYxKjmtm2RUG5uBFp5OHmjoj3mhLEwR8pOxyN99gxkRcsaOTCQ45HQXzjXJs124yA'
                 'GzXx8B9Fuebbl4bXS9E7pNc0rmz5Mriq5BciZcI/UamdIVqyTSGHSPwa+PZAC2OUd1Iv7qG7YEpnqxBbBi8GQtQIDAQAB')
WINDOWS_KEYS = {
    'chrome': r'Software\Google\Chrome\NativeMessagingHosts',
    'edge': r'Software\Microsoft\Edge\NativeMessagingHosts',
    'helium': r'Software\Chromium\NativeMessagingHosts',
    'firefox': r'Software\Mozilla\NativeMessagingHosts',
}
LINUX_DIRS = {'chrome': 'google-chrome', 'edge': 'microsoft-edge', 'helium': 'net.imput.helium'}


class FrameError(Exception):
    pass


# ----- Chrome native-messaging framing ------------------------------------
def _read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise FrameError('truncated native message')
        data.extend(chunk)
    return bytes(data)


def read_frame(stream, limit=MAX_FRAME):
    """One browser message: a 32-bit native-order length, then UTF-8 JSON. None at EOF."""
    header = stream.read(4)
    if not header:
        return None
    if len(header) < 4:
        header += _read_exact(stream, 4 - len(header))
    size = struct.unpack('<I', header)[0]
    if not 0 < size <= limit:
        raise FrameError('native message size out of range')
    try:
        value = json.loads(_read_exact(stream, size).decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise FrameError('invalid native message') from None
    if not isinstance(value, dict):
        raise FrameError('native message must be an object')
    return value


def write_frame(stream, value, limit=MAX_FRAME):
    data = json.dumps(value, separators=(',', ':')).encode('utf-8')
    if len(data) > limit:
        raise FrameError('native message too large')
    stream.write(struct.pack('<I', len(data)) + data)
    stream.flush()


# ----- broker connection ----------------------------------------------------
def connect_broker(socket_path=None):
    """Open the broker endpoint with the same peer checks as the CLI."""
    from .cli import default_socket
    path = Path(socket_path) if socket_path else default_socket()
    if os.name == 'nt':
        from .windows_rpc import connect
        connection = connect(path)
        connection.settimeout(5)
        return connection
    from .cli import _peer_credentials, _validate_socket_path
    from .runtime import anchored_socket_path
    path, directory = _validate_socket_path(path, os.getuid())
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(5)
        client.connect(anchored_socket_path(directory, path.name))
        if _peer_credentials(client)[1] != os.getuid():
            raise PermissionError('broker peer UID mismatch')
        return client
    except BaseException:
        client.close()
        raise
    finally:
        os.close(directory)


def relay(incoming, outgoing, origin, browser, connect, on_broker_closed=None):
    """Run one host session. Returns the process exit status."""
    expected = FIREFOX_EXTENSION_ID if browser == 'firefox' else EXTENSION_ORIGIN
    if origin != expected or browser not in BROWSERS:
        return 1
    try:
        hello = read_frame(incoming)
    except FrameError:
        return 1
    # Extensions built by akdbx 0.21.2 or earlier send no version; they still attach and show as outdated.
    # A worker that found a newer build on disk, and could not reload into it, says ``stale: true``.
    if (hello is None or set(hello) - {'version', 'stale'} != {'type', 'protocol', 'public_key'}
            or hello['type'] != 'hello'
            or type(hello['protocol']) is not int or hello['protocol'] != PROTOCOL
            or not isinstance(hello['public_key'], str) or not PUBLIC_KEY.fullmatch(hello['public_key'])
            or ('version' in hello and not valid_extension_version(hello['version']))
            or ('stale' in hello and hello['stale'] is not True)):
        return 1
    out_lock = threading.Lock()
    try:
        connection = connect()
    except Exception:
        with out_lock:
            write_frame(outgoing, dict(type='state', connected=False, error='broker unavailable'))
        return 0
    send_lock = threading.Lock()
    closed = threading.Event()
    attach = dict(action='extension-attach', extension_protocol=PROTOCOL, extension_id=EXTENSION_ID, browser=browser,
                  public_key=hello['public_key'])
    if 'version' in hello:
        attach['extension_version'] = hello['version']
    if 'stale' in hello:
        attach['extension_stale'] = True
    try:
        send_message(connection, attach)
    except Exception:
        connection.close()
        return 0
    hello.clear()

    def from_broker():
        from .extension_route import _wait_readable
        try:
            while not closed.is_set():
                if not _wait_readable(connection, 1.0):
                    continue
                connection.settimeout(5)
                message = receive_message(connection)
                if message.get('type') not in FROM_BROKER:
                    break
                with out_lock:
                    write_frame(outgoing, message)
        except Exception:
            pass
        finally:
            closed.set()
            try:
                connection.close()
            except Exception:
                pass
            if on_broker_closed is not None:
                on_broker_closed()

    reader = threading.Thread(target=from_broker, daemon=True, name='akdbx-host-broker')
    reader.start()
    try:
        while not closed.is_set():
            message = read_frame(incoming)
            if message is None or message.get('type') not in FROM_EXTENSION:
                break
            with send_lock:
                connection.settimeout(5)
                send_message(connection, message)
    except (FrameError, ProtocolError, OSError, TimeoutError):
        pass
    finally:
        closed.set()
        try:
            connection.close()
        except Exception:
            pass
        reader.join(2)
    return 0


def _binary_stdio():
    if os.name == 'nt':
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    return sys.stdin.buffer, sys.stdout.buffer


def main(argv=None):
    """Entry point the browser starts through the installed launcher."""
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--browser', choices=BROWSERS, required=True)
    parser.add_argument('--socket')
    parser.add_argument('origin', nargs='?', default='')
    parser.add_argument('addon_id', nargs='?', default='')
    # Chrome on Windows appends --parent-window=HWND; it is not used.
    args, _ = parser.parse_known_args(argv)
    incoming, outgoing = _binary_stdio()
    # Firefox supplies manifest path, then the manifest's fixed add-on ID.
    # The browser's allowed_extensions check and this exact caller check both apply.
    caller = args.addon_id if args.browser == 'firefox' else args.origin
    return relay(incoming, outgoing, caller, args.browser, lambda: connect_broker(args.socket),
                 on_broker_closed=lambda: os._exit(0))


# ----- installation -------------------------------------------------------
def data_home():
    if os.name == 'nt':
        return Path(os.environ['LOCALAPPDATA']) / 'akdbx' / 'extension-host'
    base = os.environ.get('XDG_DATA_HOME') or str(Path.home() / '.local' / 'share')
    return Path(base) / 'akdbx' / 'extension-host'


def linux_manifest_dir(browser):
    if sys.platform == 'darwin':
        names = {'chrome': 'Google/Chrome', 'edge': 'Microsoft Edge', 'helium': 'net.imput.helium',
                 'firefox': 'Mozilla'}
        return Path.home() / 'Library' / 'Application Support' / names[browser] / 'NativeMessagingHosts'
    if browser == 'firefox':
        return Path.home() / '.mozilla' / 'native-messaging-hosts'
    if browser in ('chrome', 'helium'):
        # Chrome and Helium use CHROME_CONFIG_HOME before XDG_CONFIG_HOME.
        base = os.environ.get('CHROME_CONFIG_HOME') or os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
    else:
        base = os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
    return Path(base) / LINUX_DIRS[browser] / 'NativeMessagingHosts'


def paths(browser, manifest_dir=None):
    home = data_home()
    if os.name == 'nt':
        return dict(launcher=home / f'{browser}.cmd', manifest=home / f'{HOST_NAME}.{browser}.json',
                    registry='HKEY_CURRENT_USER\\' + WINDOWS_KEYS[browser] + '\\' + HOST_NAME)
    directory = Path(manifest_dir) if manifest_dir else linux_manifest_dir(browser)
    return dict(launcher=home / f'{browser}.sh', manifest=directory / f'{HOST_NAME}.json')


# A Linux and macOS launcher puts this akdbx's own folder first on sys.path, so the host runs the same akdbx as the
# CLI that installed it, also when that interpreter's site-packages hold another akdbx (a wrapper deployment).
# The folder is an argument, never part of the code; -I still ignores PYTHONPATH, the user site and the cwd.
BOOTSTRAP = 'import sys;sys.path.insert(0,sys.argv.pop(1));from akdbx.extension_host import main;raise SystemExit(main())'
# The check also imports akdbx.cli: connect_broker needs it (and its dependencies) at the first connection.
_CHECK = ('import sys;sys.path.insert(0,sys.argv.pop(1)) if len(sys.argv)>1 else None;'
          'import akdbx.extension_host as h,akdbx.cli;print(h.__file__)')


def package_root():
    """The folder that holds the akdbx package this process runs (a release ``src`` or a site-packages)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _launcher_text(browser, python, socket_path, source=None):
    if os.name == 'nt':
        if source is not None:
            raise ValueError('a Windows launcher runs the akdbx of its Python; it takes no source folder')
        if any(c in python + (socket_path or '') for c in '"%\r\n^&|<>'):
            raise ValueError('the Python or socket path contains a character that a Windows launcher cannot quote')
        extra = f' --socket "{socket_path}"' if socket_path else ''
        return f'@echo off\r\n"{python}" -I -m akdbx.extension_host --browser {browser}{extra} %*\r\n'
    extra = ' --socket ' + shlex.quote(socket_path) if socket_path else ''
    start = f'-I -c {shlex.quote(BOOTSTRAP)} {shlex.quote(source)}' if source is not None else '-I -m akdbx.extension_host'
    return f'#!/bin/sh\nexec {shlex.quote(python)} {start} --browser {browser}{extra} "$@"\n'


def expected_launcher(browser, python, socket_path):
    """The launcher this akdbx writes now: on Linux and macOS it names this akdbx's own folder."""
    return _launcher_text(browser, python, socket_path, None if os.name == 'nt' else package_root())


def check_python(python, source):
    """Refuse an interpreter that would run another akdbx (or none) through the launcher.

    The check imports the host exactly as the launcher does, in a new isolated process, and compares the file
    it found with this module's own file.
    """
    import subprocess
    argv = [python, '-I', '-c', _CHECK] + ([] if source is None else [source])
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
                                cwd=tempfile.gettempdir())
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f'{python} cannot start: {exc}') from None
    lines = (result.stdout or '').strip().splitlines()
    if result.returncode != 0 or not lines:
        reason = ((result.stderr or '').strip().splitlines() or ['no output'])[-1][:300]
        raise ValueError(f'{python} cannot run the akdbx extension host ({reason}); '
                         'pass --python with the interpreter of this akdbx installation')
    found, ours = os.path.normcase(os.path.realpath(lines[-1])), os.path.normcase(os.path.realpath(__file__))
    if found != ours:
        raise ValueError(f'{python} runs another akdbx ({lines[-1][:300]}), not this one ({__file__}); '
                         'pass --python with the interpreter of this akdbx installation')


def _manifest(launcher, name=HOST_NAME, *, browser='chrome'):
    return dict(name=name, description='akdbx password manager extension host', path=str(launcher),
                type='stdio', **({'allowed_extensions': [FIREFOX_EXTENSION_ID]} if browser == 'firefox'
                                else {'allowed_origins': [EXTENSION_ORIGIN]}))


LAUNCHER_LIMIT = 4096


def _file_kind(path):
    """'missing', 'file' for a regular file, or 'other' (a symlink, junction, folder or device)."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return 'missing'
    import stat
    if stat.S_ISREG(info.st_mode) and not getattr(info, 'st_reparse_tag', 0):
        return 'file'
    return 'other'


def _read_regular(path, limit):
    """The bytes of a regular file that is not a link, or None."""
    if _file_kind(path) != 'file':
        return None
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    with os.fdopen(fd, 'rb') as source:
        return source.read(limit + 1)


def _parse_launcher(path, browser):
    """The Python, socket and source folder of the exact launcher that this installer writes; never a link.

    Every release since v0.21.0 writes the ``-m`` format; Linux and macOS releases from v0.31.1 write the
    bootstrap format that names a source folder. The values are read back from the file, the launcher is
    generated again, and only an identical file counts. Anything else is None.
    """
    data = _read_regular(path, LAUNCHER_LIMIT)
    if data is None or len(data) > LAUNCHER_LIMIT:
        return None
    try:
        text = data.decode('utf-8')
        source = None
        if os.name == 'nt':
            words = text.split('"')  # @echo off, "PYTHON", the arguments, then "SOCKET" when there is one
            python, socket_path = words[1], words[3] if len(words) == 5 else None
        else:
            words = shlex.split(text.split('\n')[1])
            python = words[1]
            if words[2:5] == ['-I', '-c', BOOTSTRAP]:
                source = words[5]
            socket_path = words[words.index('--socket') + 1] if '--socket' in words else None
        if text != _launcher_text(browser, python, socket_path, source):
            return None
        return dict(python=python, socket=socket_path, source=source)
    except (UnicodeError, ValueError, IndexError):
        return None


def _owned_launcher(path, browser):
    """True only for the exact launcher that this installer writes for these paths; never a link."""
    return _parse_launcher(path, browser) is not None


def launcher_state(browser):
    """'missing', 'foreign' (not written by akdbx), 'stale' (would not run this akdbx's host) or 'current'."""
    launcher = paths(browser)['launcher']
    if _file_kind(launcher) == 'missing':
        return 'missing'
    current = _parse_launcher(launcher, browser)
    if current is None:
        return 'foreign'
    if os.name != 'nt' and current['source'] != package_root():
        return 'stale'
    try:
        check_python(current['python'], current['source'])
    except ValueError:
        return 'stale'  # A missing interpreter, missing dependencies, or (Windows) another akdbx.
    return 'current'


def _owned_manifest(path, launcher):
    data = _read_regular(path, 64 * 1024)
    try:
        return data is not None and json.loads(data.decode('utf-8')).get('path') == str(launcher)
    except Exception:
        return False


def _replace_file(path, text, mode):
    """Write ``text`` to a new temporary file beside ``path``, then rename it over ``path``: a link there is
    replaced, never followed. Only that temporary file is ever removed."""
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(text.encode('utf-8'))
        if os.name != 'nt':
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def install(browser, *, socket_path=None, manifest_dir=None, python=None):
    """Write the launcher and manifest, then register the host for one browser."""
    if browser not in BROWSERS:
        raise ValueError('unsupported extension browser')
    python = str(Path(python or sys.executable).absolute())
    socket_path = (str(socket_path) if os.name == 'nt' else str(Path(socket_path).absolute())) if socket_path else None
    source = None if os.name == 'nt' else package_root()
    where = paths(browser, manifest_dir)
    launcher, manifest = where['launcher'], where['manifest']
    if os.name == 'nt':
        import winreg
        key = WINDOWS_KEYS[browser] + '\\' + HOST_NAME
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                current = winreg.QueryValueEx(handle, '')[0]
        except OSError:
            current = None
        if current not in (None, str(manifest)):
            raise ValueError('another org.akdbx.extension host is registered for this browser; uninstall it first')
    if _file_kind(manifest) == 'other':
        raise ValueError(f'{manifest} is a link or not a regular file; akdbx never writes through it. Remove it first')
    if _file_kind(manifest) == 'file' and not _owned_manifest(manifest, launcher):
        raise ValueError('another org.akdbx.extension manifest exists for this browser; uninstall it first')
    if _file_kind(launcher) == 'other':
        raise ValueError(f'{launcher} is a link or not a regular file; akdbx never writes through it. Remove it first')
    if _file_kind(launcher) == 'file' and not _owned_launcher(launcher, browser):
        raise ValueError(f'{launcher} exists and was not written by akdbx; move it away first')
    text = _launcher_text(browser, python, socket_path, source)
    check_python(python, source)
    launcher.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    _replace_file(launcher, text, 0o700)
    _replace_file(manifest, json.dumps(_manifest(launcher, browser=browser), indent=2), 0o644)
    if os.name == 'nt':
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, WINDOWS_KEYS[browser] + '\\' + HOST_NAME) as handle:
            winreg.SetValueEx(handle, '', 0, winreg.REG_SZ, str(manifest))
    return {k: str(v) for k, v in where.items()}


def refresh(*, python=None, socket_path=None):
    """Point every launcher that akdbx wrote for this user at this akdbx; manifests and registrations stay.

    All manifests of one browser (also those in ``--manifest-dir`` folders) name the same launcher, so this
    covers every profile. Run it after an update that moves akdbx to another folder. The interpreter is this
    CLI's own unless ``python`` is given; each launcher keeps its socket unless ``socket_path`` is given.
    """
    python = str(Path(python or sys.executable).absolute())
    socket_path = (str(socket_path) if os.name == 'nt' else str(Path(socket_path).absolute())) if socket_path else None
    source = None if os.name == 'nt' else package_root()
    found = {}
    for browser in BROWSERS:
        launcher = paths(browser)['launcher']
        kind = _file_kind(launcher)
        if kind == 'missing':
            continue
        before = _read_regular(launcher, LAUNCHER_LIMIT)
        current = _parse_launcher(launcher, browser) if kind == 'file' else None
        if current is None or before is None:
            raise ValueError(f'{launcher} was not written by akdbx; nothing was changed. Move it away first')
        found[browser] = (launcher, before, _launcher_text(browser, python, socket_path or current['socket'], source))
    if found:
        check_python(python, source)
    refreshed = []
    for browser, (launcher, before, text) in found.items():
        now = _read_regular(launcher, LAUNCHER_LIMIT)
        if now != before:
            raise ValueError(f'{launcher} changed during the refresh; run refresh again')
        if now != text.encode('utf-8'):
            _replace_file(launcher, text, 0o700)
        refreshed.append(dict(browser=browser, launcher=str(launcher)))
    return refreshed


def uninstall(browser, *, manifest_dir=None):
    """Remove only this installer's registration, manifest and launcher."""
    where = paths(browser, manifest_dir)
    launcher, manifest = where['launcher'], where['manifest']
    removed = []
    if os.name == 'nt':
        import winreg
        key = WINDOWS_KEYS[browser] + '\\' + HOST_NAME
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
                current = winreg.QueryValueEx(handle, '')[0]
            if current == str(manifest):
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
                removed.append('registry')
        except OSError:
            pass
    if _owned_manifest(manifest, launcher):
        manifest.unlink()
        removed.append('manifest')
    if _owned_launcher(launcher, browser):
        launcher.unlink()
        removed.append('launcher')
    return removed


def _content_script():
    """Fill the content script with the CDP route's own DOM checks: one source for both routes."""
    from . import browser_card, browser_password, card_processor, password_frames
    text = files('akdbx').joinpath('fill_extension', 'content.js').read_text(encoding='utf-8')
    replacements = {
        '__PASSWORD_CAPTURE__': browser_password.CAPTURE,
        '__TOTP_FIELD__': browser_password.TOTP_FIELD,
        '__PASSWORD_FILL__': browser_password.FILL,
        '__CARD_PIN_SCRIPT__': browser_card.PIN_SCRIPT,
        '__CARD_GUARD__': card_processor.GUARD,
        '__STRIPE_ELEMENTS__': card_processor.STRIPE_ELEMENTS_JSON,
        '__PASSWORD_COUNT__': password_frames.COUNT,
        '__READ_CAPTURE__': browser_password.READ_CAPTURE,
        '__QR_CAPTURE__': browser_password.QR_CAPTURE,
        '__READ__': browser_password.READ,
        '__OWNER_GUARD__': password_frames.OWNER_GUARD,
        '__READ_SELECTOR__': json.dumps(browser_password.READ_SELECTOR.pattern),
        '__MAX_READ_SELECTOR__': str(browser_password.MAX_READ_SELECTOR),
    }
    for marker, value in replacements.items():
        if text.count(marker) != 1:
            raise RuntimeError('extension template marker missing: ' + marker)
        text = text.replace(marker, value)
    return text


def trusted_origin(value):
    """The independently configured HTTPS origin of the broker's private pages."""
    from .cli import _validate_unlock_url
    from .extension_route import _origin
    origin = value.rstrip('/') if isinstance(value, str) else ''
    _validate_unlock_url(origin + '/?token=configuration-check', origin)
    return _origin(origin + '/')  # The browser serialization: no default port.


def _source_files(host_name=HOST_NAME):
    """The extension files that ``build`` writes, except config.js, with the source's own version.

    ``host_name`` is the native-messaging host that background.js connects to;
    tests use their own, and the content stamp always uses the default one.
    """
    if host_name != HOST_NAME and not re.fullmatch(r'[a-z0-9_]+(\.[a-z0-9_]+)+', host_name):
        raise ValueError('invalid host name')
    written = {}
    for item in files('akdbx').joinpath('fill_extension').iterdir():
        if not item.is_file() or item.name.startswith('.') or item.name == 'config.js':
            continue
        if item.name == 'content.js':
            data = _content_script().encode('utf-8')
        else:
            data = item.read_bytes()
        if item.name == 'manifest.json':
            manifest = json.loads(data)
            manifest['key'] = EXTENSION_KEY
            data = json.dumps(manifest, indent=2).encode('utf-8')
        if item.name == 'background.js' and host_name != HOST_NAME:
            data = data.replace(HOST_NAME.encode(), host_name.encode())
        written[item.name] = data
    # The vendored QR decoder for QR read pins (capture-totp --qr), unmodified, with its licence.
    for name in ('jsQR.js', 'jsQR.LICENSE'):
        written[name] = files('akdbx').joinpath('import_assets', name).read_bytes()
    return written


@functools.cache
def built_version():
    """The manifest version that ``build`` writes: EXTENSION_VERSION and a fourth part from the contents.

    Chrome keeps a registered extension service worker, scripts and all, until
    the manifest version changes or the extension reloads; a browser restart
    alone does not replace it. Two builds with other contents and one version
    (a development build in the same folder) left an old worker running beside
    new content scripts. The fourth part is the first 16 bits of SHA-256 over
    the files (config.js excluded, line endings normalized, default host name),
    so a change to them gives another version and a restart loads the new
    worker. The broker compares the version a worker reports with this one.
    """
    digest = hashlib.sha256()
    for name, data in sorted(_source_files().items()):
        digest.update(name.encode() + b'\0' + hashlib.sha256(data.replace(b'\r\n', b'\n')).digest())
    return EXTENSION_VERSION + '.' + str(int.from_bytes(digest.digest()[:2], 'big'))


def build(destination, *, host_name=HOST_NAME, unlock_origin=None, browser='chrome'):
    """Write the unpacked extension. An existing folder must already hold this extension.

    The popup opens pairing and unlock links only on a trusted origin, so a
    replaced host cannot send the user to a look-alike master-password page.
    ``unlock_origin`` comes from local configuration, never from the native
    host: it is the first trusted origin. At the first pairing the extension
    reads the broker's identity key over HTTPS from this origin and later follows
    the origin changes that key signs (``broker_identity``), with no rebuild.
    Every build writes a new random build ID (``BUILD_ID``): the extension
    drops broker trust saved under another build and starts again from this
    origin, while a reload of the same build keeps it.

    The manifest gets ``built_version()``, and config.js the same version: the
    worker imports config.js, so Chrome caches it with the worker, and the
    worker reports that copy, not the manifest on disk (see background.js).
    """
    destination = Path(destination)
    if browser not in BROWSERS:
        raise ValueError('unsupported extension browser')
    origin = trusted_origin(unlock_origin) if unlock_origin is not None else None
    if destination.exists():
        try:
            current = json.loads((destination / 'manifest.json').read_text(encoding='utf-8'))
        except Exception:
            current = {}
        owned = (current.get('browser_specific_settings', {}).get('gecko', {}).get('id') == FIREFOX_EXTENSION_ID
                 if browser == 'firefox' else current.get('key') == EXTENSION_KEY)
        if not owned:
            raise ValueError('destination exists and does not hold the akdbx extension; choose a new folder')
    written = _source_files(host_name)
    version = built_version()
    manifest = json.loads(written['manifest.json'])
    manifest['version'] = version
    if browser == 'firefox':
        manifest.pop('key', None)
        manifest.pop('minimum_chrome_version', None)
        manifest['browser_specific_settings'] = {'gecko': {
            'id': FIREFOX_EXTENSION_ID, 'strict_min_version': '153.0',
            'data_collection_permissions': {'required': ['none']}}}
        manifest['background'] = {'scripts': ['api.js', 'config.js', 'trust.js', 'background.js']}
        # The browser's native document IDs are required, including for child frames.
        manifest['permissions'] = [p for p in manifest['permissions'] if p != 'contextMenus'] + ['menus']
    written['manifest.json'] = json.dumps(manifest, indent=2).encode('utf-8')
    destination.mkdir(parents=True, exist_ok=True)
    for name, data in written.items():
        (destination / name).write_bytes(data)
    (destination / 'config.js').write_text(
        '"use strict";\n// Written by `akdbx extension build`: the first trusted origin for pairing and unlock links.\n'
        '// After the first pairing, origin changes signed by the broker identity key replace it.\n'
        'globalThis.AKDBX_TRUSTED_ORIGIN = ' + json.dumps(origin) + ';\n'
        '// A new random ID on every build: broker trust saved under another build no longer counts.\n'
        'globalThis.AKDBX_BUILD_ID = ' + json.dumps(secrets.token_urlsafe(16)) + ';\n'
        '// The manifest version of this build. The worker reports this copy, which Chrome caches with it.\n'
        'globalThis.AKDBX_EXTENSION_VERSION = ' + json.dumps(version) + ';\n', encoding='utf-8')
    return destination


# The build ID line in config.js: 128 random bits, base64url (trust.js BUILD_ID).
BUILD_ID = re.compile(r'^globalThis\.AKDBX_BUILD_ID = "([A-Za-z0-9_-]{22})";$', re.M)


def add_parser(commands):
    extension = commands.add_parser('extension', help='install the akdbx browser extension host, or build the extension')
    actions = extension.add_subparsers(dest='extension_command', required=True)
    python_help = ('interpreter that the launcher runs; it must import this akdbx (checked). '
                   'Default: the interpreter of this CLI')
    for name in ('install', 'uninstall'):
        command = actions.add_parser(name, help=f'{name} the native-messaging host for one browser (this user only)')
        command.add_argument('--browser', required=True, choices=BROWSERS)
        if os.name != 'nt':
            command.add_argument('--manifest-dir', type=Path,
                                 help='NativeMessagingHosts folder of a custom user-data folder, for example '
                                      '<browser_profile_root>/slot1/NativeMessagingHosts for an agent desktop slot')
        if name == 'install':
            command.add_argument('--python', type=Path, help=python_help)
    refresh_command = actions.add_parser(
        'refresh', help='point every installed host launcher at this akdbx (run after an update moves akdbx)')
    refresh_command.add_argument('--python', type=Path, help=python_help)
    build_command = actions.add_parser('build', help='write the unpacked extension to a folder (load it unpacked)')
    build_command.add_argument('--output', required=True, type=Path)
    build_command.add_argument('--browser', choices=BROWSERS, default='chrome',
                               help='extension format to build (default: chrome; Firefox requires 153+)')
    actions.add_parser('info', help='show the extension ID, host name and per-browser host locations')


def run(args, socket_path=None, unlock_origin=None):
    try:
        if args.extension_command == 'install':
            where = install(args.browser, socket_path=socket_path, manifest_dir=getattr(args, 'manifest_dir', None),
                            python=args.python)
            print(json.dumps(dict(ok=True, browser=args.browser,
                                  extension_id=FIREFOX_EXTENSION_ID if args.browser == 'firefox' else EXTENSION_ID,
                                  host=HOST_NAME,
                                  akdbx_source=package_root(), **where), indent=2))
        elif args.extension_command == 'refresh':
            refreshed = refresh(python=args.python, socket_path=socket_path)
            print(json.dumps(dict(ok=True, refreshed=refreshed, akdbx_source=package_root()), indent=2))
        elif args.extension_command == 'uninstall':
            removed = uninstall(args.browser, manifest_dir=getattr(args, 'manifest_dir', None))
            print(json.dumps(dict(ok=True, browser=args.browser, removed=removed), indent=2))
        elif args.extension_command == 'build':
            browser = getattr(args, 'browser', 'chrome')
            path = build(args.output, unlock_origin=unlock_origin, browser=browser)
            print(json.dumps(dict(ok=True, extension_id=FIREFOX_EXTENSION_ID if browser == 'firefox' else EXTENSION_ID,
                                  extension_version=built_version(),
                                  path=str(path.absolute()), trusted_origin=trusted_origin(unlock_origin)), indent=2))
        else:
            print(json.dumps(dict(ok=True, extension_id=EXTENSION_ID, extension_version=built_version(),
                                  host=HOST_NAME, protocol=PROTOCOL,
                                  akdbx_source=package_root(),
                                  browsers={b: {**{k: str(v) for k, v in paths(b).items()},
                                                'extension_id': FIREFOX_EXTENSION_ID if b == 'firefox' else EXTENSION_ID,
                                                'launcher_state': launcher_state(b)} for b in BROWSERS}), indent=2))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps(dict(ok=False, error=str(exc))), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
