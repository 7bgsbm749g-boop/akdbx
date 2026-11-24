"""Exact page URL options, with a private file form for URLs that hold a token.

The broker compares the full observed URL, query and fragment included. A URL
with a one-time token must not go in argv, where other processes, logs and
transcripts can see it, so each URL flag has a ``-file`` twin. The file is read
here and its text goes to the broker unchanged. No error names the URL.
"""
import os
import stat
from pathlib import Path

LIMIT = 4096
FLAGS = ('top-url', 'frame-url', 'target-url')


class PageURLFileError(ValueError):
    """Fixed-text refusal; never carries the URL or file contents."""


def add(parser, flag, *, required, help):
    """Add ``--FLAG`` and ``--FLAG-file``; exactly one is allowed (one is required if ``required``)."""
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument('--' + flag, help=help)
    group.add_argument('--' + flag + '-file', type=Path, metavar='PATH',
                       help=f'owned private file (mode 0600, at most {LIMIT} bytes) that holds the --{flag} value; '
                            'use it when the URL contains a token. The URL is never printed')


def _read(path):
    if os.name == 'nt':
        from .windows_security import read_private
        try:
            data, _ = read_private(path, limit=LIMIT + 2)
        except Exception:
            raise PageURLFileError('could not read it as a private Windows file') from None
        return data
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise PageURLFileError('could not open it (missing, unreadable or a symlink)') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise PageURLFileError('it must be a regular file owned by this user')
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise PageURLFileError('other users can access it; use mode 0600')
        data = b''
        while len(data) <= LIMIT + 2:
            chunk = os.read(fd, LIMIT + 3 - len(data))
            if not chunk:
                break
            data += chunk
        return data
    except OSError:
        raise PageURLFileError('could not read it') from None
    finally:
        os.close(fd)


def read(path):
    """Return the one URL line from a private file; strip only a final line break."""
    try:
        path = Path(path).expanduser()
    except RuntimeError:  # ~user that does not exist
        raise PageURLFileError('could not open it (missing, unreadable or a symlink)') from None
    data = _read(path)
    if data.startswith(b'\xef\xbb\xbf'):
        raise PageURLFileError('it must be UTF-8 without a byte order mark')
    if data.endswith(b'\r\n'):
        data = data[:-2]
    elif data.endswith(b'\n'):
        data = data[:-1]
    if not data or len(data) > LIMIT:
        raise PageURLFileError(f'it must hold one URL of 1 to {LIMIT} bytes')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise PageURLFileError('it is not UTF-8 text') from None
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7f for c in text):
        raise PageURLFileError('it must hold one URL on one line, with no spaces')
    return text


def resolve(args):
    """Move every ``*_url_file`` value into its ``*_url`` attribute.

    Return None, or a fixed error line that names only the flag.
    """
    for base in FLAGS:
        flag = '--' + base + '-file'
        name = flag[2:].replace('-', '_')
        if getattr(args, name, None) is None:
            continue
        try:
            setattr(args, name[:-len('_file')], read(getattr(args, name)))
        except PageURLFileError as exc:
            return f'{flag}: {exc}; request not sent'
        setattr(args, name, None)
    return None
