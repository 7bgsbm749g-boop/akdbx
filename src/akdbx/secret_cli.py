"""save-secret: store an operator secret from stdin or a file without displaying it.

The secret is read here, checked, and sent once over the private broker
socket. It is never placed in argv, environment variables, temporary files,
output, receipts or error messages. Every message printed below is fixed text.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import unicodedata

from .protocol import MAX_MESSAGE

COMMAND = 'save-secret'
PROTOCOL = 1
FIELD = 'password'
# Keys and tokens are small. JSON escaping (quotes, backslashes, non-ASCII)
# can still make the encoded request with its metadata larger than the
# 64 KiB frame; that is checked and refused before anything is sent.
MAX_BYTES = 32 * 1024
METADATA = ('title', 'username', 'url', 'group')
INPUT_REFUSED = 'secret refused: {}; request not sent'


class InputError(ValueError):
    """Fixed, secret-free reason for refusing local input."""


def add_parser(commands):
    help_text = ('save a secret from stdin or a file into a new entry, or into a selected entry with a fresh '
                 'search handle; the value is never shown')
    command = commands.add_parser(COMMAND, help=help_text, description=help_text + (
        '. Exactly one trailing line ending (LF or CRLF) is removed; the rest is stored exactly in the protected '
        'Password field. Pipe the value, for example: sudo cat FILE | akdbx save-secret --stdin ...'))
    for field in METADATA:
        command.add_argument('--' + field, required=True,
                             help='exact destination metadata (for an update: the selected entry\'s exact metadata)')
    source = command.add_mutually_exclusive_group(required=True)
    source.add_argument('--stdin', action='store_true', help='read the secret from piped standard input (not a terminal)')
    source.add_argument('--file', help='read the secret from this regular file; symbolic links are refused')
    command.add_argument('handle', nargs='?',
                         help='optional fresh search handle: replace that entry\'s password (old value kept in history)')


def _decode(data: bytes) -> str:
    if len(data) > MAX_BYTES + 2:
        raise InputError('input is larger than 32 KiB')
    if data.endswith(b'\r\n'):
        data = data[:-2]
    elif data.endswith(b'\n'):
        data = data[:-1]
    if not data:
        raise InputError('input is empty')
    if len(data) > MAX_BYTES:
        raise InputError('input is larger than 32 KiB')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise InputError('input is not UTF-8 text; binary files are not supported') from None
    if text.startswith('﻿'):
        raise InputError('input starts with a byte order mark')
    if any(unicodedata.category(c) in {'Cc', 'Zl', 'Zp'} for c in text):
        raise InputError('input has control characters or more than one line')
    return text


def _read_stdin() -> bytes:
    stream = sys.stdin
    try:
        if stream is None or stream.isatty():
            raise InputError('standard input is a terminal; pipe the secret instead of typing it')
        source = stream.buffer
    except InputError:
        raise
    except Exception:
        raise InputError('standard input is unavailable') from None
    return source.read(MAX_BYTES + 3)


def _read_file(path: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    try:
        # Windows has no O_NOFOLLOW: refuse a link (or reparse point) by name,
        # then require the opened file to be that same file.
        named = os.lstat(path)
        if stat.S_ISLNK(named.st_mode) or getattr(named, 'st_reparse_tag', 0):
            raise OSError
        fd = os.open(path, flags)
    except OSError:
        raise InputError('file could not be opened (missing, unreadable or a symbolic link)') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise InputError('path is not a regular file')
        if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
            raise InputError('file changed while it was opened')
        if info.st_size > MAX_BYTES + 2:
            raise InputError('input is larger than 32 KiB')
        chunks, size = [], 0
        while size <= MAX_BYTES + 2:
            chunk = os.read(fd, MAX_BYTES + 3 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b''.join(chunks)
    except InputError:
        raise
    except OSError:
        raise InputError('file could not be read') from None
    finally:
        os.close(fd)


def read_secret(args) -> str:
    return _decode(_read_stdin() if args.stdin else _read_file(args.file))


def _valid_receipt(args, payload, response) -> bool:
    if response.get('ok') is True:
        return (set(response) == {'ok', 'state', 'saved', 'metadata'} and response['state'] == 'saved'
                and response['saved'] == ('updated' if args.handle is not None else 'created')
                and response['metadata'] == payload['metadata'])
    return (response.get('ok') is False and isinstance(response.get('error'), str)
            and set(response) <= {'ok', 'error', 'unlock_url'})


def _emit(value) -> None:
    print(json.dumps(value, indent=2))


def run(args, request) -> int:
    """request(payload, before_send=None) sends one RPC; it is used for ping and the save."""
    metadata = {field: getattr(args, field) for field in METADATA}
    try:
        caps = request({'action': 'ping'})
    except (FileNotFoundError, ConnectionRefusedError):
        print('broker is not running; secret not read; request not sent', file=sys.stderr)
        return 2
    except Exception:
        print('secret save not started: broker connection or capability check failed; request not sent', file=sys.stderr)
        return 2
    if (caps.get('ok') is not True or type(caps.get('secret_save_protocol')) is not int
            or caps['secret_save_protocol'] != PROTOCOL or caps.get('secret_save_field') != FIELD):
        _emit({'ok': False, 'error': 'broker lacks secret save protocol 1; require broker 0.19.0 or newer; secret not read; request not sent'})
        return 1
    if caps.get('locked') is not False:
        refusal = {'ok': False, 'error': 'vault locked; secret not read; request not sent'}
        if isinstance(caps.get('unlock_url'), str):
            refusal['unlock_url'] = caps['unlock_url']
        _emit(refusal)
        return 1
    if caps.get('recovery_required') is not False or caps.get('writes_available') is not True:
        _emit({'ok': False, 'error': 'private writes unavailable or recovery required; secret not read; request not sent'})
        return 1
    try:
        secret = read_secret(args)
    except InputError as exc:
        print(INPUT_REFUSED.format(exc), file=sys.stderr)
        return 2
    except Exception:
        print(INPUT_REFUSED.format('input could not be read'), file=sys.stderr)
        return 2
    payload = {'action': COMMAND, 'secret_save_protocol': PROTOCOL, 'metadata': metadata, 'secret': secret}
    if args.handle is not None:
        payload['handle'] = args.handle
    if len(json.dumps(payload, separators=(',', ':')).encode('utf-8')) > MAX_MESSAGE:
        payload = secret = None
        print(INPUT_REFUSED.format('secret and metadata exceed the 64 KiB request limit after encoding'), file=sys.stderr)
        return 2
    started = False

    def mark_send():
        nonlocal started
        started = True

    try:
        response = request(payload, before_send=mark_send)
    except Exception as exc:
        if not started:
            print('secret save not started: broker connection or message check failed; request not sent', file=sys.stderr)
        elif isinstance(exc, (TimeoutError, OSError)) and not isinstance(exc, PermissionError):
            print('secret save outcome uncertain: check status and search before any retry; do not save again automatically', file=sys.stderr)
        else:
            print('secret save outcome unconfirmed: broker response rejected; check status and search before any retry', file=sys.stderr)
        return 2
    finally:
        payload = None
    try:
        valid = _valid_receipt(args, {'metadata': metadata}, response)
        # A success receipt has a fixed shape; check every failure string too.
        leaked = response.get('ok') is not True and any(secret in str(value) for value in response.values())
    except Exception:
        valid, leaked = False, True
    secret = None
    if not valid or leaked:
        print('secret save outcome unconfirmed: receipt withheld; check status and search before any retry', file=sys.stderr)
        return 2
    _emit(response)
    return 0 if response['ok'] else 1
