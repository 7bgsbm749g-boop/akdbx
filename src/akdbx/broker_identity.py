"""The broker's identity key and its signed origin statements for the browser extension.

The extension popup opens pairing and unlock links only on one trusted origin,
so a replaced native host cannot send the user to a look-alike master-password
page. The origin can change: the relay moves the public port, ``akdbx relay
rotate`` registers a new name, or the operator serves another origin. Each
broker therefore has a persistent ECDSA P-256 identity key. At each start it
signs a statement that names its current origin and a sequence number that
increases with every origin change. The extension learns the public key at its
first pairing, from the broker's HTTPS page on its trusted origin
(``/.well-known/akdbx-identity``, ``web_unlock``) and not from the native host
alone. It later accepts a new origin only in a statement that this key signed
with a higher sequence number. A replaced native host can relay these
statements, but cannot make a new one.

Canonical encoding (``fill_extension/trust.js`` makes the same bytes)::

    statement = {"key_id": K, "origin": O, "seq": N, "type": "akdbx-origin", "v": 1}

The signed bytes are the UTF-8 (here: ASCII) JSON text of the statement with
the keys sorted, no whitespace, and ``,`` and ``:`` as separators, for example
``{"key_id":"...","origin":"https://localhost:9443","seq":1,"type":"akdbx-origin","v":1}``.
Every string is printable ASCII without ``"`` or ``\\``, and ``seq`` is an
integer from 1 to 2**53 - 1, so no escape or number format can differ between
Python and JavaScript.

* ``O`` is the browser serialization of an HTTPS origin: lower-case host,
  no default port, no path, query, fragment or credentials.
* ``K`` (``key_id``) is base64url without padding of SHA-256 over the 65-byte
  uncompressed public point.
* The signature is ECDSA P-256 with SHA-256 over the signed bytes, encoded as
  ``r || s`` (32 bytes each, big-endian; the IEEE P1363 form WebCrypto uses),
  base64url without padding.

The broker sends ``{"public_key": base64url(point), "statement": {...},
"signature": ...}`` as the ``identity`` field of the extension's ``attached``
and ``state`` messages and of its answer to the popup's ``state`` request,
and the private HTTPS page server serves the same object at
``GET /.well-known/akdbx-identity``.

The private key, the last origin and its sequence number are one private file
per broker endpoint (``identity-<hash>.json``) in
``${XDG_STATE_HOME:-~/.local/state}/akdbx/broker-identity`` (Linux, 0700/0600)
or ``%LOCALAPPDATA%\\akdbx\\broker-identity`` (Windows, this user and SYSTEM
only), with the relay folder's file checks. The private key is never printed
or logged.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re

from .relay import PrivateFolder

STATEMENT_TYPE = 'akdbx-origin'
STATEMENT_VERSION = 1
MAX_SEQ = 2 ** 53 - 1
FILE_VERSION = 1
MAX_FILE = 16 * 1024
DIRECTORY_NAME = 'broker-identity'
_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
ORIGIN = re.compile(rf'https://(?:{_LABEL}(?:\.{_LABEL})*|\[[0-9a-f:.]{{2,45}}\])(?::[1-9][0-9]{{0,4}})?')
KEY_ID = re.compile(r'[A-Za-z0-9_-]{43}')
PUBLIC_KEY = re.compile(r'[A-Za-z0-9_-]{87}')
SIGNATURE = re.compile(r'[A-Za-z0-9_-]{86}')


class IdentityError(Exception):
    """Fixed text and a path only; never key material."""


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _unb64url(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def canonical_origin(value):
    """The browser serialization of the HTTPS origin of ``value``, or IdentityError.

    Callers that need an exact origin compare the result with their input.
    """
    from .extension_route import ExtensionError, _origin
    if not isinstance(value, str) or not value.startswith('https://') or len(value) > 300:
        raise IdentityError('the origin must be an HTTPS origin')
    try:
        origin = _origin(value.rstrip('/') + '/')
    except ExtensionError:
        raise IdentityError('the origin must be an HTTPS origin') from None
    if not ORIGIN.fullmatch(origin):
        raise IdentityError('the origin must be an HTTPS origin without path, query or credentials')
    return origin


def canonical_bytes(statement):
    """The exact bytes that are signed: sorted keys, no whitespace, ASCII only."""
    return json.dumps(statement, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def public_point(public_key):
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def key_id(point):
    return b64url(hashlib.sha256(point).digest())


class Identity:
    """One broker identity at one origin: the signed statement the extension receives."""

    def __init__(self, private_key, origin, seq, *, changed=False):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        if type(seq) is not int or not 1 <= seq <= MAX_SEQ:
            raise IdentityError('the origin sequence number is out of range')
        self.origin, self.seq, self.changed = canonical_origin(origin), seq, changed
        point = public_point(private_key.public_key())
        self.public_key = b64url(point)
        self.key_id = key_id(point)
        self.statement = {'type': STATEMENT_TYPE, 'v': STATEMENT_VERSION, 'origin': self.origin, 'seq': seq,
                          'key_id': self.key_id}
        r, s = decode_dss_signature(private_key.sign(canonical_bytes(self.statement), ec.ECDSA(hashes.SHA256())))
        self.signature = b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))

    def __repr__(self):
        return f'Identity(origin={self.origin!r}, seq={self.seq}, key_id={self.key_id!r})'

    def message(self):
        return {'public_key': self.public_key, 'statement': dict(self.statement), 'signature': self.signature}

    def summary(self):
        """Non-secret facts for `akdbx status`."""
        return {'key_id': self.key_id, 'origin': self.origin, 'seq': self.seq}


def verify_message(message, public_key=None):
    """Return the statement of a valid ``identity`` message, or raise IdentityError.

    It checks the shape, the origin, the key id and the signature, with
    ``public_key`` (base64url point) when given, else with the message's own key.
    The extension makes the same checks in ``trust.js``.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        statement = message['statement']
        if (not isinstance(message, dict) or set(message) != {'public_key', 'statement', 'signature'}
                or not isinstance(statement, dict)
                or set(statement) != {'type', 'v', 'origin', 'seq', 'key_id'}
                or statement['type'] != STATEMENT_TYPE or type(statement['v']) is not int
                or statement['v'] != STATEMENT_VERSION or type(statement['seq']) is not int
                or not 1 <= statement['seq'] <= MAX_SEQ or not isinstance(statement['key_id'], str)
                or not KEY_ID.fullmatch(statement['key_id'])
                or not isinstance(message['public_key'], str) or not PUBLIC_KEY.fullmatch(message['public_key'])
                or not isinstance(message['signature'], str) or not SIGNATURE.fullmatch(message['signature'])
                or canonical_origin(statement['origin']) != statement['origin']):
            raise IdentityError('invalid origin statement')
        if public_key is not None and message['public_key'] != public_key:
            raise IdentityError('the origin statement is signed by another key')
        point = _unb64url(message['public_key'])
        if key_id(point) != statement['key_id']:
            raise IdentityError('the origin statement names another key')
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        raw = _unb64url(message['signature'])
        signature = encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
        key.verify(signature, canonical_bytes(statement), ec.ECDSA(hashes.SHA256()))
    except IdentityError:
        raise
    except (InvalidSignature, KeyError, TypeError, ValueError):
        raise IdentityError('invalid origin statement') from None
    return dict(statement)


def default_directory():
    if os.name == 'nt':
        return Path(os.environ['LOCALAPPDATA']) / 'akdbx' / DIRECTORY_NAME
    base = os.environ.get('XDG_STATE_HOME', '')
    root = Path(base) if os.path.isabs(base) else Path.home() / '.local' / 'state'
    return root / 'akdbx' / DIRECTORY_NAME


DEFAULT_PIPE_NAME = 'identity-default.json'


def file_name(socket_path, *, windows=None, default_pipe=None):
    """One identity per broker endpoint, so two brokers never share a sequence number.

    On Windows the default RPC pipe name includes the logon session id, which
    changes at each sign-in. The default broker keeps one identity file across
    sessions; any other pipe gets its own file. ``default_pipe`` is the current
    session's default pipe (for tests; else it comes from windows_rpc).
    """
    windows = os.name == 'nt' if windows is None else windows
    if windows:
        endpoint = str(socket_path)
        if default_pipe is None:
            from .windows_rpc import default_pipe as current_default
            default_pipe = current_default()
        if endpoint.lower() == str(default_pipe).lower():
            return DEFAULT_PIPE_NAME
    else:
        endpoint = os.path.realpath(socket_path)
    return 'identity-' + hashlib.sha256(os.fsencode(endpoint)).hexdigest()[:32] + '.json'


class IdentityStore(PrivateFolder):
    """The private identity file of one broker endpoint."""
    error = IdentityError

    def __init__(self, directory=None, name='identity.json'):
        super().__init__(directory or default_directory())
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}\.json', name) or name.startswith('.'):
            raise ValueError('invalid identity file name')
        self.name = name

    @classmethod
    def for_endpoint(cls, socket_path, directory=None):
        return cls(directory, file_name(socket_path))

    @property
    def path(self):
        return self.directory / self.name

    def load(self):
        """``(private_key, origin, seq)`` from the saved file, or None. IdentityError when untrusted."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        data = self._read(self.name)
        if data is None:
            return None
        try:
            if len(data) > MAX_FILE:
                raise ValueError
            parsed = json.loads(data)
            if (not isinstance(parsed, dict) or set(parsed) != {'version', 'private_key', 'origin', 'seq'}
                    or parsed['version'] != FILE_VERSION or not isinstance(parsed['private_key'], str)
                    or type(parsed['seq']) is not int or not 1 <= parsed['seq'] <= MAX_SEQ
                    or canonical_origin(parsed['origin']) != parsed['origin']):
                raise ValueError
            key = serialization.load_pem_private_key(parsed['private_key'].encode('ascii'), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != 'secp256r1':
                raise ValueError
        except (ValueError, TypeError, UnicodeError, IdentityError):
            raise IdentityError(f'{self.path} is malformed') from None
        return key, parsed['origin'], parsed['seq']

    def _save(self, key, origin, seq):
        from cryptography.hazmat.primitives import serialization
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode('ascii')
        data = {'version': FILE_VERSION, 'private_key': pem, 'origin': origin, 'seq': seq}
        self._write(self.name, json.dumps(data, indent=2).encode('ascii') + b'\n')

    def announce(self, origin):
        """Sign the current origin. A new key starts at 1; another origin than the saved one adds 1.

        The file is saved before the statement is used, so a sequence number
        never repeats for another origin, even after a crash.
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        origin = canonical_origin(origin)
        saved = self.load()
        if saved is None:
            key, seq, changed = ec.generate_private_key(ec.SECP256R1()), 1, True
        else:
            key, saved_origin, seq = saved
            changed = saved_origin != origin
            if changed:
                if seq >= MAX_SEQ:
                    raise IdentityError('the origin sequence number is exhausted')
                seq += 1
        if changed:
            self._save(key, origin, seq)
        return Identity(key, origin, seq, changed=changed)
