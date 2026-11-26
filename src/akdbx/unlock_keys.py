"""Unlock keys that the user brings to the private page.

Two keys can join the master password, or replace it in a vault that has none:

- A key file. The browser uploads it in the unlock form, over the same HTTPS
  connection as the password (TLS ends at the broker, also behind the relay).
  The broker keeps it only in memory for later saves, never on disk.
- A hardware key with HMAC-SHA1 challenge-response (``hardware_key``). The
  broker asks a key on its own computer, or the page brings the responses that
  the akdbx browser extension got from a key on the browsing computer. A
  response is a key secret and is treated like the password.

The KDBX 4 composite key with a hardware key is ``SHA-256(SHA-256(password) ||
key-file key || SHA-256(response))``, and the challenge is the KDF seed: the
format that KeePassXC and other KeePass apps write. PyKeePass hashes
``SHA-256(password) || key-file key``, so the broker gives it a key file in
memory whose key is ``key-file key || SHA-256(response)``. That key file
carries a marker: a vault opened with it keeps its KDF seed on save, because a
new seed would need a new touch of the key. Only KDBX 4 vaults with an Argon2
KDF are supported: a KDBX 3 (AES-KDF) vault mixes the response in another way.
"""
from __future__ import annotations

import base64
import hashlib
import io
import re
from dataclasses import dataclass
from pathlib import Path

KEYFILE_LIMIT = 1024 * 1024
RESPONSE_BYTES = 20
SEED_BYTES = 32
CHALLENGE_BYTES = 64
# The first bytes of the in-memory key file that carries a hardware key response.
MARKER = (b'<?xml version="1.0" encoding="UTF-8"?><KeyFile><Meta><Version>2.0</Version>'
          b'<Generator>akdbx challenge-response</Generator></Meta>')
_ARGON2 = {
    b'\xefcm\xdf\x8c)DK\x91\xf7\xa9\xa4\x03\xe3\n\x0c',  # Argon2d
    b'\x9e)\x8b\x19V\xdbGs\xb2=\xfc>\xc6\xf0\xa1\xe6',  # Argon2id
}
_HEX = re.compile(r'[0-9a-fA-F]+')
# A vault header is small; this bounds the page's read of it.
_HEADER_LIMIT = 1024 * 1024


class ChallengeChanged(Exception):
    """The vault's hardware-key challenge is not the one the page showed."""


# A key may have challenge-response on both slots, and a user may have several keys.
MAX_RESPONSES = 4


@dataclass(frozen=True)
class UnlockKeys:
    """Keys from the page: a key file's bytes and hardware key responses.

    ``responses`` came from a key on the browsing computer for ``challenge``;
    ``broker_key`` asks the key on the broker's own computer instead.
    """
    keyfile: bytes | None = None
    challenge: bytes | None = None
    responses: tuple[bytes, ...] = ()
    broker_key: bool = False

    @property
    def hardware(self) -> bool:
        return bool(self.responses) or self.broker_key

    def __repr__(self) -> str:  # Never show key material in a traceback or log.
        return (f'UnlockKeys(keyfile={self.keyfile is not None}, responses={len(self.responses)}, '
                f'broker_key={self.broker_key})')


def vault_challenge(encrypted: bytes) -> bytes | None:
    """The KDF seed that KeePassXC sends to the key, or None for an unsupported vault."""
    from pykeepass.kdbx_parsing.kdbx import KDBX
    try:
        header = KDBX.header.parse(encrypted).value
        if header.major_version < 4:
            return None
        parameters = header.dynamic_header.kdf_parameters.data.dict
        if parameters['$UUID'].value not in _ARGON2:
            return None
        seed = parameters['S'].value
    except Exception:
        return None
    return bytes(seed) if isinstance(seed, (bytes, bytearray)) and 0 < len(seed) <= CHALLENGE_BYTES else None


def read_challenge(database: Path) -> bytes | None:
    """The challenge of the vault file now, for the page; None when it has none."""
    if database is None:
        return None
    try:
        with open(database, 'rb') as stream:
            return vault_challenge(stream.read(_HEADER_LIMIT))
    except (OSError, ValueError, TypeError):
        return None


def parse_hex(text: str, size: int) -> bytes:
    """Exactly ``size`` bytes of hex; spaces are ignored. Raise ValueError otherwise."""
    text = ''.join(text.split())
    if len(text) != 2 * size or not _HEX.fullmatch(text):
        raise ValueError('invalid hex')
    return bytes.fromhex(text)


def keyfile_key(data: bytes) -> bytes:
    """The key of a key file, the same way PyKeePass and KeePassXC read it.

    The parser never loads a DTD, resolves an entity or uses the network: an
    uploaded key file comes from the page, and lxml before 5.0 resolves
    external entities by default.
    """
    from lxml import etree
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
    try:
        tree = etree.fromstring(data, parser)
        version = tree.find('Meta/Version').text
        element = tree.find('Key/Data')
        if version.startswith('1.0'):
            return base64.b64decode(element.text)
        if version.startswith('2.0'):
            key = bytes.fromhex(element.text.strip())
            if bytes.fromhex(element.attrib['Hash']) != hashlib.sha256(key).digest()[:4]:
                raise ValueError('key file has an invalid hash')
            return key
        raise AttributeError
    except (etree.XMLSyntaxError, UnicodeDecodeError, AttributeError, TypeError):
        pass  # Not a key file in XML (also one without key data): hashed like KeePassXC does.
    if len(data) == 32:
        return data
    # Hex only when all 64 bytes are hex digits, as KeePassXC checks. int(x, 16)
    # also accepts underscores and surrounding whitespace.
    if len(data) == 64 and not data.strip(b'0123456789abcdefABCDEF'):
        return bytes.fromhex(data.decode('ascii'))
    return hashlib.sha256(data).digest()


def key_material(keyfile: bytes | None, response: bytes | None) -> io.BytesIO | None:
    """The key file that PyKeePass opens the vault with, in memory.

    PyKeePass gets only a key file written here (XML 2.0 with the key that
    ``keyfile_key`` read), so it never parses the user's file itself.
    """
    if keyfile is None and response is None:
        return None
    key = keyfile_key(keyfile) if keyfile is not None else b''
    head = b'<?xml version="1.0" encoding="UTF-8"?><KeyFile><Meta><Version>2.0</Version></Meta>'
    if response is not None:
        key += hashlib.sha256(response).digest()
        head = MARKER
    check = hashlib.sha256(key).digest()[:4].hex().upper()
    return io.BytesIO(head + f'<Key><Data Hash="{check}">{key.hex().upper()}</Data></Key></KeyFile>'.encode('ascii'))


def open_with_keys(encrypted: bytes, password, key_bytes: bytes | None, keys: UnlockKeys | None, opener):
    """Open with each hardware key response in turn; one wrong set of keys is one failure.

    Raise ChallengeChanged when the page's responses answer another challenge,
    and ``hardware_key.HardwareKeyError`` when no key gives a response. Neither
    says anything about the password.
    """
    from pykeepass.exceptions import CredentialsError
    from . import hardware_key
    candidates = [None]
    if keys is not None and keys.hardware:
        seed = vault_challenge(encrypted)
        if keys.responses:
            if seed is None or keys.challenge != seed:
                raise ChallengeChanged
            candidates = list(keys.responses)
        elif seed is None:
            raise hardware_key.HardwareKeyError('this vault does not use a hardware key')
        else:
            candidates = hardware_key.responses(seed)[:MAX_RESPONSES]
    failure = None
    for response in candidates:
        try:
            return opener(encrypted, password, key_material(key_bytes, response))
        except CredentialsError as exc:
            failure = exc
    raise failure


def uses_hardware_key(keyfile) -> bool:
    """True for a vault opened with a hardware key response: its KDF seed must stay."""
    getvalue = getattr(keyfile, 'getvalue', None)
    return callable(getvalue) and getvalue().startswith(MARKER)
