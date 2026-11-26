"""Unlock keys that the user brings to the private page.

Two keys can join the master password:

- A key file. The browser uploads it in the unlock form, over the same HTTPS
  connection as the password (TLS ends at the broker, also behind the relay).
  The broker keeps it only in memory for later saves, never on disk.
- A hardware key: KeePassXC's YubiKey HMAC-SHA1 challenge-response. Browsers
  cannot reach that slot of the key, so the page shows the vault's challenge,
  the user computes the response on a computer with the key (``ykman otp
  calculate``) and pastes it into the page. The response is a key secret and
  is treated like the password.

KeePassXC's KDBX 4 composite key is ``SHA-256(SHA-256(password) || key-file
key || SHA-256(response))``, and the challenge is the KDF seed. PyKeePass hashes
``SHA-256(password) || key-file key``, so the broker gives it a key file in
memory whose key is ``key-file key || SHA-256(response)``. That key file carries
a marker: a vault opened with it keeps its KDF seed on save, because a new
seed would need a new touch of the hardware key (the broker keeps the
response, not the key). Only KDBX 4 vaults with an Argon2 KDF are supported:
KeePassXC mixes a KDBX 3 (AES-KDF) response in another way.
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


@dataclass(frozen=True)
class UnlockKeys:
    """Keys from the page: a key file's bytes and a hardware key response."""
    keyfile: bytes | None = None
    challenge: bytes | None = None
    response: bytes | None = None

    def __repr__(self) -> str:  # Never show key material in a traceback or log.
        return (f'UnlockKeys(keyfile={self.keyfile is not None}, '
                f'response={self.response is not None})')


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


def padded_challenge(seed: bytes) -> bytes:
    """The 64 bytes KeePassXC sends to the key: the seed with PKCS #7 padding."""
    pad = CHALLENGE_BYTES - len(seed)
    return seed + bytes([pad]) * pad


def parse_hex(text: str, size: int) -> bytes:
    """Exactly ``size`` bytes of hex; spaces are ignored. Raise ValueError otherwise."""
    text = ''.join(text.split())
    if len(text) != 2 * size or not _HEX.fullmatch(text):
        raise ValueError('invalid hex')
    return bytes.fromhex(text)


def keyfile_key(data: bytes) -> bytes:
    """The key of a key file, the same way PyKeePass and KeePassXC read it."""
    from lxml import etree
    try:
        tree = etree.fromstring(data)
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
    except (etree.XMLSyntaxError, UnicodeDecodeError, AttributeError):
        pass
    try:
        int(data, 16)
        is_hex = True
    except ValueError:
        is_hex = False
    if len(data) == 32:
        return data
    if len(data) == 64 and is_hex:
        return bytes.fromhex(data.decode('ascii'))
    return hashlib.sha256(data).digest()


def key_material(keyfile: bytes | None, response: bytes | None) -> io.BytesIO | None:
    """The key file that PyKeePass opens the vault with, in memory."""
    if response is None:
        return io.BytesIO(keyfile) if keyfile is not None else None
    key = (keyfile_key(keyfile) if keyfile is not None else b'') + hashlib.sha256(response).digest()
    check = hashlib.sha256(key).digest()[:4].hex().upper()
    return io.BytesIO(MARKER + f'<Key><Data Hash="{check}">{key.hex().upper()}</Data></Key></KeyFile>'.encode('ascii'))


def check_challenge(encrypted: bytes, keys: UnlockKeys) -> None:
    """Raise ChallengeChanged unless the response answers this vault file's challenge."""
    if keys.response is None:
        return
    current = vault_challenge(encrypted)
    if current is None or keys.challenge is None or current != keys.challenge:
        raise ChallengeChanged


def uses_hardware_key(keyfile) -> bool:
    """True for a vault opened with a hardware key response: its KDF seed must stay."""
    getvalue = getattr(keyfile, 'getvalue', None)
    return callable(getvalue) and getvalue().startswith(MARKER)
