"""Bounded Google offline migration decoding. Never log payloads or parser errors.

The protobuf wire layout is intentionally parsed here without generated message
reprs (which would include secrets). Unknown fields, HOTP and unsupported enums
fail closed. No changes to the website or source authenticator are made.
"""
from __future__ import annotations

import base64
from urllib.parse import parse_qsl, urlsplit

from .totp import Configuration, TotpError, parse_setup

MAX_FRAMES = 8
MAX_ACCOUNTS = 32
MAX_FRAME = 8192
MAX_IMPORT = 32768


def _varint(data, pos):
    """Read one bounded unsigned 64-bit protobuf varint and return its next offset.

    Raise ValueError for truncation, overflow or an unterminated encoding.
    """
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise ValueError
        byte = data[pos]
        pos += 1
        if shift == 63 and byte > 1:
            raise ValueError
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise ValueError


def _fields(data, schema, repeated=()):
    """Decode only the supplied varint/length-delimited schema into private values.

    Reject unknown tags, wire mismatches, duplicate singular fields, truncated
    values and excessive repetitions. Diagnostics must not expose decoded keys.
    """
    result = {}
    pos = 0
    while pos < len(data):
        tag, pos = _varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if schema.get(number) != wire or number in result and number not in repeated:
            raise ValueError
        if wire == 0:
            value, pos = _varint(data, pos)
        else:
            size, pos = _varint(data, pos)
            if size > len(data) - pos:
                raise ValueError
            value, pos = data[pos:pos + size], pos + size
        if number in repeated:
            result.setdefault(number, []).append(value)
            if len(result[number]) > MAX_ACCOUNTS:
                raise ValueError
        else:
            result[number] = value
    return result


def _configuration(data):
    """Convert one migration record to a validated TOTP-only configuration.

    Reject HOTP, nonzero counters and unsupported algorithm/digit enums. Decode
    labels strictly as UTF-8 and reuse ordinary seed and URI validation. The
    result contains a secret and must remain inside the private workflow.
    """
    fields = _fields(data, {1: 2, 2: 2, 3: 2, 4: 0, 5: 0, 6: 0, 7: 0})
    if fields.get(6) != 2 or fields.get(7, 0) != 0:
        raise ValueError  # TOTP only, never silently convert HOTP.
    algorithm = {1: 'SHA1', 2: 'SHA256', 3: 'SHA512'}[fields[4]]
    digits = {1: 6, 2: 8}[fields[5]]
    label = fields.get(2, b'').decode('utf-8', errors='strict')
    issuer = fields.get(3, b'').decode('utf-8', errors='strict')
    if not label or len(label) > 512 or len(issuer) > 512:
        raise ValueError
    config = Configuration(fields[1], algorithm, digits, 30, label, issuer)
    # Reuse all ordinary seed-size, label and parameter validation.
    return parse_setup(config.uri())


def parse_import(payloads, *, label=''):
    """Decode bounded private keys/URIs or one complete Google migration batch.

    Accept 1..8 frames, up to 8192 characters each and 32768 in total, yielding
    1..32 accounts. Require consistent batch identity, every unique part and
    unique issuer/label pairs. A single ordinary setup uses parse_setup instead.
    Return secret-bearing configurations only to private callers; all parsing
    failures become a fixed TotpError without payload or decoder diagnostics.
    """
    try:
        if (not isinstance(payloads, list) or not 1 <= len(payloads) <= MAX_FRAMES
                or any(not isinstance(p, str) or not 0 < len(p) <= MAX_FRAME for p in payloads)
                or sum(len(p) for p in payloads) > MAX_IMPORT):
            raise ValueError
        if len(payloads) == 1 and not payloads[0].startswith('otpauth-migration:'):
            return (parse_setup(payloads[0], label=label),)
        parts = {}
        batch = None
        for payload in payloads:
            parsed = urlsplit(payload)
            pairs = parse_qsl(parsed.query, strict_parsing=True)
            if (parsed.scheme != 'otpauth-migration' or parsed.netloc != 'offline'
                    or parsed.path not in {'', '/'} or parsed.fragment
                    or len(pairs) != 1 or pairs[0][0] != 'data'):
                raise ValueError
            encoded = pairs[0][1]
            raw = base64.b64decode(encoded + '=' * (-len(encoded) % 4), validate=True)
            frame = _fields(raw, {1: 2, 2: 0, 3: 0, 4: 0, 5: 0}, (1,))
            if frame.get(2) != 1:
                raise ValueError
            size, index = frame.get(3, 1), frame.get(4, 0)
            if not 1 <= size <= MAX_FRAMES or not 0 <= index < size:
                raise ValueError
            identity = (size, frame.get(5, 0))
            if batch is not None and batch != identity or index in parts:
                raise ValueError
            batch = identity
            parts[index] = tuple(_configuration(entry) for entry in frame.get(1, []))
        if batch is None or set(parts) != set(range(batch[0])):
            raise ValueError
        configs = tuple(c for index in sorted(parts) for c in parts[index])
        if not 1 <= len(configs) <= MAX_ACCOUNTS:
            raise ValueError
        # Duplicate records may be confusing even if the keys happen to agree.
        labels = [(c.issuer, c.label) for c in configs]
        if len(set(labels)) != len(labels):
            raise ValueError
        return configs
    except Exception:
        raise TotpError('import rejected; use supported TOTP keys or one complete Google export batch') from None
