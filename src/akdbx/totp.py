"""RFC 6238 TOTP. Setup keys and codes never belong in RPC responses."""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit


MAX_SETUP_LENGTH = 4096
MIN_VALIDITY = 8
ALGORITHMS = {'SHA1': hashlib.sha1, 'SHA256': hashlib.sha256, 'SHA512': hashlib.sha512}


class TotpError(ValueError):
    """Fixed messages only: parser and dependency errors can contain secrets."""


def capabilities():
    return dict(totp_supported=True, totp_protocol=1)


@dataclass(frozen=True)
class Configuration:
    secret: bytes = field(repr=False)
    algorithm: str = 'SHA1'
    digits: int = 6
    period: int = 30
    label: str = ''
    issuer: str = ''

    def uri(self):
        parameters = dict(secret=base64.b32encode(self.secret).decode('ascii').rstrip('='),
                          algorithm=self.algorithm, digits=str(self.digits), period=str(self.period))
        if self.issuer:
            parameters['issuer'] = self.issuer
        return 'otpauth://totp/' + quote(self.label, safe='') + '?' + urlencode(parameters)


def parse_setup(value, *, label=''):
    """Accept a Base32 key or a strict otpauth TOTP URI, never HOTP or migrations."""
    try:
        if not isinstance(value, str) or not 0 < len(value) <= MAX_SETUP_LENGTH:
            raise ValueError
        value = value.strip()
        parameters = {}
        issuer = ''
        if value.startswith('otpauth:'):
            if any(c.isspace() or ord(c) < 32 for c in value) or re.search(r'%(?![0-9a-fA-F]{2})', value):
                raise ValueError
            parsed = urlsplit(value)
            if parsed.scheme != 'otpauth' or parsed.netloc != 'totp' or not parsed.path.startswith('/') or parsed.fragment:
                raise ValueError
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, errors='strict')
            parameters = dict(pairs)
            if len(parameters) != len(pairs) or set(parameters) - {'secret', 'issuer', 'algorithm', 'digits', 'period'}:
                raise ValueError
            label = unquote(parsed.path[1:], errors='strict')
            issuer = parameters.get('issuer', '')
            if not label or any(ord(c) < 32 or ord(c) == 127 for c in label + issuer):
                raise ValueError
            if ':' in label and issuer and label.split(':', 1)[0] != issuer:
                raise ValueError
            value = parameters['secret']
        # Manual keys are often printed in space-separated groups. No other
        # punctuation, embedded control characters or non-ASCII is accepted.
        encoded = value.replace(' ', '').upper()
        if not re.fullmatch(r'[A-Z2-7]+={0,6}', encoded):
            raise ValueError
        unpadded = encoded.rstrip('=')
        padded = unpadded + '=' * (-len(unpadded) % 8)
        if '=' in encoded and encoded != padded:
            raise ValueError
        secret = base64.b32decode(padded)
        if not 10 <= len(secret) <= 128 or base64.b32encode(secret).decode('ascii').rstrip('=') != unpadded:
            raise ValueError
        algorithm = parameters.get('algorithm', 'SHA1')
        digits_text, period_text = parameters.get('digits', '6'), parameters.get('period', '30')
        if algorithm not in ALGORITHMS or digits_text not in {'6', '8'} or not re.fullmatch(r'[0-9]{1,3}', period_text):
            raise ValueError
        period = int(period_text)
        if not 15 <= period <= 120:
            raise ValueError
        configuration = Configuration(secret, algorithm, int(digits_text), period, label, issuer)
        if len(configuration.uri()) > MAX_SETUP_LENGTH:
            raise ValueError
        return configuration
    except Exception:
        raise TotpError('invalid TOTP setup; use a Base32 key or supported otpauth TOTP URI') from None


def configured(entry):
    """Expose presence only; malformed saved OTP data still fails on fill."""
    if getattr(entry, 'otp', None) is not None:
        return True
    element = getattr(entry, '_element', None)
    return element is not None and element.find('./String[Key="otp"]') is not None


def read_configuration(entry):
    value = getattr(entry, 'otp', None)
    if value is None:
        raise TotpError('no TOTP configuration on this entry; import it privately first')
    # KeePassXC's standard otp property uses an otpauth URI. Do not interpret
    # an arbitrary custom string or an unsupported legacy format as a key.
    if not isinstance(value, str) or not value.startswith('otpauth://totp/'):
        raise TotpError('unsupported saved TOTP configuration; import it privately again')
    return parse_setup(value)


def code_at(configuration, timestamp):
    if (isinstance(timestamp, bool) or not isinstance(timestamp, (int, float))
            or not math.isfinite(timestamp) or timestamp < 0):
        raise TotpError('invalid authenticator clock; no code filled')
    counter = int(timestamp // configuration.period)
    if counter >= 2**64:
        raise TotpError('invalid authenticator clock; no code filled')
    digest = hmac.new(configuration.secret, counter.to_bytes(8, 'big'), ALGORITHMS[configuration.algorithm]).digest()
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff
    return str(number % (10**configuration.digits)).zfill(configuration.digits)


def https_origin(url):
    # Validate before reading OTP data. This is a caller-supplied assertion,
    # not a DOM/origin attestation by the X11 transport.
    from .writes import site_origin
    try:
        # Python's IDNA 2003 codec can collapse distinct browser hostnames
        # (for example faß.test and fass.test). Require the browser's ASCII
        # URL spelling, including punycode for internationalized hostnames.
        if not isinstance(url, str) or not url.isascii() or len(url) > 4096 or '\\' in url or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
            raise ValueError
        result = site_origin(url)
        if result[0] != 'https':
            raise ValueError
        return result
    except Exception:
        raise TotpError('TOTP requires a verified ASCII HTTPS site URL without credentials') from None
