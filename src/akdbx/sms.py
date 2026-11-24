"""Phone verification texts: receive SMS codes and fill them without showing them.

A *source* is one phone number that forwards its texts to the broker: the
user's own phone (an iOS Shortcuts automation, ``shortcut``), a virtual number
(``twilio``), or any other service that can POST (``webhook``). Each source
has its own 256-bit webhook token. The broker keeps only the SHA-256 of a
token, in one private state file; the token itself appears only in the
private setup page or is typed straight into a pinned field.

An incoming text is reduced at once to a masked preview (no digits, no links)
and one verification code. A text without one unambiguous code is dropped
and never kept. Codes live only in memory, for MESSAGE_TTL seconds, and each
can be filled once. No command returns a code, a token or a message body.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import Path

PROTOCOL = 1
KINDS = ('shortcut', 'twilio', 'webhook')
MESSAGE_TTL = 600
SETUP_TTL = 3600  # one hour: setting up the iPhone automation takes a while
MAX_MESSAGES = 32
MAX_SOURCES = 16
MAX_WAIT = 300
MAX_WAITERS = 4
# Per source: more texts than this in one minute are refused (HTTP 429).
RATE_LIMIT = 20
MAX_TEXT = 2048
MAX_SENDER = 64
MAX_PREVIEW = 160
# 32 rows must fit one 64 KiB RPC reply, and JSON escapes a character outside
# the BMP as 12 bytes: preview and sender are also bounded in encoded bytes.
PREVIEW_BYTES = 960
SENDER_BYTES = 320
ROUTE_IN = '/sms/in/'
ROUTE_SETUP = '/sms/setup'
ROUTE_SETUP_WAIT = '/sms/setup/wait'
# Why the last text was kept or dropped; never text content.
RESULTS = ('code', 'empty', 'no-code-word', 'no-code', 'several-codes')
NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,31}')
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}')
MESSAGE_ID = re.compile(r'[0-9a-f]{32}')
STATE_LIMIT = 64 * 1024

# Words that mark a verification text, in the languages most services use.
KEYWORDS = re.compile(
    r'code|codice|c[oó]digo|kod|otp|pin\b|passcode|password|verif|confirm|'
    r'authenticat|sign[ -]?in|log[ -]?in|one[ -]time|security|2fa|token|'
    r'best[äa]tigung|verifica|v[ée]rification|pr[üu]f', re.IGNORECASE)
# 4 to 8 digits, alone or after a short prefix such as "G-"; or 3+3 / 4+4
# digits split by one space or hyphen ("123 456", "1234-5678").
_SPLIT = re.compile(r'(?<![0-9A-Za-z+])(\d{3,4})[ -](\d{3,4})(?![0-9A-Za-z])')
_SINGLE = re.compile(r'(?<![0-9+])(?<![0-9][.,:/-])(\d{4,8})(?![0-9])(?![.,:/-][0-9])(?!\s?%)')
# A link, also one written without a scheme ("example.com/t/AbC"): its digits
# are not a code and its letters can be a sign-in token.
_LINK = re.compile(r'(?:https?://|www\.)\S+|(?<![\w@.-])[a-z0-9](?:[a-z0-9-]*[a-z0-9])?'
                   r'(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}(?::\d+)?[/?#]\S*', re.IGNORECASE)
# A digit group right after these is a card or account suffix, a reference or
# an order number, not the code ("card ending 4321", "acct ****1234", "Ref: 5678").
_NOT_CODE_BEFORE = re.compile(
    r'(?<![a-z])(?:ending(?:\s+(?:in|with))?|ends?\s+(?:in|with)|last\s+(?:\d+\s+)?(?:digits?)?|card|account|acct|a/c|'
    r'ref(?:erence)?|order|booking|invoice|ticket|[*x•#]{2,}|\*)\s*(?:no\.?|number|#)?\s*[:#.]?\s*$',
    re.IGNORECASE)
_CURRENCY = r'(?:€|\$|£|¥|₹|(?<![a-z])(?:eur|usd|gbp|chf|inr|rs\.?|kr|sek|nok|dkk|pln|zł|aud|cad))'
_AMOUNT_BEFORE = re.compile(_CURRENCY + r'\s?$', re.IGNORECASE)
_AMOUNT_AFTER = re.compile(r'^\s?' + _CURRENCY + r'(?![a-z])', re.IGNORECASE)
# A four-digit year only in date context ("(c) 2026", "May 2025").
_YEAR_BEFORE = re.compile(
    r'(?:©|\(c\)|(?<![a-z])(?:copyright|jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|'
    r'sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|year))\.?\s*\d{0,2}(?:st|nd|rd|th)?,?\s*$',
    re.IGNORECASE)
_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f​-‏ -‮⁦-⁩]')


class SmsError(Exception):
    """A refused SMS request; the message is safe to return."""


def capabilities(configured: int) -> dict:
    return dict(sms_protocol=PROTOCOL, sms_source_kinds=list(KINDS), sms_sources_configured=configured,
                sms_message_ttl=MESSAGE_TTL)


def _normal(text: str) -> str:
    return _CONTROL.sub(' ', unicodedata.normalize('NFKC', text))


def extract(text: object) -> tuple[str | None, str]:
    """The one verification code in a text and why: (code, 'code'), or (None, reason).

    Reasons: 'empty', 'no-code-word', 'no-code' (no 4-8 digit group) and
    'several-codes' (a tie between digit groups). They hold no text content.

    A text needs a verification word (code, OTP, verify ...). Links are
    ignored, and so are card or account suffixes, references, amounts and
    dated years. With several digit groups left, the one nearest a
    verification word wins; a tie is ambiguous and gives None.
    """
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT:
        return None, 'empty'
    text = _LINK.sub(' ', _normal(text))
    keywords = [m.start() for m in KEYWORDS.finditer(text)]
    if not keywords:
        return None, 'no-code-word'
    found: list[tuple[str, int, int]] = []  # every digit group: (digits, start, end)
    for match in _SPLIT.finditer(text):
        digits = match.group(1) + match.group(2)
        if 6 <= len(digits) <= 8:
            found.append((digits, *match.span()))
    for match in _SINGLE.finditer(text):
        if not any(start <= match.start() < end for _, start, end in found):
            found.append((match.group(1), *match.span()))
    candidates: dict[str, int] = {}
    for digits, start, end in sorted(found, key=lambda group: group[1]):
        # Judge each occurrence on its own context, so a reference with the
        # same digits as the labelled code does not remove the code.
        before, after = text[max(0, start - 32):start], text[end:end + 6]
        year = len(digits) == 4 and digits[:2] in {'19', '20'} and _YEAR_BEFORE.search(before)
        if not (year or _NOT_CODE_BEFORE.search(before) or _AMOUNT_BEFORE.search(before)
                or _AMOUNT_AFTER.search(after)):
            candidates.setdefault(digits, start)
    if not candidates:
        return None, 'no-code'
    if len(candidates) == 1:
        return next(iter(candidates)), 'code'
    distance = {code: min(abs(position - k) for k in keywords) for code, position in candidates.items()}
    best = min(distance.values())
    winners = [code for code, d in distance.items() if d == best]
    return (winners[0], 'code') if len(winners) == 1 else (None, 'several-codes')


def extract_code(text: object) -> str | None:
    """The one verification code in a text, or None when there is not exactly one."""
    return extract(text)[0]


def _fit(text: str, characters: int, encoded: int) -> str:
    """``text`` cut to ``characters`` and to ``encoded`` bytes of JSON (ASCII escapes), with an ellipsis."""
    if len(text) <= characters and len(json.dumps(text)) <= encoded:
        return text
    cut = text[:characters - 1]
    while cut and len(json.dumps(cut + '…')) > encoded:
        cut = cut[:-1]
    return cut + '…'


def mask(text: str) -> str:
    """A preview with every digit and link replaced; safe to show the agent."""
    text = _LINK.sub('[link]', _normal(text))
    text = re.sub(r'\d', '•', text)
    return _fit(' '.join(text.split()), MAX_PREVIEW, PREVIEW_BYTES)


def clean_sender(value: object, code: str | None = None) -> str:
    """The sender, cut to size; masked like the text when it carries ``code`` (a miswired "from")."""
    if not isinstance(value, str):
        return ''
    value = ' '.join(_normal(value).split())
    if code and code in re.sub(r'\D', '', value):
        return _fit(mask(value), MAX_SENDER, SENDER_BYTES)
    return _fit(value, MAX_SENDER, SENDER_BYTES)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def _iso(seconds: float) -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(seconds))


@dataclass
class Source:
    name: str
    kind: str
    token_sha256: str
    created: str
    received: list[float] = field(default_factory=list)  # monotonic arrival times, last minute only
    last_received: str | None = None
    # In memory only: the last text's extraction result (no content) and how
    # many texts arrived since the broker started.
    last_result: str | None = None
    count: int = 0


@dataclass
class Message:
    id: str
    source: str
    sender: str
    preview: str
    code: str
    arrived: float  # monotonic
    received_at: float  # wall clock

    def metadata(self, now: float) -> dict:
        return dict(id=self.id, source=self.source, sender=self.sender, preview=self.preview,
                    code_length=len(self.code), received_at=_iso(self.received_at),
                    age_seconds=max(0, int(now - self.arrived)))


@dataclass
class Setup:
    source: str
    kind: str
    token: str | None  # None: a test page, which never shows the webhook URL
    token_sha256: str
    expires: float


class SmsInbox:
    """Sources (durable, hashed tokens) and received codes (memory only)."""

    def __init__(self, state_path: Path | None, *, clock=time.monotonic, wall_clock=time.time) -> None:
        self.path = Path(state_path) if state_path is not None else None
        self.clock, self.wall_clock = clock, wall_clock
        self.sources: dict[str, Source] = {}
        self.messages: list[Message] = []
        self.setups: dict[str, Setup] = {}
        self.waiters = 0
        self.condition = threading.Condition()
        # Called with (source, message_id) after a text with a code is kept;
        # the broker sets it to wake SMS webhook subscriptions.
        self.on_text = None
        self._load()

    # Private state file -------------------------------------------------

    def _directory(self) -> int:
        from .runtime import prepare_private_runtime_directory
        assert self.path is not None
        if not self.path.is_absolute() or self.path.name in {'', '.', '..'}:
            raise ValueError('invalid SMS source state path')
        for folder in reversed(self.path.parent.parents):
            try:
                os.mkdir(folder, 0o700)
            except FileExistsError:
                pass
        return prepare_private_runtime_directory(self.path.parent)[1]

    def _read(self) -> bytes | None:
        if os.name == 'nt':
            from . import windows_security
            if not self.path.parent.exists():
                return None
            windows_security.ensure_private_directory(self.path.parent)
            return windows_security.read_private_optional(self.path, limit=STATE_LIMIT)
        if not os.path.lexists(self.path):
            return None  # Nothing saved yet: create and check no folder until a save.
        directory = self._directory()
        try:
            try:
                fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError:
                return None
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > STATE_LIMIT):
                    raise ValueError('invalid SMS source state')
                return os.read(fd, STATE_LIMIT + 1)
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    def _load(self) -> None:
        if self.path is None:
            return
        raw = self._read()
        if raw is None:
            return
        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('sources'), list):
                raise ValueError
            for row in data['sources'][:MAX_SOURCES]:
                name, kind, digest, created = row['name'], row['kind'], row['token_sha256'], row['created']
                if (not isinstance(name, str) or not NAME.fullmatch(name) or kind not in KINDS
                        or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)
                        or not isinstance(created, str) or len(created) > 32 or name in self.sources):
                    raise ValueError
                last = row.get('last_received')
                if last is not None and (not isinstance(last, str) or len(last) > 32):
                    raise ValueError
                self.sources[name] = Source(name, kind, digest, created, last_received=last)
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            raise ValueError('invalid SMS source state') from None

    def _save(self) -> None:
        if self.path is None:
            return
        data = json.dumps(dict(version=1, sources=[
            dict(name=s.name, kind=s.kind, token_sha256=s.token_sha256, created=s.created,
                 **({'last_received': s.last_received} if s.last_received else {}))
            for s in self.sources.values()]), sort_keys=True).encode()
        if os.name == 'nt':
            from . import windows_security
            windows_security.ensure_private_directory(self.path.parent)
            windows_security.replace_private(self.path, data)
            return
        directory = self._directory()
        name = '.sms-sources-' + uuid.uuid4().hex
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)

    # Sources -----------------------------------------------------------

    def capabilities(self) -> dict:
        with self.condition:
            return capabilities(len(self.sources))

    def prune(self) -> None:
        """Drop expired texts and setup pages; the private server calls it when idle."""
        with self.condition:
            self._prune()

    def _prune(self) -> None:
        now = self.clock()
        self.messages = [m for m in self.messages if now - m.arrived < MESSAGE_TTL]
        for key, setup in list(self.setups.items()):
            if setup.expires <= now:
                del self.setups[key]

    def add_source(self, name: object, kind: object, *, replace: bool = False) -> str:
        """Create (or with ``replace`` rotate) a source; return its new webhook token."""
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise SmsError('source name must be 1-32 lowercase letters, digits or hyphens')
        if kind not in KINDS:
            raise SmsError('source kind must be one of: ' + ', '.join(KINDS))
        if self.path is None:
            raise SmsError('this broker has no SMS source state file')
        token = secrets.token_urlsafe(32)
        with self.condition:
            if name in self.sources and not replace:
                raise SmsError('source exists; use replace to issue a new webhook URL')
            if name not in self.sources and len(self.sources) >= MAX_SOURCES:
                raise SmsError(f'at most {MAX_SOURCES} SMS sources')
            previous = self.sources.get(name)
            self.sources[name] = Source(name, kind, _hash(token), _iso(self.wall_clock()))
            try:
                self._save()
            except Exception:
                if previous is None:
                    del self.sources[name]
                else:
                    self.sources[name] = previous
                raise SmsError('SMS source not saved; nothing changed') from None
            # A rotated source invalidates its earlier setup pages.
            for key, setup in list(self.setups.items()):
                if setup.source == name:
                    del self.setups[key]
        return token

    def remove_source(self, name: object) -> bool:
        with self.condition:
            if not isinstance(name, str) or name not in self.sources:
                return False
            previous = self.sources.pop(name)
            try:
                self._save()
            except Exception:
                self.sources[name] = previous
                raise SmsError('SMS source not removed; nothing changed') from None
            self.messages = [m for m in self.messages if m.source != name]
            for key, setup in list(self.setups.items()):
                if setup.source == name:
                    del self.setups[key]
            return True

    def list_sources(self) -> list[dict]:
        with self.condition:
            return [dict(name=s.name, kind=s.kind, created=s.created,
                         **({'last_received': s.last_received} if s.last_received else {}),
                         **({'last_result': s.last_result} if s.last_result else {}))
                    for s in self.sources.values()]

    def new_setup(self, name: str, token: str) -> str:
        """A private setup-page token that shows this source's webhook URL until it expires."""
        key = secrets.token_urlsafe(32)
        with self.condition:
            self._prune()
            source = self.sources.get(name)
            if source is None or not hmac.compare_digest(source.token_sha256, _hash(token)):
                raise SmsError('unknown SMS source')
            self.setups[key] = Setup(name, source.kind, token, source.token_sha256, self.clock() + SETUP_TTL)
        return key

    def new_test_page(self, name: object) -> str:
        """A private page with only the live test step for a source; it never shows the webhook URL."""
        key = secrets.token_urlsafe(32)
        with self.condition:
            self._prune()
            source = self.sources.get(name) if isinstance(name, str) else None
            if source is None:
                raise SmsError('unknown SMS source')
            self.setups[key] = Setup(name, source.kind, None, source.token_sha256, self.clock() + SETUP_TTL)
        return key

    def setup(self, key: object) -> Setup | None:
        if not isinstance(key, str) or not TOKEN.fullmatch(key):
            return None
        with self.condition:
            self._prune()
            setup = self.setups.get(key)
            source = self.sources.get(setup.source) if setup is not None else None
            if setup is None or source is None or source.token_sha256 != setup.token_sha256:
                return None
            return setup

    def setup_status(self, key: object, after: object = None, timeout: float = 0) -> dict | None:
        """For a setup page's live test: the source's text count and last result.

        Waits up to ``timeout`` seconds for a text after count ``after``. None
        when the setup page is not valid. It never returns text content.
        """
        if not self.setup(key):
            return None
        deadline = self.clock() + max(0.0, min(float(timeout), 10.0))
        with self.condition:
            while True:
                setup = self.setups.get(key)
                source = self.sources.get(setup.source) if setup is not None else None
                if source is None or source.token_sha256 != setup.token_sha256:
                    return None
                if not isinstance(after, int) or source.count > after:
                    return dict(count=source.count, result=source.last_result)
                remaining = deadline - self.clock()
                if remaining <= 0:
                    return dict(count=source.count, result=source.last_result)
                self.condition.wait(remaining)

    # Messages ------------------------------------------------------------

    def source_for(self, token: object) -> Source | None:
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            return None
        digest = _hash(token)
        found = None
        with self.condition:
            for source in self.sources.values():
                if hmac.compare_digest(source.token_sha256, digest):
                    found = source
        return found

    def receive(self, token: object, sender: object, text: object) -> str:
        """Accept one forwarded text: 'kept', 'dropped', 'limited' or 'unknown'."""
        source = self.source_for(token)
        if source is None:
            return 'unknown'
        now = self.clock()
        with self.condition:
            source.received = [t for t in source.received if now - t < 60]
            if len(source.received) >= RATE_LIMIT:
                return 'limited'
            source.received.append(now)
            source.last_received = _iso(self.wall_clock())
            code, source.last_result = extract(text)
            source.count += 1
            self.condition.notify_all()
            if code is None:
                return 'dropped'
            self._prune()
            message = Message(secrets.token_hex(16), source.name, clean_sender(sender, code), mask(text), code, now,
                              self.wall_clock())
            self.messages.append(message)
            del self.messages[:-MAX_MESSAGES]
            self.condition.notify_all()
        if self.on_text is not None:
            try:
                self.on_text(message.source, message.id)
            except Exception:
                pass  # A notification failure never drops a received text.
        return 'kept'

    def newest(self, source: str | None, since: float) -> tuple[str, str] | None:
        """The newest kept text received at or after ``since``: (source, message id), or None."""
        with self.condition:
            self._prune()
            found = self._matching(since, source)
            return (found[-1].source, found[-1].id) if found else None

    def _matching(self, since: float | None, source: str | None) -> list[Message]:
        return [m for m in self.messages
                if (since is None or m.received_at >= since) and (source is None or m.source == source)]

    def wait(self, *, since: object = None, source: object = None, timeout: object = 0, ready=lambda: True) -> list[dict]:
        """Codes received at or after ``since`` (wall-clock seconds), newest first.

        With a timeout, wait up to that many seconds for the first one. This is
        an event wait on the inbox, not a poll of any outside service.
        """
        if since is not None and (isinstance(since, bool) or not isinstance(since, (int, float))):
            raise SmsError('since must be a Unix time in seconds')
        if source is not None and (not isinstance(source, str) or not NAME.fullmatch(source)):
            raise SmsError('unknown SMS source')
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 <= timeout <= MAX_WAIT:
            raise SmsError(f'timeout must be 0-{MAX_WAIT} seconds')
        deadline = self.clock() + timeout
        with self.condition:
            if source is not None and source not in self.sources:
                raise SmsError('unknown SMS source')
            if timeout and self.waiters >= MAX_WAITERS:
                raise SmsError('too many SMS waits; try again later')
            self.waiters += 1
            try:
                while True:
                    self._prune()
                    found = self._matching(since, source)
                    remaining = deadline - self.clock()
                    if found or remaining <= 0 or not ready():
                        break
                    self.condition.wait(min(remaining, 1.0))
            finally:
                self.waiters -= 1
            now = self.clock()
            return [m.metadata(now) for m in sorted(found, key=lambda m: m.arrived, reverse=True)]

    def restore(self, message: Message) -> None:
        """Put back a message whose fill never started, unless it has expired."""
        with self.condition:
            if self.clock() - message.arrived < MESSAGE_TTL and all(m.id != message.id for m in self.messages):
                self.messages.append(message)
                self.messages.sort(key=lambda m: m.arrived)

    def take(self, message_id: object) -> Message:
        """Remove and return one unexpired message; each code is used once."""
        if not isinstance(message_id, str) or not MESSAGE_ID.fullmatch(message_id):
            raise SmsError('unknown or expired SMS message')
        with self.condition:
            self._prune()
            for index, message in enumerate(self.messages):
                if message.id == message_id:
                    return self.messages.pop(index)
        raise SmsError('unknown or expired SMS message')


def webhook_url(origin: str, token: str) -> str:
    return origin.rstrip('/') + ROUTE_IN + token


# Broker actions ----------------------------------------------------------

COMMANDS = ('sms-add-source', 'sms-remove-source', 'sms-sources', 'sms-wait', 'pin-code-target', 'fill-sms-code',
            'subscribe-sms', 'sms-subscription-status', 'unsubscribe-sms', 'sms-test-page')
FILL_START_TIMEOUT = 4.0


def _failure(started=False, *, kind='code'):
    from .browser_card import failure
    return failure(started, kind=kind)


def _https_url(value: object) -> bool:
    from urllib.parse import urlsplit
    if not isinstance(value, str) or len(value) > 4096:
        return False
    parts = urlsplit(value)
    return parts.scheme == 'https' and bool(parts.hostname) and parts.username is None and parts.password is None


def dispatch(broker, request: dict, delivery_ready) -> dict:
    """SMS actions of an unlocked broker. Responses never hold a code, token or body."""
    action = request.get('action')
    inbox: SmsInbox = broker.sms
    if type(request.get('sms_protocol')) is not int or request['sms_protocol'] != PROTOCOL:
        return dict(ok=False, error='SMS protocol 1 required')
    try:
        if action == 'sms-sources':
            if set(request) != {'action', 'sms_protocol'}:
                raise SmsError('invalid SMS request')
            return dict(ok=True, sources=inbox.list_sources())
        if action == 'sms-remove-source':
            if set(request) != {'action', 'sms_protocol', 'name'}:
                raise SmsError('invalid SMS request')
            return dict(ok=True, removed=inbox.remove_source(request['name']))
        if action == 'sms-add-source':
            return _add_source(broker, request, delivery_ready)
        if action == 'sms-wait':
            if set(request) - {'action', 'sms_protocol', 'since', 'source', 'timeout'}:
                raise SmsError('invalid SMS request')
            return dict(ok=True, messages=inbox.wait(since=request.get('since'), source=request.get('source'),
                                                     timeout=request.get('timeout', 0), ready=delivery_ready))
        if action == 'pin-code-target':
            from . import browser_slots
            from .browser_card import CardTargetError
            from .browser_slots import SlotError
            try:
                pin = {k: v for k, v in request.items() if k != 'sms_protocol'}
                return broker.code_targets.pin({**pin, 'code_protocol': 1})
            except SlotError as exc:
                return dict(ok=False, error=str(exc))
            except (CardTargetError, Exception):
                return _failure()
        if action == 'fill-sms-code':
            return _fill(broker, request, delivery_ready)
        if action == 'subscribe-sms':
            # Under the inbox lock a text kept now is either found by the lookup
            # or published after the subscription exists: none falls between.
            with inbox.condition:
                return broker.sms_notifications.subscribe_text(request, received=inbox.newest)
        if action == 'sms-test-page':
            if set(request) != {'action', 'sms_protocol', 'name'}:
                raise SmsError('invalid SMS request')
            origin = getattr(getattr(broker, 'unlock_link', None), 'origin', None)
            if not isinstance(origin, str) or not origin.startswith('https://'):
                raise SmsError('this broker has no HTTPS private page origin')
            key = inbox.new_test_page(request['name'])
            return dict(ok=True, name=request['name'], private_url=origin + ROUTE_SETUP + '?token=' + key)
        if action in {'sms-subscription-status', 'unsubscribe-sms'}:
            if set(request) != {'action', 'sms_protocol', 'subscription_id'}:
                raise SmsError('invalid SMS request')
            return broker.sms_notifications.status(request['subscription_id'], cancel=action == 'unsubscribe-sms')
    except SmsError as exc:
        return dict(ok=False, error=str(exc))
    return dict(ok=False, error='unknown action')


def _consume_target(broker, request):
    """A DOM code pin, or an X11 pin-target pin. Either way the token is spent."""
    from .browser_card import CardTargetError
    token = request.get('target')
    try:
        return 'dom', broker.code_targets.consume(token)
    except CardTargetError:
        pass
    return 'x11', broker.targets.consume({'target': token, 'target_protocol': request.get('target_protocol')})


def _deadline(broker, request):
    deadline = request.get('start_deadline')
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not broker.clock() < deadline <= broker.clock() + FILL_START_TIMEOUT):
        raise SmsError('autofill not started: request expired')
    return deadline


def _deliver(broker, route, pin, value, field, ready, deadline):
    """Type ``value`` through the pinned DOM field or X11 window; a fill receipt."""
    from .target import DELIVERY as X11_DELIVERY, DeliveryError
    if route == 'dom':
        try:
            return broker.code_targets.fill(pin, value, field, ready, deadline)
        finally:
            broker.code_targets._close(pin)
    remaining = deadline - broker.clock()
    if remaining <= 0 or not broker._keyboard_lock.acquire(timeout=remaining):
        return dict(ok=False, error='autofill not started: request expired')
    try:
        if not ready():
            return dict(ok=False, error='autofill not started: request expired')
        broker.typer.deliver(pin, [value], ready)
        return dict(ok=True, filled=field, target_delivery=X11_DELIVERY)
    except DeliveryError as exc:
        from .target import failure
        return failure(exc.started)
    finally:
        broker._keyboard_lock.release()


def _add_source(broker, request, delivery_ready):
    allowed = {'action', 'sms_protocol', 'name', 'kind', 'replace'}
    has_target = 'target' in request
    if has_target:
        allowed |= {'target', 'target_protocol', 'start_deadline'}
    if set(request) - allowed or type(request.get('replace', False)) is not bool:
        raise SmsError('invalid SMS request')
    origin = getattr(getattr(broker, 'unlock_link', None), 'origin', None)
    if not isinstance(origin, str) or not origin.startswith('https://'):
        raise SmsError('this broker has no HTTPS private page origin')
    route = pin = None
    if has_target:
        # Spend the pin first: a refused request never leaves it usable.
        try:
            route, pin = _consume_target(broker, request)
        except Exception:
            return _failure()
        if route != 'dom' or pin['field'] != 'webhook-url':
            if route == 'dom':
                broker.code_targets._close(pin)
            return _failure()
    try:
        token = inbox_token = broker.sms.add_source(request.get('name'), request.get('kind'),
                                                    replace=request.get('replace', False))
    except BaseException:
        if pin is not None:
            broker.code_targets._close(pin)
        raise
    receipt = dict(ok=True, name=request['name'], kind=request['kind'])
    if not has_target:
        key = broker.sms.new_setup(request['name'], inbox_token)
        return dict(receipt, private_url=origin + ROUTE_SETUP + '?token=' + key)
    try:
        deadline = _deadline(broker, request)
    except SmsError:
        broker.code_targets._close(pin)
        return dict(receipt, **_failure(), private_url=origin + ROUTE_SETUP + '?token=' + broker.sms.new_setup(request['name'], token))
    result = _deliver(broker, route, pin, webhook_url(origin, token), 'webhook-url',
                      lambda: delivery_ready() and broker.clock() < deadline, deadline)
    if not result.get('ok'):
        # The source exists; its setup page is the fallback.
        result = dict(result, private_url=origin + ROUTE_SETUP + '?token=' + broker.sms.new_setup(request['name'], token))
    return dict(receipt, **result)


def _fill(broker, request, delivery_ready):
    allowed = {'action', 'sms_protocol', 'message', 'target', 'target_protocol', 'target_url', 'start_deadline'}
    if set(request) - allowed:
        raise SmsError('invalid SMS request')
    # The target pin is single use, even when the message is invalid. The
    # message returns to the inbox when no key or value was sent.
    try:
        message = broker.sms.take(request.get('message'))
    except SmsError:
        message = None
    try:
        route, pin = _consume_target(broker, request)
    except Exception:
        if message is not None:
            broker.sms.restore(message)
            return _failure()
        return dict(ok=False, error='unknown or expired SMS message')
    close = (lambda: broker.code_targets._close(pin)) if route == 'dom' else (lambda: None)
    if message is None:
        close()
        return dict(ok=False, error='unknown or expired SMS message')
    refusal = None
    if route == 'x11' and not _https_url(request.get('target_url')):
        refusal = dict(ok=False, error='autofill not started: X11 code fill needs --target-url')
    elif route == 'dom' and pin['field'] != 'one-time-code':
        refusal = _failure()
    else:
        try:
            deadline = _deadline(broker, request)
        except SmsError as exc:
            refusal = dict(ok=False, error=str(exc))
    if refusal is not None:
        close()
        broker.sms.restore(message)
        return refusal
    ready = lambda: delivery_ready() and broker.clock() < deadline
    try:
        result = _deliver(broker, route, pin, message.code, 'one-time-code', ready, deadline)
    except Exception:
        return dict(ok=False, error='code fill outcome uncertain; do not retry automatically')
    if not result.get('ok') and 'not started' in str(result.get('error', '')):
        broker.sms.restore(message)
    return result
