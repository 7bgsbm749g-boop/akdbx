"""Browser-extension fill route: broker -> native-messaging host -> extension -> DOM.

This is a second delivery route next to the Chrome DevTools Protocol (CDP)
route. It lets the user's everyday browser stay free of a remote-debugging
port, which would give every process of the same user full control of that
profile. It is not a way to hide automation from a website.

Two callers use it:

* agents and the CLI: ``list-password-frames``, ``pin-*-target`` and the fill
  commands with ``--route extension``. The model is the CDP model: the browser
  reports tabs, frames, documents and URLs; a single-use 30-second target pin
  binds tab, document, origin and the retained element; a fresh search handle
  authorizes each fill; receipts never contain a value.
* the user, through the extension popup (click, context menu or keyboard
  shortcut): the extension asks which entries match the focused field's frame,
  shows metadata only, and fills after the user picks one.

Security model:

* The native host is a same-user process launched by the browser for the fixed
  extension ID. It connects to the broker's private socket or named pipe with
  the CLI's peer checks and relays bounded JSON messages; it keeps nothing.
* A channel can receive values only after **pairing**. The extension keeps an
  ECDH P-256 key pair in ``chrome.storage.session`` (memory only) and sends
  only its public key. The broker stores a SHA-256 digest of that public key
  for its own lifetime only. The user approves a new key on the broker's
  private HTTPS page by entering the master password and checking that the
  page shows the code the popup computes from its own key.
* Every value is **sealed** with AES-256-GCM under a key that the broker's
  per-connection ECDH key and the extension's private key agree, and bound to
  the pin or selection it answers. The sealed payload also carries the tab,
  document, frame chain and kind that the broker authorized; the extension
  fills only when they equal its own browser facts, so a host cannot redirect
  a value by changing the facts in transit. The native host and any process
  that replaces it relay only ciphertext; without the extension's private key
  it never receives a value.
* Origin and frame identity come from the browser (``tabs``, ``webNavigation``
  and injection results), never from page content. The broker applies the
  same frame policies as the CDP route: logins need the exact credential
  origin in a same-site frame chain; cards go only to the merchant's own
  frames or to the supported processor frames (Adyen, Computop, Stripe) below
  same-origin merchant frames; identities and verification codes go only to
  frames of the top origin.
  The user-click popup never serves Stripe's classic Card Element frame; only
  the agent pin route fills it.
* Values exist only in the broker, the relay, the extension's memory and the
  field that receives them. There is no clipboard, no storage and no logging.
* Secret capture (``pin-password-target --mode read`` and ``capture-secret``)
  uses the CDP route's own read checks in the extension. The broker seals the
  read request with the pin's facts; the extension seals the value it read to
  the broker under a second key that only the broker and the extension agree
  (``CAPTURE_INFO``), so the host relays ciphertext in both directions.
* A child frame's ``<iframe>`` owner is found with a nonce handshake between
  the parent's and the child's isolated worlds, then held by the CDP route's
  owner guard and checked again before a value moves.
* Hit tests use ``elementFromPoint`` in the extension's isolated world. Unlike
  CDP's ``DOM.getNodeForLocation`` it skips click-through covers
  (``pointer-events: none``, ``inert``, a popover's ``::backdrop``), so only the
  CDP route refuses a field under such a cover.
* Pairing and unlock links open only on the origin that the extension trusts.
  The broker's ``attached`` and ``state`` messages carry its signed origin
  statement (``broker_identity``); the extension learns the signing key when it
  first receives it, confirmed by the broker's HTTPS page on the trusted origin
  (``/.well-known/akdbx-identity``), and then follows an origin change only in a statement signed
  by that key with a higher sequence number.
"""
from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
import base64
import hashlib
import json
import os
import re
import secrets
import select
import sys
import threading
import time
import unicodedata
from importlib.resources import files
from urllib.parse import urlsplit

from .browser_slots import SlotError
from .protocol import ProtocolError, receive_message, send_message
from .public_suffix import registrable_domain
from .target import TargetError, DeliveryError
from .totp import https_origin

EXTENSION_ID = 'jjoamaejjkldcjcpgncoomoaagdfimhg'
EXTENSION_ORIGIN = 'chrome-extension://' + EXTENSION_ID + '/'
HOST_NAME = 'org.akdbx.extension'
PROTOCOL = 1
DELIVERY = 'extension-dom-v1'
CAPTURE_PROTOCOL = 1
CAPTURE_DELIVERY = 'extension-dom-read-v1'
# The first fill extension version that reads secrets and holds child-frame owners.
CAPTURE_VERSION = (0, 4, 0)
TOTP_VERSION = (0, 10, 0)
# Verification-code pins (pin-code-target --route extension) for SMS codes and webhook URLs.
CODE_VERSION = (0, 13, 0)
# QR read pins (capture-totp --qr): the extension decodes the pinned image itself.
QR_VERSION = (0, 14, 0)
# Firefox QR read pins: the first build that decodes only from an origin-clean canvas
# (convertToBlob), which a content script with <all_urls> host access cannot skip.
FIREFOX_QR_VERSION = (0, 14, 2)
# Identity pins with an explicit field purpose (pin-identity-target --field-purpose).
FIELD_PURPOSE_VERSION = (0, 7, 0)
# Card pins with an explicit field purpose, and ARIA expiry dropdowns (pin-card-target --field-purpose).
CARD_PURPOSE_VERSION = (0, 18, 0)
# The toolbar popup offers the inbox's texted codes for a focused one-time-code field.
POPUP_SMS_VERSION = (0, 15, 0)
MAX_POPUP_TEXTS = 8
# A popup text code that never reached the field goes back to the inbox only with
# the sealed token that its release carried, within this many seconds.
RESTORE_TTL = 30
MAX_RESTORES = 16
ROUTES = ('cdp', 'extension')
CHROMIUM_BROWSERS = ('helium', 'chrome', 'edge', 'chromium', 'brave')
BROWSERS = (*CHROMIUM_BROWSERS, 'firefox')
FIREFOX_EXTENSION_ID = 'akdbx@akdbx.org'
QR_VERSIONS = {**dict.fromkeys(CHROMIUM_BROWSERS, QR_VERSION), 'firefox': FIREFOX_QR_VERSION}
TTL = 30
MATCH_TTL = 60
MAX_CHANNELS = 4
MAX_PINS = 16
MAX_MATCH_HANDLES = 64
MAX_PAIRINGS = 8
PAIRING_TTL = 600
MAX_CHAIN = 9
MAX_FRAMES = 64
MAX_TABS = 4
MAX_ENTRIES = 20
MATCH_BUDGET = 36 * 1024  # Encoded entries before sealing; leaves room for base64 and facts.
MAX_POPUP_REQUESTS = 4
PUBLIC_KEY = re.compile(r'[A-Za-z0-9_-]{87}')  # base64url, 65-byte uncompressed P-256 point
HKDF_INFO = b'akdbx-extension-v1'
CAPTURE_INFO = b'akdbx-extension-capture-v1'  # Extension -> broker: captured secrets only.
# A 4096-character value of 3-byte characters and its one-document chain, sealed and
# base64url-encoded, fits with room; the host's frames stop at 64 KiB.
MAX_CAPTURE_SEALED = 48 * 1024
CODE_PREFIX = b'akdbx-pairing-code\0'
CHANNEL_ID = re.compile(r'[0-9a-f]{8}')
PAGE_ID = re.compile(r'([0-9a-f]{8})\.([0-9]{1,10})')
DOCUMENT_ID = re.compile(r'[0-9A-Za-z-]{1,64}')
PIN_ID = re.compile(r'[0-9a-f]{32}')
CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
NO_EXTENSION = 'extension route unavailable: no paired akdbx browser extension is connected'
# The fill extension's own version, independent of the akdbx package version.
# Bump it whenever the built extension changes: tests/fill_extension_fingerprint.json
# records each version's contents, and test_extension_route.py checks the record.
# A build adds a fourth part from its contents (extension_host.built_version), and
# a loaded extension reports that four-part version. The release signs that same
# generic Firefox build on AMO, so a signed add-on reports it too. Add-ons that
# the removed `akdbx extension sign` (0.53.0 to 0.54.x) signed have nine digits there.
EXTENSION_VERSION_FORMAT = re.compile(r'(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})')
REPORTED_VERSION_FORMAT = re.compile(EXTENSION_VERSION_FORMAT.pattern + r'(\.(0|[1-9][0-9]{0,8}))?')
EXTENSION_VERSION = json.loads(files('akdbx').joinpath('fill_extension', 'manifest.json')
                               .read_text(encoding='utf-8'))['version']
if not EXTENSION_VERSION_FORMAT.fullmatch(EXTENSION_VERSION):
    raise RuntimeError('the packaged fill extension has an invalid version')
STALE = ('extension route unavailable: the browser runs an older akdbx extension service worker than the '
         'extension files on disk (stale build); restart the browser, or reload akdbx on chrome://extensions, '
         'then pair it again')
MISMATCH = ('extension route unavailable: the browser runs akdbx extension {loaded}, another build than this '
            "broker's {expected}; rebuild the folder the browser loads with this akdbx "
            '(`akdbx extension build --output FOLDER`), or restart the broker if akdbx was updated; then reload akdbx '
            'on chrome://extensions and pair it again. A signed Firefox add-on: install the signed XPI from the '
            "release of this broker's akdbx version")


def valid_extension_version(value):
    """True for MAJOR.MINOR.PATCH, optionally .BUILD, of ASCII digits, at most 23 characters."""
    return isinstance(value, str) and len(value) <= 23 and REPORTED_VERSION_FORMAT.fullmatch(value) is not None


def version_parts(version):
    """MAJOR, MINOR, PATCH of a valid reported version: the build part does not order versions."""
    return tuple(int(part) for part in version.split('.')[:3])


def version_status(version, stale=False):
    """How a loaded extension's version compares with the one this akdbx build ships.

    An extension built by akdbx 0.21.2 or earlier does not report a version, so a missing
    version means an outdated extension. ``stale``: the worker found a newer build on disk
    and could not reload into it, so a browser restart or reload fixes it. ``mismatch``: the
    same MAJOR.MINOR.PATCH as this broker's build with another (or no) fourth part, so the
    browser loads other contents than this akdbx builds; a rebuild with this akdbx (or a
    broker restart after an update) fixes it. The release's AMO-signed Firefox add-on is the
    same generic build, with the same version.
    """
    if version is None:
        return 'outdated'
    if stale:
        return 'stale'
    loaded, shipped = version_parts(version), version_parts(EXTENSION_VERSION)
    if loaded == shipped:
        from .extension_host import built_version
        return 'current' if version == built_version() else 'mismatch'
    return 'outdated' if loaded < shipped else 'newer'


class StaleExtension(SlotError):
    """The paired worker runs another build: refuse with a message that names the fix.

    A SlotError, because the broker returns that error's message as it is.
    """

    def __init__(self, message=STALE):
        super().__init__(message)


class ExtensionError(Exception):
    """Internal only: callers return fixed, value-free errors."""


def _text(value, limit=4096):
    return isinstance(value, str) and 0 < len(value) <= limit


def _origin(url):
    """Serialized exact HTTPS origin of a browser-reported document URL."""
    try:
        scheme, host, port = https_origin(url)
    except Exception:
        raise ExtensionError() from None
    if scheme != 'https':
        raise ExtensionError()
    return 'https://' + (f'[{host}]' if ':' in host else host) + ('' if port == 443 else f':{port}')


def _secure(url):
    from .browser_card import CardTargetError, secure_url
    try:
        return secure_url(url)
    except CardTargetError:
        raise ExtensionError() from None


def login_origin(chain):
    """Same-site-chain-v1 for browser-reported chains; return the field origin.

    Every document from the top page to the field frame must be HTTPS and share
    one registrable domain under the vendored Public Suffix List. Hosts without
    a registrable domain (IP literals, public suffixes) need one exact origin.
    """
    origins = [_origin(hop['url']) for hop in chain]
    if len(origins) > 1:
        sites = {registrable_domain(urlsplit(origin).hostname or '') for origin in origins}
        if None in sites:
            if len(set(origins)) != 1:
                raise ExtensionError()
        elif len(sites) != 1:
            raise ExtensionError()  # Hostile top around a real login frame, or the reverse.
    return origins[-1]


def processor_for(url):
    from . import card_processor
    for name, check in (('adyen', card_processor.adyen_url), ('computop', card_processor.computop_url),
                        ('stripe', card_processor.stripe_url)):
        if check(url):
            return name
    return None


def card_route(chain, processor):
    """Merchant frames only, or one supported processor frame under them."""
    top = _secure(chain[0]['url'])
    if processor is None:
        if any(_secure(hop['url']) != top for hop in chain):
            raise ExtensionError()
        return
    if (len(chain) < 2 or len(chain) > 16 or processor_for(chain[-1]['url']) != processor
            or _secure(chain[-1]['url']) == top or any(_secure(hop['url']) != top for hop in chain[:-1])):
        raise ExtensionError()


def popup_route(chain):
    """The user-click popup never serves a Stripe classic Card Element document.

    Its inputs have no id, so only the agent pin route, which checks the exact
    type, autocomplete token, unique name, merchant iframe owner and hit test,
    may target them. This holds at any depth, including a top-level document.
    """
    from . import card_processor
    if any(card_processor.stripe_element(hop['url']) == 'card-element' for hop in chain):
        raise ExtensionError()


def identity_route(chain):
    top = _secure(chain[0]['url'])
    if any(_secure(hop['url']) != top for hop in chain):
        raise ExtensionError()


def _facts(message):
    """Validate browser-reported tab/document facts that the extension sends."""
    tab_id, document_id, top_url, chain = (message.get(k) for k in ('tab_id', 'document_id', 'top_url', 'chain'))
    if (type(tab_id) is not int or not 0 <= tab_id < 2**31 or not isinstance(document_id, str)
            or not DOCUMENT_ID.fullmatch(document_id) or not _text(top_url) or not isinstance(chain, list)
            or not 0 < len(chain) <= MAX_CHAIN):
        raise ExtensionError()
    for hop in chain:
        if (not isinstance(hop, dict) or set(hop) != {'document_id', 'url'} or not isinstance(hop['document_id'], str)
                or not DOCUMENT_ID.fullmatch(hop['document_id']) or not _text(hop['url'])):
            raise ExtensionError()
    if chain[0]['url'] != top_url or chain[-1]['document_id'] != document_id:
        raise ExtensionError()
    if len({hop['document_id'] for hop in chain}) != len(chain):
        raise ExtensionError()
    return tab_id, document_id, top_url, [dict(hop) for hop in chain]


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def public_key_bytes(value):
    """Decode and validate the extension's uncompressed P-256 public key."""
    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(value, str) or not PUBLIC_KEY.fullmatch(value):
        raise ExtensionError()
    raw = base64.urlsafe_b64decode(value + '=')
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        raise ExtensionError() from None
    if len(raw) != 65 or raw[0] != 4:
        raise ExtensionError()
    return raw


def pairing_code(digest):
    """The code both the popup and the pairing page compute from the key digest."""
    mac = hashlib.sha256(CODE_PREFIX + digest).digest()
    letters = ''.join(CODE_ALPHABET[b % len(CODE_ALPHABET)] for b in mac[:8])
    return letters[:4] + '-' + letters[4:]


def _wait_readable(connection, timeout):
    """True when a message byte (or EOF) is ready; never consumes data."""
    if os.name == 'nt':
        import pywintypes
        import win32pipe
        deadline = time.monotonic() + timeout
        while True:
            try:
                _, available, _ = win32pipe.PeekNamedPipe(connection.handle, 0)
            except pywintypes.error:
                return True  # Broken pipe: let the read report EOF.
            if available:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
    readable, _, _ = select.select([connection], [], [], timeout)
    return bool(readable)


class Channel:
    """One attached native host, bound to one browser profile's extension."""

    def __init__(self, hub, connection, browser, public_key, version=None, stale=False):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        self.hub, self.connection, self.browser, self.version = hub, connection, browser, version
        # Set at attach, or later when the worker answers a call with "stale".
        self.stale = stale
        self.public_key = public_key
        self.digest = hashlib.sha256(public_key).digest()
        own = ec.generate_private_key(ec.SECP256R1())
        self.broker_public_key = own.public_key().public_bytes(serialization.Encoding.X962,
                                                               serialization.PublicFormat.UncompressedPoint)
        shared = own.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key))
        # From fill extension 0.4.0 both keys bind the version the extension reported:
        # a host that reports another version makes every sealed message fail.
        bound = b'/' + version.encode('ascii') if self.supports_capture() else b''
        self._seal_key = HKDF(hashes.SHA256(), 32, salt=bytes(32),
                              info=HKDF_INFO + bound + public_key + self.broker_public_key).derive(shared)
        # A separate key for the other direction: a value the broker sealed can never pass as a capture.
        self._capture_key = HKDF(hashes.SHA256(), 32, salt=bytes(32),
                                 info=CAPTURE_INFO + bound + public_key + self.broker_public_key).derive(shared)
        self.id = secrets.token_hex(4)
        self.send_lock = threading.Lock()
        self.pending = {}
        self.pending_lock = threading.Lock()
        self.counter = 0
        self.closed = threading.Event()
        self.requests = threading.BoundedSemaphore(MAX_POPUP_REQUESTS)

    def seal(self, values, context):
        """Encrypt values for the paired extension only, bound to one pin or selection."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)
        data = json.dumps(values, separators=(',', ':')).encode('utf-8')
        sealed = AESGCM(self._seal_key).encrypt(nonce, data, context.encode('utf-8'))
        return dict(iv=b64url(nonce), data=b64url(sealed))

    def open(self, sealed, context):
        """Decrypt one capture the paired extension sealed to the broker; None if it does not verify."""
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if not isinstance(sealed, dict) or set(sealed) != {'iv', 'data'} or not all(
                isinstance(sealed[k], str) and 0 < len(sealed[k]) <= MAX_CAPTURE_SEALED for k in ('iv', 'data')):
            return None
        try:
            nonce = base64.urlsafe_b64decode(sealed['iv'] + '=' * (-len(sealed['iv']) % 4))
            data = base64.urlsafe_b64decode(sealed['data'] + '=' * (-len(sealed['data']) % 4))
            if len(nonce) != 12:
                return None
            plain = AESGCM(self._capture_key).decrypt(nonce, data, context.encode('utf-8'))
            payload = json.loads(plain.decode('utf-8'))
        except (InvalidTag, ValueError, UnicodeError, TypeError):
            return None
        return payload if isinstance(payload, dict) else None

    def supports(self, version):
        return self.version is not None and version_parts(self.version) >= version

    def supports_capture(self):
        return self.supports(CAPTURE_VERSION)

    def send(self, message):
        with self.send_lock:
            if self.closed.is_set():
                raise ExtensionError()
            self.connection.settimeout(5)
            send_message(self.connection, message)

    def refusal(self):
        """The refusal for a stale or mismatched build that this broker already knows, else None."""
        status = version_status(self.version, self.stale)
        if status == 'stale':
            return StaleExtension()
        if status == 'mismatch':
            from .extension_host import built_version
            return StaleExtension(MISMATCH.format(loaded=self.version, expected=built_version()))
        return None

    def checked_call(self, op, timeout, **payload):
        """A frame list or pin call, refused when this worker runs a stale or mismatched build.

        The broker knows a stale build from the reported version; the worker
        also checks the manifest on disk before each such call and answers
        ``{"ok": false, "error": "stale"}`` when the folder holds a newer build.
        """
        refusal = self.refusal()
        if refusal is not None:
            raise refusal
        result = self.call(op, timeout, **payload)
        if result.get('ok') is False and result.get('error') == 'stale':
            self.stale = True
            raise StaleExtension()
        return result

    def call(self, op, timeout, **payload):
        """Send one broker request to the extension and wait for its reply."""
        with self.pending_lock:
            self.counter += 1
            ident = self.counter
            slot = [threading.Event(), None]
            self.pending[ident] = slot
        try:
            self.send(dict(type='call', id=ident, op=op, **payload))
            if not slot[0].wait(max(0.01, timeout)) or not isinstance(slot[1], dict):
                raise ExtensionError()
            return slot[1]
        except (ProtocolError, OSError, TimeoutError):
            raise ExtensionError() from None
        finally:
            with self.pending_lock:
                self.pending.pop(ident, None)

    def notify(self, op, **payload):
        """Fire-and-forget request (pin release); its reply is ignored."""
        try:
            with self.pending_lock:
                self.counter += 1
                ident = self.counter
            self.send(dict(type='call', id=ident, op=op, **payload))
        except Exception:
            pass

    def resolve(self, message):
        ident = message.get('id')
        with self.pending_lock:
            slot = self.pending.get(ident) if type(ident) is int else None
        if slot is not None and isinstance(message.get('result'), dict):
            slot[1] = message['result']
            slot[0].set()

    def close(self):
        self.closed.set()
        with self.pending_lock:
            for slot in self.pending.values():
                slot[0].set()
        try:
            self.connection.close()
        except Exception:
            pass


@dataclass
class ExtensionPin:
    hub: object
    channel: Channel
    tab_id: int
    document_id: str
    pin_id: str
    kind: str
    mode: str
    top_url: str
    frame_url: str
    chain: list
    created: float
    expires: float
    processor: str | None = None
    spec: dict | None = None
    closed: bool = dataclass_field(default=False)

    @property
    def read_kind(self):
        """Read pins only: 'text', or 'qr' for a decoded QR code (capture-totp only)."""
        return (self.spec or {}).get('read_kind', 'text')

    def __getitem__(self, key):
        # The identity manager reads a pin's field the way it reads a CDP pin.
        if key == 'field':
            return self.mode
        raise KeyError(key)

    def close(self):
        if not self.closed:
            self.closed = True
            self.channel.notify('release', tab_id=self.tab_id, document_id=self.document_id, pin_id=self.pin_id,
                                chain=self.chain)


@dataclass
class Selection:
    entry: object
    channel_id: str
    tab_id: int
    document_id: str
    kind: str
    chain: list
    expires: float


class ExtensionHub:
    """Channels, pairings, pins and popup selections for the extension route."""

    def __init__(self, broker, *, default_route=None):
        if default_route is None:
            default_route = 'extension' if sys.platform == 'darwin' else 'cdp'
        if default_route not in ROUTES:
            raise ValueError('default fill route must be cdp or extension')
        self.broker = broker
        self.default_route = default_route
        self.clock = broker.clock
        self._lock = threading.Lock()
        self.channels = {}
        self.approved = []
        self.pairings = {}
        # Orders an approval or a paired attach against a pairing subscription, so neither misses the other.
        self._paired_lock = threading.Lock()
        self.pins = {}
        self.selections = {}
        self.restores = {}  # sealed restore token -> (SMS message, channel id, expiry)
        self._closed = False
        # The broker's signed origin statement (broker_identity.Identity), once serve announces it.
        self.identity = None

    def set_identity(self, identity):
        """Use a new signed origin statement and send it to every attached extension."""
        self.identity = identity
        self.refresh()

    # ----- capabilities and state ---------------------------------------
    def capabilities(self):
        from .extension_host import built_version
        with self._lock:
            channels = list(self.channels.values())
            approved = set(self.approved)
        state = dict(extension_protocol=PROTOCOL, extension_delivery=DELIVERY, extension_id=EXTENSION_ID,
                     extension_totp_protocol=1, extension_totp_min_version='0.10.0',
                     extension_popup_totp_protocol=1, extension_popup_totp_min_version='0.12.0',
                     extension_popup_sms_protocol=1,
                     extension_popup_sms_min_version='.'.join(map(str, POPUP_SMS_VERSION)),
                     extension_code_protocol=1, extension_code_min_version='.'.join(map(str, CODE_VERSION)),
                     extension_qr_capture_min_version='.'.join(map(str, QR_VERSION)),
                     extension_qr_capture_firefox_min_version='.'.join(map(str, FIREFOX_QR_VERSION)),
                     extension_capture_protocol=CAPTURE_PROTOCOL, extension_capture_delivery=CAPTURE_DELIVERY,
                     fill_routes=list(ROUTES),
                     default_fill_route=self.default_route,
                     extension_host_browsers=list(BROWSERS),
                     extension_connected=bool(channels),
                     extension_paired=any(c.digest in approved for c in channels),
                     extension_version_expected=built_version(),
                     extension_browsers=[dict(browser=c.browser, paired=c.digest in approved, version=c.version,
                                              version_status=version_status(c.version, c.stale))
                                         for c in channels])
        pairing = [dict(browser=c.browser, **info) for c in channels if c.digest not in approved
                   for info in [self._pairing_info(c.digest)] if info.get('url')]
        if pairing:
            state['extension_pairing'] = pairing
        if self.identity is not None:
            state['extension_trust'] = self.identity.summary()
        return state

    def _pairing_info(self, digest):
        """Pending pairing for a digest: code and private approval link."""
        now = self.clock()
        with self._lock:
            for token, (item, expires) in list(self.pairings.items()):
                if expires <= now:
                    self.pairings.pop(token, None)
            token = next((t for t, (d, _) in self.pairings.items() if d == digest), None)
            if token is None:
                while len(self.pairings) >= MAX_PAIRINGS:
                    self.pairings.pop(next(iter(self.pairings)))
                token = secrets.token_urlsafe(32)
                self.pairings[token] = (digest, now + PAIRING_TTL)
        base = getattr(self.broker.writes, 'public_base', None)
        info = dict(code=pairing_code(digest))
        # A blocked unlock link also blocks pairing: offer no pairing link.
        if isinstance(base, str) and base.startswith('https://') and not self.broker.unlock_blocked:
            info['url'] = base.rstrip('/') + '/extension/pair?token=' + token
        return info

    def _state(self, channel, kind='state'):
        with self._lock:
            paired = channel.digest in self.approved
        locked = self.broker.locked
        message = dict(type=kind, channel=channel.id, paired=paired, locked=locked, protocol=PROTOCOL,
                       broker_public_key=b64url(channel.broker_public_key))
        identity = self.identity
        if identity is not None:
            # Signed by the broker's identity key: a relaying host cannot change it.
            message['identity'] = identity.message()
            # The extension seals captured secrets only to a broker key that this signs.
            message['channel_signature'] = identity.sign_channel(channel.broker_public_key, channel.public_key)
        if not paired:
            message['pairing'] = self._pairing_info(channel.digest)
        # A blocked link is never offered; the agent replaces it after asking the user.
        if locked and self.broker.unlock_url and not self.broker.unlock_blocked:
            message['unlock_url'] = self.broker.unlock_url
        return message

    def refresh(self):
        """Push state after an unlock or pairing approval; never blocks callers on a slow host."""
        with self._lock:
            channels = list(self.channels.values())
        for channel in channels:
            try:
                channel.send(self._state(channel))
            except Exception:
                pass

    # ----- pairing (private HTTPS page) ---------------------------------
    def pairing_code(self, token):
        """Return the code shown on the approval page, or None for a bad token."""
        if not isinstance(token, str) or not 0 < len(token) <= 128:
            return None
        with self._lock:
            found = self.pairings.get(token)
            if found is None or found[1] <= self.clock():
                return None
            digest = found[0]
        return pairing_code(digest)

    def clear_targets(self):
        with self._lock:
            pins, self.pins = self.pins, {}
            self.selections.clear()
            self.restores.clear()
            self.pairings.clear()
        for pin in pins.values():
            pin.close()

    def revoke_pairings(self):
        """Invalidate every pending pairing link.

        The unlock page calls this when its link is blocked or replaced, so a
        pairing link from before never gets the new link's attempts.
        """
        with self._lock:
            self.pairings.clear()

    def approve(self, token):
        """Mark one pending key as paired, after the page verified the master password.

        The pending link belongs to the key, not to one host connection: it still
        works while the extension reconnects (an idle service worker, a host
        restart), and the key is paired when it attaches again.
        """
        with self._paired_lock:
            with self._lock:
                found = self.pairings.pop(token, None) if isinstance(token, str) else None
                if found is None or found[1] <= self.clock():
                    return False
                digest = found[0]
                if digest not in self.approved:
                    while len(self.approved) >= MAX_PAIRINGS:
                        self.approved.pop(0)
                    self.approved.append(digest)
            # Without an attached channel the event waits for the key's next attach.
            self._announce(digest)
        self.refresh()
        return True

    def _browser_for(self, digest):
        """Called under _lock: the browser of an attached channel with this key, or None."""
        return next((c.browser for c in self.channels.values() if c.digest == digest and not c.closed.is_set()), None)

    def _announce(self, digest):
        """Called under _paired_lock: wake pairing waits when this key is approved and attached.

        The event means the browser can fill now, so status shows it paired.
        """
        with self._lock:
            browser = self._browser_for(digest) if digest in self.approved else None
        notifier = getattr(self.broker, 'pairing_notifications', None)
        if browser is not None and notifier is not None:
            try:
                notifier.publish_paired(pairing_code(digest), browser)
            except Exception:
                pass  # A notification failure never undoes a pairing.

    def subscribe_paired(self, request):
        """Register a pairing webhook; an approval cannot fall between the check and the registration."""
        def paired(code):
            with self._lock:
                approved = set(self.approved)
                if code is None:
                    # Any browser: one that is attached and paired now.
                    found = [c.browser for c in self.channels.values()
                             if c.digest in approved and not c.closed.is_set()]
                    return found[0] if found else None
                found = [d for d in approved if pairing_code(d) == code]
                return self._browser_for(found[0]) if found else None  # Paired, but only if attached now.
        with self._paired_lock:
            return self.broker.pairing_notifications.subscribe_pairing(request, paired=paired)

    def _paired_channel(self, channel_id=None):
        with self._lock:
            channels = [c for c in self.channels.values() if c.digest in self.approved and not c.closed.is_set()
                        and (channel_id is None or c.id == channel_id)]
        return channels

    # ----- attached host connection ---------------------------------------
    def attach(self, connection, request):
        """Serve one long-lived host connection until it closes."""
        try:
            # A host relaying an extension built by akdbx 0.21.2 or earlier sends no version.
            if (set(request) - {'extension_version', 'extension_stale'} != {'action', 'extension_protocol',
                                                                             'extension_id', 'browser', 'public_key'}
                    or request.get('extension_stale', True) is not True
                    or type(request.get('extension_protocol')) is not int or request['extension_protocol'] != PROTOCOL
                    or request.get('extension_id') != EXTENSION_ID or request.get('browser') not in BROWSERS):
                raise ExtensionError()
            public_key = public_key_bytes(request['public_key'])
            version = request.get('extension_version')
            if 'extension_version' in request and not valid_extension_version(version):
                raise ExtensionError()
        except ExtensionError:
            send_message(connection, dict(type='error', error='extension attach refused'))
            return
        channel = Channel(self, connection, request['browser'], public_key, version,
                          stale=request.get('extension_stale') is True)
        with self._lock:
            if self._closed or len(self.channels) >= MAX_CHANNELS:
                channel = None
            else:
                self.channels[channel.id] = channel
        if channel is None:
            send_message(connection, dict(type='error', error='extension attach refused'))
            return
        try:
            channel.send(self._state(channel, 'attached'))
            # An approved key that attaches (again) is usable now: wake the waits for it.
            with self._paired_lock:
                self._announce(channel.digest)
            while not channel.closed.is_set():
                if not _wait_readable(connection, 1.0):
                    if self._closed:
                        break
                    continue
                connection.settimeout(5)
                message = receive_message(connection, deadline=time.monotonic() + 5)
                kind = message.get('type')
                if kind == 'reply':
                    channel.resolve(message)
                elif kind == 'request':
                    self._spawn_request(channel, message)
                else:
                    break
        except Exception:
            pass
        finally:
            with self._lock:
                self.channels.pop(channel.id, None)
                stale = [t for t, p in self.pins.items() if p.channel is channel]
                for token in stale:
                    self.pins.pop(token, None)
            channel.close()

    def close(self):
        with self._lock:
            self._closed = True
            channels = list(self.channels.values())
        for channel in channels:
            channel.close()

    def _spawn_request(self, channel, message):
        if not channel.requests.acquire(blocking=False):
            self._respond(channel, message, dict(ok=False, error='extension request refused; busy'))
            return

        def run():
            try:
                self._respond(channel, message, self.popup(channel, message))
            finally:
                channel.requests.release()
        threading.Thread(target=run, daemon=True, name='akdbx-extension-request').start()

    @staticmethod
    def _respond(channel, message, result):
        ident = message.get('id')
        if isinstance(ident, str) and 0 < len(ident) <= 64:
            try:
                channel.send(dict(type='response', id=ident, result=result))
            except Exception:
                pass

    # ----- user-click popup requests ------------------------------------
    def popup(self, channel, message):
        """Extension-initiated requests: state, match (metadata only) and release (values).

        Only the popup's own user-gesture path sends match and release; the
        extension refuses them from any other context.
        """
        op = message.get('op')
        try:
            if op == 'state':
                if set(message) != {'type', 'id', 'op'}:
                    raise ExtensionError()
                return dict(ok=True, **{k: v for k, v in self._state(channel).items() if k != 'type'})
            with self._lock:
                paired = channel.digest in self.approved
            if not paired:
                return dict(ok=False, error='extension not paired; open the pairing page from the extension')
            if self.broker.locked:
                return dict(ok=False, error='vault locked', **({'unlock_url': self.broker.unlock_url}
                                                             if self.broker.unlock_url and not self.broker.unlock_blocked
                                                             else {}))
            if op in {'match', 'release', 'restore'}:
                handler = {'match': self._match, 'release': self._release, 'restore': self._restore}[op]

                def perform():
                    with self.broker._vault_lock:
                        return handler(channel, message)
                return self.broker.session.run(perform, self.broker._locked_response)
        except ExtensionError:
            pass
        except Exception:
            return dict(ok=False, error='extension request failed')
        return dict(ok=False, error='extension request refused; page, frame or field not supported')

    def _match(self, channel, message):
        required = {'type', 'id', 'op', 'tab_id', 'document_id', 'top_url', 'chain', 'kind'}
        if message.get('kind') == 'totp':
            required.add('probe_id')
            if not isinstance(message.get('probe_id'), str) or not PIN_ID.fullmatch(message['probe_id']):
                raise ExtensionError()
        if set(message) != required:
            raise ExtensionError()
        tab_id, document_id, top_url, chain = _facts(message)
        popup_route(chain)
        kind = message['kind']
        from .versions import active_entries
        from .cards import is_card, metadata, read_card
        from .identities import is_identity, MARKER as IDENTITY_MARKER
        from .secrets_capture import is_secret_record
        from .writes import allowed_origins, passwordless_identity
        entries = []
        vault = self.broker.vault
        if kind in {'login', 'totp'}:
            from .totp import configured
            if kind == 'totp' and (len(chain) != 1 or not channel.supports((0, 12, 0))):
                raise ExtensionError()
            target = https_origin(login_origin(chain))
            for entry in active_entries(vault):
                try:
                    if is_card(entry) or is_identity(entry) or is_secret_record(entry):
                        continue
                    if target not in allowed_origins(entry) or kind == 'totp' and not configured(entry):
                        continue
                    item = dict(title=entry.title or '', username=entry.username or '')
                    if passwordless_identity(entry):
                        item['passwordless'] = True
                except Exception:
                    continue
                entries.append((item, entry, kind))
            if kind == 'totp' and channel.supports(POPUP_SMS_VERSION):
                entries.extend(self._texts())
        elif kind == 'card':
            card_route(chain, processor_for(chain[-1]['url']) if len(chain) > 1 else None)
            from datetime import datetime, timezone
            now = datetime.fromtimestamp(self.broker.wall_clock(), timezone.utc)
            for entry in active_entries(vault):
                try:
                    if not is_card(entry):
                        continue
                    values = read_card(entry)
                    if (int(values['year']), int(values['month'])) < (now.year, now.month):
                        continue
                    info = metadata(entry)
                    item = dict(title=info['title'], brand=info['brand'], last_four=info['last_four'])
                except Exception:
                    continue
                entries.append((item, entry, kind))
        elif kind == 'identity':
            identity_route(chain)
            for entry in active_entries(vault):
                try:
                    if not is_identity(entry) or entry.get_custom_property(IDENTITY_MARKER) != 'v1':
                        continue
                    item = dict(title=entry.title or '')
                except Exception:
                    continue
                entries.append((item, entry, kind))
        else:
            raise ExtensionError()
        # Bound the encoded list before issuing handles: sealing grows it by about
        # a third (base64), and the transport refuses frames over 64 KiB.
        bounded, budget = [], MATCH_BUDGET
        for item, entry, selected in entries:
            size = len(json.dumps(dict(item, handle='0' * 64), separators=(',', ':'))) + 1
            if all(len(str(v).encode('utf-8')) <= 1024 for v in item.values()) and size <= budget:
                bounded.append((item, entry, selected))
                budget -= size
            if len(bounded) == MAX_ENTRIES:
                break
        entries = bounded
        result = []
        now = self.clock()
        with self._lock:
            for token, item in list(self.selections.items()):
                if item.expires <= now:
                    self.selections.pop(token, None)
            for item, entry, selected in entries:
                while len(self.selections) >= MAX_MATCH_HANDLES:
                    self.selections.pop(next(iter(self.selections)))
                handle = secrets.token_hex(32)
                self.selections[handle] = Selection(entry, channel.id, tab_id, document_id, selected, chain,
                                                    now + MATCH_TTL)
                result.append(dict(item, handle=handle))
        # Seal the list so a relay cannot pair a shown label with another handle.
        facts = dict(tab_id=tab_id, document_id=document_id, chain=chain, kind=kind)
        if kind == 'totp':
            facts['probe_id'] = message['probe_id']
        return dict(ok=True, sealed=channel.seal(dict(values=dict(entries=result), facts=facts), 'match'))

    def _release(self, channel, message):
        """Return the values for one selected entry, bound to the matched document."""
        if set(message) != {'type', 'id', 'op', 'handle', 'tab_id', 'document_id', 'top_url', 'chain',
                            'roles', 'formats'}:
            raise ExtensionError()
        handle = message.get('handle')
        with self._lock:
            selection = self.selections.pop(handle, None) if isinstance(handle, str) else None
        if selection is None or selection.expires <= self.clock() or selection.channel_id != channel.id:
            raise ExtensionError()
        tab_id, document_id, top_url, chain = _facts(message)
        if (tab_id, document_id, chain) != (selection.tab_id, selection.document_id, selection.chain):
            raise ExtensionError()  # A navigation or another frame: match again.
        popup_route(chain)
        roles, formats = message.get('roles'), message.get('formats')
        if (not isinstance(roles, list) or not 0 < len(roles) <= 16 or len(set(roles)) != len(roles)
                or not all(isinstance(r, str) for r in roles) or not isinstance(formats, dict)
                or set(formats) - set(roles) or not all(isinstance(v, str) for v in formats.values())):
            raise ExtensionError()
        entry = selection.entry
        values = {}
        if selection.kind == 'login':
            from .secrets_capture import is_secret_record
            from .writes import allowed_origins, passwordless_identity
            if set(roles) - {'username', 'password'} or formats:
                raise ExtensionError()
            if https_origin(login_origin(chain)) not in allowed_origins(entry):
                raise ExtensionError()
            if 'password' in roles and (passwordless_identity(entry) or is_secret_record(entry)):
                raise ExtensionError()
            for role in roles:
                value = (entry.username if role == 'username' else entry.password) or ''
                self.broker._validate_credential_text(value)
                if value:
                    values[role] = value
        elif selection.kind == 'totp':
            from .totp import MIN_VALIDITY, code_at, read_configuration
            from .writes import allowed_origins
            if roles != ['totp'] or formats or len(chain) != 1 or https_origin(top_url) not in allowed_origins(entry):
                raise ExtensionError()
            config = read_configuration(entry)
            now = self.broker.wall_clock()
            if config.period - now % config.period < MIN_VALIDITY:
                return dict(ok=False, error='TOTP near expiry; open akdbx again after the code changes')
            values['totp'] = code_at(config, now)
        elif selection.kind == 'sms':
            # A texted code for the focused one-time-code field. The text is spent
            # here, once; only the extension's sealed token puts it back (_restore).
            if (roles != ['totp'] or formats or len(chain) != 1 or not channel.supports(POPUP_SMS_VERSION)
                    or not isinstance(selection.entry, str)):
                raise ExtensionError()
            from .sms import SmsError
            try:
                text = self.broker.sms.take(selection.entry)
            except SmsError:
                return dict(ok=False, error='text expired or already used; open akdbx again')
            token = secrets.token_hex(32)
            with self._lock:
                for key, (_, _, expires) in list(self.restores.items()):
                    if expires <= self.clock():
                        self.restores.pop(key, None)
                while len(self.restores) >= MAX_RESTORES:
                    self.restores.pop(next(iter(self.restores)))
                self.restores[token] = (text, channel.id, self.clock() + RESTORE_TTL)
            values.update(code=text.code, restore=token)
        elif selection.kind == 'card':
            from . import card_processor
            from .cards import FILL_FIELDS, value_for
            processor = processor_for(chain[-1]['url']) if len(chain) > 1 else None
            card_route(chain, processor)
            for role in roles:
                fmt = formats.get(role)
                if role not in FILL_FIELDS or (processor and not card_processor.supported_request(
                        processor, chain[-1]['url'], role)):
                    raise ExtensionError()
                if processor in {'computop', 'stripe'} and role == 'cc-exp' and fmt != 'MM/YY':
                    raise ExtensionError()
                try:
                    values[role] = value_for(entry, role, fmt, self.broker.wall_clock())
                except Exception:
                    if role == 'cc-csc':
                        continue  # An optional security code may be absent.
                    raise ExtensionError() from None
        else:
            from .identities import FILL_FIELDS as IDENTITY_FIELDS, _value_for
            identity_route(chain)
            if formats:
                raise ExtensionError()
            for role in roles:
                if role not in IDENTITY_FIELDS:
                    raise ExtensionError()
                try:
                    values[role] = _value_for(entry, role)
                except Exception:
                    continue  # Empty identity fields are skipped, never invented.
        if not values:
            raise ExtensionError()
        for value in values.values():
            if not isinstance(value, str) or len(value) > 4096 or any(
                    unicodedata.category(c) == 'Cc' and c != '\n' for c in value):
                raise ExtensionError()
        # The extension fills only if these broker-authorized facts equal its own.
        facts = dict(tab_id=tab_id, document_id=document_id, chain=chain, kind=selection.kind, roles=roles,
                     formats=formats)
        try:
            sealed = channel.seal(dict(values=values, facts=facts), 'release:' + handle)
        except Exception:
            if selection.kind == 'sms':
                self._put_back(values['restore'], channel)  # Nothing left the broker.
            raise
        finally:
            values.clear()
        return dict(ok=True, sealed=sealed)

    def _texts(self):
        """The inbox's unexpired texts, newest first: metadata only, never a code.

        A text names no site that akdbx can verify, so the popup shows each one's
        sender and masked preview, and the user picks the one this site sent.
        """
        inbox = getattr(self.broker, 'sms', None)
        if inbox is None:
            return []
        rows = []
        for row in inbox.wait()[:MAX_POPUP_TEXTS]:
            item = dict(kind='sms', source=row['source'], sender=row['sender'], preview=row['preview'],
                        code_length=row['code_length'], age_seconds=row['age_seconds'])
            rows.append((item, row['id'], 'sms'))
        return rows

    def _put_back(self, token, channel):
        with self._lock:
            item = self.restores.get(token) if isinstance(token, str) else None
            if item is None or item[1] != channel.id:
                return False
            del self.restores[token]
        if item[2] <= self.clock():
            return False
        self.broker.sms.restore(item[0])
        return True

    def _restore(self, channel, message):
        """A popup text code that never reached the field goes back to the inbox, once.

        Only the token sealed inside that release can do it, so a relaying host
        that saw the handle cannot put a used code back.
        """
        if set(message) != {'type', 'id', 'op', 'token'} or not isinstance(message.get('token'), str):
            raise ExtensionError()
        if not self._put_back(message['token'], channel):
            raise ExtensionError()
        return dict(ok=True)

    # ----- agent route: discovery ----------------------------------------
    def _channels_for(self, request):
        page_id = request.get('page_id')
        if page_id is None:
            return self._paired_channel(), None
        match = PAGE_ID.fullmatch(page_id) if isinstance(page_id, str) else None
        if match is None:
            raise ExtensionError()
        return self._paired_channel(match[1]), int(match[2])

    def frames(self, request):
        """Read-only frame listing in the CDP listing's shape, without URLs or values."""
        from . import password_frames
        allowed = {'action', 'password_protocol', 'frame_protocol', 'top_url', 'route'}
        if (set(request) - {'page_id'} != allowed or request.get('route') != 'extension'
                or type(request.get('password_protocol')) is not int or request['password_protocol'] != 1
                or type(request.get('frame_protocol')) is not int or request['frame_protocol'] != password_frames.PROTOCOL
                or not _text(request.get('top_url'))):
            raise ExtensionError()
        _origin(request['top_url'])
        channels, tab_id = self._channels_for(request)
        found, refused, hidden = [], None, False
        for channel in channels:
            refusal = channel.refusal()
            if refusal is not None and tab_id is not None:
                raise refusal  # The page ID names this browser.
            # A refused browser still answers, so that its open tabs keep an exact URL unique
            # across paired browsers: a worker that found a newer build on disk counts them.
            result = channel.call('frames', 10, top_url=request['top_url'], tab_id=tab_id)
            if result.get('ok') is False and result.get('error') == 'stale':
                channel.stale = True
                refusal, matching = channel.refusal(), result.get('tabs')
                if set(result) != {'ok', 'error', 'tabs'} or type(matching) is not int or matching < 0:
                    raise ExtensionError()
            else:
                tabs = result.get('tabs')
                if result.get('ok') is not True or not isinstance(tabs, list) or len(tabs) > MAX_TABS:
                    raise ExtensionError()
                matching = len(tabs)
                if refusal is None:
                    found.extend((channel, tab) for tab in tabs)
            if refusal is not None:
                # The refusal of a browser that has the URL open names the fix that applies.
                if matching > 0 and not hidden:
                    refused, hidden = refusal, True
                refused = refused or refusal
        # A URL also open in a refused browser does not name one tab: refuse with the fix, never pick the other.
        if refused is not None and (hidden or not found):
            raise refused
        if len(found) != 1:
            raise ExtensionError()  # Missing or ambiguous: pass --page-id.
        channel, tab = found[0]
        frames = tab.get('frames') if isinstance(tab, dict) else None
        if (not isinstance(tab, dict) or type(tab.get('tab_id')) is not int or (tab_id is not None and tab['tab_id'] != tab_id)
                or not isinstance(frames, list) or not 0 < len(frames) <= MAX_FRAMES + 1):
            raise ExtensionError()
        records = {}
        for frame in frames:
            if (not isinstance(frame, dict) or set(frame) != {'document_id', 'parent_document_id', 'url', 'visible_fields'}
                    or not isinstance(frame['document_id'], str) or not DOCUMENT_ID.fullmatch(frame['document_id'])
                    or not (frame['parent_document_id'] is None or isinstance(frame['parent_document_id'], str)
                            and DOCUMENT_ID.fullmatch(frame['parent_document_id']))
                    or not _text(frame['url'], 8192) or frame['document_id'] in records):
                raise ExtensionError()
            records[frame['document_id']] = frame
        tops = [f for f in records.values() if f['parent_document_id'] is None]
        if len(tops) != 1 or tops[0]['url'] != request['top_url']:
            raise ExtensionError()
        listed = []
        for frame in list(records.values())[:MAX_FRAMES]:
            path = [frame]
            while path[-1]['parent_document_id'] is not None and len(path) <= MAX_CHAIN:
                parent = records.get(path[-1]['parent_document_id'])
                if parent is None:
                    break
                path.append(parent)
            path.reverse()
            complete = path[0]['parent_document_id'] is None and len(path) <= MAX_CHAIN
            try:
                origin = _origin(frame['url'])
            except ExtensionError:
                origin = None
            eligible = False
            if complete and origin is not None:
                try:
                    login_origin([dict(document_id=f['document_id'], url=f['url']) for f in path])
                    eligible = True
                except ExtensionError:
                    eligible = False
            fields = frame['visible_fields']
            if not (isinstance(fields, dict) and set(fields) == {'password', 'text'}
                    and all(type(v) is int and 0 <= v <= 512 for v in fields.values())):
                fields = None
            listed.append(dict(frame_id=frame['document_id'], parent_frame_id=frame['parent_document_id'],
                               depth=len(path) - 1, origin=origin or 'opaque-or-insecure', eligible=eligible,
                               visible_fields=fields if eligible else None))
        return dict(ok=True, page_id=channel.id + '.' + str(tab['tab_id']), main_frame_id=tops[0]['document_id'],
                    frame_policy=password_frames.POLICY, route='extension', frames=listed,
                    truncated=len(records) > MAX_FRAMES)

    # ----- agent route: pins and delivery ---------------------------------
    def _pin(self, kind, request, spec, frame_url=None, *, hardened=True, needs=None):
        """Ask the browser to retain one element; return the browser facts and pin id.

        ``hardened``: the pin needs fill extension 0.4.0 or newer, which reads
        secrets and holds child-frame owners. An older extension would pin a
        child-frame login without the owner check, so it is refused.
        ``needs``: the lowest fill extension version that applies this spec, or
        a mapping of browser kind to that version (a kind it omits is refused).
        """
        self.prune()
        channels, tab_id = self._channels_for(request)
        if tab_id is None or len(channels) != 1 or not isinstance(request.get('frame_id'), str) \
                or not DOCUMENT_ID.fullmatch(request['frame_id']) or not _text(request.get('top_url')):
            raise ExtensionError()
        if hardened and not channels[0].supports_capture():
            raise ExtensionError()
        if isinstance(needs, dict):
            needs = needs.get(channels[0].browser)
            if needs is None:
                raise ExtensionError()
        if needs is not None and not channels[0].supports(needs):
            raise ExtensionError()
        with self._lock:
            if self._closed or len(self.pins) >= MAX_PINS:
                raise ExtensionError()
        channel = channels[0]
        result = channel.checked_call('pin', 8, tab_id=tab_id, document_id=request['frame_id'], top_url=request['top_url'],
                              frame_url=frame_url, kind=kind, spec=spec)
        created = self.clock()
        pin_id = result.get('pin_id')
        try:
            if (result.get('ok') is not True or set(result) != {'ok', 'pin_id', 'chain'}
                    or not isinstance(pin_id, str) or not PIN_ID.fullmatch(pin_id)):
                raise ExtensionError()
            _, _, _, chain = _facts(dict(tab_id=tab_id, document_id=request['frame_id'], top_url=request['top_url'],
                                         chain=result['chain']))
            if frame_url is not None and chain[-1]['url'] != frame_url:
                raise ExtensionError()
        except ExtensionError:
            if isinstance(pin_id, str) and PIN_ID.fullmatch(pin_id):
                channel.notify('release', tab_id=tab_id, document_id=request['frame_id'], pin_id=pin_id,
                               chain=result.get('chain'))
            raise
        return channel, tab_id, pin_id, chain, created

    def _publish(self, pin):
        token = secrets.token_hex(32)
        with self._lock:
            if self._closed or len(self.pins) >= MAX_PINS:
                pin.close()
                raise ExtensionError()
            self.pins[token] = pin
        return token

    def pin_password(self, request):
        from . import password_frames
        mode = request.get('mode')
        required = {'action', 'password_protocol', 'page_id', 'frame_id', 'top_url', 'selector', 'mode', 'route'}
        optional = set(request) & {'password_purpose', 'allow_autocomplete_off', 'frame_protocol', 'frame_origin'}
        if (set(request) != required | optional | ({'username_selector'} if mode == 'login' else set())
                or request.get('route') != 'extension'
                or type(request.get('password_protocol')) is not int or request['password_protocol'] != 1
                or mode not in {'username', 'password', 'login', 'totp'}
                or ('password_purpose' in request and (mode != 'password'
                                                      or request['password_purpose'] not in {'current-password', 'new-password'}))
                or ('allow_autocomplete_off' in request and (request['allow_autocomplete_off'] is not True
                                                             or mode != 'password' or 'password_purpose' not in request))
                or ('frame_protocol' in request) != ('frame_origin' in request)
                or ('frame_protocol' in request and (type(request['frame_protocol']) is not int
                                                     or request['frame_protocol'] != password_frames.PROTOCOL))):
            raise ExtensionError()
        for key in ('selector',) + (('username_selector',) if mode == 'login' else ()):
            if not _text(request[key]):
                raise ExtensionError()
        _origin(request['top_url'])
        frame_origin = None
        if 'frame_origin' in request:
            try:
                frame_origin = password_frames.canonical_origin(request['frame_origin'])
            except TargetError:
                raise ExtensionError() from None
        spec = dict(selector=request['selector'], username_selector=request.get('username_selector'), mode=mode,
                    password_purpose=request.get('password_purpose'),
                    allow_autocomplete_off=request.get('allow_autocomplete_off', False), frame_origin=frame_origin)
        # A child-frame pin needs the extension that holds the frame owners.
        return self._frame_pin('password', mode, request, spec, frame_origin, hardened=frame_origin is not None,
                               needs=TOTP_VERSION if mode == 'totp' else None)

    def _frame_pin(self, kind, mode, request, spec, frame_origin, *, hardened, needs=None):
        channel, tab_id, pin_id, chain, created = self._pin(kind, request, spec, hardened=hardened, needs=needs)
        try:
            if frame_origin is None:
                # The main frame of the exact top URL, as on the CDP route.
                if len(chain) != 1 or chain[0]['url'] != request['top_url']:
                    raise ExtensionError()
            elif len(chain) < 2 or login_origin(chain) != frame_origin:
                raise ExtensionError()
            if self.clock() >= created + TTL:
                raise ExtensionError()
        except ExtensionError:
            channel.notify('release', tab_id=tab_id, document_id=request['frame_id'], pin_id=pin_id, chain=chain)
            raise
        pin = ExtensionPin(self, channel, tab_id, request['frame_id'], pin_id, kind, mode, request['top_url'],
                           chain[-1]['url'], chain, created, created + TTL, spec=spec)
        token = self._publish(pin)
        return dict(ok=True, target=token, expires_in=TTL, target_delivery=DELIVERY)

    def pin_read(self, request):
        """A read pin for secret capture: the CDP read pin's request shape plus ``route``.

        The extension reads only in the top document: a child frame's text would
        need its position checked through every parent document, which the
        extension cannot map exactly for every iframe (padding, transforms), so
        a frame route (``frame_origin``) is refused. The CDP route reads there.
        ``read_kind: "qr"`` (capture-totp only) decodes a QR code in the pinned
        image, canvas or inline SVG; it needs fill extension 0.14.0 or newer in a
        Chromium browser, or 0.14.2 or newer in Firefox. A Firefox content script
        with <all_urls> host access can read a tainted canvas; from 0.14.2 the
        pin decodes only pixels that passed convertToBlob's origin-clean check.
        """
        from . import browser_password
        required = {'action', 'password_protocol', 'page_id', 'frame_id', 'top_url', 'selector', 'mode',
                    'capture_protocol', 'route'}
        qr = 'read_kind' in request
        if (set(request) != required | ({'read_kind'} if qr else set()) or qr and request['read_kind'] != 'qr'
                or request.get('route') != 'extension' or request.get('mode') != 'read'
                or type(request.get('password_protocol')) is not int or request['password_protocol'] != 1
                or type(request.get('capture_protocol')) is not int or request['capture_protocol'] != CAPTURE_PROTOCOL):
            raise ExtensionError()
        selector = request['selector']
        # No attribute or functional selectors: pin success must not test the secret.
        if (not _text(selector) or len(selector) > browser_password.MAX_READ_SELECTOR
                or not browser_password.READ_SELECTOR.fullmatch(selector)):
            raise ExtensionError()
        _origin(request['top_url'])
        spec = dict(selector=selector, frame_origin=None)
        if qr:
            spec['read_kind'] = 'qr'  # A text pin's spec stays as before, for older extensions.
        return self._frame_pin('read', 'read', request, spec, None, hardened=True, needs=QR_VERSIONS if qr else None)

    def pin_element(self, kind, request):
        """Card, identity or code field pin; same request shape as the CDP route plus ``route``.

        A code pin (``pin-code-target``: an SMS code or a webhook URL) needs the
        exact frame URL, as on the CDP route, and fill extension 0.13.0 or newer.
        It applies the CDP code pin's own DOM checks, and every document from the
        top page to the field must have the top page's exact origin.
        """
        from . import card_processor
        from .browser_code import FIELDS as CODE_FIELDS
        from .cards import FILL_FIELDS as CARD_FIELDS
        from .identities import FILL_FIELDS as IDENTITY_FIELDS
        protocol = kind + '_protocol'
        allowed = {'action', protocol, 'page_id', 'frame_id', 'top_url', 'selector', 'field', 'route'}
        allowed |= set(request) & {'frame_url'}
        processor = request.get('processor')
        if kind == 'card' and 'processor' in request:
            allowed |= {'processor', 'processor_protocol'}
        fields = {'card': CARD_FIELDS, 'identity': IDENTITY_FIELDS, 'code': CODE_FIELDS}[kind]
        from .browser_card import CardTargetError, field_purpose
        try:
            purpose, allow_off = field_purpose(kind, request)
        except CardTargetError:
            raise ExtensionError() from None
        allowed |= set(request) & {'field_purpose', 'allow_autocomplete_off'}
        if (set(request) != allowed or request.get('route') != 'extension'
                or type(request.get(protocol)) is not int or request[protocol] != 1
                or request.get('field') not in fields or not _text(request.get('selector'))
                or ('frame_url' in request and not _text(request['frame_url']))
                or (kind == 'code' and 'frame_url' not in request)):
            raise ExtensionError()
        if processor is not None and (processor not in card_processor.PROCESSORS
                                      or type(request.get('processor_protocol')) is not int
                                      or request['processor_protocol'] != card_processor.PROTOCOL):
            raise ExtensionError()
        _secure(request['top_url'])
        spec = dict(selector=request['selector'], field=request['field'], processor=processor)
        if purpose is not False:
            # Fill extension 0.7.0 (identities) and 0.18.0 (cards) and newer apply the
            # field purpose; an older one ignores it, and so refuses the field.
            spec.update(field_purpose=purpose, allow_autocomplete_off=allow_off)
        # An extension older than 0.13.0 has no code pin; it is never asked for one.
        needs = (CODE_VERSION if kind == 'code' else None if purpose is False else
                 CARD_PURPOSE_VERSION if kind == 'card' else FIELD_PURPOSE_VERSION)
        channel, tab_id, pin_id, chain, created = self._pin(kind, request, spec, request.get('frame_url'), hardened=False,
                                                            needs=needs)
        try:
            if kind == 'card':
                card_route(chain, processor)
                if processor is not None and not card_processor.supported_request(processor, chain[-1]['url'],
                                                                                   request['field']):
                    raise ExtensionError()
            else:
                identity_route(chain)  # Identities and codes: only frames of the top origin.
        except ExtensionError:
            channel.notify('release', tab_id=tab_id, document_id=request['frame_id'], pin_id=pin_id, chain=chain)
            raise
        if self.clock() >= created + TTL:
            channel.notify('release', tab_id=tab_id, document_id=request['frame_id'], pin_id=pin_id, chain=chain)
            raise ExtensionError()
        pin = ExtensionPin(self, channel, tab_id, request['frame_id'], pin_id, kind, request['field'],
                           request['top_url'], chain[-1]['url'], chain, created, created + TTL, processor, spec=spec)
        token = self._publish(pin)
        return dict(ok=True, target=token, expires_in=TTL, field=request['field'], **{kind + '_delivery': DELIVERY})

    def take(self, token, kind):
        """Atomically take one extension pin of this kind; None if the token is not ours.

        A token of ours for another kind (a read pin given to a fill) is used up
        and refused, as a CDP pin is: a wrong command never leaves it reusable.
        """
        if not isinstance(token, str):
            return None
        with self._lock:
            pin = self.pins.pop(token, None)
        if pin is not None and pin.kind != kind:
            pin.close()
            raise TargetError()
        return pin

    def prune(self):
        now = self.clock()
        with self._lock:
            expired = [self.pins.pop(t) for t, p in list(self.pins.items()) if p.expires <= now]
        for pin in expired:
            pin.close()

    def _deliver(self, pin, values, ready, deadline):
        """Send values to the retained element. Returns the browser state string."""
        remaining = min(deadline - self.clock(), TTL)
        if pin.closed or pin.expires <= self.clock() or remaining <= 0 or not ready():
            return 'refused'
        max_age_ms = max(0, min(TTL * 1000, (deadline - pin.created) * 1000))
        try:
            # The pinned field spec and the deadline are authorized here, not by the relay.
            facts = dict(tab_id=pin.tab_id, document_id=pin.document_id, chain=pin.chain, kind=pin.kind,
                         pin_id=pin.pin_id, spec=pin.spec, max_age_ms=max_age_ms)
            sealed = pin.channel.seal(dict(values=values, facts=facts), 'fill:' + pin.pin_id)
            result = pin.channel.call('fill', remaining + 0.5, tab_id=pin.tab_id, document_id=pin.document_id,
                                      pin_id=pin.pin_id, top_url=pin.top_url, chain=pin.chain, kind=pin.kind,
                                      sealed=sealed, max_age_ms=max_age_ms)
        except ExtensionError:
            return 'uncertain'
        state = result.get('state')
        return state if set(result) == {'state'} and state in {'filled', 'refused'} else 'uncertain'

    def read(self, pin, site_origins, ready, start_deadline):
        """Return the read pin's checked value; the caller saves it and never returns it over RPC.

        The broker seals the request with the pin's facts, so a host cannot point
        it at another element. The extension answers with the value sealed under
        the capture key and bound to the same pin and facts.
        """
        if pin.kind != 'read' or pin.mode != 'read':
            raise TargetError()
        try:
            if https_origin(pin.frame_url) not in site_origins:
                raise TargetError()
        except TargetError:
            raise
        except Exception:
            raise TargetError() from None
        remaining = min(start_deadline - self.clock(), TTL)
        if pin.closed or pin.expires <= self.clock() or remaining <= 0 or not ready():
            raise TargetError()
        max_age_ms = max(0, min(TTL * 1000, (start_deadline - pin.created) * 1000))
        facts = dict(tab_id=pin.tab_id, document_id=pin.document_id, chain=pin.chain, kind=pin.kind,
                     pin_id=pin.pin_id, spec=pin.spec, max_age_ms=max_age_ms)
        try:
            sealed = pin.channel.seal(dict(values={}, facts=facts), 'read:' + pin.pin_id)
            result = pin.channel.call('read', remaining + 0.5, tab_id=pin.tab_id, document_id=pin.document_id,
                                      pin_id=pin.pin_id, top_url=pin.top_url, chain=pin.chain, kind=pin.kind,
                                      sealed=sealed, max_age_ms=max_age_ms)
        except ExtensionError:
            raise TargetError() from None
        if set(result) != {'state', 'sealed'} or result.get('state') != 'read':
            raise TargetError()
        payload = pin.channel.open(result['sealed'], 'capture:' + pin.pin_id)
        expected = dict(tab_id=pin.tab_id, document_id=pin.document_id, chain=pin.chain, pin_id=pin.pin_id)
        if (payload is None or set(payload) != {'value', 'facts'} or payload['facts'] != expected
                or not isinstance(payload['value'], str)):
            raise TargetError()
        return payload['value']

    def deliver_password(self, pin, mode, username, password, site_origins, ready, start_deadline):
        """The field document's origin must exactly equal one of the credential's origins."""
        try:
            if (mode not in {'username', 'password', 'login', 'totp'} or mode != pin.mode
                    or pin.kind != 'password' or https_origin(pin.frame_url) not in site_origins):
                raise DeliveryError(False)
        except DeliveryError:
            raise
        except Exception:
            raise DeliveryError(False) from None
        if mode == 'totp':
            if (not pin.channel.supports(TOTP_VERSION) or username != '' or not isinstance(password, str)
                    or not re.fullmatch(r'(?:[0-9]{6}|[0-9]{8})', password) or not ready()):
                raise DeliveryError(False)
            try:
                # Only the public digit count leaves the broker before format preflight.
                result = pin.channel.call('check-totp', min(3, max(.001, start_deadline - self.clock())),
                                          tab_id=pin.tab_id, document_id=pin.document_id, pin_id=pin.pin_id,
                                          chain=pin.chain, digits=len(password))
                if set(result) != {'ok'} or result.get('ok') is not True:
                    raise ExtensionError()
            except ExtensionError:
                raise DeliveryError(False) from None
        values = dict(mode=mode, username=username if mode in {'login', 'username'} else '',
                      password=password if mode != 'username' else '')
        state = self._deliver(pin, values, ready, start_deadline)
        values.clear()
        if state != 'filled':
            raise DeliveryError(state == 'uncertain')

    def fill_element(self, pin, value, field, ready, deadline=None, *, notify_page=False):
        from .browser_card import failure
        if field != pin.mode:
            return failure(kind=pin.kind)
        deadline = self.clock() + 4 if deadline is None else deadline
        values = dict(value=value)
        if notify_page:
            if pin.kind != 'identity' or not pin.channel.supports((0, 9, 0)):
                return failure(kind=pin.kind)
            values['notify_page'] = True
        state = self._deliver(pin, values, ready, deadline)
        values.clear()
        if state == 'filled':
            return dict(ok=True, filled=field, **{pin.kind + '_delivery': DELIVERY})
        return failure(state == 'uncertain', kind=pin.kind)


class RoutedTargets:
    """Card/identity target manager that adds the extension route to the CDP one."""

    def __init__(self, cdp, hub, kind, *, native=None, android=None):
        self.android = android
        self.cdp, self.hub, self.kind, self.native = cdp, hub, kind, native

    def __getattr__(self, name):
        return getattr(self.cdp, name)

    def __setattr__(self, name, value):
        # Settings such as `profile` or `clock` belong to the CDP manager.
        if name in {'cdp', 'hub', 'kind', 'native', 'android'}:
            object.__setattr__(self, name, value)
        else:
            setattr(self.cdp, name, value)

    def prune(self):
        self.hub.prune()
        self.cdp.prune()

    def capabilities(self):
        return self.cdp.capabilities()

    def pin(self, request):
        from .browser_card import CardTargetError
        route = request.get('route', self.hub.default_route)
        if route == 'extension':
            from . import browser_slots
            browser_slots.refuse_extension(request)
            try:
                return self.hub.pin_element(self.kind, {**request, 'route': 'extension'})
            except ExtensionError:
                raise CardTargetError() from None
        if route != 'cdp':
            raise CardTargetError()
        return self.cdp.pin({k: v for k, v in request.items() if k != 'route'})

    def consume(self, token):
        from .browser_card import CardTargetError
        try:
            pin = self.native.take(token, self.kind) if self.native is not None else None
            if pin is None and self.android is not None:
                pin = self.android.take(token)
                if pin is not None and pin.mode != self.kind:
                    pin.close()
                    raise CardTargetError()
            if pin is None:
                pin = self.hub.take(token, self.kind)
        except TargetError:
            raise CardTargetError() from None
        return pin if pin is not None else self.cdp.consume(token)

    def fill(self, pin, value, field, ready, deadline=None, *, notify_page=False):
        from .native_fields import NativePin
        from .android_route import AndroidPin
        if isinstance(pin, AndroidPin):
            return self.android.fill_element(pin, value, field, ready, deadline, notify_page=notify_page)
        if isinstance(pin, NativePin):
            return self.native.fill(pin, value, field, ready, deadline, notify_page=notify_page)
        if isinstance(pin, ExtensionPin):
            return self.hub.fill_element(pin, value, field, ready, deadline, notify_page=notify_page)
        return self.cdp.fill(pin, value, field, ready, deadline, notify_page=notify_page)

    def _close(self, pin):
        from .native_fields import NativePin
        from .android_route import AndroidPin
        if isinstance(pin, (AndroidPin, ExtensionPin, NativePin)):
            pin.close()
        else:
            self.cdp._close(pin)
