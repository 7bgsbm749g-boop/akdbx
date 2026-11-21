"""Broker side of the akdbx relay (protocol v1): open the private pages from any device.

The relay forwards encrypted TLS connections. TLS ends in this broker, with a
key that never leaves this computer, so the relay cannot read the master
password or any other value on the private pages. The broker trusts nothing
that the relay sends: the private pages keep every check (one-time token,
``Host`` and ``Origin``, the three-attempt link block), and the client checks
each name and certificate that the relay returns.

The relay directory (``relay.json`` and ``tls.pem``) is private: Linux mode
0700/0600 under ``${XDG_STATE_HOME:-~/.local/state}/akdbx/relay``, Windows
this user and SYSTEM only under ``%LOCALAPPDATA%\\akdbx\\relay``. The bearer
secret and the private key are never printed or logged; every message here is
fixed text, a name, an origin, a time or an exception type.
"""
from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, field
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import re
import socket
import ssl
import stat
import sys
import threading
import time
from urllib.parse import urlsplit

from . import __version__

DEFAULT_RELAY = 'https://relay.akdbx.link:8443'
PROTOCOL = 1
CONFIG_NAME = 'relay.json'
TLS_NAME = 'tls.pem'
API_TIMEOUT = 30
# The relay answers a certificate request within its 90 s deadline; wait 10 s more.
CERTIFICATE_TIMEOUT = 120
MAX_RESPONSE = 1024 * 1024
MAX_FILE = 256 * 1024
BROKER_ID = re.compile(r'[a-z2-7]{12}')
SECRET = re.compile(r'[A-Za-z0-9_-]{43}')
STREAM_ID = re.compile(r'[0-9a-f]{32}')
ERROR_CODE = re.compile(r'[a-z_]{1,64}')
DNS_NAME = re.compile(r'(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+')
PEM_CERTIFICATE = re.compile(rb'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?')
MAX_STREAMS = 64
CONTROL_MESSAGE_LIMIT = 4096
# The relay pings every 30 s; with no frame for 90 s the connection is dead.
CONTROL_IDLE_TIMEOUT = 90
# The relay pings idle streams every 30 s and closes them after 5 minutes.
STREAM_IDLE_TIMEOUT = 330
CONNECT_TIMEOUT = 10
MAX_BACKOFF = 60.0
# A control connection that stayed up this long resets the backoff to 1 s.
STABLE_CONNECTION = 30.0
RENEW_CHECK = 6 * 3600.0
RENEW_RETRY_MIN = 300.0


class RelayError(Exception):
    """A relay call failed. The message is fixed text and never holds the secret."""

    def __init__(self, message, *, status=None, code=None, retry_after=None):
        super().__init__(message)
        self.status, self.code, self.retry_after = status, code, retry_after


class RelayStoreError(Exception):
    """The relay directory or one of its files fails the private-file checks."""


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def wait_text(seconds):
    """'about N minutes' style text for a retry_after value."""
    if seconds is None:
        return ''
    if seconds < 90:
        return f'about {max(1, int(seconds))} seconds'
    if seconds < 90 * 60:
        return f'about {round(seconds / 60)} minutes'
    if seconds < 36 * 3600:
        return f'about {round(seconds / 3600)} hours'
    return f'about {round(seconds / 86400)} days'


# Endpoint and control API


@dataclass(frozen=True)
class Endpoint:
    """The relay's control API base URL.

    ``context`` and ``connect_host`` exist for tests: a private CA for the
    relay, and an address to dial while TLS (SNI, certificate check) and the
    ``Host`` header keep the URL's name. Production uses the system trust
    store and DNS.
    """
    url: str
    host: str
    port: int
    context: ssl.SSLContext | None = field(default=None, compare=False, repr=False)
    connect_host: str | None = field(default=None, compare=False)

    @classmethod
    def parse(cls, url, *, context=None, connect_host=None):
        parsed = urlsplit(url.strip() if isinstance(url, str) else '')
        try:
            port = parsed.port
        except ValueError:
            port = -1
        host = (parsed.hostname or '').lower()
        if (parsed.scheme != 'https' or not DNS_NAME.fullmatch(host) or parsed.username is not None
                or parsed.password is not None or parsed.path not in {'', '/'} or parsed.query
                or parsed.fragment or port == -1 or host.count('.') < 2):
            raise ValueError('the relay URL must be an HTTPS origin such as ' + DEFAULT_RELAY)
        port = 443 if port is None else port
        normalized = f'https://{host}' + ('' if port == 443 else f':{port}')
        return cls(normalized, host, port, context, connect_host)

    @property
    def domain(self):
        """Broker names are ``<id>.<domain>``, where the control host is ``relay.<domain>``."""
        return self.host.split('.', 1)[1]

    @property
    def ws_url(self):
        return 'wss://' + self.url[len('https://'):]

    def ssl_context(self):
        if self.context is not None:
            return self.context
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def open_socket(self, timeout):
        """A verified TLS connection to the control host name."""
        raw = socket.create_connection((self.connect_host or self.host, self.port), timeout=timeout)
        try:
            return self.ssl_context().wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class _Connection(http.client.HTTPSConnection):
    def __init__(self, endpoint, timeout):
        super().__init__(endpoint.host, endpoint.port, timeout=timeout, context=endpoint.ssl_context())
        self._endpoint = endpoint

    def connect(self):
        self.sock = self._endpoint.open_socket(self.timeout)


def _retry_after(body_value, header_value):
    for value in (body_value, header_value):
        if type(value) is int and 0 <= value <= 366 * 86400:
            return value
        if isinstance(value, str) and value.isdigit() and int(value) <= 366 * 86400:
            return int(value)
    return None


ERROR_TEXT = {
    'rate_limited': 'the relay limits how often this can be done',
    'registrations_paused': 'the relay is not accepting new registrations now',
    'issuance_paused': 'the relay cannot issue certificates now',
    'acme_failed': 'the certificate authority did not issue the certificate',
    'unauthorized': ("the relay did not accept this broker's secret; run 'akdbx relay disable --forget' "
                     "and then 'akdbx relay enable' for a new name"),
    'unknown_stream': 'the relay does not know this stream',
}


def _describe(status, code, retry_after):
    text = ERROR_TEXT.get(code) or (f'the relay refused the request ({code})' if code
                                    else f'the relay answered HTTP {status}')
    if retry_after is not None:
        text += f'; try again in {wait_text(retry_after)}'
    return text


def _call(endpoint, path, body, *, secret=None, timeout=API_TIMEOUT):
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json',
               'User-Agent': f'akdbx/{__version__}'}
    if secret is not None:
        headers['Authorization'] = 'Bearer ' + secret
    connection = _Connection(endpoint, timeout)
    try:
        connection.request('POST', '/api/v1/' + path, json.dumps(body).encode(), headers)
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE + 1)
        retry_header = response.getheader('Retry-After')
    except (OSError, http.client.HTTPException) as exc:
        # The exception type only: never a request, header or body.
        raise RelayError(f'could not reach the relay at {endpoint.url} ({type(exc).__name__})') from None
    finally:
        connection.close()
    if len(data) > MAX_RESPONSE:
        raise RelayError('the relay sent a response that is too large')
    try:
        payload = json.loads(data) if data else None
    except (ValueError, UnicodeDecodeError):
        payload = None
    if response.status >= 400:
        payload = payload if isinstance(payload, dict) else {}
        code = payload.get('error')
        code = code if isinstance(code, str) and ERROR_CODE.fullmatch(code) else None
        retry = _retry_after(payload.get('retry_after'), retry_header)
        raise RelayError(_describe(response.status, code, retry), status=response.status, code=code,
                         retry_after=retry)
    if not isinstance(payload, dict):
        raise RelayError('the relay sent an invalid response')
    return payload


@dataclass(frozen=True)
class Registration:
    name: str
    broker_id: str
    public_port: int
    secret: str = field(repr=False)


def register(endpoint):
    """POST /register. Check every field: the relay is not trusted to name this broker."""
    payload = _call(endpoint, 'register', {'protocol': PROTOCOL, 'client': f'akdbx/{__version__}'})
    broker_id, name = payload.get('broker_id'), payload.get('name')
    secret, port = payload.get('secret'), payload.get('public_port')
    if (payload.get('protocol', PROTOCOL) != PROTOCOL or not isinstance(broker_id, str)
            or not BROKER_ID.fullmatch(broker_id) or name != f'{broker_id}.{endpoint.domain}'
            or not isinstance(secret, str) or not SECRET.fullmatch(secret)
            or type(port) is not int or not 1 <= port <= 65535):
        raise RelayError('the relay sent an invalid registration')
    return Registration(name, broker_id, port, secret)


# Keys and certificates


def new_key_and_csr(name):
    """A new ECDSA P-256 key (PEM, unencrypted) and a CSR with exactly one DNS name."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
           .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode('ascii')


@dataclass(frozen=True)
class CertificateInfo:
    not_before: datetime.datetime
    not_after: datetime.datetime

    @property
    def renew_at(self):
        """Renew when less than one third of the lifetime remains."""
        return self.not_after - (self.not_after - self.not_before) / 3

    def as_dict(self):
        return {'certificate_not_after': _rfc3339(self.not_after),
                'certificate_renews_after': _rfc3339(self.renew_at)}


def _rfc3339(value):
    return value.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def check_chain(chain_pem, name, key_pem=None):
    """Return the leaf's validity, after checking it is this broker's certificate.

    The leaf (first certificate) must name exactly ``name`` and no address,
    and, with ``key_pem``, hold that key's public key. The browser checks the
    chain against its own trust store.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    blocks = PEM_CERTIFICATE.findall(chain_pem)
    if not blocks or len(blocks) > 8:
        raise RelayError('the relay sent an invalid certificate chain')
    try:
        certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
        leaf = certificates[0]
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except Exception:
        raise RelayError('the relay sent an invalid certificate chain') from None
    if (names.get_values_for_type(x509.DNSName) != [name] or names.get_values_for_type(x509.IPAddress)
            or len(list(names)) != 1):
        raise RelayError('the relay sent a certificate for another name')
    if key_pem is not None:
        key = serialization.load_pem_private_key(key_pem, password=None)
        wanted = key.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
        if leaf.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo) != wanted:
            raise RelayError('the relay sent a certificate for another key')
    info = CertificateInfo(leaf.not_valid_before_utc, leaf.not_valid_after_utc)
    if info.not_after <= info.not_before:
        raise RelayError('the relay sent an invalid certificate chain')
    return info


def request_certificate(endpoint, registration_or_config):
    """New key, CSR and certificate. Return ``(tls_pem, info)``: key first, then the chain."""
    name, secret = registration_or_config.name, registration_or_config.secret
    key_pem, csr_pem = new_key_and_csr(name)
    payload = _call(endpoint, 'certificate', {'csr': csr_pem}, secret=secret, timeout=CERTIFICATE_TIMEOUT)
    chain = payload.get('certificate')
    if not isinstance(chain, str) or len(chain) > MAX_FILE // 2:
        raise RelayError('the relay sent an invalid certificate chain')
    chain_pem = chain.encode('ascii', 'replace')
    info = check_chain(chain_pem, name, key_pem)
    if info.not_after <= _utcnow():
        raise RelayError('the relay sent an expired certificate')
    return key_pem + b''.join(PEM_CERTIFICATE.findall(chain_pem)), info


# Saved configuration


@dataclass
class RelayConfig:
    relay: str
    name: str
    broker_id: str
    public_port: int
    enabled: bool
    secret: str = field(repr=False)

    @property
    def origin(self):
        return f'https://{self.name}' + ('' if self.public_port == 443 else f':{self.public_port}')

    def to_json(self):
        return {'version': 1, 'relay': self.relay, 'name': self.name, 'broker_id': self.broker_id,
                'public_port': self.public_port, 'origin': self.origin, 'enabled': self.enabled,
                'secret': self.secret}

    @classmethod
    def from_json(cls, data):
        try:
            if not isinstance(data, dict) or data.get('version') != 1:
                raise ValueError
            endpoint = Endpoint.parse(data['relay'])
            config = cls(endpoint.url, data['name'], data['broker_id'], data['public_port'],
                         data['enabled'], data['secret'])
            if (not isinstance(config.broker_id, str) or not BROKER_ID.fullmatch(config.broker_id)
                    or config.name != f'{config.broker_id}.{endpoint.domain}'
                    or type(config.public_port) is not int or not 1 <= config.public_port <= 65535
                    or type(config.enabled) is not bool or not isinstance(config.secret, str)
                    or not SECRET.fullmatch(config.secret) or data.get('origin') != config.origin):
                raise ValueError
            return config
        except (KeyError, TypeError, ValueError):
            raise RelayStoreError('the saved relay configuration is malformed') from None

    @classmethod
    def from_registration(cls, endpoint, registration, *, enabled=False):
        return cls(endpoint.url, registration.name, registration.broker_id, registration.public_port,
                   enabled, registration.secret)


def default_directory():
    if os.name == 'nt':
        return Path(os.environ['LOCALAPPDATA']) / 'akdbx' / 'relay'
    base = os.environ.get('XDG_STATE_HOME', '')
    root = Path(base) if os.path.isabs(base) else Path.home() / '.local' / 'state'
    return root / 'akdbx' / 'relay'


class RelayStore:
    """The private relay directory: ``relay.json`` (with the secret) and ``tls.pem`` (key and chain).

    Linux: a 0700 folder of this user below folders that no other user can
    replace, files mode 0600 opened without following symbolic links.
    Windows: a folder and files that only this user and SYSTEM can open, on a
    trusted local NTFS path. A file that fails these checks is refused, never
    repaired.
    """

    def __init__(self, directory=None):
        self.directory = Path(os.path.abspath(directory or default_directory()))

    @property
    def config_path(self):
        return self.directory / CONFIG_NAME

    @property
    def tls_path(self):
        return self.directory / TLS_NAME

    def exists(self):
        try:
            self.directory.lstat()
            return True
        except FileNotFoundError:
            return False

    # Linux

    def _posix_directory(self, *, create):
        from .runtime import prepare_private_runtime_directory, open_private_runtime_directory
        if create:
            for folder in reversed(self.directory.parents):
                with suppress(FileExistsError):
                    os.mkdir(folder, 0o700)
        try:
            opener = prepare_private_runtime_directory if create else open_private_runtime_directory
            return opener(self.directory)[1]
        except (OSError, RuntimeError) as exc:
            raise RelayStoreError(f'{self.directory} must be a folder that you own with mode 0700, below '
                                  'folders owned by you or root that group and others cannot write '
                                  f'({exc})') from None

    def _posix_read(self, name):
        directory = self._posix_directory(create=False)
        try:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            except FileNotFoundError:
                return None
            except OSError:
                raise RelayStoreError(f'{self.directory / name} must be a regular file') from None
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_FILE):
                    raise RelayStoreError(f'{self.directory / name} must be a regular file that you own '
                                          'with mode 0600')
                data = b''
                while len(data) <= MAX_FILE:
                    chunk = os.read(fd, MAX_FILE + 1 - len(data))
                    if not chunk:
                        break
                    data += chunk
                if len(data) > MAX_FILE:
                    raise RelayStoreError(f'{self.directory / name} is too large')
                return data
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    def _posix_write(self, name, data):
        directory = self._posix_directory(create=True)
        temporary = f'.{name}.{os.urandom(8).hex()}'
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)
            os.close(directory)

    # Windows

    def _windows(self, *, create):
        from . import windows_security
        if not create and not self.directory.exists():
            return None
        try:
            if create:
                windows_security.ensure_private_directory(self.directory.parent)
            windows_security.ensure_private_directory(self.directory)
        except Exception:
            raise RelayStoreError(f'{self.directory} must be a folder that only this user, SYSTEM and '
                                  'administrators can access') from None
        return windows_security

    def _windows_read(self, name):
        security = self._windows(create=False)
        if security is None:
            return None
        try:
            return security.read_private_optional(self.directory / name, limit=MAX_FILE)
        except Exception:
            raise RelayStoreError(f'{self.directory / name} must be a file that only this user and SYSTEM '
                                  'can open') from None

    def _windows_write(self, name, data):
        security = self._windows(create=True)
        try:
            security.replace_private(self.directory / name, data)
        except Exception:
            raise RelayStoreError(f'{self.directory / name} could not be saved') from None

    # Shared

    def _read(self, name):
        if not self.exists():
            return None
        return self._windows_read(name) if os.name == 'nt' else self._posix_read(name)

    def _write(self, name, data):
        if os.name == 'nt':
            self._windows_write(name, data)
        else:
            self._posix_write(name, data)

    def load(self):
        """The saved configuration, or None when there is none. Raise RelayStoreError when untrusted."""
        data = self._read(CONFIG_NAME)
        if data is None:
            return None
        try:
            parsed = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            raise RelayStoreError('the saved relay configuration is malformed') from None
        return RelayConfig.from_json(parsed)

    def save(self, config):
        self._write(CONFIG_NAME, json.dumps(config.to_json(), indent=2).encode() + b'\n')

    def read_tls(self):
        return self._read(TLS_NAME)

    def save_tls(self, data):
        self._write(TLS_NAME, data)

    def certificate(self, name):
        """The saved certificate's validity, or None without a usable key and certificate."""
        data = self.read_tls()
        if data is None:
            return None
        key_start = data.find(b'-----BEGIN PRIVATE KEY-----')
        key_end = data.find(b'-----END PRIVATE KEY-----')
        if key_start != 0 or key_end < 0:
            return None
        try:
            return check_chain(data[key_end:], name, data[:key_end + len(b'-----END PRIVATE KEY-----\n')])
        except Exception:
            return None

    def forget(self):
        """Delete the saved files and the folder. The registration on the relay expires unused."""
        if not self.exists():
            return
        if os.name != 'nt':
            directory = self._posix_directory(create=False)
            try:
                for name in (TLS_NAME, CONFIG_NAME, '.relay.lock'):
                    with suppress(FileNotFoundError):
                        os.unlink(name, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            self._windows(create=False)
            for name in (TLS_NAME, CONFIG_NAME):
                with suppress(FileNotFoundError):
                    (self.directory / name).unlink()
        with suppress(OSError):
            os.rmdir(self.directory)

    def lock(self):
        """Hold the relay for one broker. Raise RelayStoreError when another process holds it.

        One registration has one control connection: a second broker would
        replace the first one's connection again and again.
        """
        if os.name == 'nt':
            import win32api
            import win32event
            digest = hashlib.sha256(os.path.normcase(str(self.directory)).encode()).hexdigest()[:32]
            handle = win32event.CreateMutex(None, False, f'Local\\akdbx-relay-{digest}')
            if win32api.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
                handle.Close()
                raise RelayStoreError('another akdbx process uses the relay now')
            return _Held(handle.Close)
        from .runtime import acquire_lifecycle_lock
        directory = self._posix_directory(create=True)
        try:
            descriptor = acquire_lifecycle_lock(directory, 'relay')
        except RuntimeError:
            raise RelayStoreError('another akdbx process uses the relay now') from None
        finally:
            os.close(directory)
        return _Held(lambda: os.close(descriptor))


class _Held:
    def __init__(self, release):
        self._release = release

    def release(self):
        release, self._release = self._release, None
        if release is not None:
            release()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()


def saved_origin(store=None):
    """The origin of an enabled, trusted saved relay configuration, else None."""
    store = store or RelayStore()
    try:
        config = store.load()
    except Exception:
        return None
    return config.origin if config is not None and config.enabled else None


# Enable


def call_with_retry(call, *, max_wait=300.0, sleep=time.sleep, notify=None):
    """Retry a 429 or 503 answer while its retry_after fits in ``max_wait`` seconds in total."""
    waited = 0.0
    while True:
        try:
            return call()
        except RelayError as exc:
            if exc.status not in (429, 503) or exc.retry_after is None or waited + exc.retry_after > max_wait:
                raise
            if notify is not None:
                notify(f'{exc}; waiting')
            sleep(max(1, exc.retry_after))
            waited += max(1, exc.retry_after)


def enable(store, endpoint, *, sleep=time.sleep, notify=None):
    """Register (once), get a certificate when none is usable, and mark the relay enabled.

    The registration is saved before the certificate request, so a failed
    request is resumed by the next ``enable`` without a new registration.
    Return ``(config, certificate_info, created)``.
    """
    config = store.load()
    created = False
    if config is not None and config.relay != endpoint.url:
        raise RelayError(f'this broker is registered with {config.relay}; run '
                         "'akdbx relay disable --forget' before you use another relay")
    if config is None:
        registration = call_with_retry(lambda: register(endpoint), sleep=sleep, notify=notify)
        config = RelayConfig.from_registration(endpoint, registration)
        store.save(config)
        created = True
    info = store.certificate(config.name)
    if info is None or info.renew_at <= _utcnow():
        tls_pem, info = call_with_retry(lambda: request_certificate(endpoint, config), sleep=sleep,
                                        notify=notify)
        store.save_tls(tls_pem)
    if not config.enabled:
        config.enabled = True
        store.save(config)
    return config, info, created


# Relay client


def _log(message):
    print('akdbx relay: ' + message, file=sys.stderr, flush=True)


class RelayClient:
    """Keep the control WebSocket up, splice each stream to the loopback page, renew the certificate.

    ``reload_tls`` loads the renewed ``tls.pem`` into the running page; open
    connections keep their TLS session, new ones get the new certificate.
    """

    def __init__(self, endpoint, config, store, local_port, *, reload_tls, certificate=None,
                 log=_log, clock=_utcnow, monotonic=time.monotonic, jitter=random.random,
                 max_streams=MAX_STREAMS):
        self.endpoint, self.config, self.store, self.local_port = endpoint, config, store, local_port
        self._reload_tls, self._log, self._clock = reload_tls, log, clock
        self._monotonic, self._jitter = monotonic, jitter
        self.certificate = certificate if certificate is not None else store.certificate(config.name)
        self._stop = threading.Event()
        self.connected = threading.Event()
        self._lock = threading.Lock()
        self._control = None
        self._live = set()
        self._slots = threading.BoundedSemaphore(max_streams)
        self._threads = []
        self.streams_opened = 0
        self.renewal_failures = 0
        self.last_renewal_error = None
        self.delays = []  # the reconnect waits, for tests and status

    # Lifecycle

    def start(self):
        for target, name in ((self._control_loop, 'akdbx-relay-control'),
                             (self._renew_loop, 'akdbx-relay-renew')):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def stop(self, timeout=5):
        self._stop.set()
        with self._lock:
            sockets = list(self._live)
            control = self._control
        for item in ([control] if control is not None else []) + sockets:
            _abort(item)
        for thread in self._threads:
            thread.join(timeout)

    def status(self):
        result = {'connected': self.connected.is_set(), 'name': self.config.name, 'origin': self.config.origin}
        if self.certificate is not None:
            result.update(self.certificate.as_dict())
        if self.last_renewal_error is not None:
            result['renewal_error'] = self.last_renewal_error
        return result

    # WebSockets

    def _websocket(self, path, timeout):
        import websocket
        sock = self.endpoint.open_socket(CONNECT_TIMEOUT)
        try:
            ws = websocket.WebSocket(enable_multithread=True, skip_utf8_validation=True)
            ws.settimeout(CONNECT_TIMEOUT)
            ws.connect(self.endpoint.ws_url + path, socket=sock, suppress_origin=True,
                       header=['Authorization: Bearer ' + self.config.secret])
            ws.settimeout(timeout)
            return ws
        except BaseException:
            _abort(sock)
            raise

    def _control_loop(self):
        delay = 1.0
        down_reported = False
        while not self._stop.is_set():
            started = None
            try:
                ws = self._websocket('/api/v1/connect', CONTROL_IDLE_TIMEOUT)
            except Exception as exc:
                if not down_reported:
                    self._log(f'cannot connect to {self.endpoint.url} ({_reason(exc)}); retrying')
                    down_reported = True
            else:
                with self._lock:
                    if self._stop.is_set():
                        _abort(ws)
                        break
                    self._control = ws
                started = self._monotonic()
                self.connected.set()
                down_reported = False
                self._log(f'connected; the private pages are at {self.config.origin}')
                try:
                    self._control_session(ws)
                except Exception as exc:
                    if not self._stop.is_set():
                        self._log(f'control connection lost ({_reason(exc)}); reconnecting')
                        down_reported = True
                finally:
                    self.connected.clear()
                    with self._lock:
                        self._control = None
                    _abort(ws)
            if self._stop.is_set():
                break
            if started is not None and self._monotonic() - started >= STABLE_CONNECTION:
                delay = 1.0
            wait = delay * (0.5 + 0.5 * self._jitter())
            self.delays.append(wait)
            self._stop.wait(wait)
            delay = min(delay * 2, MAX_BACKOFF)

    def _control_session(self, ws):
        import websocket
        while not self._stop.is_set():
            opcode, data = ws.recv_data()
            if opcode == websocket.ABNF.OPCODE_CLOSE:
                raise ConnectionError('closed by the relay')
            if opcode != websocket.ABNF.OPCODE_TEXT:
                raise ConnectionError('unexpected binary frame')
            if len(data) > CONTROL_MESSAGE_LIMIT:
                continue
            try:
                message = json.loads(data)
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(message, dict):
                continue
            kind = message.get('type')
            if kind == 'ping':
                ws.send('{"type":"pong"}')
            elif kind == 'open':
                stream = message.get('stream')
                if isinstance(stream, str) and STREAM_ID.fullmatch(stream):
                    self._open_stream(stream)
            # Unknown message types are ignored, as the protocol requires.

    def _open_stream(self, stream):
        if not self._slots.acquire(blocking=False):
            return  # Too many streams: the relay times this one out.
        try:
            threading.Thread(target=self._stream, args=(stream,), name='akdbx-relay-stream', daemon=True).start()
        except BaseException:
            self._slots.release()
            raise

    def _track(self, item):
        with self._lock:
            if self._stop.is_set():
                _abort(item)
                raise ConnectionError('stopping')
            self._live.add(item)

    def _stream(self, stream):
        ws = local = None
        try:
            ws = self._websocket(f'/api/v1/stream/{stream}', STREAM_IDLE_TIMEOUT)
            self._track(ws)
            local = socket.create_connection(('127.0.0.1', self.local_port), timeout=CONNECT_TIMEOUT)
            local.settimeout(STREAM_IDLE_TIMEOUT)
            self._track(local)
            with self._lock:
                self.streams_opened += 1
            upstream = threading.Thread(target=_local_to_ws, args=(local, ws), name='akdbx-relay-stream-up',
                                        daemon=True)
            upstream.start()
            _ws_to_local(ws, local)
            with suppress(OSError):
                local.shutdown(socket.SHUT_RDWR)
            upstream.join(10)
        except Exception:
            pass  # The phone sees a closed connection; nothing secret to report.
        finally:
            with self._lock:
                self._live.discard(ws)
                self._live.discard(local)
            for item in (ws, local):
                if item is not None:
                    _abort(item)
            self._slots.release()

    # Renewal

    def _renew_loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.renew_if_due())

    def renew_if_due(self):
        """Renew when less than a third of the lifetime remains; return seconds until the next check."""
        now = self._clock()
        if self.certificate is not None and now < self.certificate.renew_at:
            return max(60.0, min((self.certificate.renew_at - now).total_seconds(), RENEW_CHECK))
        try:
            tls_pem, info = request_certificate(self.endpoint, self.config)
            self.store.save_tls(tls_pem)
            self._reload_tls(self.store.tls_path)
        except Exception as exc:
            self.renewal_failures += 1
            self.last_renewal_error = str(exc) if isinstance(exc, (RelayError, RelayStoreError)) else _reason(exc)
            retry = getattr(exc, 'retry_after', None) or 0
            delay = max(float(retry), min(RENEW_RETRY_MIN * 2 ** (self.renewal_failures - 1), RENEW_CHECK))
            self._log(f'certificate renewal failed ({self.last_renewal_error}); next try in {wait_text(delay)}')
            return delay
        self.certificate = info
        self.renewal_failures = 0
        self.last_renewal_error = None
        self._log(f'renewed the certificate for {self.config.name}; valid until {_rfc3339(info.not_after)}')
        return max(60.0, min((info.renew_at - self._clock()).total_seconds(), RENEW_CHECK))


def _reason(exc):
    status = getattr(exc, 'status_code', None) or getattr(exc, 'status', None)
    return f'{type(exc).__name__} {status}' if isinstance(status, int) else type(exc).__name__


def _abort(item):
    """Close a socket or WebSocket now, waking any thread blocked on it."""
    sock = getattr(item, 'sock', item)
    if sock is not None:
        with suppress(OSError, AttributeError):
            sock.shutdown(socket.SHUT_RDWR)
    with suppress(Exception):
        if hasattr(item, 'shutdown') and hasattr(item, 'sock'):
            item.shutdown()
        else:
            item.close()


def _ws_to_local(ws, local):
    import websocket
    while True:
        opcode, data = ws.recv_data()
        if opcode != websocket.ABNF.OPCODE_BINARY:
            return  # A close ends the stream; a text frame is a protocol error.
        local.sendall(data)


def _local_to_ws(local, ws):
    import websocket
    try:
        while True:
            data = local.recv(65536)
            if not data:
                break
            ws.send(data, websocket.ABNF.OPCODE_BINARY)
    except Exception:
        pass
    # Ask the relay to close; its close reply ends the reading side.
    with suppress(Exception):
        ws.send_close()
