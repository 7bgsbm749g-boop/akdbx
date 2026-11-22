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

DEFAULT_RELAY = 'https://relay.akdbx.link'
# Brokers registered before 0.28.0 saved this URL; it names the same relay.
OLD_DEFAULT_RELAY = 'https://relay.akdbx.link:8443'
PROTOCOL = 1
CONFIG_NAME = 'relay.json'
TLS_NAME = 'tls.pem'
LOCK_NAME = '.relay.lock'
# A new registration that `akdbx relay rotate` saved before its certificate arrived.
ROTATE_NAME = 'rotate.json'
API_TIMEOUT = 30
# The relay answers a certificate request within its 90 s deadline; wait 10 s more.
CERTIFICATE_TIMEOUT = 120
MAX_RESPONSE = 1024 * 1024
MAX_FILE = 256 * 1024
BROKER_ID = re.compile(r'[a-z2-7]{12}')
SECRET = re.compile(r'[A-Za-z0-9_-]{43}')
STREAM_ID = re.compile(r'[0-9a-f]{32}')
DNS_NAME = re.compile(r'(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+')
PEM_CERTIFICATE = re.compile(rb'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?')
MAX_STREAMS = 64
# Protocol v1 limits: a control message is at most 4 KiB, a stream message at
# most 256 KiB, and a message has at most 256 fragments.
CONTROL_MESSAGE_LIMIT = 4096
STREAM_MESSAGE_LIMIT = 256 * 1024
MAX_FRAGMENTS = 256
# The relay pings every 30 s; with no frame for 90 s the connection is dead.
CONTROL_IDLE_TIMEOUT = 90
# The relay pings idle streams every 30 s and closes them after 5 minutes.
STREAM_IDLE_TIMEOUT = 330
CONNECT_TIMEOUT = 10
# The most the broker reads from the relay before the 101 upgrade answer is
# accepted: status line, headers and any error body. websocket-client reads a
# non-101 body by its Content-Length into memory, so a larger answer aborts the
# connection instead.
UPGRADE_RESPONSE_LIMIT = 64 * 1024
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


class RelayUnreachable(RelayError):
    """The relay could not be reached (connection or TLS failure); no answer was read."""


class RelayStoreError(Exception):
    """The relay directory or one of its files fails the private-file checks."""


class RelayBusy(Exception):
    """Another akdbx process (a running broker) holds the relay lock. Not a trust failure."""


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
    if seconds < 48 * 3600:
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
                or parsed.fragment or port == -1 or port == 0 or host.count('.') < 2):
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


def endpoint(url):
    """The production endpoint for a saved or given relay URL (tests replace this)."""
    return Endpoint.parse(url)


def _endpoint_for(url):
    # Looked up at call time, so a test's replacement of ``endpoint`` applies.
    return endpoint(url)


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
    # Only fixed text: a relay-supplied code could echo the bearer secret.
    text = ERROR_TEXT.get(code) or f'the relay answered HTTP {status}'
    if retry_after is not None:
        text += f'; try again in {wait_text(retry_after)}'
    return text


def _call(endpoint, path, body, *, secret=None, timeout=API_TIMEOUT, method='POST'):
    headers = {'Accept': 'application/json', 'User-Agent': f'akdbx/{__version__}'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if secret is not None:
        headers['Authorization'] = 'Bearer ' + secret
    connection = _Connection(endpoint, timeout)
    try:
        connection.request(method, '/api/v1/' + path, None if body is None else json.dumps(body).encode(),
                           headers)
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE + 1)
        retry_header = response.getheader('Retry-After')
    except (OSError, http.client.HTTPException) as exc:
        # The exception type only: never a request, header or body.
        raise RelayUnreachable(f'could not reach the relay at {endpoint.url} ({type(exc).__name__})') from None
    finally:
        connection.close()
    if len(data) > MAX_RESPONSE:
        raise RelayError('the relay sent a response that is too large')
    if 300 <= response.status < 400:
        # Never followed: a redirect would resend the bearer secret to another address.
        raise RelayError(f'the relay answered HTTP {response.status} (a redirect, not followed)',
                         status=response.status)
    try:
        payload = json.loads(data) if data else None
    except (ValueError, UnicodeDecodeError):
        payload = None
    if response.status >= 400:
        payload = payload if isinstance(payload, dict) else {}
        code = payload.get('error')
        code = code if isinstance(code, str) and code in ERROR_TEXT else None
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


@dataclass(frozen=True)
class BrokerInfo:
    """What the relay says about this broker now: its public port and, if it moved, its control URL."""
    public_port: int
    relay_url: str | None


def same_relay(first, second):
    """True when two saved or given relay URLs name the same control host (only the port may differ)."""
    try:
        return Endpoint.parse(first).host == Endpoint.parse(second).host
    except ValueError:
        return False


def broker_info(endpoint, config):
    """GET /broker. Check every field: the relay is not trusted to move this broker to another name or host.

    The answer must name this broker exactly, give a port in 1..65535 and, if
    it gives a control URL, an HTTPS origin on the same host as the saved one
    (only the port may differ). Older relays answer 404 (a RelayError).
    """
    payload = _call(endpoint, 'broker', None, secret=config.secret, method='GET')
    port, url = payload.get('public_port'), payload.get('relay_url')
    if (payload.get('protocol', PROTOCOL) != PROTOCOL or payload.get('name') != config.name
            or type(port) is not int or not 1 <= port <= 65535):
        raise RelayError('the relay sent an invalid broker description')
    if url is None:
        return BrokerInfo(port, None)
    try:
        if not isinstance(url, str) or urlsplit(url).path not in {'', '/'}:
            raise ValueError
        given = Endpoint.parse(url)
    except ValueError:
        raise RelayError('the relay sent an invalid control URL') from None
    if given.host != Endpoint.parse(config.relay).host:
        raise RelayError('the relay sent a control URL on another host')
    return BrokerInfo(port, given.url)


@dataclass(frozen=True)
class Refresh:
    """The result of ``refresh``: the config to use, what changed (fixed text) and any warning."""
    config: 'RelayConfig'
    changes: tuple = ()
    warning: str | None = None


def _alternate(config, alternate):
    """``alternate`` when it is another URL of the saved relay host, else None."""
    try:
        if alternate and alternate != config.relay and same_relay(config.relay, alternate):
            return Endpoint.parse(alternate).url
    except ValueError:
        pass
    return None


def refresh(store, config, endpoint_factory=None, alternate=DEFAULT_RELAY):
    """Ask the relay for this broker's public port and control URL; save them when they changed.

    The relay moves brokers to a new public port (8443 to 443) with this call.
    When the saved URL cannot be reached (for example, the old port is closed),
    ask once more at ``alternate`` if it is on the same host: the answer is
    checked the same way, so the secret only goes to the same verified host.
    Any failure (an older relay's 404, no network, a refused or invalid answer)
    keeps the saved values and returns a warning: the broker still starts.
    """
    endpoint_factory = endpoint_factory or _endpoint_for
    try:
        try:
            info = broker_info(endpoint_factory(config.relay), config)
        except RelayUnreachable:
            other = _alternate(config, alternate)
            if other is None:
                raise
            info = broker_info(endpoint_factory(other), config)
            if info.relay_url is None:
                info = BrokerInfo(info.public_port, other)
    except RelayError as exc:
        if exc.status == 404:
            return Refresh(config, (), f'the relay at {config.relay} cannot report a new public port '
                                       '(an older relay); keeping the saved one')
        return Refresh(config, (), f'could not check the public port with the relay ({exc}); keeping '
                                   'the saved one')
    except (OSError, ValueError) as exc:
        return Refresh(config, (), f'could not check the public port with the relay ({type(exc).__name__}); '
                                   'keeping the saved one')
    changes = []
    relay_url = info.relay_url or config.relay
    if info.public_port != config.public_port:
        changes.append(f'relay moved the public port from {config.public_port} to {info.public_port}')
    if relay_url != config.relay:
        changes.append(f'relay moved its control URL from {config.relay} to {relay_url}')
    if not changes:
        return Refresh(config)
    updated = RelayConfig(relay_url, config.name, config.broker_id, info.public_port, config.enabled,
                          config.secret)
    try:
        store.save(updated)  # atomic: a temporary private file, then a rename
    except (RelayStoreError, OSError) as exc:
        reason = exc if isinstance(exc, RelayStoreError) else type(exc).__name__
        return Refresh(config, (), f'the relay moved this broker, but the change could not be saved ({reason}); '
                                   'keeping the saved values')
    return Refresh(updated, tuple(changes))


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


class PrivateFolder:
    """A private folder of small files, read and written with the same checks as the relay files.

    Linux: a 0700 folder of this user below folders that no other user can
    replace, files mode 0600 opened without following symbolic links.
    Windows: a folder and files that only this user and SYSTEM can open, on a
    trusted local NTFS path. A file that fails these checks is refused, never
    repaired. Failures raise ``self.error`` with fixed text and a path.
    """
    error = RelayStoreError

    def __init__(self, directory):
        self.directory = Path(os.path.abspath(directory))

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
            raise self.error(f'{self.directory} must be a folder that you own with mode 0700, below '
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
                raise self.error(f'{self.directory / name} must be a regular file') from None
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_FILE):
                    raise self.error(f'{self.directory / name} must be a regular file that you own '
                                     'with mode 0600')
                data = b''
                while len(data) <= MAX_FILE:
                    chunk = os.read(fd, MAX_FILE + 1 - len(data))
                    if not chunk:
                        break
                    data += chunk
                if len(data) > MAX_FILE:
                    raise self.error(f'{self.directory / name} is too large')
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
            raise self.error(f'{self.directory} must be a folder that only this user, SYSTEM and '
                             'administrators can access') from None
        return windows_security

    def _windows_read(self, name):
        security = self._windows(create=False)
        if security is None:
            return None
        try:
            return security.read_private_optional(self.directory / name, limit=MAX_FILE)
        except Exception:
            raise self.error(f'{self.directory / name} must be a file that only this user and SYSTEM '
                             'can open') from None

    def _windows_write(self, name, data):
        security = self._windows(create=True)
        try:
            security.replace_private(self.directory / name, data)
        except Exception:
            raise self.error(f'{self.directory / name} could not be saved') from None

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

    def remove(self, name):
        """Delete one file of this folder by its fixed name; a missing file is fine."""
        if not self.exists():
            return
        if os.name != 'nt':
            directory = self._posix_directory(create=False)
            try:
                with suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            self._windows(create=False)
            with suppress(FileNotFoundError):
                (self.directory / name).unlink()


class RelayStore(PrivateFolder):
    """The private relay directory: ``relay.json`` (with the secret) and ``tls.pem`` (key and chain).

    ``rotate.json`` holds a new registration while ``akdbx relay rotate`` gets
    its certificate. The folder and file checks are ``PrivateFolder``'s.
    """

    def __init__(self, directory=None):
        super().__init__(directory or default_directory())

    @property
    def config_path(self):
        return self.directory / CONFIG_NAME

    @property
    def tls_path(self):
        return self.directory / TLS_NAME

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

    def load_rotation(self):
        """The new registration of an unfinished ``relay rotate``, or None."""
        data = self._read(ROTATE_NAME)
        if data is None:
            return None
        try:
            parsed = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            raise RelayStoreError('the saved relay rotation is malformed') from None
        return RelayConfig.from_json(parsed)

    def save_rotation(self, config):
        self._write(ROTATE_NAME, json.dumps(config.to_json(), indent=2).encode() + b'\n')

    def clear_rotation(self):
        self.remove(ROTATE_NAME)

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
        """Delete the saved files by their fixed names, without reading them, and the empty folder.

        Only the folder is checked, so this also removes untrusted or malformed
        files. The registration on the relay expires unused.
        """
        if not self.exists():
            return
        if os.name != 'nt':
            directory = self._posix_directory(create=False)
            try:
                for name in (TLS_NAME, CONFIG_NAME, ROTATE_NAME, LOCK_NAME):
                    with suppress(FileNotFoundError):
                        os.unlink(name, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            self._windows(create=False)
            for name in (TLS_NAME, CONFIG_NAME, ROTATE_NAME):
                with suppress(FileNotFoundError):
                    (self.directory / name).unlink()
        with suppress(OSError):
            os.rmdir(self.directory)

    def remove_folder(self):
        """After ``forget`` and the lock release: delete the lock file and the empty folder.

        Windows cannot delete the lock file while this process holds it open,
        and never deletes one that another process holds.
        """
        if not self.exists():
            return
        if os.name == 'nt':
            self._windows(create=False)
            with suppress(OSError):
                (self.directory / LOCK_NAME).unlink()
        with suppress(OSError):
            os.rmdir(self.directory)

    def lock(self):
        """Hold the relay for one broker.

        Raise RelayBusy when another process holds it, and RelayStoreError when
        the folder or the lock file fails the private-file checks. One
        registration has one control connection: a second broker would replace
        the first one's connection again and again.

        The lock is the file ``.relay.lock`` in the relay folder, held open for
        the broker's lifetime: Linux takes an exclusive ``flock``; Windows opens
        it with share mode 0, which every logon session sees.
        """
        if os.name == 'nt':
            return self._windows_lock()
        from .runtime import acquire_lifecycle_lock
        directory = self._posix_directory(create=True)
        try:
            descriptor = acquire_lifecycle_lock(directory, 'relay')  # opens LOCK_NAME
        except RuntimeError as exc:
            if isinstance(exc.__cause__, BlockingIOError):
                raise RelayBusy('another akdbx process uses the relay now') from None
            raise RelayStoreError(f'{self.directory / LOCK_NAME} must be a regular file that you own '
                                  'with mode 0600') from None
        except OSError:
            raise RelayStoreError(f'{self.directory / LOCK_NAME} must be a regular file that you own '
                                  'with mode 0600') from None
        finally:
            os.close(directory)
        return _Held(lambda: os.close(descriptor))

    def _windows_lock(self):
        import pywintypes
        import win32con
        import win32file
        security = self._windows(create=True)
        path = self.directory / LOCK_NAME
        try:
            # Share mode 0: no other process, in any logon session, can open
            # the file until this handle closes (or this process exits).
            handle = win32file.CreateFile(
                str(path), win32con.GENERIC_READ | win32con.GENERIC_WRITE | win32con.READ_CONTROL, 0,
                security.private_attributes(), win32con.OPEN_ALWAYS, security.FILE_FLAG_OPEN_REPARSE_POINT,
                None)
        except pywintypes.error as exc:
            if exc.winerror == 32:  # ERROR_SHARING_VIOLATION
                raise RelayBusy('another akdbx process uses the relay now') from None
            raise RelayStoreError(f'{path} must be a file that only this user and SYSTEM can open') from None
        try:
            info = win32file.GetFileInformationByHandle(handle)
            if (info[0] & (win32con.FILE_ATTRIBUTE_REPARSE_POINT | win32con.FILE_ATTRIBUTE_DIRECTORY)
                    or info[7] != 1):
                raise PermissionError('the relay lock must be a regular, unlinked file')
            security.check_acl(handle)
        except Exception:
            handle.Close()
            raise RelayStoreError(f'{path} must be a file that only this user and SYSTEM can open') from None
        return _Held(handle.Close)


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


def enable(store, endpoint, *, sleep=time.sleep, notify=None, endpoint_factory=None, refreshed=None):
    """Register (once), get a certificate when none is usable, and mark the relay enabled.

    The registration is saved before the certificate request, so a failed
    request is resumed by the next ``enable`` without a new registration.
    A saved registration first asks the relay for its current public port and
    control URL (``refresh``); the result goes to the ``refreshed`` list.
    A saved URL on the same host with another port is the same relay.
    Return ``(config, certificate_info, created)``.
    """
    config = store.load()
    created = False
    if store.load_rotation() is not None:
        # Its new name may already own tls.pem: a certificate for the old name would replace it.
        raise RelayError("an earlier 'akdbx relay rotate' did not finish; run 'akdbx relay rotate' again")
    if config is not None and not same_relay(config.relay, endpoint.url):
        raise RelayError(f'this broker is registered with {config.relay}; run '
                         "'akdbx relay disable --forget' before you use another relay")
    if config is not None:
        given, fallback = endpoint, endpoint_factory or _endpoint_for
        factory = lambda url: given if url == given.url else fallback(url)  # noqa: E731
        result = refresh(store, config, factory, alternate=endpoint.url)
        if refreshed is not None:
            refreshed.append(result)
        config = result.config
        if config.relay != endpoint.url:
            endpoint = factory(config.relay)
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


# Rotate


@dataclass(frozen=True)
class Rotation:
    """The result of ``rotate``: the configuration before and after, and the new certificate."""
    previous: 'RelayConfig'
    config: 'RelayConfig'
    certificate: CertificateInfo
    resumed: bool


def _same_registration(pending, config):
    return (same_relay(pending.relay, config.relay) and pending.name == config.name
            and pending.broker_id == config.broker_id and pending.secret == config.secret)


def rotate(store, *, sleep=time.sleep, notify=None, endpoint_factory=None):
    """Register a new name with the saved relay, get its certificate, then switch the saved files to it.

    The caller holds the relay lock, so no broker uses the files meanwhile.
    The new registration is saved in ``rotate.json`` before the certificate
    request: a failed or rate-limited request is resumed by the next call
    without another registration. The switch writes ``tls.pem`` (new key and
    chain), then ``relay.json``, then deletes ``rotate.json``; each write is a
    private temporary file and a rename. After an interruption between the two
    writes, the next call sees that ``tls.pem`` already holds the new name and
    only finishes the switch; after one between the ``relay.json`` write and
    the delete, it only deletes ``rotate.json``. The old name is no longer
    used; the relay has no call to delete it. Return a ``Rotation``.
    """
    config = store.load()
    if config is None:
        raise RelayError("this broker has no relay registration; run 'akdbx relay enable' first")
    endpoint = (endpoint_factory or _endpoint_for)(config.relay)
    pending = store.load_rotation()
    if pending is not None and _same_registration(pending, config):
        # The switch was saved, but rotate.json was not deleted: finish it and never register again.
        info = store.certificate(config.name)
        if info is not None and info.renew_at > _utcnow():
            store.clear_rotation()
            return Rotation(config, config, info, True)
    elif pending is not None and (not same_relay(pending.relay, config.relay) or pending.name == config.name):
        store.clear_rotation()  # Left from another relay, or not this registration: start again.
        pending = None
    resumed = pending is not None
    if pending is None:
        registration = call_with_retry(lambda: register(endpoint), sleep=sleep, notify=notify)
        pending = RelayConfig.from_registration(endpoint, registration, enabled=config.enabled)
        if pending.name == config.name:
            raise RelayError('the relay sent the current name again')
        store.save_rotation(pending)
    info = store.certificate(pending.name)
    if info is None or info.renew_at <= _utcnow():
        tls_pem, info = call_with_retry(lambda: request_certificate(endpoint, pending), sleep=sleep,
                                        notify=notify)
        store.save_tls(tls_pem)
    switched = RelayConfig(pending.relay, pending.name, pending.broker_id, pending.public_port, config.enabled,
                           pending.secret)
    store.save(switched)
    store.clear_rotation()
    return Rotation(config, switched, info, resumed)


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
                 max_streams=MAX_STREAMS, wait=None, moved=()):
        self.endpoint, self.config, self.store, self.local_port = endpoint, config, store, local_port
        self.moved = tuple(moved)  # what the refresh at serve start changed (fixed text)
        self._reload_tls, self._log, self._clock = reload_tls, log, clock
        self._monotonic, self._jitter = monotonic, jitter
        self.certificate = certificate if certificate is not None else store.certificate(config.name)
        self._stop = threading.Event()
        self._wait = wait or self._stop.wait
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
        if self.moved:
            result['moved'] = list(self.moved)
        return result

    # WebSockets

    def _websocket(self, path, timeout):
        import websocket
        sock = self.endpoint.open_socket(CONNECT_TIMEOUT)
        try:
            ws = websocket.WebSocket(enable_multithread=True, skip_utf8_validation=True)
            ws.settimeout(CONNECT_TIMEOUT)
            # redirect_limit=0: a redirect would resend the bearer secret on a
            # new, unverified connection (even ws://) and let the relay make
            # this broker connect to its local network. Only 101 is accepted;
            # anything else is a failed attempt with the normal backoff.
            # The upgrade reads go through a byte budget; the verified socket
            # itself is unchanged and carries the frames after the 101.
            ws.connect(self.endpoint.ws_url + path, socket=_UpgradeBudget(sock, UPGRADE_RESPONSE_LIMIT),
                       suppress_origin=True, redirect_limit=0,
                       header=['Authorization: Bearer ' + self.config.secret])
            if ws.getstatus() != 101:
                raise ConnectionError('the relay did not switch protocols')
            ws.sock = sock
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
            self._wait(wait)
            delay = min(delay * 2, MAX_BACKOFF)

    def _control_session(self, ws):
        import websocket
        while not self._stop.is_set():
            opcode, data = _recv_message(ws, CONTROL_MESSAGE_LIMIT)
            if opcode == websocket.ABNF.OPCODE_CLOSE:
                raise ConnectionError('closed by the relay')
            if opcode != websocket.ABNF.OPCODE_TEXT:
                raise ConnectionError('unexpected binary frame')
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


class UpgradeTooLarge(ConnectionError):
    """The relay's upgrade answer was over UPGRADE_RESPONSE_LIMIT; the connection is aborted."""


class _UpgradeBudget:
    """A socket view that reads at most `limit` bytes, for the HTTP upgrade only.

    Every other attribute is the wrapped socket's, so TLS stays the verified
    connection from Endpoint.open_socket. At the limit the socket is aborted.
    """

    def __init__(self, sock, limit):
        self._sock = sock
        self._left = limit

    def recv(self, bufsize, *flags):
        if self._left <= 0:
            _abort(self._sock)
            raise UpgradeTooLarge(f'the relay upgrade answer is over {UPGRADE_RESPONSE_LIMIT} bytes')
        data = self._sock.recv(min(bufsize, self._left), *flags)
        self._left -= len(data)
        return data

    def __getattr__(self, name):
        return getattr(self._sock, name)


class MessageTooLarge(ConnectionError):
    """The relay sent a message over the protocol limits; the connection is aborted."""


def _recv_message(ws, limit, max_fragments=MAX_FRAGMENTS):
    """The next text or binary message as ``(opcode, bytes)``, or a close as ``(OPCODE_CLOSE, payload)``.

    The library's reader buffers a frame of any declared length and joins any
    number of fragments. Here each frame header is read first, and
    MessageTooLarge is raised before a payload is read when the message would
    pass ``limit`` bytes or ``max_fragments`` fragments, or a control frame
    would pass 125 bytes. The caller aborts the connection. Pings are answered
    and pongs skipped, as the library does.
    """
    from websocket import ABNF, WebSocketProtocolException
    frames = ws.frame_buffer
    parts, size, kind, fragments = [], 0, None, 0
    while True:
        if frames.needs_header():
            frames.recv_header()
        if frames.needs_length():
            frames.recv_length()
        opcode, length = frames.header[4], frames.length
        if opcode >= 0x8:
            if length > 125:
                raise MessageTooLarge('control frame too large')
        else:
            fragments += 1
            if fragments > max_fragments or size + length > limit:
                raise MessageTooLarge('message too large')
        frame = ws.recv_frame()
        if frame.opcode == ABNF.OPCODE_CLOSE:
            with suppress(Exception):
                ws.send_close()
            return frame.opcode, frame.data
        if frame.opcode == ABNF.OPCODE_PING:
            ws.pong(frame.data)
            continue
        if frame.opcode == ABNF.OPCODE_PONG:
            continue
        if (frame.opcode == ABNF.OPCODE_CONT) != (kind is not None):
            raise WebSocketProtocolException('illegal fragment')
        if kind is None:
            kind = frame.opcode
        parts.append(frame.data)
        size += len(frame.data)
        if frame.fin:
            return kind, b''.join(parts)


def _ws_to_local(ws, local):
    import websocket
    while True:
        opcode, data = _recv_message(ws, STREAM_MESSAGE_LIMIT)
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
