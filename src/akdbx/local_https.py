"""Loopback HTTPS private pages for Linux and Windows; never an unprotected TCP proxy.

The broker terminates TLS itself on 127.0.0.1. The page checks ``Host`` and
``Origin`` against one configured origin and trusts no proxy identity header.
"""
from contextlib import ExitStack, contextmanager
import ipaddress
from http.server import HTTPServer
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import threading
from urllib.parse import urlsplit

from http import HTTPStatus

from .web_unlock import (ThreadingUnixHTTPServer, UnlockState, handler_for, _page,
                         MAX_HTTP_CONNECTIONS)
from .broker import open_vault_with_password


LOOPBACK = {'localhost', '127.0.0.1'}
DNS_NAME = re.compile(r'(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+')


def is_loopback_origin(value):
    try:
        return urlsplit(value).hostname in LOOPBACK
    except ValueError:
        return False


def local_origin(value, local_port=None):
    """Return ``(origin, listen_port)``. The listener always binds 127.0.0.1.

    A loopback origin (``https://localhost:PORT`` or ``https://127.0.0.1:PORT``)
    is served on its own port. Any other origin is a remote one, such as the
    Tailscale Serve name of this computer: Tailscale Serve proxies it to the
    loopback listener on ``local_port``, so other devices can unlock.
    """
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        port = -1
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path not in {'', '/'} or parsed.query
            or parsed.fragment or port == -1):
        raise ValueError('unlock origin must be an HTTPS origin without path, query or credentials')
    if parsed.hostname in LOOPBACK:
        if port is None or not 1024 <= port <= 65535 or local_port not in (None, port):
            raise ValueError('loopback unlock origin must be https://localhost:PORT or https://127.0.0.1:PORT (1024-65535)')
        # Use one exact origin spelling for Host/Origin checks and all links.
        return f'https://{parsed.hostname}:{port}', port
    host = parsed.hostname
    if not DNS_NAME.fullmatch(host) or _is_address(host):
        raise ValueError('a remote unlock origin needs a DNS name, such as the Tailscale Serve name')
    if type(local_port) is not int or not 1024 <= local_port <= 65535:
        raise ValueError('a remote unlock origin needs --local-port (1024-65535) for the loopback listener')
    # The browser serialization: no default port.
    return f'https://{host}' + ('' if port in (None, 443) else f':{port}'), local_port


def _is_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class LoopbackHTTPSServer(ThreadingUnixHTTPServer):
    """The shared bounded private-page server, on a 127.0.0.1 TLS listener."""

    address_family = socket.AF_INET
    # Linux SO_REUSEADDR only lets a restart bind over the TIME_WAIT
    # connections that this server's closes leave; no socket can bind while a
    # listener exists. On Windows it would let another socket share the port,
    # so Windows uses SO_EXCLUSIVEADDRUSE instead. Never SO_REUSEPORT.
    allow_reuse_address = os.name != 'nt'
    allow_reuse_port = False

    def __init__(self, address, handler, context, origin):
        self._connection_slots = threading.BoundedSemaphore(MAX_HTTP_CONNECTIONS)
        self._deadline_lock = threading.Lock()
        self._deadlines = {}
        self._runtime_fd = self._lifecycle_lock = None
        self.context, self.local_origin = context, origin
        HTTPServer.__init__(self, address, handler)

    def server_bind(self):
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        HTTPServer.server_bind(self)

    def get_request(self):
        request, address = super().get_request()
        try:
            # Do not perform TLS handshakes in the accepting thread. The shared
            # connection deadline and worker cap also bound slow TLS clients.
            request = self.context.wrap_socket(request, server_side=True,
                                               do_handshake_on_connect=False)
            return request, address
        except BaseException:
            request.close()
            self._connection_slots.release()
            raise

    def finish_request(self, request, address):
        request.do_handshake()
        super().finish_request(request, address)

    def shutdown(self):
        super().shutdown()
        close_capture = getattr(self, 'close_capture', None)
        if close_capture is not None:
            close_capture()


def start_capture_socket(server, state, path):
    """Linux: serve only the native host's ``/totp/capture`` on a private Unix socket.

    The browser native host sends a captured authenticator setup here, as on
    the Unix-socket route; Windows uses a capture pipe instead. The route
    requires a same-UID peer and refuses proxy headers. This socket serves no
    page, so it cannot unlock the vault.
    """
    from .import_web import handle_import
    page = handler_for(state)

    class CaptureHandler(page):
        def do_GET(self):
            self._send(HTTPStatus.NOT_FOUND, _page('Not found', '<p>Not found.</p>'))

        def do_POST(self):
            if urlsplit(self.path).path != '/totp/capture' or not handle_import(self, state):
                self.do_GET()

    capture = ThreadingUnixHTTPServer(str(path), CaptureHandler)
    thread = threading.Thread(target=capture.serve_forever, name='akdbx-totp-capture', daemon=True)
    try:
        thread.start()
    except BaseException:
        capture.server_close()
        raise

    def close():
        capture.shutdown()
        capture.server_close()
        thread.join(5)
    server.close_capture = close


@contextmanager
def _posix_checked_file(path, *, private):
    """Open one PEM file without following a final symlink and check it.

    The key must be a regular file of this user that no other user can read or
    write (mode 0600 or stricter): only the key proves the page to a browser or
    a verifying proxy. The certificate is public; it must be a regular file.
    """
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError('TLS certificate and key must be regular files')
        if private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & ~0o600):
            raise PermissionError("TLS key must be this user's file with mode 0600")
        # OpenSSL reopens this exact checked file, not a pathname that can change.
        yield f'/proc/self/fd/{fd}'
    finally:
        os.close(fd)


def load_certificate(context, certificate, private_key):
    """Load the PEM pair through checked handles. Key bytes never enter output."""
    with ExitStack() as stack:
        if os.name == 'nt':
            from .windows_security import trusted_directory, checked_handle
            # Keep verified certificate/key paths anchored while OpenSSL loads them.
            for path in (certificate, private_key):
                stack.enter_context(trusted_directory(path.parent))
                stack.enter_context(checked_handle(path))
            paths = certificate, private_key
        else:
            paths = (stack.enter_context(_posix_checked_file(certificate, private=False)),
                     stack.enter_context(_posix_checked_file(private_key, private=True)))
        # An encrypted certificate key must fail rather than letting OpenSSL
        # start an inaccessible terminal password prompt.
        context.load_cert_chain(*paths, password=lambda: b'')


def start_local_unlock_server(broker, database, keyfile, public_base_url, certificate,
                              private_key, opener=open_vault_with_password, *, local_port=None,
                              before_start=None, capture_socket=None):
    origin, port = local_origin(public_base_url, local_port)
    if certificate is None or private_key is None:
        raise ValueError('the private HTTPS page requires --tls-cert and --tls-key')
    certificate, private_key = Path(certificate).absolute(), Path(private_key).absolute()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    load_certificate(context, certificate, private_key)
    state = UnlockState(broker, database, keyfile, opener, public_base=origin)
    server = LoopbackHTTPSServer(('127.0.0.1', port), handler_for(state), context, origin)
    url = state.url
    broker.unlock_url = url
    broker.unlock_link = state
    broker.writes.public_base = origin
    broker.merges.database = database
    server.write_manager = broker.writes
    thread = threading.Thread(target=server.serve_forever, name='akdbx-web-unlock', daemon=True)
    try:
        if before_start is not None:
            before_start(server)
        if capture_socket is not None:
            start_capture_socket(server, state, capture_socket)
        thread.start()
    except BaseException:
        close_capture = getattr(server, 'close_capture', None)
        if close_capture is not None:
            close_capture()
        server.server_close()
        raise
    return server, url
