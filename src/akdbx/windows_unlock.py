"""Local HTTPS private pages for Windows; never an unprotected TCP proxy."""
from contextlib import ExitStack
import ipaddress
from http.server import HTTPServer
from pathlib import Path
import re
import socket
import ssl
import threading
from urllib.parse import urlsplit

from .web_unlock import (ThreadingUnixHTTPServer, UnlockState, handler_for,
                         MAX_HTTP_CONNECTIONS)
from .broker import open_vault_with_password


LOOPBACK = {'localhost', '127.0.0.1'}
DNS_NAME = re.compile(r'(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+')


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
        raise ValueError('Windows unlock origin must be an HTTPS origin without path, query or credentials')
    if parsed.hostname in LOOPBACK:
        if port is None or not 1024 <= port <= 65535 or local_port not in (None, port):
            raise ValueError('Windows unlock origin must be https://localhost:PORT or https://127.0.0.1:PORT (1024-65535)')
        # Use one exact origin spelling for Host/Origin checks and all links.
        return f'https://{parsed.hostname}:{port}', port
    host = parsed.hostname
    if not DNS_NAME.fullmatch(host) or _is_address(host):
        raise ValueError('a remote Windows unlock origin needs a DNS name, such as the Tailscale Serve name')
    if type(local_port) is not int or not 1024 <= local_port <= 65535:
        raise ValueError('a remote Windows unlock origin needs --local-port (1024-65535) for the loopback listener')
    # The browser serialization: no default port.
    return f'https://{host}' + ('' if port in (None, 443) else f':{port}'), local_port


def _is_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class WindowsHTTPServer(ThreadingUnixHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = False
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
        capture = getattr(self, 'capture', None)
        if capture is not None:
            stop, thread = capture
            stop.set()
            thread.join(5)


def start_capture_pipe(server, broker, path):
    """Serve the browser native host's capture pipe until ``server`` shuts down.

    The first pipe instance is created here, so a name that another process
    holds fails the broker start. Requests are served one at a time, each
    within a short deadline.
    """
    import time
    from .import_web import serve_capture_connection
    from .windows_rpc import accept_connections, new_pipe, pipe_name
    name = pipe_name(path, capture=True)
    pending = new_pipe(name, first=True)
    stop = threading.Event()

    def handle(connection):
        with connection:
            serve_capture_connection(connection, broker, time.monotonic() + 5)

    thread = threading.Thread(target=accept_connections, args=(name, pending, handle, stop),
                              name='akdbx-totp-capture', daemon=True)
    try:
        thread.start()
    except BaseException:
        pending.Close()
        raise
    server.capture = (stop, thread)


def start_windows_unlock_server(broker, database, keyfile, public_base_url, certificate,
                               private_key, opener=open_vault_with_password, *, local_port=None,
                               capture_pipe=None):
    from .windows_security import trusted_directory, checked_handle
    origin, port = local_origin(public_base_url, local_port)
    if certificate is None or private_key is None:
        raise ValueError('Windows requires --tls-cert and --tls-key for its trusted local HTTPS page')
    certificate, private_key = Path(certificate).absolute(), Path(private_key).absolute()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Keep verified certificate/key paths anchored while OpenSSL loads them.
    # Private key bytes never enter RPC, output, argv, or a staging file.
    with ExitStack() as stack:
        for path in (certificate, private_key):
            stack.enter_context(trusted_directory(path.parent))
            stack.enter_context(checked_handle(path))
        # An encrypted certificate key must fail rather than letting OpenSSL
        # start an inaccessible terminal password prompt.
        context.load_cert_chain(certificate, private_key, password=lambda: b'')
    state = UnlockState(broker, database, keyfile, opener)
    server = WindowsHTTPServer(('127.0.0.1', port), handler_for(state), context, origin)
    url = origin + '/?token=' + state.token
    broker.unlock_url = url
    broker.writes.public_base = origin
    broker.merges.database = database
    server.write_manager = broker.writes
    thread = threading.Thread(target=server.serve_forever, name='akdbx-web-unlock', daemon=True)
    try:
        if capture_pipe is not None:
            start_capture_pipe(server, broker, capture_pipe)
        thread.start()
    except BaseException:
        capture = getattr(server, 'capture', None)
        if capture is not None:
            capture[0].set()
            capture[1].join(5)
        server.server_close()
        raise
    return server, url
