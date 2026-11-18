"""Local HTTPS private pages for Windows; never an unprotected TCP proxy."""
from contextlib import ExitStack
from http.server import HTTPServer
from pathlib import Path
import socket
import ssl
import threading
from urllib.parse import urlsplit

from .web_unlock import (ThreadingUnixHTTPServer, UnlockState, handler_for,
                         MAX_HTTP_CONNECTIONS)
from .broker import open_vault_with_password


def local_origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.hostname not in {'localhost', '127.0.0.1'}
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {'', '/'} or parsed.query or parsed.fragment
            or parsed.port is None or not 1024 <= parsed.port <= 65535):
        raise ValueError('Windows unlock origin must be https://localhost:PORT or https://127.0.0.1:PORT (1024-65535)')
    # Use one exact origin spelling for Host/Origin checks and all links.
    return f'https://{parsed.hostname}:{parsed.port}', parsed.port


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


def start_windows_unlock_server(broker, database, keyfile, public_base_url, certificate,
                               private_key, opener=open_vault_with_password):
    from .windows_security import trusted_directory, checked_handle
    origin, port = local_origin(public_base_url)
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
        thread.start()
    except BaseException:
        server.server_close()
        raise
    return server, url
