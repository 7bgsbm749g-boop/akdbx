"""Windows parts of the loopback HTTPS private pages; the server is shared."""
import threading

from .broker import open_vault_with_password
from .local_https import (LOOPBACK, DNS_NAME, LoopbackHTTPSServer, local_origin,  # noqa: F401
                          start_local_unlock_server)

# The shared server under its earlier Windows name.
WindowsHTTPServer = LoopbackHTTPSServer


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
    def close():
        stop.set()
        thread.join(5)
    server.close_capture = close


def start_windows_unlock_server(broker, database, keyfile, public_base_url, certificate,
                               private_key, opener=open_vault_with_password, *, local_port=None,
                               capture_pipe=None):
    before_start = None
    if capture_pipe is not None:
        before_start = lambda server: start_capture_pipe(server, broker, capture_pipe)
    return start_local_unlock_server(broker, database, keyfile, public_base_url, certificate,
                                     private_key, opener, local_port=local_port,
                                     before_start=before_start)
