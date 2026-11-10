"""The caller cannot select a debugging endpoint or weaken profile checks."""
import os
from pathlib import Path
import socket
import sys

import pytest

from akdbx.browser_password import BrowserPasswords, CDP, endpoint, verify_peer
from akdbx.target import TargetError


@pytest.fixture
def profile(tmp_path):
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    # The fixture's parent directories must be private/owned, as in production.
    for path in [tmp_path, tmp_path.parent]:
        if path.stat().st_uid == os.getuid():
            path.chmod(0o700)
    return profile


@pytest.mark.parametrize('data', ['0\n/devtools/browser/id', '65536\n/devtools/browser/id',
                                 '1234\nws://remote.invalid/', '1234\n/devtools/page/id',
                                 '1234\n/devtools/browser/id\nextra', 'a' * 257])
def test_untrusted_endpoint_file_fails(profile, data):
    (profile / 'DevToolsActivePort').write_text(data)
    with pytest.raises(TargetError):
        endpoint(profile)


def test_exact_endpoint_and_symlink_permissions(profile, tmp_path):
    port = profile / 'DevToolsActivePort'
    port.write_text('12345\n/devtools/browser/synthetic-id')
    port.chmod(0o600)
    assert endpoint(profile) == 'ws://127.0.0.1:12345/devtools/browser/synthetic-id'
    port.chmod(0o666)
    with pytest.raises(TargetError):
        endpoint(profile)
    port.chmod(0o600)
    other = tmp_path / 'other'
    port.rename(other)
    port.symlink_to(other)
    with pytest.raises(OSError):
        endpoint(profile)
    link = tmp_path / 'link'
    link.symlink_to(profile)
    with pytest.raises(TargetError):
        endpoint(link)


def test_real_connected_peer_uid_before_accept():
    # The kernel must identify the server even before userspace accept().
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        client.settimeout(2)
        client.connect(listener.getsockname())
        verify_peer(client)


@pytest.mark.parametrize('case', ['foreign', 'missing', 'duplicate', 'listener-only', 'client-only',
                                  'malformed', 'oversized-line', 'oversized-table', 'unavailable'])
def test_connected_peer_refuses_untrusted_kernel_rows(monkeypatch, case):
    import io
    loopback = f'{int.from_bytes(socket.inet_aton("127.0.0.1"), sys.byteorder):08X}'
    server, client = f'{loopback}:3039', f'{loopback}:D431'
    row = f'0: {server} {client} 01 0:0 0:0 0 {os.getuid()} 0 1\n'
    data = {
        'foreign': row.replace(f' {os.getuid()} 0 1', f' {os.getuid() + 1} 0 1'),
        'missing': '',
        'duplicate': row * 2,
        'listener-only': row.replace(client, '00000000:0000').replace(' 01 ', ' 0A '),
        'client-only': row.replace(f'{server} {client}', f'{client} {server}'),
        'malformed': f'0: {server} {client} 01\n',
        'oversized-line': 'x' * 1025,
        'oversized-table': 'header\n' * 16384,
        'unavailable': '',
    }[case].encode()
    class Connected:
        family = socket.AF_INET
        def getsockname(self):
            return '127.0.0.1', 54321
        def getpeername(self):
            return '127.0.0.1', 12345
    def table(path, mode):
        assert path == '/proc/self/net/tcp' and mode == 'rb'
        if case == 'unavailable':
            raise PermissionError()
        return io.BytesIO(data)
    monkeypatch.setattr('builtins.open', table)
    with pytest.raises((TargetError, PermissionError)):
        verify_peer(Connected())


def test_foreign_uid_listener_receives_no_websocket_bytes(profile):
    """An owned stale port file cannot authorize a different UID's TCP peer."""
    import select
    import shutil
    import subprocess
    sudo = shutil.which('sudo')
    if sudo is None:
        pytest.skip('requires sudo -n -u nobody for the isolated foreign-UID listener')
    script = '''import socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)
    print(listener.getsockname()[1], flush=True)
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(3)
        print(len(connection.recv(4096)), flush=True)
'''
    with subprocess.Popen([sudo, '-n', '-u', 'nobody', '/usr/bin/python3', '-c', script],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        try:
            assert select.select([process.stdout], [], [], 3)[0], 'listener did not start'
            line = process.stdout.readline().strip()
            if not line and process.poll() is not None:
                pytest.skip('unprivileged foreign-UID test requires sudo permission')
            port = int(line)
            metadata = profile / 'DevToolsActivePort'
            metadata.write_text(f'{port}\n/devtools/browser/synthetic-stale-file')
            metadata.chmod(0o600)
            with pytest.raises(TargetError):
                CDP(profile)
            assert process.stdout.readline().strip() == '0'
        finally:
            # The server has bounded accept/read timeouts; no persistent process.
            process.wait(timeout=10)
        assert process.returncode == 0


def test_websocket_redirect_never_opens_another_connection(profile):
    from concurrent.futures import ThreadPoolExecutor
    import websocket
    with socket.socket() as listener, socket.socket() as redirected:
        for server in (listener, redirected):
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            server.settimeout(3)
        metadata = profile / 'DevToolsActivePort'
        metadata.write_text(f'{listener.getsockname()[1]}\n/devtools/browser/synthetic-redirect')
        metadata.chmod(0o600)
        def reply():
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                data = b''
                while b'\r\n\r\n' not in data and len(data) < 8192:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                connection.sendall(f'HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:{redirected.getsockname()[1]}/devtools/browser/other\r\nContent-Length: 0\r\n\r\n'.encode())
                return data
        with ThreadPoolExecutor(max_workers=1) as pool:
            response = pool.submit(reply)
            with pytest.raises(websocket.WebSocketException):
                CDP(profile)
            assert response.result(timeout=4).startswith(b'GET /devtools/browser/synthetic-redirect ')
        redirected.setblocking(False)
        with pytest.raises(BlockingIOError):
            redirected.accept()


def test_expiry_capacity_consumption_and_close(monkeypatch):
    from akdbx.browser_password import MAX_PINS
    class Pin:
        closed = False
        def close(self):
            self.closed = True
    now = [0]
    targets = BrowserPasswords(clock=lambda: now[0])
    pins = [Pin() for _ in range(MAX_PINS)]
    targets.pins = {str(i): (30, pin) for i, pin in enumerate(pins)}
    assert targets.consume('0') is pins[0]
    assert '0' not in targets.pins
    with pytest.raises(TargetError):
        targets.consume('0')
    now[0] = 30
    targets.prune()
    assert not targets.pins and all(pin.closed for pin in pins[1:])
    targets.pins = {'next': (60, pins[0])}
    targets.close()
    assert pins[0].closed and not targets.pins


def test_pin_capacity_refuses_before_connect(monkeypatch):
    from akdbx import browser_password
    targets = BrowserPasswords(clock=lambda: 0)
    targets.pins = {str(i): (30, object()) for i in range(browser_password.MAX_PINS)}
    def forbidden(*args, **kwargs):
        pytest.fail('capacity overflow opened a browser connection')
    monkeypatch.setattr(browser_password, 'CDP', forbidden)
    with pytest.raises(TargetError):
        targets.pin(dict(action='pin-password-target', password_protocol=1, page_id='synthetic-page',
                         frame_id='synthetic-frame', top_url='https://example.test/login', selector='#password', mode='password'))


def test_stalled_browser_pin_does_not_block_vault_search(monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from akdbx import browser_password
    from akdbx.broker import Broker
    from test_broker import Entry, Vault, RecordingTyper
    entered, release = threading.Event(), threading.Event()
    def stalled(profile):
        entered.set()
        assert release.wait(5), 'synthetic CDP stall was not released'
        raise TargetError()
    monkeypatch.setattr(browser_password, 'CDP', stalled)
    broker = Broker(Vault([Entry()]), RecordingTyper())
    request = dict(action='pin-password-target', password_protocol=1, page_id='page', frame_id='frame',
                   top_url='https://example.test/login', selector='#password', mode='password')
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(broker.dispatch, request)
        try:
            assert entered.wait(2)
            result = pool.submit(broker.dispatch, dict(action='search')).result(timeout=1)
            assert result['ok'] and len(result['entries']) == 1
            assert not pending.done()
        finally:
            release.set()
        assert not pending.result(timeout=2)['ok']
    assert broker.passwords._creating == 0


def test_concurrent_pin_capacity_counts_connections_in_progress(monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from akdbx import browser_password
    entered = threading.Barrier(3)
    release = threading.Event()
    calls = []
    def stalled(profile):
        calls.append(True)
        entered.wait(timeout=2)
        assert release.wait(5)
        raise TargetError()
    monkeypatch.setattr(browser_password, 'MAX_PINS', 2)
    monkeypatch.setattr(browser_password, 'CDP', stalled)
    targets = BrowserPasswords()
    request = dict(action='pin-password-target', password_protocol=1, page_id='page', frame_id='frame',
                   top_url='https://example.test/login', selector='#password', mode='password')
    def attempt():
        with pytest.raises(TargetError):
            targets.pin(request)
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(attempt) for _ in range(2)]
        try:
            entered.wait(timeout=2)
            attempt()
            assert len(calls) == 2 and targets._creating == 2
        finally:
            release.set()
        for future in pending:
            future.result(timeout=2)
    assert targets._creating == 0 and not targets.pins


def test_shutdown_during_pin_capture_closes_connection_and_refuses_pin(monkeypatch):
    from akdbx import browser_password
    targets = BrowserPasswords()
    class Connection:
        closed = False
        def __init__(self, profile):
            pass
        def close(self):
            self.closed = True
        def call(self, method, params=None, session=None, **kwargs):
            if method == 'Target.getTargetInfo':
                return {'targetInfo': dict(type='page', url='https://example.test/login', targetId='page')}
            if method == 'Target.attachToTarget':
                return dict(sessionId='session')
            if method == 'Page.getFrameTree':
                return {'frameTree': {'frame': dict(id='frame', url='https://example.test/login')}}
            if method == 'Page.createIsolatedWorld':
                return dict(executionContextId=1)
            if method == 'Runtime.evaluate':
                targets.close()
                return {'result': dict(type='object', objectId='node')}
            return {}
    connection = Connection(None)
    monkeypatch.setattr(browser_password, 'CDP', lambda profile: connection)
    with pytest.raises(TargetError):
        targets.pin(dict(action='pin-password-target', password_protocol=1, page_id='page', frame_id='frame',
                         top_url='https://example.test/login', selector='#password', mode='password'))
    assert connection.closed and not targets.pins and targets._creating == 0
