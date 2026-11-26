"""Windows profile, endpoint-file and peer checks for the Chromium DOM routes.

No browser runs here. A caller cannot select a debugging endpoint or weaken
these checks: the profile comes only from broker startup configuration.
"""
import os
from pathlib import Path
import socket
import sys
import threading
import time

import pytest

if sys.platform != 'win32':
    pytest.skip('native Windows APIs required', allow_module_level=True)

import win32file
import win32security

from akdbx import browser_card, browser_password, cdp_peer, windows_browser, windows_security as security
from akdbx.browser_card import CardTargetError
from akdbx.target import TargetError
from akdbx.windows_browser import BrowserEndpointError
from akdbx.cdp_peer import MIB_TCP_STATE_ESTAB, _Row
from test_windows_native import private_dir  # noqa: F401

VALID = b'12345\n/devtools/browser/synthetic-id'
PUBLIC = 'D:P(A;;FA;;;WD)'


@pytest.fixture
def profile(private_dir):
    path = private_dir / 'profile'
    win32file.CreateDirectory(str(path), security.private_attributes(directory=True))
    return path


def set_dacl(path, sddl):
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    win32security.SetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION, descriptor)


def test_exact_endpoint_from_a_private_profile(profile):
    security.write_new(profile / 'DevToolsActivePort', VALID)
    expected = 'ws://127.0.0.1:12345/devtools/browser/synthetic-id'
    assert windows_browser.endpoint(profile) == expected
    assert browser_password.endpoint(profile) == expected
    assert browser_card.browser_endpoint(profile) == expected


@pytest.mark.parametrize('data', [b'0\n/devtools/browser/id', b'65536\n/devtools/browser/id',
                                  b'1234\nws://remote.invalid/', b'1234\n/devtools/page/id',
                                  b'1234\n/devtools/browser/id\nextra', b'1234\r\n/devtools/browser/id',
                                  b'1234\n/devtools/browser/\xff', b'a' * 257, b''])
def test_untrusted_endpoint_file_fails(profile, data):
    security.write_new(profile / 'DevToolsActivePort', data)
    with pytest.raises(BrowserEndpointError):
        windows_browser.endpoint(profile)
    with pytest.raises(TargetError):
        browser_password.endpoint(profile)
    with pytest.raises(CardTargetError):
        browser_card.browser_endpoint(profile)


@pytest.mark.parametrize('damage', ['missing-profile', 'no-profile', 'missing-file', 'public-file', 'public-profile',
                                    'public-parent', 'hard-link', 'file-as-profile', 'stream', 'unc'])
def test_profile_another_user_could_change_is_refused(profile, private_dir, damage):
    port = profile / 'DevToolsActivePort'
    if damage != 'missing-file':
        security.write_new(port, VALID)
    target = profile
    if damage == 'missing-profile':
        target = private_dir / 'absent'
    elif damage == 'no-profile':
        target = None
    elif damage == 'public-file':
        set_dacl(port, PUBLIC)
    elif damage == 'public-profile':
        set_dacl(profile, PUBLIC)
    elif damage == 'public-parent':
        set_dacl(private_dir, PUBLIC)
    elif damage == 'hard-link':
        os.link(port, profile / 'second-name')
    elif damage == 'file-as-profile':
        target = port
    elif damage == 'stream':
        target = Path(str(profile) + ':stream')
    elif damage == 'unc':
        target = Path(r'\\localhost\C$') / profile.relative_to(profile.anchor)
    for check, error in ((windows_browser.endpoint, BrowserEndpointError), (browser_password.endpoint, TargetError),
                         (browser_card.browser_endpoint, CardTargetError)):
        with pytest.raises(error):
            check(target)


def test_profile_through_a_junction_is_refused(profile, private_dir):
    import subprocess
    security.write_new(profile / 'DevToolsActivePort', VALID)
    link = private_dir / 'linked-profile'
    created = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(profile)], capture_output=True, timeout=10)
    if created.returncode:
        pytest.skip('directory junctions are unavailable')
    try:
        with pytest.raises(BrowserEndpointError):
            windows_browser.endpoint(link)
    finally:
        os.rmdir(link)


def test_real_connected_peer_is_verified_before_accept():
    # The kernel must identify the server even before userspace accept().
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        client.settimeout(2)
        client.connect(listener.getsockname())
        cdp_peer.verify_peer(client)
        browser_password.verify_peer(client)
        browser_card.verify_peer(client)


def row(server, client, *, pid=None, state=MIB_TCP_STATE_ESTAB, local='127.0.0.1', remote='127.0.0.1'):
    def address(value):
        return int.from_bytes(socket.inet_aton(value), 'little')
    return _Row(state, address(local), socket.htons(server), address(remote), socket.htons(client),
                os.getpid() if pid is None else pid)


def test_peer_is_found_in_a_large_table_in_any_position():
    unrelated = [row(1000 + index % 60000, 2000 + index % 60000, pid=4321) for index in range(50000)]
    for rows in ([row(12345, 54321), *unrelated], [*unrelated, row(12345, 54321)]):
        assert cdp_peer.server_pid(12345, 54321, rows, time.monotonic() + 1) == os.getpid()


@pytest.mark.parametrize('case', ['missing', 'duplicate', 'listener-only', 'client-only', 'closing', 'other-address',
                                  'system-process', 'reversed-ports'])
def test_ambiguous_or_missing_kernel_rows_refuse(case):
    rows = {
        'missing': [],
        'duplicate': [row(12345, 54321), row(12345, 54321, pid=os.getpid() + 4)],
        'listener-only': [row(12345, 0, state=2)],
        'client-only': [row(54321, 12345)],
        'closing': [row(12345, 54321, state=8)],
        'other-address': [row(12345, 54321, local='192.0.2.1')],
        'system-process': [row(12345, 54321, pid=4)],
        'reversed-ports': [row(54321, 12345)],
    }[case]
    with pytest.raises(cdp_peer.PeerError):
        cdp_peer.server_pid(12345, 54321, rows, time.monotonic() + 1)


@pytest.mark.parametrize('case', ['other-user', 'different-integrity', 'pid-reused', 'not-loopback', 'table-unavailable', 'oversized-table',
                                  'slow-table'])
def test_untrusted_peer_receives_no_websocket_bytes(profile, monkeypatch, case):
    """An owned stale port file cannot authorize a different peer."""
    received = []
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        security.write_new(profile / 'DevToolsActivePort',
                           f'{listener.getsockname()[1]}\n/devtools/browser/synthetic-id'.encode())

        def serve():
            listener.settimeout(5)
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            with connection:
                connection.settimeout(1)
                try:
                    received.append(connection.recv(4096))
                except OSError:
                    received.append(b'')
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        if case == 'other-user':
            def refuse(_pid):
                raise PermissionError('Windows peer must have the same user and desktop session')
            monkeypatch.setattr(security, 'verify_process', refuse)
        elif case == 'different-integrity':
            levels = iter([0x3000, 0x2000])
            monkeypatch.setattr(security, 'integrity_level', lambda _: next(levels))
        elif case == 'pid-reused':
            answers = iter([os.getpid(), os.getpid() + 4])
            monkeypatch.setattr(cdp_peer, 'server_pid', lambda *_: next(answers))
        elif case == 'not-loopback':
            real = socket.socket.getpeername
            monkeypatch.setattr(socket.socket, 'getpeername', lambda self: ('192.0.2.1', real(self)[1]))
        elif case == 'table-unavailable':
            def unavailable(_deadline):
                raise BrowserEndpointError()
            monkeypatch.setattr(cdp_peer, 'tcp_rows', unavailable)
        elif case == 'oversized-table':
            monkeypatch.setattr(cdp_peer, 'MAX_TCP_TABLE_BYTES', 8)
        else:
            monkeypatch.setattr(cdp_peer, 'PEER_SCAN_TIMEOUT', 0.0)
        with pytest.raises(TargetError):
            browser_password.CDP(profile)
        monkeypatch.undo()
        worker.join(timeout=10)
    # The refused connection was closed before the WebSocket handshake.
    assert received == [b'']


def test_same_user_peer_reaches_the_handshake(profile):
    """The positive control for the refusal cases: this peer does get the request."""
    received = []
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        security.write_new(profile / 'DevToolsActivePort',
                           f'{listener.getsockname()[1]}\n/devtools/browser/synthetic-id'.encode())

        def serve():
            listener.settimeout(5)
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(2)
                received.append(connection.recv(4096))
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        # No WebSocket server answers; the handshake fails after it was sent.
        with pytest.raises(Exception) as failed:
            browser_password.CDP(profile)
        assert not isinstance(failed.value, TargetError)
        worker.join(timeout=10)
    assert received and received[0].startswith(b'GET /devtools/browser/synthetic-id HTTP/1.1')
    assert b'Origin:' not in received[0]
