"""Endpoint trust, authorization lifetimes and non-secret failure receipts."""
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from akdbx.broker import Broker
from akdbx.browser_card import BrowserCards, CardTargetError, browser_endpoint, failure
from akdbx.cards import value_for
from test_card_chromium import CardEntry
from test_broker import RecordingTyper, Vault


@pytest.mark.parametrize('content', ['80\nhttp://evil.test', '0\n/devtools/browser/id',
    '65536\n/devtools/browser/id', '12\n/devtools/page/id', '12\n/devtools/browser/id\nextra',
    '12\n/devtools/browser/' + 'a'*300, '１２\n/devtools/browser/id'])
def test_untrusted_endpoint_metadata_is_refused(tmp_path, content):
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    (profile / 'DevToolsActivePort').write_text(content)
    with pytest.raises(Exception):
        browser_endpoint(profile)


def test_endpoint_symlink_writable_file_and_replaceable_profile_refused(tmp_path):
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    source = tmp_path / 'source'
    source.write_text('1234\n/devtools/browser/synthetic-id')
    active = profile / 'DevToolsActivePort'
    active.symlink_to(source)
    with pytest.raises(Exception): browser_endpoint(profile)
    active.unlink()
    active.write_text(source.read_text())
    active.chmod(0o666)
    with pytest.raises(Exception): browser_endpoint(profile)
    active.chmod(0o600)
    assert browser_endpoint(profile) == 'ws://127.0.0.1:1234/devtools/browser/synthetic-id'
    profile.chmod(0o777)
    with pytest.raises(Exception): browser_endpoint(profile)


def test_foreign_uid_endpoint_receives_no_websocket_bytes(tmp_path):
    """A stale owned port file must not authorize another user's listener."""
    import select
    import shutil
    import subprocess
    from akdbx.browser_card import CDP
    sudo = shutil.which('sudo')
    assert sudo is not None, 'foreign-UID regression requires sudo -n -u nobody'
    script = '''import os, socket
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)
    print(listener.getsockname()[1], os.getuid(), flush=True)
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(3)
        print(len(connection.recv(8192)), flush=True)
'''
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    with subprocess.Popen([sudo, '-n', '-u', 'nobody', '/usr/bin/python3', '-c', script],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        try:
            assert select.select([process.stdout], [], [], 3)[0], 'listener did not start'
            port, uid = map(int, process.stdout.readline().split())
            assert uid != os.getuid(), 'listener must run as a different UID'
            active = profile / 'DevToolsActivePort'
            active.write_text(f'{port}\n/devtools/browser/synthetic-stale-file')
            active.chmod(0o600)
            with pytest.raises(Exception) as refused:
                CDP(profile)
            output, error = process.communicate(timeout=8)
            assert process.returncode == 0, error
            assert output.strip() == '0', 'foreign listener received WebSocket handshake bytes'
            assert isinstance(refused.value, CardTargetError)
        finally:
            # This exact child owns bounded accept/read deadlines; no shared process.
            process.wait(timeout=10)


def test_endpoint_redirect_never_connects_to_second_listener(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    import socket
    import websocket
    from akdbx.browser_card import CDP
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    with socket.socket() as listener, socket.socket() as redirected:
        for server in (listener, redirected):
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            server.settimeout(3)
        active = profile / 'DevToolsActivePort'
        active.write_text(f'{listener.getsockname()[1]}\n/devtools/browser/synthetic-redirect')
        active.chmod(0o600)
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
            with pytest.raises((CardTargetError, websocket.WebSocketException)):
                CDP(profile)
            assert response.result(timeout=4).startswith(b'GET /devtools/browser/synthetic-redirect ')
        redirected.setblocking(False)
        with pytest.raises(BlockingIOError):
            redirected.accept()


def test_connected_endpoint_uid_is_verified_before_userspace_accept():
    import socket
    from akdbx.browser_card import verify_peer
    with socket.socket() as listener, socket.socket() as client:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        client.settimeout(2)
        client.connect(listener.getsockname())
        verify_peer(client)
        server, _ = listener.accept()
        with server:
            verify_peer(client)


@pytest.mark.parametrize('case', ['foreign', 'missing', 'duplicate', 'listener-only',
    'client-only', 'malformed', 'invalid-uid', 'oversized-line', 'oversized-table', 'unavailable'])
def test_connected_endpoint_refuses_missing_or_untrusted_kernel_proof(monkeypatch, case):
    import io
    import socket
    import sys
    from akdbx.browser_card import verify_peer
    loopback = f'{int.from_bytes(socket.inet_aton("127.0.0.1"), sys.byteorder):08X}'
    server, client = f'{loopback}:3039', f'{loopback}:D431'
    row = f'0: {server} {client} 01 0:0 0:0 0 {os.getuid()} 0 1\n'
    data = {
        'foreign': row.replace(f' {os.getuid()} 0 1', f' {os.getuid()+1} 0 1'),
        'missing': '',
        'duplicate': row * 2,
        'listener-only': row.replace(client, '00000000:0000').replace(' 01 ', ' 0A '),
        'client-only': row.replace(f'{server} {client}', f'{client} {server}'),
        'malformed': f'0: {server} {client} 01\n',
        'invalid-uid': row.replace(f' {os.getuid()} 0 1', ' unknown 0 1'),
        'oversized-line': row + 'x' * 1025,
        'oversized-table': row + 'header\n' * 16384,
        'unavailable': '',
    }[case].encode()
    class Connected:
        family = socket.AF_INET
        def getsockname(self): return '127.0.0.1', 54321
        def getpeername(self): return '127.0.0.1', 12345
    def table(path, mode):
        assert path == '/proc/self/net/tcp' and mode == 'rb'
        if case == 'unavailable':
            raise PermissionError()
        return io.BytesIO(data)
    monkeypatch.setattr('builtins.open', table)
    with pytest.raises((CardTargetError, OSError, ValueError)):
        verify_peer(Connected())


@pytest.mark.parametrize('changed', ['family', 'local', 'remote'])
def test_connected_endpoint_refuses_non_ipv4_loopback(changed):
    import socket
    from akdbx.browser_card import verify_peer
    connection = SimpleNamespace(family=socket.AF_INET,
        getsockname=lambda: ('127.0.0.1', 54321), getpeername=lambda: ('127.0.0.1', 12345))
    if changed == 'family': connection.family = socket.AF_INET6
    elif changed == 'local': connection.getsockname = lambda: ('192.0.2.1', 54321)
    else: connection.getpeername = lambda: ('192.0.2.1', 12345)
    with pytest.raises(CardTargetError):
        verify_peer(connection)


def test_fixture_waits_for_complete_header_after_empty_file_creation(tmp_path, monkeypatch):
    import test_card_chromium as lab
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    active = profile / 'DevToolsActivePort'
    active.write_text('')
    active.chmod(0o600)
    observed_incomplete = threading.Event()
    original = browser_endpoint
    def observe(path):
        try:
            return original(path)
        except CardTargetError:
            observed_incomplete.set()
            raise
    monkeypatch.setattr(lab, 'browser_endpoint', observe)
    errors = []
    def publish():
        if not observed_incomplete.wait(2):
            errors.append('reader did not reject the incomplete file')
            return
        active.write_text('1234\n/devtools/browser/synthetic-complete-id')
    writer = threading.Thread(target=publish)
    writer.start()
    try:
        endpoint = lab.wait_for_browser_endpoint(profile, SimpleNamespace(poll=lambda: None), time.monotonic()+3)
        assert endpoint == 'ws://127.0.0.1:1234/devtools/browser/synthetic-complete-id'
    finally:
        writer.join(timeout=3)
    assert observed_incomplete.is_set() and not writer.is_alive() and not errors


class FakeCDP:
    def __init__(self, result='filled', fail_at=None):
        self.result, self.fail_at, self.closed, self.calls = result, fail_at, 0, []
    def close(self): self.closed += 1
    def call(self, method, params=None, session=None):
        self.calls.append(method)
        if method == self.fail_at:
            raise RuntimeError('4111111111111111 MUST NOT escape')
        if method == 'Page.getFrameTree':
            return dict(frameTree=dict(frame=dict(id='frame', url='https://example.test/pay')))
        return dict(result=dict(value=self.result))


def target(cdp, clock):
    return dict(cdp=cdp, session='session', obj='object', field='cc-number', created=clock(), expires=clock()+30,
                request=dict(top_url='https://example.test/pay', frame_url='https://example.test/pay', frame_id='frame'))


@pytest.mark.parametrize('stage,expected', [('Page.getFrameTree', 'not-started'), ('Runtime.callFunctionOn', 'uncertain')])
def test_transport_exceptions_never_disclose_and_do_not_claim_safe_retry(stage, expected):
    cards = BrowserCards(clock=lambda: 0)
    cdp = FakeCDP(fail_at=stage)
    result = cards.fill(target(cdp, lambda: 0), '4111111111111111', 'cc-number', lambda: True)
    assert not result['ok'] and result['delivery'] == expected
    assert '4111111111111111' not in str(result)
    assert cdp.closed


@pytest.mark.parametrize('result,delivery', [('uncertain', 'uncertain'), ('refused', 'not-started'), ('unexpected', 'uncertain')])
def test_transport_only_accepts_explicit_fill_receipt(result, delivery):
    cards = BrowserCards(clock=lambda: 0)
    cdp = FakeCDP(result)
    assert cards.fill(target(cdp, lambda: 0), '4111111111111111', 'cc-number', lambda: True)['delivery'] == delivery


@pytest.mark.parametrize('changes', [dict(card_protocol=True), dict(field='password'), dict(start_deadline=float('nan')),
    dict(start_deadline=float('inf')), dict(start_deadline=0), dict(extra=True)])
def test_malformed_fill_consumes_both_authorizations_without_any_transport(changes):
    broker = Broker(Vault([CardEntry()]), RecordingTyper())
    cdp = FakeCDP()
    broker.card_targets.pins['target'] = target(cdp, broker.clock)
    selected = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    request = dict(action='fill-card', card_protocol=1, field='cc-number', target='target', handle=selected)
    request.update(changes)
    assert not broker.dispatch(request)['ok']
    assert not broker.card_targets.pins and selected not in broker._handles
    assert cdp.closed and not cdp.calls and broker.typer.events == []


def test_invalid_handle_still_closes_and_consumes_target():
    broker = Broker(Vault([CardEntry()]), RecordingTyper())
    cdp = FakeCDP()
    broker.card_targets.pins['target'] = target(cdp, broker.clock)
    result = broker.dispatch(dict(action='fill-card', card_protocol=1, field='cc-number', target='target', handle='invalid'))
    assert not result['ok'] and not broker.card_targets.pins and cdp.closed and not cdp.calls


def test_prune_and_close_release_connections_and_expired_cards_refuse():
    clock = [0]
    cards = BrowserCards(clock=lambda: clock[0])
    one, two = FakeCDP(), FakeCDP()
    cards.pins['a'], cards.pins['b'] = target(one, lambda: 0), target(two, lambda: 10)
    clock[0] = 30
    cards.prune()
    assert one.closed and not two.closed and set(cards.pins) == {'b'}
    cards.close()
    assert two.closed and not cards.pins
    with pytest.raises(ValueError): value_for(CardEntry(), 'cc-number', None, 2208988800)  # 2040


def test_unconfigured_browser_and_locked_broker_never_access_transport():
    broker = Broker(None, RecordingTyper())
    assert broker.dispatch(dict(action='fill-card'))['error'] == 'vault locked'
    broker.vault = Vault([CardEntry()])
    assert not broker.dispatch(dict(action='pin-card-target', card_protocol=1))['ok']
    assert not broker.card_targets.pins and broker.typer.events == []
