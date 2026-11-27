"""Endpoint trust, authorization lifetimes and non-secret failure receipts."""
import json
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


FOREIGN_LISTENER = '''import os, socket
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


def _foreign_account_command(sudo):
    """Return (UID, argv) that run Python as another unprivileged account.

    A different user cannot always run the test's interpreter. macOS
    /usr/bin/python3 is an Xcode shim, and a setup-python build can sit under
    the runner's private home. Probe each candidate as that account, from /,
    with an empty environment and HOME=/, and keep every failure's stderr.
    """
    import pwd
    import subprocess
    import sys
    account = '_www' if sys.platform == 'darwin' else 'nobody'
    uid = pwd.getpwnam(account).pw_uid
    assert uid not in (0, os.getuid()), f'{account} must be a different unprivileged UID'
    candidates = []
    if sys.platform == 'darwin':
        try:  # Resolve the shim as the runner, which has a developer directory.
            candidates.append(subprocess.run(['/usr/bin/xcrun', '--find', 'python3'], capture_output=True,
                                             text=True, timeout=30, check=True).stdout.strip())
        except (OSError, subprocess.SubprocessError):
            pass
        candidates += ['/opt/homebrew/bin/python3', '/usr/local/bin/python3']
    candidates += ['/usr/bin/python3', os.path.realpath(sys.executable)]
    failures, seen = [], set()
    for python in candidates:
        if not python or not os.path.isfile(python) or os.path.realpath(python) in seen:
            continue
        seen.add(os.path.realpath(python))
        argv = [sudo, '-n', '-u', account, '/usr/bin/env', '-i', 'HOME=/', 'PATH=/usr/bin:/bin',
                python, '-I', '-S', '-c']
        try:
            probe = subprocess.run([*argv, 'import os, socket; print(os.getuid())'], cwd='/',
                                   capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            failures.append(f'{python}: probe timed out; stderr: {error.stderr!r}')
            continue
        if probe.returncode == 0 and probe.stdout.strip() == str(uid):
            return uid, argv
        failures.append(f'{python}: exit {probe.returncode}; stdout {probe.stdout.strip()!r}; '
                        f'stderr {probe.stderr.strip()[-800:]!r}')
    pytest.fail(f'no Python interpreter runs as {account} (UID {uid}): ' + ' | '.join(failures or ['none found']))


def test_foreign_uid_endpoint_receives_no_websocket_bytes(tmp_path):
    """A stale owned port file must not authorize another user's listener."""
    if os.environ.get('AKDBX_TEST_FOREIGN_UID') != '1':
        pytest.skip('foreign-UID regression requires AKDBX_TEST_FOREIGN_UID=1 and passwordless sudo')
    import select
    import shutil
    import subprocess
    from akdbx.browser_card import CDP
    sudo = shutil.which('sudo')
    assert sudo is not None, 'foreign-UID regression requires sudo -n'
    expected_uid, argv = _foreign_account_command(sudo)
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    with subprocess.Popen([*argv, FOREIGN_LISTENER], cwd='/', stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as process:
        def startup_failure(reason):
            if process.poll() is None:
                process.terminate()  # sudo relays SIGTERM to the listener
            _, error = process.communicate(timeout=10)
            pytest.fail(f'foreign listener {reason} (exit {process.returncode}): {error.strip()[-800:]}')
        try:
            if not select.select([process.stdout], [], [], 15)[0]:
                startup_failure('did not start in 15 s')
            header = process.stdout.readline().split()
            if len(header) != 2:
                startup_failure(f'printed {header!r} instead of its port and UID')
            port, uid = map(int, header)
            assert uid == expected_uid, f'listener runs as UID {uid}, expected foreign UID {expected_uid}'
            active = profile / 'DevToolsActivePort'
            active.write_text(f'{port}\n/devtools/browser/synthetic-stale-file')
            active.chmod(0o600)
            with pytest.raises(Exception) as refused:
                CDP(profile)
            output, error = process.communicate(timeout=10)
            # Exit 0 proves the listener accepted the broker's TCP connection.
            assert process.returncode == 0, f'foreign listener failed: {error.strip()[-800:]}'
            assert output.strip() == '0', f'foreign listener received WebSocket handshake bytes: {output!r}'
            assert isinstance(refused.value, CardTargetError)
        finally:
            # This exact child owns bounded accept/read deadlines; no shared process.
            if process.poll() is None:
                process.terminate()  # sudo relays SIGTERM to the listener
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
    if case == 'oversized-table':
        monkeypatch.setattr('akdbx.cdp_peer.MAX_TCP_TABLE_BYTES', len(data) - 1)
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


def test_fixture_reconnects_after_pre_pin_websocket_peer_closes(tmp_path):
    import base64
    import hashlib
    import socket
    from concurrent.futures import ThreadPoolExecutor
    import test_card_chromium as lab
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    release = threading.Event()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(2)
        listener.settimeout(3)
        (profile / 'DevToolsActivePort').write_text(
            f'{listener.getsockname()[1]}\n/devtools/browser/synthetic-startup')
        (profile / 'DevToolsActivePort').chmod(0o600)
        def serve():
            requests = []
            for attempt in range(2):
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    data = b''
                    while b'\r\n\r\n' not in data and len(data) < 8192:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    requests.append(data)
                    if attempt == 0:
                        continue  # Own server is not ready for its first handshake.
                    key = next(line.split(b':', 1)[1].strip() for line in data.splitlines()
                               if line.lower().startswith(b'sec-websocket-key:'))
                    accept = base64.b64encode(hashlib.sha1(
                        key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
                    connection.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                        b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
                    assert release.wait(3), 'test did not close its prepared connection'
            return requests
        with ThreadPoolExecutor(max_workers=1) as pool:
            response = pool.submit(serve)
            cdp = None
            try:
                cdp = lab.connect_test_browser(profile, SimpleNamespace(poll=lambda: None),
                                               time.monotonic()+5)
                assert cdp.socket.getstatus() == 101
            finally:
                if cdp is not None:
                    cdp.close()
                release.set()
            requests = response.result(timeout=4)
            assert len(requests) == 2
            assert all(r.startswith(b'GET /devtools/browser/synthetic-startup ') for r in requests)


@pytest.mark.parametrize('error', [CardTargetError, PermissionError])
def test_fixture_does_not_retry_security_refusals(tmp_path, monkeypatch, error):
    import test_card_chromium as lab
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    (profile / 'DevToolsActivePort').write_text('12345\n/devtools/browser/synthetic-refusal')
    (profile / 'DevToolsActivePort').chmod(0o600)
    attempts = []
    def refused(_):
        attempts.append(True)
        raise error()
    monkeypatch.setattr(lab, 'CDP', refused)
    with pytest.raises(error):
        lab.connect_test_browser(profile, SimpleNamespace(poll=lambda: None), time.monotonic()+3)
    assert len(attempts) == 1


def test_fixture_transient_retries_stop_at_startup_deadline(tmp_path, monkeypatch):
    import test_card_chromium as lab
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    (profile / 'DevToolsActivePort').write_text('12345\n/devtools/browser/synthetic-timeout')
    (profile / 'DevToolsActivePort').chmod(0o600)
    clock, attempts = [0.0], []
    def sleep(seconds): clock[0] += seconds
    def timeout(_):
        attempts.append(True)
        raise TimeoutError()
    monkeypatch.setattr(lab, 'time', SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    monkeypatch.setattr(lab, 'CDP', timeout)
    with pytest.raises(AssertionError, match='did not accept a verified debugging connection'):
        lab.connect_test_browser(profile, SimpleNamespace(poll=lambda: None), .1)
    assert clock[0] == .1 and len(attempts) == 2


@pytest.mark.parametrize('missing', ['browser', 'openssl', 'Xvfb'])
@pytest.mark.parametrize('required', [False, True])
def test_missing_browser_dependencies_skip_locally_and_fail_in_card_ci(monkeypatch, missing, required):
    import test_card_chromium as lab
    tools = {'google-chrome': '/synthetic/chrome', 'openssl': '/synthetic/openssl', 'Xvfb': '/synthetic/Xvfb'}
    tools.pop('google-chrome' if missing == 'browser' else missing)
    monkeypatch.setattr(lab.shutil, 'which', tools.get)
    if required:
        monkeypatch.setenv('AKDBX_REQUIRE_CARD_CHROMIUM', '1')
    else:
        monkeypatch.delenv('AKDBX_REQUIRE_CARD_CHROMIUM', raising=False)
    with pytest.raises(pytest.fail.Exception if required else pytest.skip.Exception):
        lab.card_browser_binary()


def test_card_browser_dependency_check_accepts_chromium_fallback(monkeypatch):
    import test_card_chromium as lab
    tools = {'chromium': '/synthetic/chromium', 'openssl': '/synthetic/openssl', 'Xvfb': '/synthetic/Xvfb'}
    monkeypatch.setattr(lab.shutil, 'which', tools.get)
    monkeypatch.setenv('AKDBX_REQUIRE_CARD_CHROMIUM', '1')
    assert lab.card_browser_binary() == '/synthetic/chromium'


def test_foreign_uid_test_does_not_start_process_without_opt_in(monkeypatch):
    import subprocess
    monkeypatch.delenv('AKDBX_TEST_FOREIGN_UID', raising=False)
    def forbidden(*args, **kwargs):
        pytest.fail('foreign-UID process started without opt-in')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    with pytest.raises(pytest.skip.Exception):
        test_foreign_uid_endpoint_receives_no_websocket_bytes(None)


def test_required_foreign_uid_test_fails_when_sudo_is_missing(monkeypatch):
    import shutil
    monkeypatch.setenv('AKDBX_TEST_FOREIGN_UID', '1')
    monkeypatch.setattr(shutil, 'which', lambda _: None)
    with pytest.raises(AssertionError, match='requires sudo'):
        test_foreign_uid_endpoint_receives_no_websocket_bytes(None)


class FakeCDP:
    def __init__(self, result='filled', fail_at=None):
        self.result, self.fail_at, self.closed, self.calls = result, fail_at, 0, []
    def close(self): self.closed += 1
    def call(self, method, params=None, session=None):
        self.calls.append(method)
        writing = method == 'Runtime.callFunctionOn' and 'this.fill(value' in params.get('functionDeclaration','')
        if method == self.fail_at and (method != 'Runtime.callFunctionOn' or writing):
            raise RuntimeError('4111111111111111 MUST NOT escape')
        if method == 'Page.getFrameTree':
            return dict(frameTree=dict(frame=dict(id='frame', url='https://example.test/pay')))
        if method == 'DOM.getNodeForLocation':
            return dict(backendNodeId=1,frameId='frame')
        if method == 'Runtime.callFunctionOn' and not writing:
            return dict(result=dict(value=dict(x=10,y=10,rootX=10,rootY=10,width=100,height=100)))
        return dict(result=dict(value=self.result))


def target(cdp, clock):
    return dict(cdp=cdp, session='session', obj='object',input_node=1, field='cc-number', created=clock(), expires=clock()+30,
                request=dict(top_url='https://example.test/pay', frame_url='https://example.test/pay', frame_id='frame'))


@pytest.mark.parametrize('stage,expected', [('Page.getFrameTree', 'not-started'),
    ('DOM.getNodeForLocation','not-started'), ('Runtime.callFunctionOn', 'uncertain')])
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


@pytest.mark.parametrize('covered_after_write',[False,True])
def test_native_hit_mismatch_blocks_dispatch_or_reports_uncertainty(covered_after_write):
    class Covered(FakeCDP):
        def __init__(self):
            super().__init__()
            self.hits=0
            self.writes=0
        def call(self,method,params=None,session=None):
            if method=='DOM.getNodeForLocation':
                self.hits+=1
                if not covered_after_write or self.hits>1:
                    return dict(backendNodeId=99,frameId='frame')
            if method=='Runtime.callFunctionOn' and 'this.fill(value' in params.get('functionDeclaration',''):
                self.writes+=1
            return super().call(method,params,session)
    cards=BrowserCards(clock=lambda:0)
    cdp=Covered()
    result=cards.fill(target(cdp,lambda:0),'4111111111111111','cc-number',lambda:True)
    assert result==failure(covered_after_write)
    assert cdp.writes==int(covered_after_write) and cdp.closed
    assert '4111111111111111' not in str(result)


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


CARD_PIN = ['pin-card-target', '--page-id', 'P', '--frame-id', 'F', '--top-url', 'https://shop.example/',
            '--frame-url', 'https://shop.example/', '--selector', '#month', '--field', 'cc-exp-month']
CARD_CAPS = dict(ok=True, locked=False, cards_supported=True, card_protocol=1, card_delivery='cdp-card-element-v1',
                 card_browser_configured=True, default_fill_route='cdp', card_processor_frames_protocol=1,
                 card_processors=['adyen', 'computop', 'stripe'], stripe_card_element=True)


@pytest.mark.parametrize('extra, caps, error', [
    (['--field-purpose', 'cc-exp-month'], CARD_CAPS, 'broker lacks card field purpose protocol 1'),
    (['--allow-autocomplete-off'], CARD_CAPS | dict(card_field_purpose_protocol=1),
     '--allow-autocomplete-off needs --field-purpose'),
    (['--field-purpose', 'cc-exp-year'], CARD_CAPS | dict(card_field_purpose_protocol=1),
     '--field-purpose must name the same detail as --field'),
    (['--field-purpose', 'cc-exp-month', '--processor', 'stripe'], CARD_CAPS | dict(card_field_purpose_protocol=1),
     '--field-purpose does not apply to a --processor frame'),
])
def test_cli_refuses_card_purpose_options_before_sending(extra, caps, error, monkeypatch, capsys):
    from akdbx import cli
    calls = []

    def broker(_, payload, **kwargs):
        calls.append(payload)
        return caps
    monkeypatch.setattr(cli, 'request', broker)
    assert cli.main(CARD_PIN + extra) == 1
    assert calls == [{'action': 'ping'}]
    assert json.loads(capsys.readouterr().out)['error'] == error + '; pin request not sent'


def test_cli_refuses_a_card_purpose_the_card_route_does_not_take(capsys):
    from akdbx import cli
    with pytest.raises(SystemExit):
        cli.main(CARD_PIN[:-1] + ['cc-exp', '--field-purpose', 'cc-exp'])
    capsys.readouterr()


def test_cli_sends_the_card_purpose_options(monkeypatch, capsys):
    from akdbx import cli
    sent = []

    def broker(_, payload, **kwargs):
        if payload['action'] == 'ping':
            return CARD_CAPS | dict(card_field_purpose_protocol=1)
        sent.append(payload)
        return dict(ok=True, field='cc-exp-month', target='c' * 64, expires_in=30, card_delivery='cdp-card-element-v1')
    monkeypatch.setattr(cli, 'request', broker)
    assert cli.main(CARD_PIN + ['--field-purpose', 'cc-exp-month', '--allow-autocomplete-off']) == 0
    assert cli.main(CARD_PIN) == 0
    assert sent[0]['field_purpose'] == 'cc-exp-month' and sent[0]['allow_autocomplete_off'] is True
    assert not {'field_purpose', 'allow_autocomplete_off'} & set(sent[1])
    capsys.readouterr()


def test_status_advertises_card_field_purpose():
    assert BrowserCards().capabilities()['card_field_purpose_protocol'] == 1
