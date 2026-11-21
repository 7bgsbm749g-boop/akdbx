"""The broker side of the akdbx relay against an in-process fake relay (loopback only)."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
import datetime
import json
import os
from pathlib import Path
import re
import socket
import stat
import threading
import time
import tracemalloc
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from pykeepass import create_database

from akdbx import cli, relay as relay_module, relay_cli
from akdbx.broker import Broker
from akdbx.local_https import reload_certificate, start_local_unlock_server
from akdbx.relay import RelayClient, RelayError, RelayStore, check_chain
from relay_fakes import FakeRelay, FakeWS, phone_request
from test_broker import RecordingTyper, running_broker

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Linux paths and file modes; Windows: test_windows_native.py')
MASTER = 'synthetic relay master'
NO_BROKER = '/nonexistent/akdbx-test/akdbx.sock'
DAY = datetime.timedelta(days=1)


@pytest.fixture
def fake(tmp_path, monkeypatch):
    relay = FakeRelay(tmp_path)
    monkeypatch.setattr(relay_module, 'endpoint', relay.endpoint)
    monkeypatch.delenv('AKDBX_UNLOCK_ORIGIN', raising=False)
    yield relay
    relay.stop()


def run_cli(capsys, *argv):
    argv = list(argv)
    if '--socket' not in argv:
        # Never reach a real broker of this user from a test.
        argv = ['--socket', NO_BROKER, *argv]
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, (json.loads(captured.out) if captured.out.strip() else None), captured


def enable(fake, capsys):
    code, result, captured = run_cli(capsys, 'relay', 'enable', '--relay', fake.url)
    assert code == 0, captured
    return result, captured


def secret_of(store=None):
    return (store or RelayStore()).load().secret


def wait_until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, 'condition not reached'
        time.sleep(0.02)


# Enable, status, disable


def test_enable_registers_and_saves_a_private_key_and_certificate(fake, capsys):
    result, captured = enable(fake, capsys)
    name = result['name']
    assert re.fullmatch(r'[a-z2-7]{12}\.akdbx\.link', name)
    assert result['origin'] == f'https://{name}:8443' and result['enabled'] and result['registered_now']
    assert 'akdbx serve VAULT' in result['next'] and result['origin'] in result['next']
    store = RelayStore()
    secret = secret_of(store)
    assert secret not in captured.out + captured.err
    assert 'PRIVATE KEY' not in captured.out + captured.err
    # Private folder and files.
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700
    for path in (store.config_path, store.tls_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert sorted(p.name for p in store.directory.iterdir()) == ['.relay.lock', 'relay.json', 'tls.pem']
    # One ECDSA P-256 CSR with exactly the broker name; the saved key matches the leaf.
    [csr] = fake.csrs
    assert isinstance(csr.public_key(), ec.EllipticCurvePublicKey) and csr.public_key().curve.name == 'secp256r1'
    names = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == [name] and len(list(names)) == 1
    assert store.certificate(name) is not None
    assert result['certificate_not_after'] == store.certificate(name).as_dict()['certificate_not_after']


def test_enable_again_keeps_the_name_and_certificate(fake, capsys):
    first, _ = enable(fake, capsys)
    second, _ = enable(fake, capsys)
    assert second['name'] == first['name'] and not second['registered_now']
    assert fake.register_calls == 1 and len(fake.csrs) == 1


def test_enable_waits_for_short_retry_after_answers(fake, capsys):
    fake.register_errors = [(429, 'rate_limited', 1)]
    fake.certificate_errors = [(503, 'issuance_paused', 2), (429, 'rate_limited', 3)]
    args = cli.parser().parse_args(['relay', 'enable', '--relay', fake.url])
    cli.resolve_unlock_origin(args)
    sleeps = []
    assert relay_cli.run(args, lambda: None, sleep=sleeps.append) == 0
    assert sleeps == [1, 2, 3]
    captured = capsys.readouterr()
    assert 'try again in about 2 seconds; waiting' in captured.err
    assert secret_of() not in captured.out + captured.err


def test_enable_reports_long_waits_and_resumes_a_saved_registration(fake, capsys):
    fake.register_errors = [(503, 'registrations_paused', 86400)]
    code, result, _ = run_cli(capsys, 'relay', 'enable', '--relay', fake.url)
    assert code == 1 and result['retry_after'] == 86400
    assert 'not accepting new registrations' in result['error'] and 'about 24 hours' in result['error']
    assert RelayStore().load() is None
    fake.certificate_errors = [(502, 'acme_failed'), (429, 'rate_limited', 3600)]
    code, result, _ = run_cli(capsys, 'relay', 'enable', '--relay', fake.url)
    assert code == 1 and result['registered'] and 'did not issue' in result['error']
    assert 'run \'akdbx relay enable\' again' in result['next']
    saved = RelayStore().load()
    assert saved.name == result['name'] and not saved.enabled
    code, result, _ = run_cli(capsys, 'relay', 'enable', '--relay', fake.url)
    assert code == 1 and result['retry_after'] == 3600 and 'about 60 minutes' in result['error']
    code, result, _ = run_cli(capsys, 'relay', 'enable', '--relay', fake.url)
    assert code == 0 and result['name'] == saved.name and not result['registered_now']
    assert fake.register_calls == 2  # the refused call and one registration


def test_relay_answers_are_checked_not_trusted(fake, capsys, tmp_path):
    fake.bad_name = 'paypal.com'
    code, result, _ = run_cli(capsys, 'relay', 'enable', '--relay', fake.url)
    assert code == 1 and result['error'] == 'the relay sent an invalid registration'
    assert RelayStore().load() is None
    # A certificate for another key or another name is refused.
    fake.bad_name = None
    enable(fake, capsys)
    config = RelayStore().load()
    key_pem, _ = relay_module.new_key_and_csr(config.name)
    tls = RelayStore().read_tls()
    chain = tls[tls.index(b'-----END PRIVATE KEY-----'):]
    with pytest.raises(RelayError, match='another key'):
        check_chain(chain, config.name, key_pem)
    with pytest.raises(RelayError, match='another name'):
        check_chain(chain, 'abcdefghijkl.akdbx.link')
    with pytest.raises(RelayError, match='invalid certificate chain'):
        check_chain(b'not a certificate', config.name)
    with pytest.raises(ValueError):
        relay_module.Endpoint.parse('http://relay.akdbx.link:8443')
    with pytest.raises(ValueError):
        relay_module.Endpoint.parse('https://relay.akdbx.link:8443/api')


def test_status_disable_and_forget(fake, capsys):
    enabled, _ = enable(fake, capsys)
    code, status, captured = run_cli(capsys, 'relay', 'status')
    assert code == 0 and status['enabled'] and status['name'] == enabled['name']
    assert status['origin'] == enabled['origin'] and status['broker'] == {'running': False}
    assert status['certificate_not_after'] and status['certificate_expired'] is False
    assert secret_of() not in captured.out + captured.err
    code, disabled, _ = run_cli(capsys, 'relay', 'disable')
    assert code == 0 and disabled['enabled'] is False and disabled['registered']
    store = RelayStore()
    assert store.config_path.exists() and store.tls_path.exists() and not store.load().enabled
    assert relay_module.saved_origin() is None
    again, _ = enable(fake, capsys)
    assert again['name'] == enabled['name'] and fake.register_calls == 1
    code, forgot, _ = run_cli(capsys, 'relay', 'disable', '--forget')
    assert code == 0 and forgot['forgot'] and not store.directory.exists()
    code, status, _ = run_cli(capsys, 'relay', 'status')
    assert code == 0 and status['registered'] is False


def test_status_reports_a_running_broker_connection(fake, capsys):
    enable(fake, capsys)
    args = cli.parser().parse_args(['relay', 'status'])
    cli.resolve_unlock_origin(args)
    for state, expected in (({'connected': True, 'renewal_error': 'the relay cannot issue certificates now'},
                             {'running': True, 'uses_relay': True, 'connected': True,
                              'renewal_error': 'the relay cannot issue certificates now'}),
                            (None, {'running': True, 'uses_relay': False})):
        response = {'ok': True, **({'relay': state} if state else {})}
        assert relay_cli.run(args, lambda: response) == 0
        assert json.loads(capsys.readouterr().out)['broker'] == expected


@pytest.mark.parametrize('damage', ['config-mode', 'tls-mode', 'folder-mode', 'symlink', 'malformed'])
def test_untrusted_relay_files_are_refused(fake, capsys, tmp_path, damage):
    enable(fake, capsys)
    store = RelayStore()
    if damage == 'config-mode':
        store.config_path.chmod(0o644)
    elif damage == 'tls-mode':
        store.tls_path.chmod(0o640)
    elif damage == 'folder-mode':
        store.directory.chmod(0o750)
    elif damage == 'symlink':
        target = tmp_path / 'elsewhere.json'
        target.write_bytes(store.config_path.read_bytes())
        target.chmod(0o600)
        store.config_path.unlink()
        store.config_path.symlink_to(target)
    else:
        store.config_path.write_text('{"version": 1}')
    if damage != 'tls-mode':
        assert relay_module.saved_origin() is None
    code, result, _ = run_cli(capsys, '--socket', str(tmp_path / 'p' / 'b.sock'), 'relay', 'status')
    assert code == 2 and result['error'].startswith('the relay directory cannot be trusted')
    code, _, captured = run_cli(capsys, '--socket', str(tmp_path / 'p' / 'b.sock'), 'serve', str(tmp_path / 'v.kdbx'))
    assert code == 2 and 'refusing to start: the saved relay configuration cannot be trusted' in captured.err
    # Nothing was repaired.
    if damage == 'folder-mode':
        assert stat.S_IMODE(store.directory.stat().st_mode) == 0o750


def test_unlock_origin_precedence(fake, capsys, monkeypatch):
    def origin(*argv):
        args = cli.parser().parse_args([*argv, 'status'])
        cli.resolve_unlock_origin(args)
        return args.unlock_origin

    assert origin() == 'https://localhost:9443'
    enabled, _ = enable(fake, capsys)
    assert origin() == enabled['origin']
    monkeypatch.setenv('AKDBX_UNLOCK_ORIGIN', 'https://node.example:9443')
    assert origin() == 'https://node.example:9443'
    assert origin('--unlock-origin', 'https://other.example:9443') == 'https://other.example:9443'
    code, status, _ = run_cli(capsys, 'relay', 'status')
    assert 'AKDBX_UNLOCK_ORIGIN is set' in status['warning']
    monkeypatch.delenv('AKDBX_UNLOCK_ORIGIN')
    run_cli(capsys, 'relay', 'disable')
    assert origin() == 'https://localhost:9443'


# serve


@pytest.fixture
def database(tmp_path):
    path = tmp_path / 'vault.kdbx'
    create_database(str(path), password=MASTER).save()
    return path


def test_serve_uses_the_saved_relay_and_unlocks_from_a_phone(fake, capsys, tmp_path, database, monkeypatch):
    enabled, _ = enable(fake, capsys)
    origin, name = enabled['origin'], enabled['name']
    leaf = RelayStore().read_tls()
    leaf = x509.load_pem_x509_certificate(leaf[leaf.index(b'-----BEGIN CERTIFICATE-----'):])
    seen = {}

    def exercise(socket_path, broker):
        assert broker.unlock_url.startswith(origin + '/?token=')
        wait_until(broker.relay.connected.is_set)
        ping = broker.dispatch({'action': 'ping'})
        assert ping['relay']['connected'] and ping['relay']['origin'] == origin
        assert secret_of() not in json.dumps(ping)
        phone = fake.acme_ca.client_context()
        path = '/?' + urlsplit(broker.unlock_url).query
        status, body, peer = phone_request(fake.public_port, name, phone, path=path)
        assert status == 200 and b'password' in body.lower()
        assert x509.load_der_x509_certificate(peer) == leaf
        # The page still checks Host and Origin; the relay is not trusted.
        form = urlencode({'password': MASTER}).encode()
        headers = (('Origin', origin), ('Content-Type', 'application/x-www-form-urlencoded'))
        assert phone_request(fake.public_port, name, phone, 'POST', path, headers, form,
                             host='attacker.example')[0] == 404
        assert broker.locked
        status, body, _ = phone_request(fake.public_port, name, phone, 'POST', path, headers, form)
        seen['status'], seen['unlocked'] = status, not broker.locked
        assert MASTER.encode() not in body

    monkeypatch.setattr(cli, 'X11Typer', RecordingTyper)
    monkeypatch.setattr(cli, 'serve', exercise)
    code = cli.main(['--socket', str(tmp_path / 'private' / 'broker.sock'), 'serve', str(database)])
    captured = capsys.readouterr()
    assert code == 0 and seen == {'status': 200, 'unlocked': True}, captured.err
    assert f'Relay: the private pages open at {origin}' in captured.err
    assert 'Open the private HTTPS page: ' + origin + '/?token=' in captured.err
    assert secret_of() not in captured.out + captured.err
    # The relay lock is released when serve returns.
    RelayStore().lock().release()


def test_serve_refuses_options_that_conflict_with_the_relay(fake, capsys, tmp_path, database):
    socket_option = ['--socket', str(tmp_path / 'private' / 'broker.sock')]
    code, _, captured = run_cli(capsys, *socket_option, 'serve', str(database), '--relay')
    assert code == 2 and "run 'akdbx relay enable' first" in captured.err
    enable(fake, capsys)
    code, _, captured = run_cli(capsys, *socket_option, 'serve', str(database), '--tls-cert', 'c.pem',
                                '--tls-key', 'k.pem')
    assert code == 2 and 'the akdbx relay is enabled' in captured.err
    code, _, captured = run_cli(capsys, *socket_option, '--unlock-origin', 'https://node.example:9443',
                                'serve', str(database), '--relay')
    assert code == 2 and '--relay sets the origin itself' in captured.err
    held = RelayStore().lock()
    try:
        code, _, captured = run_cli(capsys, *socket_option, 'serve', str(database))
        assert code == 2 and 'another akdbx broker uses the relay' in captured.err
    finally:
        held.release()


def test_an_explicit_origin_serves_without_the_relay(fake, capsys, tmp_path, database, monkeypatch):
    enable(fake, capsys)
    seen = {}

    def exercise(socket_path, broker):
        seen['relay'] = broker.relay
        seen['url'] = broker.unlock_url

    monkeypatch.setattr(cli, 'X11Typer', RecordingTyper)
    monkeypatch.setattr(cli, 'serve', exercise)
    monkeypatch.setenv('AKDBX_UNLOCK_ORIGIN', 'https://node.example:9443')
    assert cli.main(['--socket', str(tmp_path / 'private' / 'broker.sock'), 'serve', str(database)]) == 0
    assert seen['relay'] is None and seen['url'].startswith('https://node.example:9443/?token=')


def test_serve_relay_ignores_an_inherited_origin_variable(fake, capsys, tmp_path, database, monkeypatch):
    # N4: the units and tasks that setup writes run serve --relay, whatever the environment holds.
    enabled, _ = enable(fake, capsys)
    seen = []

    def exercise(socket_path, broker):
        seen.append((broker.relay is not None, broker.unlock_url))

    monkeypatch.setattr(cli, 'X11Typer', RecordingTyper)
    monkeypatch.setattr(cli, 'serve', exercise)
    monkeypatch.setenv('AKDBX_UNLOCK_ORIGIN', 'https://node.example:9443')
    socket_option = ['--socket', str(tmp_path / 'private' / 'broker.sock')]
    assert cli.main([*socket_option, 'serve', str(database), '--relay']) == 0
    warned = capsys.readouterr().err
    assert ('AKDBX_UNLOCK_ORIGIN is https://node.example:9443' in warned and enabled['origin'] in warned
            and 'unset AKDBX_UNLOCK_ORIGIN' in warned)
    # An explicit option that names the relay origin itself is accepted; another one is still refused.
    # The variable still differs, so the warning is still printed.
    assert cli.main([*socket_option, '--unlock-origin', enabled['origin'] + '/', 'serve', str(database),
                     '--relay']) == 0
    assert 'AKDBX_UNLOCK_ORIGIN is https://node.example:9443' in capsys.readouterr().err
    assert [relay for relay, _ in seen] == [True, True]
    assert all(url.startswith(enabled['origin'] + '/?token=') for _, url in seen)
    code, _, captured = run_cli(capsys, *socket_option, '--unlock-origin', 'https://node.example:9443', 'serve',
                                str(database), '--relay')
    assert code == 2 and f'--relay sets the origin itself ({enabled["origin"]})' in captured.err


# The relay client


@pytest.fixture
def page(fake, capsys, tmp_path):
    """An enabled relay and the real loopback unlock page with its certificate."""
    enable(fake, capsys)
    store = RelayStore()
    config = store.load()
    broker = Broker(None, RecordingTyper())
    with __import__('socket').socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    server, url = start_local_unlock_server(broker, tmp_path / 'unused.kdbx', None, config.origin,
                                            store.tls_path, store.tls_path, local_port=port)
    yield SimpleNamespace(store=store, config=config, server=server, url=url, port=port, broker=broker)
    server.shutdown()
    server.server_close()


def client_for(fake, page, **options):
    logs = []
    options.setdefault('jitter', lambda: 0.0)
    client = RelayClient(fake.endpoint(), page.config, page.store, page.port, log=logs.append,
                         reload_tls=lambda path: reload_certificate(page.server, path, path), **options)
    return client, logs


def get_page(fake, page, connection_context=None):
    path = '/?' + urlsplit(page.url).query
    return phone_request(fake.public_port, page.config.name, connection_context or fake.acme_ca.client_context(),
                         path=path)


def test_streams_are_spliced_to_the_real_tls_page(fake, page):
    client, logs = client_for(fake, page)
    client.start()
    try:
        wait_until(client.connected.is_set)
        with ThreadPoolExecutor(6) as pool:
            results = list(pool.map(lambda _: get_page(fake, page), range(6)))
        assert all(status == 200 for status, _, _ in results)
        assert client.streams_opened == 6 and fake.streams == 6
        # Control pings are answered; unknown and malformed messages are ignored.
        fake.control.send_text('{"type":"future","stream":"x"}')
        fake.control.send_text('{"type":"open","stream":"../../etc"}')
        fake.control.send_text('not json')
        fake.ping_control()
        wait_until(lambda: {'type': 'pong'} in fake.control_messages)
        assert client.connected.is_set() and client.streams_opened == 6
        wait_until(lambda: not client._live)
    finally:
        client.stop()
    assert not any(secret_of() in line for line in logs)
    assert any('connected; the private pages are at ' + page.config.origin in line for line in logs)


def test_the_client_reconnects_after_the_relay_drops_it(fake, page):
    client, logs = client_for(fake, page)
    client.start()
    try:
        wait_until(client.connected.is_set)
        fake.drop_control()
        wait_until(lambda: fake.control_connects == 2 and client.connected.is_set())
        assert client.delays and client.delays[0] == 0.5  # 1 s with full jitter applied
        assert get_page(fake, page)[0] == 200
    finally:
        client.stop()
    assert any('control connection lost' in line for line in logs)


def test_reconnect_backoff_doubles_to_60_seconds_with_jitter(fake, page):
    fake.reject_connects = 8
    waits = []
    client, logs = client_for(fake, page, jitter=lambda: 1.0, wait=waits.append)
    client.start()
    try:
        wait_until(client.connected.is_set)
    finally:
        client.stop()
    assert waits == [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0]
    # A failing relay is reported once, not on every attempt.
    assert sum('cannot connect' in line for line in logs) == 1
    assert 'WebSocketBadStatusException 401' in logs[0]
    jittered, _ = client_for(fake, page, jitter=lambda: 0.0)
    assert jittered._jitter() == 0.0


def test_renewal_hot_reloads_the_page_without_dropping_connections(fake, page, capsys):
    store, name = page.store, page.config.name
    old_tls = store.read_tls()
    old_leaf = x509.load_pem_x509_certificate(old_tls[old_tls.index(b'-----BEGIN CERTIFICATE-----'):])
    info = store.certificate(name)
    client, logs = client_for(fake, page)
    # Not due: a check later, never sooner than a minute and at most six hours.
    assert 60 <= client.renew_if_due() <= 6 * 3600 and len(fake.csrs) == 1
    client.start()
    try:
        wait_until(client.connected.is_set)
        raw = __import__('socket').create_connection(('127.0.0.1', fake.public_port), timeout=20)
        held = fake.acme_ca.client_context().wrap_socket(raw, server_hostname=name)
        assert x509.load_der_x509_certificate(held.getpeercert(True)) == old_leaf
        # Less than a third of the lifetime is left.
        client._clock = lambda: info.renew_at + datetime.timedelta(seconds=1)
        assert client.renew_if_due() >= 60
        assert len(fake.csrs) == 2 and store.read_tls() != old_tls
        status, _, peer = get_page(fake, page)
        new_leaf = x509.load_der_x509_certificate(peer)
        assert status == 200 and new_leaf != old_leaf and new_leaf == store_leaf(store)
        assert new_leaf.public_key().public_numbers() != old_leaf.public_key().public_numbers()  # key rotated
        # The connection opened before the renewal still works.
        path = '/?' + urlsplit(page.url).query
        held.sendall(f'GET {path} HTTP/1.1\r\nHost: {name}:8443\r\nConnection: close\r\n\r\n'.encode())
        assert held.recv(64).split(b' ', 2)[1] == b'200'
        held.close()
        assert client.status()['certificate_not_after'] == store.certificate(name).as_dict()['certificate_not_after']
    finally:
        client.stop()
    assert any(line.startswith('renewed the certificate for ' + name) for line in logs)
    assert stat.S_IMODE(store.tls_path.stat().st_mode) == 0o600


def store_leaf(store):
    tls = store.read_tls()
    return x509.load_pem_x509_certificate(tls[tls.index(b'-----BEGIN CERTIFICATE-----'):])


def test_failed_renewal_waits_for_retry_after_and_keeps_the_old_certificate(fake, page):
    info = page.store.certificate(page.config.name)
    old = page.store.read_tls()
    client, logs = client_for(fake, page, clock=lambda: info.renew_at + DAY)
    fake.certificate_errors = [(503, 'issuance_paused', 7200)]
    assert client.renew_if_due() == 7200
    assert page.store.read_tls() == old and client.renewal_failures == 1
    assert client.status()['renewal_error'] == 'the relay cannot issue certificates now; try again in about 2 hours'
    fake.certificate_errors = [(502, 'acme_failed')]
    assert client.renew_if_due() == 600  # 5 minutes doubling
    assert client.renew_if_due() >= 60 and client.renewal_failures == 0 and 'renewal_error' not in client.status()
    assert not any(secret_of() in line for line in logs)


def test_an_expired_or_missing_certificate_renews_at_once(fake, page):
    now = datetime.datetime.now(datetime.timezone.utc)
    for certificate in (relay_module.CertificateInfo(now - 91 * DAY, now - DAY), None):
        client, _ = client_for(fake, page)
        client.certificate = certificate
        assert client.renew_if_due() >= 60 and client.certificate.not_after > now
    assert len(fake.csrs) == 3


def test_the_secret_never_appears_in_reprs_or_errors(fake, capsys):
    enable(fake, capsys)
    config = RelayStore().load()
    assert config.secret not in repr(config)
    fake.certificate_errors = [(401, 'unauthorized')]
    with pytest.raises(RelayError) as error:
        relay_module.request_certificate(fake.endpoint(), config)
    assert config.secret not in str(error.value) and 'relay disable --forget' in str(error.value)
    unreachable = relay_module.Endpoint.parse('https://relay.akdbx.link:1', connect_host='127.0.0.1')
    with pytest.raises(RelayError) as error:
        relay_module.register(unreachable)
    assert str(error.value) == 'could not reach the relay at https://relay.akdbx.link:1 (ConnectionRefusedError)'


def test_one_broker_holds_the_relay(fake, capsys):
    enable(fake, capsys)
    first = RelayStore().lock()
    try:
        with pytest.raises(relay_module.RelayBusy, match='another akdbx process'):
            RelayStore().lock()
        # enable while a broker runs reports the running relay and changes nothing.
        code, result, _ = run_cli(capsys, 'relay', 'enable', '--relay', fake.url)
        assert code == 0 and result['changed'] is False
        code, result, _ = run_cli(capsys, 'relay', 'disable', '--forget')
        assert code == 1 and 'stop it' in result['error']
    finally:
        first.release()
    RelayStore().lock().release()


# Review fixes: redirects, message limits, status of a running broker, locks and repair


def flood(ws, first, chunk, count):
    """Send ``first`` and then ``chunk`` up to ``count`` times, until the broker closes the connection."""
    def send():
        with suppress(OSError):
            ws.send_raw(first)
            for _ in range(count):
                ws.send_raw(chunk)
    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    return thread


def closed_by_broker(ws, timeout=10):
    """True when the broker ends the WebSocket within ``timeout`` seconds."""
    ws.sock.settimeout(timeout)
    try:
        while ws.recv()[0] != 8:
            pass
        return True
    except TimeoutError:
        return False
    except (ConnectionError, OSError):
        return True


def test_websocket_redirects_are_not_followed(fake, page):
    # Another loopback port, as a service on the broker's own network would be.
    seen = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    listener.settimeout(0.1)
    done = threading.Event()

    def accept():
        while not done.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                with suppress(OSError):
                    seen.append(conn.recv(65536))
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    fake.redirect = f'ws://127.0.0.1:{listener.getsockname()[1]}'
    holder = {}
    client, logs = client_for(fake, page, wait=lambda seconds: holder['client']._stop.set())
    holder['client'] = client
    try:
        client._control_loop()  # one attempt; its backoff wait stops the loop
        assert fake.upgrade_requests == 1 and client.delays == [0.5] and not client.connected.is_set()
        assert any('cannot connect' in line for line in logs)
        client._stop.clear()
        client._slots.acquire()
        client._stream('0' * 32)  # a stream upgrade does not follow a redirect either
        assert fake.upgrade_requests == 2 and client.streams_opened == 0
        time.sleep(0.3)
    finally:
        done.set()
        listener.close()
        thread.join(2)
    assert seen == []
    assert secret_of() not in ''.join(logs)


def test_an_oversize_upgrade_answer_is_aborted_at_the_limit(fake, page):
    # A 503 that claims 1 GiB and streams it: websocket-client would keep it all in memory.
    fake.oversize_upgrades = 1
    holder = {}
    client, logs = client_for(fake, page, wait=lambda seconds: holder['client']._stop.set())
    holder['client'] = client
    tracemalloc.start()
    try:
        client._control_loop()  # one attempt; its backoff wait stops the loop
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 1024 * 1024, peak
    assert client.delays == [0.5] and not client.connected.is_set()
    assert any('cannot connect' in line and 'UpgradeTooLarge' in line for line in logs)
    # The normal backoff follows, and a 101 upgrade still connects through the same path.
    fake.oversize_upgrades = 2
    waits = []
    client, logs = client_for(fake, page, jitter=lambda: 1.0, wait=waits.append)
    client.start()
    try:
        wait_until(client.connected.is_set)
        assert get_page(fake, page)[0] == 200
    finally:
        client.stop()
    assert waits == [1.0, 2.0]
    assert sum('cannot connect' in line for line in logs) == 1


def test_the_control_channel_aborts_an_oversize_frame_before_reading_it(fake, page):
    client, logs = client_for(fake, page)
    client.start()
    try:
        wait_until(client.connected.is_set)
        ws = fake.control
        tracemalloc.start()
        try:
            # The header declares 1 TiB; 4 MiB follow.
            sender = flood(ws, FakeWS.header(1, 2 ** 40), b'x' * 65536, 64)
            wait_until(lambda: fake.control is not ws)
            sender.join(10)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert peak < 1024 * 1024
        # A failed connection: the normal backoff, then a new control connection.
        wait_until(lambda: fake.control_connects == 2 and client.connected.is_set())
    finally:
        client.stop()
    assert any('control connection lost (MessageTooLarge)' in line for line in logs)


def test_the_control_channel_aborts_endless_continuation_frames(fake, page):
    client, logs = client_for(fake, page)
    client.start()
    try:
        wait_until(client.connected.is_set)
        ws = fake.control
        flood(ws, FakeWS.header(1, 1, fin=False) + b'{', FakeWS.header(0, 1, fin=False) + b' ', 100000)
        wait_until(lambda: fake.control is not ws)
    finally:
        client.stop()
    assert any('control connection lost (MessageTooLarge)' in line for line in logs)


def test_a_stream_aborts_an_oversize_message_or_endless_continuation_frames(fake, page):
    client, _ = client_for(fake, page)
    client.start()
    try:
        wait_until(client.connected.is_set)
        for first, chunk, count in (
                (FakeWS.header(2, 2 ** 40), b'x' * 65536, 64),
                (FakeWS.header(2, 1, fin=False) + b'\x16', FakeWS.header(0, 1, fin=False) + b'\x03', 100000)):
            waiter = fake.open_stream()
            tracemalloc.start()
            try:
                sender = flood(waiter['ws'], first, chunk, count)
                # At once: the loopback page itself drops a silent TLS client only after 5 s.
                assert closed_by_broker(waiter['ws'], timeout=2)
                sender.join(10)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            assert peak < 1024 * 1024
            waiter['done'].set()
        wait_until(lambda: not client._live)
        assert client.connected.is_set()  # a bad stream does not end the control connection
    finally:
        client.stop()


def ws_pair():
    """A client WebSocket and the relay side of it over a socket pair (no handshake)."""
    import websocket
    near, far = socket.socketpair()
    near.settimeout(5)
    ws = websocket.WebSocket(skip_utf8_validation=True)
    ws.sock, ws.connected = near, True
    return ws, FakeWS(far)


@pytest.mark.parametrize('limit', [4096, 256 * 1024])  # protocol v1: control and stream messages
def test_messages_up_to_the_protocol_limits_are_read_and_larger_ones_are_not(limit):
    fragments = relay_module.MAX_FRAGMENTS
    piece = limit // fragments
    ws, relay = ws_pair()

    def send():
        relay.send(9, b'keepalive')  # a ping between messages is answered, not returned
        for index in range(fragments):
            relay.send(2 if index == 0 else 0, b'a' * piece, fin=index == fragments - 1)
    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    assert relay_module._recv_message(ws, limit) == (2, b'a' * limit)
    sender.join(5)
    # One byte more: refused from the header alone (no payload is ever sent).
    relay.send_raw(FakeWS.header(2, limit + 1))
    with pytest.raises(relay_module.MessageTooLarge):
        relay_module._recv_message(ws, limit)
    ws, relay = ws_pair()
    relay.send_raw(FakeWS.header(2, 0, fin=False) + FakeWS.header(0, 0, fin=False) * fragments)
    with pytest.raises(relay_module.MessageTooLarge):  # one fragment more
        relay_module._recv_message(ws, limit)
    ws, relay = ws_pair()
    relay.send_raw(FakeWS.header(9, 126))
    with pytest.raises(relay_module.MessageTooLarge):  # a control frame is at most 125 bytes
        relay_module._recv_message(ws, limit)


def test_status_after_disable_asks_the_running_broker(fake, capsys, tmp_path):
    enabled, _ = enable(fake, capsys)
    origin, token = enabled['origin'], 'T' * 43
    # A locked broker that serves through the relay: its ping holds the relay unlock URL.
    broker = Broker(None, RecordingTyper())
    broker.relay = SimpleNamespace(status=lambda: {'connected': True, 'name': enabled['name'], 'origin': origin})
    broker.unlock_link = SimpleNamespace(origin=origin, blocked=False)
    broker.unlock_url = f'{origin}/?token={token}'
    socket_path = tmp_path / 'private' / 'broker.sock'
    with running_broker(socket_path, broker):
        run_cli(capsys, 'relay', 'disable')
        # The CLI now expects the localhost origin; the broker still uses the relay.
        code, status, captured = run_cli(capsys, '--socket', str(socket_path), 'relay', 'status')
    assert code == 0 and status['enabled'] is False
    assert status['broker'] == {'running': True, 'uses_relay': True, 'connected': True, 'origin': origin}
    assert 'still uses the relay' in status['next']
    assert token not in captured.out + captured.err
    response = broker.dispatch({'action': 'relay-status'})
    assert 'unlock_url' not in response and token not in json.dumps(response)


def test_a_failed_broker_check_is_unknown_not_stopped(fake, capsys):
    enable(fake, capsys)
    args = cli.parser().parse_args(['relay', 'status'])
    cli.resolve_unlock_origin(args)
    for error, running in ((cli.ProtocolError('broker returned an untrusted unlock URL'), 'unknown'),
                           (PermissionError('broker peer UID does not match the configured broker UID'), 'unknown'),
                           (ValueError('configured unlock origin is invalid'), 'unknown'),
                           (FileNotFoundError(), False), (ConnectionRefusedError(), False)):
        def broker_status():
            raise error
        assert relay_cli.run(args, broker_status) == 0
        broker = json.loads(capsys.readouterr().out)['broker']
        assert broker['running'] == running, error
        if running == 'unknown':
            assert broker['error'] == f'the broker check failed ({type(error).__name__})'


def test_a_busy_or_failing_windows_pipe_is_unknown_not_stopped(fake, capsys, monkeypatch):
    # windows_rpc.connect: FileNotFoundError for a missing pipe, a plain OSError for a
    # busy pipe or failed pipe I/O. Only the missing pipe means no broker runs.
    monkeypatch.setattr(relay_cli, 'os', SimpleNamespace(name='nt'), raising=False)
    enable(fake, capsys)
    args = cli.parser().parse_args(['relay', 'status'])
    cli.resolve_unlock_origin(args)
    for error, running in ((OSError('Windows broker pipe busy or unavailable'), 'unknown'),
                           (OSError('Windows pipe I/O failed'), 'unknown'),
                           (FileNotFoundError('Windows broker pipe not found'), False)):
        def broker_status():
            raise error
        assert relay_cli.run(args, broker_status) == 0
        assert json.loads(capsys.readouterr().out)['broker']['running'] == running, error


def test_serve_relay_names_unlock_url_when_it_refuses_it(fake, capsys, tmp_path, database):
    enable(fake, capsys)
    code, _, captured = run_cli(capsys, '--socket', str(tmp_path / 'private' / 'broker.sock'), 'serve',
                                str(database), '--relay', '--unlock-url', 'https://node.example:9443')
    assert code == 2 and '--unlock-url' in captured.err


@pytest.mark.parametrize('damage', ['config-mode', 'malformed'])
def test_forget_removes_untrusted_or_malformed_files(fake, capsys, damage):
    enable(fake, capsys)
    store = RelayStore()
    if damage == 'config-mode':
        store.config_path.chmod(0o644)
    else:
        store.config_path.write_text('{"version": 1, "secret": "not json')
    with pytest.raises(relay_module.RelayStoreError):
        store.load()
    code, result, _ = run_cli(capsys, 'relay', 'disable', '--forget')
    assert code == 0 and result['forgot'] and not store.directory.exists()


def test_forget_still_refuses_an_untrusted_folder(fake, capsys):
    enable(fake, capsys)
    store = RelayStore()
    store.directory.chmod(0o750)
    code, result, _ = run_cli(capsys, 'relay', 'disable', '--forget')
    assert code == 2 and result['error'].startswith('the relay directory cannot be trusted')
    assert store.config_path.exists() and store.tls_path.exists()


def test_a_folder_trust_failure_is_not_reported_as_a_running_broker(fake, capsys, tmp_path, database):
    state = Path(os.environ['XDG_STATE_HOME'])
    state.chmod(0o777)
    try:
        with pytest.raises(relay_module.RelayStoreError):
            RelayStore().lock()
        code, result, _ = run_cli(capsys, 'relay', 'enable', '--relay', fake.url)
        assert code == 2 and result['error'].startswith('the relay directory cannot be trusted')
        assert 'running broker' not in result['error']
    finally:
        state.chmod(0o700)
    enable(fake, capsys)
    (RelayStore().directory / '.relay.lock').chmod(0o644)
    with pytest.raises(relay_module.RelayStoreError):
        RelayStore().lock()
    code, _, captured = run_cli(capsys, '--socket', str(tmp_path / 'private' / 'broker.sock'), 'serve',
                                str(database))
    assert code == 2 and 'the relay directory cannot be trusted' in captured.err
    assert 'another akdbx broker' not in captured.err


def test_origins_compare_by_host_and_effective_port():
    # The serve --relay warning uses the same identity as client validation: no false warning.
    assert cli._same_origin('https://Node.Example:443', 'https://node.example')
    assert cli._same_origin('https://node.example:8443/', 'https://node.example:8443')
    assert not cli._same_origin('https://node.example:9443', 'https://node.example:8443')
    assert not cli._same_origin('https://other.example:8443', 'https://node.example:8443')
    assert not cli._same_origin('https://node.example:bad', 'https://node.example')
    # Origins that clients reject are never the same as the relay origin, so the warning is printed.
    assert not cli._same_origin('https://node.example/help', 'https://node.example')
    assert not cli._same_origin('https://node.example:0', 'https://node.example')
    assert not cli._same_origin('http://node.example', 'http://node.example')
