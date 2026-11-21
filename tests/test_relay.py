"""The broker side of the akdbx relay against an in-process fake relay (loopback only)."""
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import os
import re
import stat
import time
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
from relay_fakes import FakeRelay, phone_request
from test_broker import RecordingTyper

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
        with pytest.raises(relay_module.RelayStoreError, match='another akdbx process'):
            RelayStore().lock()
        # enable while a broker runs reports the running relay and changes nothing.
        code, result, _ = run_cli(capsys, 'relay', 'enable', '--relay', fake.url)
        assert code == 0 and result['changed'] is False
        code, result, _ = run_cli(capsys, 'relay', 'disable', '--forget')
        assert code == 1 and 'stop it' in result['error']
    finally:
        first.release()
    RelayStore().lock().release()
