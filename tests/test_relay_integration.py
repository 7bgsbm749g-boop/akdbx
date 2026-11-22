"""End to end through the real relay server from github.com/7bgsbm749g-boop/akdbx-relay.

Runs only when ``akdbx_relay`` is importable (``pip install`` that repository).
With ``AKDBX_RELAY_SOURCE`` set to a checkout of it, the relay issues the
certificate through its real ACME client against the fake ACME and Cloudflare
servers of that repository's tests; otherwise a local issuer signs the CSR.
Everything stays on 127.0.0.1.
"""
import asyncio
import datetime
import importlib.util
import os
from pathlib import Path
import sys
import threading
import time
from urllib.parse import urlencode, urlsplit

import pytest

pytest.importorskip('akdbx_relay', reason='the akdbx-relay server is not installed')
pytestmark = pytest.mark.skipif(os.name == 'nt', reason='the relay server runs on Linux')

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

from akdbx import relay as relay_module  # noqa: E402
from akdbx.broker import Broker  # noqa: E402
from akdbx.local_https import reload_certificate, start_local_unlock_server  # noqa: E402
from akdbx.relay import Endpoint, RelayClient, RelayStore  # noqa: E402
from relay_fakes import CA, now, phone_request  # noqa: E402
from test_broker import RecordingTyper  # noqa: E402

from akdbx_relay.config import Config  # noqa: E402
from akdbx_relay.relay import Relay  # noqa: E402
from akdbx_relay.store import Store  # noqa: E402

MASTER = 'synthetic relay master'


class LocalIssuer:
    """The relay's issuer interface, signing with a local CA."""

    def __init__(self):
        self.ca = CA('local issuer CA')
        self.calls = []

    async def issue(self, name, csr_pem, deadline=None):
        self.calls.append(name)
        csr = x509.load_pem_x509_csr(csr_pem)
        cert = self.ca.sign(csr.public_key(), name, now() - datetime.timedelta(minutes=5),
                            now() + datetime.timedelta(days=90))
        return (cert.public_bytes(serialization.Encoding.PEM) + self.ca.pem).decode()

    async def cleanup_stale_records(self):
        return None


def relay_test_fakes():
    """FakeACME and FakeCloudflare from an akdbx-relay checkout, or None."""
    source = os.environ.get('AKDBX_RELAY_SOURCE')
    if not source or not (Path(source) / 'tests' / 'fakes.py').is_file():
        return None
    root = Path(source) / 'tests'
    spec = importlib.util.spec_from_file_location('akdbx_relay_tests', root / '__init__.py',
                                                  submodule_search_locations=[str(root)])
    package = importlib.util.module_from_spec(spec)
    sys.modules['akdbx_relay_tests'] = package
    spec.loader.exec_module(package)
    return importlib.import_module('akdbx_relay_tests.fakes')


class LoopThread:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def run(self, coroutine, timeout=60):
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result(timeout)

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)
        self.loop.close()


@pytest.fixture
def real_relay(tmp_path):
    control_ca = CA('relay control CA')
    cert_file, key_file = control_ca.leaf_files('relay.akdbx.link', tmp_path)
    cfg = Config(domain='akdbx.link', public_hosts=['127.0.0.1'], public_port=0, health_host='127.0.0.1',
                 health_port=0, control_cert_file=str(cert_file), control_key_file=str(key_file),
                 state_path=str(tmp_path / 'relay.sqlite3'), acme_account_key_file=str(tmp_path / 'acme.pem'),
                 dns_propagation_seconds=0, acme_timeout=30, conn_burst_per_ip=100, max_handshakes_per_ip=32)
    fakes = relay_test_fakes()
    started = []
    if fakes is not None:
        from akdbx_relay.cloudflare import CloudflareDNS
        from akdbx_relay.issuer import ACMEIssuer
        cloudflare = fakes.FakeCloudflare().start()
        acme = fakes.FakeACME(cloudflare).start()
        started += [acme, cloudflare]
        cfg.acme_directory, cfg.cloudflare_api = acme.base + '/directory', cloudflare.api
        cfg.cloudflare_token, cfg.cloudflare_zone_id = cloudflare.token, cloudflare.zone_id
        phone_ca_pem = acme.ca.pem
    cfg.validate()
    loop = LoopThread()

    async def start():
        store = Store(cfg.state_path)
        if fakes is not None:
            dns = CloudflareDNS(cfg.cloudflare_api, cfg.cloudflare_token, cfg.cloudflare_zone_id, timeout=5)
            issuer = ACMEIssuer(cfg, store, dns)
        else:
            issuer = LocalIssuer()
        relay = Relay(cfg, store, issuer)
        await relay.start()
        return relay

    relay = loop.run(start())
    if fakes is None:
        phone_ca_pem = relay.issuer.ca.pem
    endpoint = Endpoint.parse(f'https://relay.akdbx.link:{relay.public_port}',
                              context=control_ca.client_context(), connect_host='127.0.0.1')
    import ssl
    phone = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    phone.load_verify_locations(cadata=(phone_ca_pem.decode() if isinstance(phone_ca_pem, bytes)
                                        else phone_ca_pem))
    yield relay, endpoint, phone, fakes is not None
    loop.run(relay.stop())
    relay.store.close()
    loop.close()
    for item in started:
        item.stop()


def leaf_of(store):
    tls = store.read_tls()
    return x509.load_pem_x509_certificate(tls[tls.index(b'-----BEGIN CERTIFICATE-----'):])


def test_phone_reaches_the_unlock_page_through_the_real_relay(real_relay, tmp_path, monkeypatch):
    relay, endpoint, phone, real_acme = real_relay
    store = RelayStore()
    config, info, created = relay_module.enable(store, endpoint)
    # Relays from the port move answer 443; older ones 8443. Port 443 has no port in the origin.
    assert created and config.enabled and config.public_port in (443, 8443)
    assert config.origin == f'https://{config.name}' + ('' if config.public_port == 443 else ':8443')
    # GET /api/v1/broker: the same name and port as the registration, and the control URL on the
    # advertised port. A relay from before this call answers 404, which keeps the saved values.
    described = relay_module.refresh(store, config, lambda url: endpoint)
    if described.warning is None:
        advertised = 'https://relay.akdbx.link' + ('' if config.public_port == 443 else f':{config.public_port}')
        assert described.config.public_port == config.public_port and described.config.relay == advertised
        store.save(config)  # the test relay listens on a random port, not the advertised one
    else:
        assert 'older relay' in described.warning and described.config is config

    from pykeepass import create_database
    database = tmp_path / 'vault.kdbx'
    create_database(str(database), password=MASTER).save()
    broker = Broker(None, RecordingTyper())
    with __import__('socket').socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    server, url = start_local_unlock_server(broker, database, None, config.origin, store.tls_path,
                                            store.tls_path, local_port=port)
    logs = []
    client = RelayClient(endpoint, config, store, port, log=logs.append,
                         reload_tls=lambda path: reload_certificate(server, path, path))
    broker.relay = client.start()
    try:
        deadline = time.monotonic() + 10
        while config.broker_id not in relay.controls:
            assert time.monotonic() < deadline, 'the broker did not connect to the relay'
            time.sleep(0.02)
        path = '/?' + urlsplit(url).query
        status, body, peer = phone_request(relay.public_port, config.name, phone, path=path)
        assert status == 200 and b'password' in body.lower()
        assert x509.load_der_x509_certificate(peer) == leaf_of(store)
        # The broker's own checks still apply behind the relay.
        form = urlencode({'password': MASTER}).encode()
        headers = (('Origin', config.origin), ('Content-Type', 'application/x-www-form-urlencoded'))
        assert phone_request(relay.public_port, config.name, phone, 'POST', path, headers, form,
                             host='attacker.example')[0] == 404
        assert broker.locked
        status, _, _ = phone_request(relay.public_port, config.name, phone, 'POST', path, headers, form)
        assert status == 200 and not broker.locked
        # Renewal through the real relay, then hot reload.
        old = leaf_of(store)
        client._clock = lambda: info.renew_at + datetime.timedelta(seconds=1)
        assert client.renew_if_due() >= 60
        renewed = leaf_of(store)
        assert renewed != old
        _, _, peer = phone_request(relay.public_port, config.name, phone, path='/')
        assert x509.load_der_x509_certificate(peer) == renewed
        assert broker.dispatch({'action': 'ping'})['relay']['connected'] is True
    finally:
        client.stop()
        server.shutdown()
        server.server_close()
    assert not any(config.secret in line for line in logs)
    if os.environ.get('AKDBX_RELAY_SOURCE'):
        assert real_acme, 'AKDBX_RELAY_SOURCE is set but its tests/fakes.py was not found'


def test_rotate_gets_a_new_name_and_certificate_from_the_real_relay(real_relay):
    relay, endpoint, phone, real_acme = real_relay
    store = RelayStore()
    config, _, _ = relay_module.enable(store, endpoint)
    rotation = relay_module.rotate(store, endpoint_factory=lambda url: endpoint)
    assert rotation.previous.name == config.name and rotation.config.name != config.name
    assert store.load().name == rotation.config.name and store.load_rotation() is None
    assert store.certificate(rotation.config.name) is not None and store.certificate(config.name) is None
    names = leaf_of(store).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == [rotation.config.name]
    # The relay accepts the new secret: it describes the broker under the new name.
    assert relay_module.broker_info(endpoint, store.load()).public_port == rotation.config.public_port
