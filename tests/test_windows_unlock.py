"""Real loopback TLS and private-page checks, without a Windows desktop."""
from datetime import datetime, timedelta, timezone
from http.client import HTTPSConnection
import ipaddress
import ssl
import threading
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from akdbx.broker import Broker
from akdbx.web_unlock import UnlockState, handler_for
from akdbx.windows_unlock import WindowsHTTPServer, local_origin


@pytest.fixture
def certificates(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                           x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'synthetic-cert.pem', tmp_path / 'synthetic-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


@pytest.fixture
def local_server(certificates):
    broker = Broker(None, object())
    def opener(_path, password, _key):
        if password != 'synthetic master':
            raise ValueError('synthetic failure')
        return SimpleNamespace(entries=[])
    state = UnlockState(broker, None, None, opener)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*certificates)
    server = WindowsHTTPServer(('127.0.0.1', 0), handler_for(state), context, '')
    server.local_origin = f'https://127.0.0.1:{server.server_port}'
    server.write_manager = broker.writes
    broker.writes.public_base = server.local_origin
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client_context = ssl.create_default_context(cafile=str(certificates[0]))
    def call(method='GET', body=None, headers=None, token=None):
        client = HTTPSConnection('127.0.0.1', server.server_port, context=client_context, timeout=3)
        try:
            client.request(method, '/?token=' + (token or state.token), body, headers or {})
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            client.close()
    try:
        yield server, broker, state, call
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()
        thread.join(3)


def test_trusted_https_unlock_rotates_token_and_disables_cache(local_server):
    server, broker, state, call = local_server
    old = state.token
    status, headers, body = call()
    assert status == 200 and headers['Cache-Control'] == 'no-store'
    assert b'Master password' in body
    status, _, body = call('POST', urlencode({'password': 'synthetic master'}),
                           {'Origin': server.local_origin, 'Content-Type': 'application/x-www-form-urlencoded'})
    assert status == 200 and not broker.locked and state.token != old
    assert b'synthetic master' not in body and call(token=old)[0] == 404


@pytest.mark.parametrize('headers', [ {'Host': 'attacker.test'}, {'Origin': 'https://attacker.test'},
    {'Origin': 'null'}, {'Host': 'localhost'}, {'Host': 'attacker.test', 'Tailscale-User-Login': 'forged'}])
def test_host_origin_or_forged_proxy_identity_cannot_unlock(local_server, headers):
    _, broker, _, call = local_server
    assert call('POST', urlencode({'password': 'synthetic master'}), headers)[0] == 404
    assert broker.locked


def test_invalid_token_or_wrong_password_cannot_unlock(local_server):
    _, broker, _, call = local_server
    assert call(token='invalid')[0] == 404
    assert call('POST', urlencode({'password': 'wrong'}))[0] == 401
    assert broker.locked


@pytest.mark.parametrize('value', ['http://localhost:9443', 'https://example.test:9443',
    'https://0.0.0.0:9443', 'https://localhost', 'https://localhost:0', 'https://localhost:443',
    'https://user@localhost:9443', 'https://localhost:9443/write', 'https://localhost:9443/?token=x'])
def test_remote_or_unprotected_origin_refused(value):
    with pytest.raises(ValueError):
        local_origin(value)


def test_loopback_https_origin_normalized():
    assert local_origin('https://localhost:9443/') == ('https://localhost:9443', 9443)
