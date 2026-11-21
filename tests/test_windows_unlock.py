"""Real loopback TLS and private-page checks, without a Windows desktop."""
from datetime import datetime, timedelta, timezone
from http.client import HTTPSConnection
import ipaddress
import ssl
import subprocess
import sys
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


def test_cli_import_does_not_require_unix_socket_support():
    probe = subprocess.run([sys.executable, '-c',
        "import socket; socket.__dict__.pop('AF_UNIX', None); "
        "from akdbx import cli; cli.main(['--version'])"],
        capture_output=True, text=True, timeout=10)
    assert probe.returncode == 0, probe.stderr


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


def test_https_page_blocks_the_link_after_three_failures_until_a_new_link(local_server):
    # The loopback HTTPS page is the Windows route and the Linux HTTPS route.
    server, broker, state, call = local_server
    state.public_base = server.local_origin
    broker.unlock_link = state
    form = {'Origin': server.local_origin, 'Content-Type': 'application/x-www-form-urlencoded'}
    old = state.token
    assert [call('POST', urlencode({'password': 'wrong'}), form)[0] for _ in range(3)] == [401, 401, 403]
    status, _, body = call('POST', urlencode({'password': 'synthetic master'}), form)
    assert status == 403 and b'Ask your agent for a new unlock link' in body and broker.locked
    ping = broker.dispatch({'action': 'ping'})
    assert ping['unlock_blocked'] is True and 'unlock_url' not in ping
    fresh = broker.dispatch({'action': 'new-unlock-link', 'user_confirmed': True})['unlock_url']
    assert fresh.startswith(server.local_origin + '/?token=') and state.token != old
    assert call(token=old)[0] == 404
    assert call('POST', urlencode({'password': 'synthetic master'}), form)[0] == 200 and not broker.locked


@pytest.mark.parametrize('value', ['http://localhost:9443', 'https://example.test:9443',
    'https://0.0.0.0:9443', 'https://localhost', 'https://localhost:0', 'https://localhost:443',
    'https://user@localhost:9443', 'https://localhost:9443/write', 'https://localhost:9443/?token=x'])
def test_remote_or_unprotected_origin_refused(value):
    with pytest.raises(ValueError):
        local_origin(value)


def test_loopback_https_origin_normalized():
    assert local_origin('https://localhost:9443/') == ('https://localhost:9443', 9443)


def test_private_pages_use_a_referrer_policy_that_keeps_the_post_origin(local_server):
    # Under no-referrer, Chromium sends Origin: null on a form POST and the
    # Origin checks refuse it; same-origin keeps the real origin there.
    _, _, _, call = local_server
    status, headers, body = call()
    assert status == 200 and headers['Referrer-Policy'] == 'same-origin'
    assert b'<meta name="referrer" content="same-origin">' in body


@pytest.mark.parametrize('value, port, expected', [
    ('https://node.tailnet.ts.net:9443', 9444, ('https://node.tailnet.ts.net:9443', 9444)),
    ('https://node.tailnet.ts.net/', 9444, ('https://node.tailnet.ts.net', 9444)),
    ('https://node.tailnet.ts.net:443', 9444, ('https://node.tailnet.ts.net', 9444)),
    ('https://localhost:9443', 9443, ('https://localhost:9443', 9443)),
])
def test_remote_origin_listens_on_its_loopback_port(value, port, expected):
    assert local_origin(value, port) == expected


@pytest.mark.parametrize('value, port', [
    ('https://node.tailnet.ts.net:9443', None), ('https://node.tailnet.ts.net:9443', 80),
    ('https://node.tailnet.ts.net:9443', 70000), ('https://100.64.0.1:9443', 9444),
    ('https://[fd7a:115c:a1e0::1]:9443', 9444), ('https://localhost:9443', 9444),
    ('http://node.tailnet.ts.net', 9444), ('https://node.tailnet.ts.net/unlock', 9444),
    ('https://user@node.tailnet.ts.net', 9444), ('https://node', 9444),
])
def test_remote_origin_without_a_valid_local_port_or_name_refused(value, port):
    with pytest.raises(ValueError):
        local_origin(value, port)


def test_remote_origin_unlocks_only_with_its_own_host_and_origin(local_server):
    # Tailscale Serve keeps the browser's Host and Origin when it proxies to
    # the loopback listener; the page accepts only the configured remote name.
    server, broker, _, call = local_server
    remote = 'https://node.tailnet.ts.net:9443'
    server.local_origin = broker.writes.public_base = remote
    form = urlencode({'password': 'synthetic master'})
    assert call('POST', form, {'Origin': remote})[0] == 404  # loopback Host
    assert call('POST', form, {'Host': 'node.tailnet.ts.net:9443', 'Origin': 'https://attacker.test'})[0] == 404
    assert broker.locked
    assert call('POST', form, {'Host': 'node.tailnet.ts.net:9443', 'Origin': remote,
                               'Tailscale-User-Login': 'not-trusted@example.test'})[0] == 200
    assert not broker.locked


def test_remote_unlock_docs_require_a_verified_serve_target():
    # An unverified Serve target accepts any listener that takes the freed
    # loopback port, which could then collect the master password.
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for name in ('docs/windows.md', 'docs/private-pages.md', 'README.md',
                 'skills/akdbx/references/windows.md', 'skills/akdbx/references/vps-setup.md'):
        text = (root / name).read_text(encoding='utf-8')
        commands = re.findall(r'^\s*(?:sudo )?tailscale serve .*$', text, re.M)
        assert all('https+insecure' not in c and 'http://' not in c for c in commands), name
    docs = (root / 'docs/private-pages.md').read_text(encoding='utf-8')
    assert re.search(r'^\s*tailscale serve --bg --https=\d+ https://127\.0\.0\.1:\d+\s*$', docs, re.M)
