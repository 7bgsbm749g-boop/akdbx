"""The loopback HTTPS private page on Linux: same flags and checks as Windows."""
from http.client import HTTPSConnection
import os
import socket
import ssl
import sys
from urllib.parse import urlencode, urlsplit

import pytest
from pykeepass import PyKeePass, create_database

from akdbx import cli
from akdbx.broker import Broker
from akdbx.local_https import start_local_unlock_server
from test_broker import RecordingTyper
from test_windows_unlock import certificates  # noqa: F401

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Linux file-mode checks')
MASTER = 'synthetic loopback master'


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


@pytest.fixture
def private_pair(certificates):
    cert, key = certificates
    key.chmod(0o600)
    cert.chmod(0o664)  # a public certificate may be group-writable
    return cert, key


def post(port, cafile, path, form, host, origin):
    client = HTTPSConnection('127.0.0.1', port, context=ssl.create_default_context(cafile=str(cafile)), timeout=30)
    try:
        client.putrequest('POST', path, skip_host=True)
        for name, value in (('Host', host), ('Origin', origin), ('Content-Type', 'application/x-www-form-urlencoded'),
                            ('Content-Length', str(len(form))), ('Tailscale-User-Login', 'forged@example.test')):
            client.putheader(name, value)
        client.endheaders(form.encode())
        response = client.getresponse()
        return response.status, response.read()
    finally:
        client.close()


@pytest.mark.parametrize('remote', [False, True])
def test_linux_serve_unlocks_through_the_loopback_https_page(remote, private_pair, tmp_path, monkeypatch, capsys):
    cert, key = private_pair
    database = tmp_path / 'vault.kdbx'
    create_database(str(database), password=MASTER).save()
    port = free_port()
    origin = 'https://node.tailnet.ts.net:9443' if remote else f'https://localhost:{port}'
    host = urlsplit(origin).netloc
    seen = {}

    def exercise(socket_path, broker):
        assert broker.locked and broker.unlock_url.startswith(origin + '/?token=')
        path = '/?' + urlsplit(broker.unlock_url).query
        form = urlencode({'password': MASTER})
        # A wrong Host or Origin is refused before any key derivation.
        assert post(port, cert, path, form, 'attacker.test', origin)[0] == 404
        assert post(port, cert, path, form, host, 'https://attacker.test')[0] == 404
        assert broker.locked
        seen['status'], body = post(port, cert, path, form, host, origin)
        assert MASTER.encode() not in body
        seen['unlocked'] = not broker.locked

    monkeypatch.setattr(cli, 'X11Typer', RecordingTyper)
    monkeypatch.setattr(cli, 'serve', exercise)
    options = ['--local-port', str(port)] if remote else []
    assert cli.main(['--socket', str(tmp_path / 'private' / 'broker.sock'), '--unlock-origin', origin,
                     'serve', str(database), '--tls-cert', str(cert), '--tls-key', str(key), *options]) == 0
    assert seen == {'status': 200, 'unlocked': True}
    assert 'Open the private HTTPS page: ' + origin + '/?token=' in capsys.readouterr().err


@pytest.mark.parametrize('change', ['key-readable', 'key-group', 'cert-directory', 'key-symlink', 'key-missing'])
def test_unsafe_certificate_files_are_refused(change, private_pair, tmp_path):
    cert, key = private_pair
    if change == 'key-readable':
        key.chmod(0o644)
    elif change == 'key-group':
        key.chmod(0o640)
    elif change == 'cert-directory':
        cert = tmp_path
    elif change == 'key-symlink':
        link = tmp_path / 'linked-key.pem'
        link.symlink_to(key)
        key = link
    else:
        key = tmp_path / 'missing-key.pem'
    broker = Broker(None, RecordingTyper())
    try:
        with pytest.raises((PermissionError, OSError)):
            start_local_unlock_server(broker, tmp_path / 'vault.kdbx', None,
                                      f'https://localhost:{free_port()}', cert, key)
        assert broker.unlock_url is None
    finally:
        broker.unlock_notifications.close()


def test_listener_binds_only_loopback_and_refuses_plaintext(private_pair, tmp_path):
    cert, key = private_pair
    port = free_port()
    broker = Broker(None, RecordingTyper())
    server, url = start_local_unlock_server(broker, tmp_path / 'vault.kdbx', None,
                                            f'https://127.0.0.1:{port}', cert, key)
    try:
        assert server.server_address == ('127.0.0.1', port)
        # A second listener cannot share the port.
        with pytest.raises(OSError):
            start_local_unlock_server(broker, tmp_path / 'vault.kdbx', None,
                                      f'https://127.0.0.1:{port}', cert, key)
        with socket.create_connection(('127.0.0.1', port), timeout=5) as plain:
            plain.sendall(b'GET /?token=x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
            assert b'HTTP/1.' not in plain.recv(4096)
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()
