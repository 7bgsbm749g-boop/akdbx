"""The loopback HTTPS private page on Linux: same flags and checks as Windows."""
from http.client import HTTPSConnection
import json
import os
import socket
import ssl
import sys
from urllib.parse import urlencode, urlsplit

import pytest
from pykeepass import PyKeePass, create_database

from akdbx import cli, web_unlock
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


@pytest.mark.parametrize('change', ['key-readable', 'key-group', 'key-executable', 'cert-directory', 'key-symlink',
                                    'key-missing'])
def test_unsafe_certificate_files_are_refused(change, private_pair, tmp_path):
    cert, key = private_pair
    if change == 'key-readable':
        key.chmod(0o644)
    elif change == 'key-group':
        key.chmod(0o640)
    elif change == 'key-executable':
        key.chmod(0o700)
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
            try:
                assert b'HTTP/1.' not in plain.recv(4096)
            except ConnectionResetError:
                pass  # Darwin can reject non-TLS input with RST instead of EOF.
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()


def test_restart_binds_the_port_right_after_a_served_request(private_pair, tmp_path):
    # The server closes each connection first, which leaves TIME_WAIT sockets
    # on its port; a restart must still bind it at once.
    cert, key = private_pair
    port = free_port()
    origin = f'https://127.0.0.1:{port}'
    for _ in range(2):
        broker = Broker(None, RecordingTyper())
        server, url = start_local_unlock_server(broker, tmp_path / 'vault.kdbx', None, origin, cert, key)
        try:
            for _ in range(3):
                client = HTTPSConnection('127.0.0.1', port, timeout=5,
                                         context=ssl.create_default_context(cafile=str(cert)))
                client.request('GET', '/?' + urlsplit(url).query)
                response = client.getresponse()
                assert response.status == 200
                response.read()
                client.close()
        finally:
            server.shutdown()
            server.server_close()
            broker.unlock_notifications.close()


def test_native_host_capture_through_the_capture_socket(private_pair, tmp_path):
    from akdbx import browser_import
    from test_web_unlock import call
    cert, key = private_pair
    database = tmp_path / 'vault.kdbx'
    vault = create_database(str(database), password=MASTER)
    vault.add_entry(vault.root_group, 'Synthetic', 'synthetic-user', 'synthetic password', url='https://example.test/')
    vault.save()
    capture = tmp_path / 'private' / 'akdbx-unlock.sock'
    port = free_port()
    origin = f'https://localhost:{port}'
    broker = Broker(None, RecordingTyper())
    server, url = start_local_unlock_server(broker, database, None, origin, cert, key, capture_socket=capture)
    try:
        assert oct(capture.stat().st_mode & 0o777) == '0o600'
        # The socket serves no page and cannot unlock, even with a proxy identity.
        path = '/?' + urlsplit(url).query
        assert call(capture, 'GET', path)[0] == 404
        assert call(capture, 'POST', path, urlencode({'password': MASTER}))[0] == 404
        assert broker.locked
        assert post(port, cert, path, urlencode({'password': MASTER}), f'localhost:{port}', origin)[0] == 200
        selected = broker.dispatch({'action': 'search', 'query': 'Synthetic'})['entries'][0]
        prepared = broker.dispatch({'action': 'setup-totp', 'handle': selected['handle'],
                                    'metadata': {k: selected[k] for k in ('title', 'username', 'url', 'group')}})
        assert prepared['ok'], prepared
        config = {'extension_id': 'a' * 32, 'origin': origin, 'socket': str(capture)}
        uri = 'otpauth://totp/Example:synthetic-user?secret=JBSWY3DPEHPK3PXP&issuer=Example'
        message = {'private_url': prepared['private_url'], 'source_url': 'https://example.test/setup', 'payloads': [uri]}
        with pytest.raises(ValueError):
            browser_import.capture({**message, 'source_url': 'https://evil.test/setup'}, config)
        before = database.read_bytes()
        assert browser_import.capture(message, config) == browser_import.RECEIPT
        assert database.read_bytes() == before
        assert broker.writes.get(prepared['write_handle']).import_candidates
        with pytest.raises(ValueError):  # replay
            browser_import.capture(message, config)
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()
    assert not capture.exists()


def test_a_live_capture_socket_stops_a_second_broker(private_pair, tmp_path):
    cert, key = private_pair
    capture = tmp_path / 'private' / 'akdbx-unlock.sock'
    first, second = Broker(None, RecordingTyper()), Broker(None, RecordingTyper())
    server, _ = start_local_unlock_server(first, tmp_path / 'vault.kdbx', None, f'https://localhost:{free_port()}',
                                          cert, key, capture_socket=capture)
    port = free_port()
    try:
        with pytest.raises(RuntimeError):
            start_local_unlock_server(second, tmp_path / 'vault.kdbx', None, f'https://localhost:{port}',
                                      cert, key, capture_socket=capture)
        # The second broker's HTTPS listener was closed again.
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', port))
    finally:
        server.shutdown()
        server.server_close()
        for broker in (first, second):
            broker.unlock_notifications.close()


def get(port, cafile, path, host):
    client = HTTPSConnection('127.0.0.1', port, context=ssl.create_default_context(cafile=str(cafile)), timeout=30)
    try:
        client.putrequest('GET', path, skip_host=True)
        client.putheader('Host', host)
        client.putheader('Tailscale-User-Login', 'forged@example.test')
        client.endheaders()
        response = client.getresponse()
        return response.status, response.read()
    finally:
        client.close()


@pytest.mark.parametrize('given', ['https://node.tailnet.ts.net', 'https://node.tailnet.ts.net:443'])
def test_a_port_443_origin_has_no_port_and_the_page_names_the_computer(given, private_pair, tmp_path, monkeypatch):
    monkeypatch.setattr(web_unlock, 'computer_name', lambda: 'box<&>')
    cert, key = private_pair
    port = free_port()
    broker = Broker(None, RecordingTyper())
    server, url = start_local_unlock_server(broker, tmp_path / 'vault.kdbx', None, given, cert, key,
                                            local_port=port)
    try:
        assert url.startswith('https://node.tailnet.ts.net/?token=')
        assert broker.unlock_link.origin == 'https://node.tailnet.ts.net'
        status, body = get(port, cert, '/?' + urlsplit(url).query, 'node.tailnet.ts.net')
        assert status == 200
        # The loopback page shows no login (and never a forged Tailscale header).
        assert b'<p>Unlock AKDBX on <strong>box&lt;&amp;&gt;</strong>.</p>' in body
        assert b'local user' not in body and b'forged' not in body
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()


def request(port, cafile, method, path, headers):
    client = HTTPSConnection('127.0.0.1', port, context=ssl.create_default_context(cafile=str(cafile)), timeout=30)
    try:
        client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in headers:
            client.putheader(name, value)
        client.endheaders()
        response = client.getresponse()
        return response.status, response.headers, response.read()
    finally:
        client.close()


@pytest.mark.parametrize('remote', [False, True])
def test_the_identity_page_serves_only_the_public_statement_on_the_checked_host(remote, private_pair, tmp_path):
    from akdbx import broker_identity
    from akdbx.extension_route import EXTENSION_ID
    cert, key = private_pair
    port = free_port()
    given = 'https://node.tailnet.ts.net' if remote else f'https://localhost:{port}'
    broker = Broker(None, RecordingTyper())
    server, url = start_local_unlock_server(broker, tmp_path / 'vault.kdbx', None, given, cert, key,
                                            local_port=port if remote else None)
    origin = server.local_origin
    host = urlsplit(origin).netloc
    path = '/.well-known/akdbx-identity'
    extension = 'chrome-extension://' + EXTENSION_ID
    try:
        # No identity yet (a broker that could not load its key): nothing to serve.
        assert request(port, cert, 'GET', path, [('Host', host)])[0] == 404
        identity = broker_identity.IdentityStore(tmp_path / 'identity').announce(origin)
        broker.extension.set_identity(identity)
        for extra in ([], [('Origin', extension)], [('Origin', origin)]):
            status, headers, body = request(port, cert, 'GET', path, [('Host', host), *extra])
            assert status == 200, extra
            assert headers['Content-Type'] == 'application/json'
            assert headers['Cache-Control'] == 'no-store'
            assert 'Access-Control-Allow-Origin' not in headers
            message = json.loads(body)
            assert message == identity.message()
            assert broker_identity.verify_message(message)['origin'] == origin
            assert b'PRIVATE' not in body and set(message) == {'public_key', 'statement', 'signature'}
        # The Host check stays; a web page on another origin, or another extension, cannot read it.
        for refused in ([('Host', 'attacker.test')], [],
                        [('Host', host), ('Origin', 'https://attacker.test')],
                        [('Host', host), ('Origin', 'chrome-extension://' + 'a' * 32)],
                        [('Host', host), ('Origin', 'null')],
                        [('Host', host), ('Host', host)]):
            assert request(port, cert, 'GET', path, refused)[0] == 404, refused
        # Only GET.
        for method in ('POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'):
            status, headers, _ = request(port, cert, method, path, [('Host', host), ('Content-Length', '0')])
            assert status == 405 and headers['Allow'] == 'GET', method
        # Other routes are unchanged: the unlock page still refuses the extension's Origin and other methods.
        token_path = '/?' + urlsplit(url).query
        assert request(port, cert, 'GET', token_path, [('Host', host), ('Origin', extension)])[0] == 404
        assert request(port, cert, 'GET', token_path, [('Host', host)])[0] == 200
        assert request(port, cert, 'PUT', token_path, [('Host', host), ('Content-Length', '0')])[0] == 501
        assert request(port, cert, 'GET', path + 'x', [('Host', host)])[0] == 404
    finally:
        server.shutdown()
        server.server_close()
        broker.unlock_notifications.close()

@pytest.mark.parametrize('browser', ['chrome', 'firefox'])
def test_import_host_default_registration(tmp_path, browser, monkeypatch):
    from akdbx import browser_import
    import subprocess
    from pathlib import Path
    root = tmp_path.resolve()
    monkeypatch.setenv('HOME', str(root))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(root / '.config'))
    monkeypatch.setenv('CHROME_CONFIG_HOME', str(root / 'chrome-config'))
    tool = Path(sys.executable).with_name('akdbx-browser-import')
    command = [str(tool), 'install-host', '--browser', browser, '--origin', 'https://localhost:9443',
               '--socket', str(root / 'run' / 'u')]
    if browser == 'chrome':
        command += ['--extension-id', 'a' * 32]
    subprocess.run(command, check=True, capture_output=True)
    if sys.platform == 'darwin':
        vendor = 'Google/Chrome' if browser == 'chrome' else 'Mozilla'
        directory = root / 'Library/Application Support' / vendor / 'NativeMessagingHosts'
    else:
        directory = root / ('chrome-config/google-chrome/NativeMessagingHosts' if browser == 'chrome'
                            else '.mozilla/native-messaging-hosts')
    spec = json.loads((directory / 'org.akdbx.private_import.json').read_bytes())
    assert spec['path'] == str(tool)
    if browser == 'firefox':
        assert spec['allowed_extensions'] == [browser_import.FIREFOX_ID] and 'allowed_origins' not in spec
    else:
        assert spec['allowed_origins'] == ['chrome-extension://' + 'a' * 32 + '/']
    assert browser_import.load_config(browser_import.config_path(browser))['socket'] == str(root / 'run' / 'u')

    if browser == 'chrome':
        # Register a second Chromium browser, preserving the first manifest and config.
        command[command.index('chrome')] = 'edge'
        subprocess.run(command, check=True, capture_output=True)
        edge = (root / 'Library/Application Support/Microsoft Edge/NativeMessagingHosts' if sys.platform == 'darwin'
                else root / '.config/microsoft-edge/NativeMessagingHosts')
        name = 'org.akdbx.private_import.json'
        assert json.loads((edge / name).read_bytes()) == json.loads((directory / name).read_bytes()) == spec
        command[command.index('edge')] = 'helium'
        command[-1] = 'b' * 32
        assert subprocess.run(command, capture_output=True).returncode == 1
        assert browser_import.load_config(browser_import.config_path())['extension_id'] == 'a' * 32
