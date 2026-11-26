"""Native macOS broker checks. Temporary synthetic vaults and certificates only."""
import os
from pathlib import Path
import socket
import sys
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from akdbx import cli, macos, runtime, target
from akdbx.broker import Broker, serve
from akdbx.persistence import VaultStore
from akdbx.target import DeliveryError, TargetError
from test_local_https import certificates, private_pair  # noqa: F401

native = pytest.mark.skipif(sys.platform != 'darwin', reason='requires the real Darwin kernel')


@pytest.mark.parametrize('error', [0, 2, 9, 13])
def test_acl_absence_is_distinct_from_lookup_failure(monkeypatch, error):
    import ctypes
    import errno
    def lookup(*args):
        assert ctypes.get_errno() == 0
        ctypes.set_errno(error)
        return None
    libc = SimpleNamespace(acl_get_fd_np=lookup, acl_get_entry=lambda *args: None,
                           acl_get_tag_type=lambda *args: None, acl_free=lambda *args: None)
    monkeypatch.setattr(ctypes, 'CDLL', lambda *args, **kwargs: libc)
    ctypes.set_errno(errno.ENOENT)  # An old errno must not turn an unknown failure into success.
    if error == errno.ENOENT:
        macos.require_private_acl(123)
    else:
        with pytest.raises(PermissionError):
            macos.require_private_acl(123)


def test_macos_never_falls_back_to_window_input():
    typer = macos.NoWindowDelivery()
    with pytest.raises(TargetError):
        typer.capture(1, 2)
    with pytest.raises(DeliveryError) as error:
        typer.deliver(None, ['synthetic'], lambda: True)
    assert error.value.started is False


def test_macos_native_host_locations(monkeypatch, tmp_path):
    from akdbx.extension_host import linux_manifest_dir
    monkeypatch.setattr(sys, 'platform', 'darwin')
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    assert linux_manifest_dir('chrome') == tmp_path / 'Library/Application Support/Google/Chrome/NativeMessagingHosts'
    assert linux_manifest_dir('edge') == tmp_path / 'Library/Application Support/Microsoft Edge/NativeMessagingHosts'


@native
def test_macos_default_socket_and_capabilities(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    assert cli.default_socket() == tmp_path / 'Library/Application Support/akdbx/run/s'
    assert target.capabilities()['target_fill_delivery'] == 'unavailable'
    assert target.capabilities()['target_fill_modes'] == []


@native
def test_fresh_home_runtime_is_created_through_trusted_components(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path.resolve())
    path = cli.default_socket()
    macos.prepare_runtime(path, create_ancestors=True)
    for folder in (tmp_path / 'Library', tmp_path / 'Library/Application Support',
                   path.parent.parent, path.parent):
        assert stat_mode(folder) == 0o700


@native
def test_tls_key_allow_acl_is_refused_even_with_private_mode(tmp_path):
    from akdbx.local_https import _posix_checked_file
    key = tmp_path / 'synthetic-key'
    key.write_text('not a real key')
    key.chmod(0o600)
    subprocess.run(['/bin/chmod', '+a', 'everyone allow read', str(key)], check=True)
    assert stat_mode(key) == 0o600
    with pytest.raises(PermissionError, match='ACL'):
        with _posix_checked_file(key, private=True):
            pass


@native
def test_runtime_allow_acl_is_refused_even_with_private_mode(tmp_path):
    folder = tmp_path.resolve() / 'runtime'
    folder.mkdir(mode=0o700)
    subprocess.run(['/bin/chmod', '+a', 'everyone allow search,read', str(folder)], check=True)
    assert stat_mode(folder) == 0o700
    with pytest.raises(PermissionError, match='ACL'):
        runtime.open_private_runtime_directory(folder)


def test_foreign_rpc_peer_is_refused_before_dispatch(monkeypatch):
    from akdbx.broker import _serve_connection
    from akdbx.protocol import send_message
    left, right = socket.socketpair()
    calls = []
    broker = SimpleNamespace(dispatch=lambda *args, **kwargs: calls.append(True) or {'ok': True})
    monkeypatch.setattr(sys, 'platform', 'darwin')
    monkeypatch.setattr(macos, 'peer_credentials', lambda connection: (os.getpid(), os.getuid() + 1, os.getgid()))
    try:
        send_message(right, {'action': 'ping'})
        _serve_connection(left, broker)
        assert not calls
    finally:
        left.close()
        right.close()


@native
@pytest.mark.parametrize('custom_socket', [None, 's', 'U'])
def test_documented_first_launch_uses_extension_route(tmp_path, monkeypatch, private_pair, custom_socket):
    from pykeepass import create_database
    monkeypatch.setattr(Path, 'home', lambda: tmp_path.resolve())
    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path / 'state'))
    monkeypatch.delenv('AKDBX_DEFAULT_FILL_ROUTE', raising=False)
    monkeypatch.delenv('AKDBX_UNLOCK_ORIGIN', raising=False)
    database = tmp_path / 'synthetic.kdbx'
    create_database(str(database), password='synthetic only master').save()
    database.chmod(0o600)
    options = []
    expected_socket = cli.default_socket()
    if custom_socket:
        # A valid main path must not grow when deriving the capture path.
        padding = 99 - len(os.fsencode(tmp_path.resolve() / 'r' / 's'))
        assert padding >= 0
        expected_socket = tmp_path.resolve() / ('r' + 'x' * padding) / custom_socket
        options = ['--socket', str(expected_socket)]
    seen = []
    def exercise(path, broker):
        seen.append(broker.dispatch({'action': 'ping'}))
        assert path == expected_socket
        assert path.parent.is_dir()
        capture_name = 's' if path.name.casefold() == 'u' else 'u'
        assert (path.parent / capture_name).is_socket()
    monkeypatch.setattr(cli, 'serve', exercise)
    cdp_options = ['--password-browser-profile', str(tmp_path / 'profile'), '--default-fill-route', 'cdp'] if custom_socket == 's' else []
    cert, key = private_pair
    assert cli.main([*options, '--unlock-origin', 'https://localhost:9443', 'serve', str(database),
                     '--tls-cert', str(cert), '--tls-key', str(key), *cdp_options]) == 0
    assert seen[0]['fill_routes'] == ['cdp', 'extension']
    assert seen[0]['default_fill_route'] == ('cdp' if cdp_options else 'extension')
    assert seen[0]['sms_protocol'] == 1 and seen[0]['sms_fill_routes'] == (['cdp'] if cdp_options else [])


@native
def test_real_darwin_peer_credentials():
    left, right = socket.socketpair()
    try:
        assert cli._peer_credentials(left) == (os.getpid(), os.getuid(), os.getgid())
    finally:
        left.close()
        right.close()


@native
def test_real_darwin_socket_path_rechecks_open_directory(tmp_path):
    folder = tmp_path.resolve() / 'r'
    _, fd = runtime.prepare_private_runtime_directory(folder)
    try:
        assert runtime.anchored_socket_path(fd, 's') == str(folder / 's')
        folder.chmod(0o755)
        with pytest.raises(RuntimeError, match='0700'):
            runtime.anchored_socket_path(fd, 's')
        with pytest.raises(ValueError):
            runtime.anchored_socket_path(fd, '../other')
    finally:
        os.close(fd)


@native
def test_macos_broker_rpc_checks_actual_socket_peer(tmp_path):
    path = tmp_path.resolve() / 'r' / 's'
    broker = Broker(None, macos.NoWindowDelivery())
    stop = threading.Event()
    errors = []
    def run():
        try:
            serve(path, broker, stop)
        except Exception as error:
            errors.append(type(error).__name__)
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while not path.exists() and not errors and time.monotonic() < deadline:
            time.sleep(.02)
        assert path.is_socket() and not errors, errors
        state = cli.request(path, {'action': 'ping'}, expected_unlock_origin='https://localhost:9443')
        assert state['ok'] is True and state['locked'] is True
        assert state['target_fill_modes'] == []
    finally:
        stop.set()
        worker.join(5)
        broker.unlock_notifications.close()
    assert not worker.is_alive() and not errors


@native
def test_macos_encrypted_vault_save_and_reload(tmp_path):
    from pykeepass import create_database, PyKeePass
    folder = tmp_path.resolve() / 'vault'
    folder.mkdir(mode=0o700)
    database = folder / 'synthetic.kdbx'
    original = create_database(str(database), password='synthetic-only master')
    original.add_entry(original.root_group, 'Original', 'alice', 'synthetic-old')
    original.save()
    database.chmod(0o600)
    store = VaultStore(database)
    vault = store.open('synthetic-only master')
    saved = store.commit(vault, lambda candidate: candidate.add_entry(candidate.root_group,
                         'Added', 'bob', 'synthetic-new'))
    assert saved.find_entries(title='Added', first=True).username == 'bob'
    reopened = PyKeePass(str(database), password='synthetic-only master')
    assert reopened.find_entries(title='Original', first=True).password == 'synthetic-old'
    assert reopened.find_entries(title='Added', first=True).password == 'synthetic-new'
    assert stat_mode(database) == 0o600


def stat_mode(path):
    return path.stat().st_mode & 0o777


@native
def test_macos_preview_merge_and_read_receipt(tmp_path, monkeypatch):
    import shutil
    import uuid
    from pykeepass import create_database, PyKeePass
    folder = tmp_path.resolve()
    target_file, source = folder / 'target.kdbx', folder / 'source.kdbx'
    create_database(str(target_file), password='synthetic-only master')
    shutil.copyfile(target_file, source)
    branch = PyKeePass(source, password='synthetic-only master')
    branch.add_entry(branch.root_group, 'Imported', 'synthetic', 'synthetic')
    branch.save()
    before = target_file.read_bytes()
    broker = Broker(VaultStore(target_file).open('synthetic-only master'), object())
    monkeypatch.setenv('PATH', '')
    assert broker.dispatch({'action': 'ping'})['merge_available']
    request = {'action': 'merge', 'source': str(source)}
    preview = broker.dispatch({**request, 'operation_id': uuid.uuid4().hex, 'check': True})
    assert preview['state'] == 'checked' and target_file.read_bytes() == before
    saved = broker.dispatch({**request, 'operation_id': uuid.uuid4().hex})
    assert saved['state'] == 'saved', saved
    assert broker.dispatch({'action': 'merge-status', 'operation_id': saved['operation_id']}) == saved
    assert PyKeePass(target_file, password='synthetic-only master').find_entries(title='Imported', first=True)


@native
@pytest.mark.parametrize('location', ['ancestor', 'profile', 'port'])
def test_cdp_routes_refuse_extended_allow_acl(tmp_path, location):
    from akdbx import browser_card, browser_password
    parent = tmp_path.resolve() / 'profiles'
    profile = parent / 'slot1'
    parent.mkdir(mode=0o700)
    profile.mkdir(mode=0o700)
    port = profile / 'DevToolsActivePort'
    port.write_text('12345\n/devtools/browser/synthetic')
    port.chmod(0o600)
    validators = [browser_card.browser_endpoint, browser_password.endpoint]
    for endpoint in validators:
        assert endpoint(profile) == 'ws://127.0.0.1:12345/devtools/browser/synthetic'
    path = dict(ancestor=parent, profile=profile, port=port)[location]
    subprocess.run(['/bin/chmod', '+a', 'everyone allow read', str(path)], check=True)
    for endpoint in validators:
        with pytest.raises(PermissionError, match='ACL'):
            endpoint(profile)


@native
@pytest.mark.parametrize('case', ['duplicate', 'missing', 'truncated', 'unknown-layout', 'foreign', 'timeout'])
def test_darwin_refuses_ambiguous_or_incomplete_snapshot(monkeypatch, case):
    """Mutate only a real kernel snapshot between acquisition and parsing."""
    from akdbx import cdp_peer
    parse = cdp_peer._darwin_rows

    def changed(data, local, remote, deadline):
        if case == 'duplicate':
            data = bytes(data[:-24]) + bytes(data[24:])
        elif case == 'missing':
            data = bytes(data[:24]) + bytes(data[-24:])
        elif case == 'truncated':
            data = data[:-1]
        elif case == 'unknown-layout':
            data = bytes(data[:24]) + bytes(4) + bytes(data[28:])
        elif case == 'foreign':
            uid = os.getuid()
            monkeypatch.setattr(os, 'getuid', lambda: uid + 1)
        else:
            deadline = 0
        parse(data, local, remote, deadline)

    with socket.socket() as listener, socket.socket() as client:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        client.connect(listener.getsockname())
        cdp_peer.verify_peer(client)
        monkeypatch.setattr(cdp_peer, '_darwin_rows', changed)
        with pytest.raises(cdp_peer.PeerError):
            cdp_peer.verify_peer(client)


def test_darwin_refuses_oversized_table_before_allocation(monkeypatch):
    import ctypes
    from akdbx import cdp_peer

    calls = []

    def sysctl(name, buffer, size, *_):
        assert buffer is None
        calls.append(name)
        ctypes.cast(size, ctypes.POINTER(ctypes.c_size_t))[0] = cdp_peer.MAX_TCP_TABLE_BYTES + 1
        return 0

    monkeypatch.setattr(ctypes, 'CDLL', lambda *a, **kw: SimpleNamespace(sysctlbyname=sysctl))
    monkeypatch.setattr(ctypes, 'create_string_buffer', lambda *_: pytest.fail('oversized kernel table allocation'))
    with pytest.raises(cdp_peer.PeerError):
        cdp_peer._darwin_peer(('127.0.0.1', 12345), ('127.0.0.1', 23456), time.monotonic() + 1)
    assert calls == [b'net.inet.tcp.pcblist64']
