"""Native macOS broker checks. Temporary synthetic vaults and certificates only."""
import os
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from akdbx import cli, macos, runtime, target
from akdbx.broker import Broker, serve
from akdbx.persistence import VaultStore
from akdbx.target import DeliveryError, TargetError

native = pytest.mark.skipif(sys.platform != 'darwin', reason='requires the real Darwin kernel')


def test_macos_never_falls_back_to_window_input():
    typer = macos.NoWindowDelivery()
    with pytest.raises(TargetError):
        typer.capture(1, 2)
    with pytest.raises(DeliveryError) as error:
        typer.deliver(None, ['synthetic'], lambda: True)
    assert error.value.started is False


def test_macos_refuses_cdp_configuration_before_startup(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'platform', 'darwin')
    args = SimpleNamespace(password_browser_profile=Path('/synthetic/profile'),
                           card_browser_profile=None, browser_profile_root=None)
    assert cli._serve(args, None, None, None, None) == 2
    assert 'extension route only' in capsys.readouterr().err


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
