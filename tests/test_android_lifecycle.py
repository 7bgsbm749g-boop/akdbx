"""Registration, non-waking discovery and concurrent Android operation leases."""
import contextlib
import json
import socket
import sys
import threading
from pathlib import Path

import pytest

from akdbx import android_cli, android_lifecycle, android_setup, android_worker
from akdbx.android_route import AndroidError, AndroidTargets, Device, load_devices
from akdbx.cli import parser


def args(*words):
    return parser().parse_args(['android', *words])


def managed(tmp_path, idle=120):
    return Device('phone', '/opt/sdk/platform-tools/adb', 5043, 'emulator-5584',
                  dict(sdk='/opt/sdk', avd_home=str(tmp_path), avd='test', idle_seconds=idle))


def registry(path, device):
    entry = dict(adb=device.adb, adb_server_port=device.port, serial=device.serial)
    if device.managed:
        entry['managed'] = device.managed
    path.write_text(json.dumps({'version': 1, 'devices': {device.name: entry}}))
    path.chmod(0o600)


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux device ownership')
def test_attach_and_repeat_preserve_other_devices(tmp_path, monkeypatch):
    cfg = tmp_path / 'devices.json'
    original = Device('external', '/usr/bin/adb', 5037, 'ABC')
    registry(cfg, original)
    monkeypatch.setenv('AKDBX_ANDROID_DEVICES', str(cfg))
    adb = tmp_path / 'adb'
    adb.touch(mode=0o700)

    class Transport:
        def __init__(self, device):
            assert device.serial == 'XYZ'

        def run(self, *command):
            import subprocess
            output = {('get-state',): b'device', ('shell', 'settings', 'get', 'secure', 'speak_password'): b'0'}
            return subprocess.CompletedProcess(command, 0, output.get(command, b''))

    monkeypatch.setattr(android_setup, 'Adb', Transport)
    setup = args('setup', '--device', 'tablet', '--attach', 'XYZ', '--adb', str(adb))
    assert android_setup.setup(setup)['changed']
    assert not android_setup.setup(setup)['changed']
    assert cfg.stat().st_mode & 0o777 == 0o600
    devices = load_devices(cfg)
    assert devices['external'] == original and devices['tablet'].managed is None
    setup.attach = 'OTHER'
    with pytest.raises(AndroidError, match='already registered'):
        android_setup.setup(setup)
    assert load_devices(cfg) == devices


def test_status_list_and_locked_commands_leave_emulator_asleep(tmp_path, monkeypatch):
    cfg = tmp_path / 'devices.json'
    phone = managed(tmp_path)
    registry(cfg, phone)
    powers = AndroidTargets(cfg)
    monkeypatch.setattr(android_lifecycle, 'use', lambda d: pytest.fail('unexpected wake'))
    monkeypatch.setattr(android_lifecycle, 'runtime', lambda d: ('test-unit', tmp_path / 'absent'))
    caps = powers.capabilities()
    assert caps['android_managed_devices']['phone']['state'] == 'asleep'
    assert powers.list_devices({})['devices'][0]['reachable'] is False
    called = []

    def locked(payload, timeout=None):
        called.append(payload['action'])
        if payload['action'] == 'ping':
            return {'ok': True, 'locked': True, **caps}
        return {'ok': False, 'error': 'vault locked'}

    assert android_cli.run(args('google-sign-in', 'handle', '--device', 'phone'), locked) == 1
    assert called == ['ping', 'android-google-sign-in']


def test_operation_holds_matching_device_and_releases_on_failure(tmp_path, monkeypatch):
    cfg = tmp_path / 'devices.json'
    phone = managed(tmp_path)
    registry(cfg, phone)
    monkeypatch.setenv('AKDBX_ANDROID_DEVICES', str(cfg))
    caps = AndroidTargets(cfg).capabilities()
    sequence = []

    @contextlib.contextmanager
    def lease(device):
        assert device == phone
        sequence.append('ready')
        try:
            yield
        finally:
            sequence.append('released')

    monkeypatch.setattr(android_lifecycle, 'use', lease)

    def inspect(payload, timeout=None):
        if payload['action'] == 'ping':
            return {'ok': True, 'locked': True, **caps}
        assert sequence == ['ready']
        sequence.append('inspect')
        return {'ok': False, 'error': 'device busy'}

    command = args('inspect', '--device', 'phone')
    assert android_cli.run(command, inspect) == 1
    assert sequence == ['ready', 'inspect', 'released']
    registry(cfg, managed(tmp_path, idle=200))
    assert android_cli.run(command, inspect) == 1
    assert sequence == ['ready', 'inspect', 'released']


def test_concurrent_leases_hold_until_last_disconnect(tmp_path):
    done = threading.Event()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        address = str(tmp_path / 'ready')
        listener.bind(address)
        listener.listen()

        def worker():
            android_worker.serve(listener, .15, lambda: True)
            done.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as second:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as first:
                first.connect(address)
                second.connect(address)
                assert first.recv(1) == second.recv(1) == b'1'
            assert not done.wait(.3)
        assert done.wait(2)
        thread.join()


def test_live_listener_never_adopted():
    with socket.socket() as owner:
        owner.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        owner.bind(('127.0.0.1', 0))
        port = owner.getsockname()[1]
        owner.listen()
        with pytest.raises(OSError):
            android_worker.ensure_free(port)
    android_worker.ensure_free(port)


def test_create_refuses_existing_avd_before_running_installer(tmp_path):
    (tmp_path / 'test.avd').mkdir()
    with pytest.raises(AndroidError, match='already exists'):
        android_setup.provision(Path('/unused'), tmp_path, 'test')
