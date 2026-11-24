"""Registration, non-waking discovery and concurrent Android operation leases."""
import contextlib
import json
import os
import socket
import sys
import threading
from pathlib import Path

import pytest

from akdbx import android_cli, android_lifecycle, android_setup, android_worker
from akdbx.android_route import Adb, AndroidError, AndroidTargets, Device, load_devices
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


def test_avd_registry_name_is_independent_of_device_alias(tmp_path):
    phone = managed(tmp_path)
    cfg = tmp_path / 'devices.json'
    phone.managed['avd'] = 'Pixel_6_API_35'
    registry(cfg, phone)
    assert load_devices(cfg)['phone'].managed['avd'] == 'Pixel_6_API_35'
    phone.managed['avd'] = '../other'
    registry(cfg, phone)
    with pytest.raises(AndroidError):
        load_devices(cfg)


def test_run_refuses_offline_attached_device_before_launch(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / 'devices.json'
    registry(cfg, Device('tablet', '/unused/adb', 5037, 'ZX'))
    monkeypatch.setenv('AKDBX_ANDROID_DEVICES', str(cfg))
    monkeypatch.setattr(Adb, 'server_running', lambda self: False)
    monkeypatch.setattr(android_cli.subprocess, 'run', lambda *a, **k: pytest.fail('launched program'))
    assert android_cli.run(args('run', '--device', 'tablet', '--', 'adb', 'devices'), None) == 1
    assert 'adb server not running' in capsys.readouterr().out


def test_wrapped_command_cannot_pass_lease_to_background_children(tmp_path, monkeypatch):
    cfg = tmp_path / 'devices.json'
    registry(cfg, managed(tmp_path))
    monkeypatch.setenv('AKDBX_ANDROID_DEVICES', str(cfg))
    lease, peer = socket.socketpair()
    with lease, peer:
        monkeypatch.setattr(android_lifecycle, 'use', lambda device: contextlib.nullcontext(lease))
        fd = f'/proc/self/fd/{lease.fileno()}'
        program = ('import os, sys; '
                   'sys.exit(os.path.exists(sys.argv[1]) and os.readlink(sys.argv[1]) == sys.argv[2])')
        command = args('run', '--device', 'phone', '--', sys.executable, '-c', program, fd, os.readlink(fd))
        assert android_cli.run(command, None) == 0


def test_managed_server_only_listens_on_private_unix_socket(tmp_path, monkeypatch):
    device = managed(tmp_path)
    original = {}

    class Captured(Exception):
        pass

    @contextlib.contextmanager
    def capture(argv, env):
        original.update(argv=argv, env=env)
        raise Captured
        yield

    monkeypatch.setattr(android_worker, 'child', capture)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        free = probe.getsockname()[1]
    monkeypatch.setattr(android_worker, 'ensure_free', lambda port: None)
    with pytest.raises(Captured):
        android_worker.run(tmp_path, device.adb, free, device.serial, device.managed)
    endpoint = 'localfilesystem:' + str(tmp_path / 'adb')
    assert original['argv'] == [device.adb, '-L', endpoint, 'nodaemon', 'server']
    assert original['env']['ADB_SERVER_SOCKET'] == endpoint
    for flag in ('ADB_USB', 'ADB_MDNS', 'ADB_EMU'):
        assert original['env'][flag] == '0'


def test_managed_client_uses_owned_unix_peer(tmp_path, monkeypatch):
    device = managed(tmp_path)
    monkeypatch.setattr(android_lifecycle, 'runtime', lambda device: ('unit', tmp_path))
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(tmp_path / 'adb'))
        listener.listen()
        transport = Adb(device)
        assert transport._environment()['ADB_SERVER_SOCKET'] == 'localfilesystem:' + str(tmp_path / 'adb')
        with transport._connect(1) as connected:
            assert connected.family == socket.AF_UNIX


def test_local_start_failure_precedes_google_fill(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / 'devices.json'
    device = managed(tmp_path)
    registry(cfg, device)
    monkeypatch.setenv('AKDBX_ANDROID_DEVICES', str(cfg))
    caps = AndroidTargets(cfg).capabilities()
    sent = []

    def request(payload, **kwargs):
        sent.append(payload['action'])
        return {'ok': True, 'locked': False, **caps}

    def unavailable(device):
        raise TimeoutError

    monkeypatch.setattr(android_lifecycle, 'use', unavailable)
    command = args('google-sign-in', 'handle', '--device', device.name)
    assert android_cli.run(command, request) == 1
    assert sent == ['ping']
    assert 'request not sent' in capsys.readouterr().out


@pytest.mark.parametrize('loaded', [b'loaded', b'not-found'])
def test_overlapping_start_waits_for_lease_socket(tmp_path, monkeypatch, loaded):
    from subprocess import CompletedProcess
    unit_dir = tmp_path / 'unit'
    monkeypatch.setattr(android_lifecycle, 'runtime', lambda d: ('test-unit', unit_dir))
    with socket.socket(socket.AF_UNIX) as listener:
        def ready():
            unit_dir.mkdir()
            listener.bind(str(unit_dir / 'ready'))
            listener.listen()

        starts = []
        def control(argv, **kwargs):
            if argv[0] == 'systemctl':
                return CompletedProcess(argv, 0, loaded)
            starts.append(1)
            if len(starts) == 1:
                if loaded == b'loaded':
                    # Another client has reserved the unit, but its dir is still missing.
                    threading.Timer(.3, ready).start()
                return CompletedProcess(argv, 1)
            ready()
            return CompletedProcess(argv, 0)

        def worker():
            import time
            for _ in range(100):
                if (unit_dir / 'ready').is_socket():
                    with listener.accept()[0] as conn:
                        conn.sendall(b'1')
                    return
                time.sleep(.025)

        monkeypatch.setattr(android_lifecycle.subprocess, 'run', control)
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        with android_lifecycle.use(managed(tmp_path)):
            assert len(starts) == (1 if loaded == b'loaded' else 2)
        thread.join(3)
        assert not thread.is_alive()


def test_listener_owner_on_ipv4_only_linux(monkeypatch):
    from types import SimpleNamespace
    orig = Path.read_text
    def ipv4_only(path, *args, **kwargs):
        if path == Path('/proc/net/tcp6'):
            raise FileNotFoundError
        return orig(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', ipv4_only)
    with socket.socket() as owned:
        owned.bind(('127.0.0.1', 0))
        owned.listen()
        process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
        assert android_worker.owns_listener(process, owned.getsockname()[1])


def test_worker_boots_registers_then_stops_its_children(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from subprocess import CompletedProcess

    device = managed(tmp_path)
    settings = {**device.managed, 'idle_seconds': .01}
    operations = []

    @contextlib.contextmanager
    def launched(argv, env):
        name = Path(argv[0]).name
        operations.append(('started', name))
        try:
            yield SimpleNamespace(poll=lambda: None)
        finally:
            operations.append(('stopped', name))

    def adb_shell(argv, **kwargs):
        command = tuple(argv[argv.index('shell') + 1:])
        operations.append(command)
        return CompletedProcess(argv, 0, b'1' if command[0] == 'getprop' else b'0')

    @contextlib.contextmanager
    def adb_connection(address, process):
        def register(message):
            assert message == b'0012host:emulator:5585'
            operations.append(('registered',))
        yield SimpleNamespace(sendall=register, recv=lambda size: b'')

    monkeypatch.setattr(android_worker, 'child', launched)
    monkeypatch.setattr(android_worker, 'owns_listener', lambda *args: True)
    monkeypatch.setattr(android_worker, 'ensure_free', lambda port: None)
    monkeypatch.setattr(android_worker, 'private_adb', adb_connection)
    monkeypatch.setattr(android_worker.subprocess, 'run', adb_shell)
    android_worker.run(tmp_path, device.adb, 0, device.serial, settings)
    assert operations == [('started', 'adb'), ('started', 'emulator'), ('registered',),
                          ('getprop', 'sys.boot_completed'), ('settings', 'put', 'secure', 'speak_password', '0'),
                          ('settings', 'get', 'secure', 'speak_password'), ('stopped', 'emulator'), ('stopped', 'adb')]
    assert not (tmp_path / 'ready').exists()
