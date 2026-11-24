"""Local ownership of optional Android emulators. No vault or approval operations."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from .android_route import AndroidError, Device


def unit_name(device: Device) -> str:
    # A stable name prevents two clients from starting competing workers.
    data = [device.name, device.adb, device.port, device.serial, device.managed]
    key = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:20]
    return f'akdbx-android-{key}'


def runtime(device: Device) -> tuple[str, Path]:
    unit = unit_name(device)
    return unit, Path(f'/run/user/{os.getuid()}') / unit


def state(device: Device) -> str:
    if device.managed is None:
        return 'external'
    if not sys.platform.startswith('linux'):
        return 'unsupported'
    _, directory = runtime(device)
    if (directory / 'ready').is_socket():
        return 'awake'
    return 'starting-or-stopping' if directory.exists() else 'asleep'


@contextlib.contextmanager
def use(device: Device):
    """Hold a connection for the operation; closing the last starts the idle period."""
    if device.managed is None:
        yield
        return
    if not sys.platform.startswith('linux'):
        raise AndroidError('managed Android emulators require Linux with systemd --user and KVM')
    unit, directory = runtime(device)
    address = str(directory / 'ready')
    deadline = time.monotonic() + 210
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        while True:
            try:
                client.connect(address)
                client.settimeout(10)
                if client.recv(1) == b'1':
                    break
            except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError):
                pass
            client.close()
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if time.monotonic() >= deadline:
                raise AndroidError(f'Android startup timed out; check journalctl --user -u {unit}')
            if not directory.exists():
                argv = ['systemd-run', '--user', '--quiet', '--collect', '--expand-environment=no', '--service-type=exec', '--unit', unit,
                        '-p', f'RuntimeDirectory={unit}', '-p', 'RuntimeDirectoryMode=0700',
                        '-p', 'UMask=0077', '-p', 'KillMode=mixed', '-p', 'TimeoutStopSec=45',
                        sys.executable, '-I', str(Path(__file__).with_name('android_worker.py').resolve()),
                        str(directory), device.adb, str(device.port), device.serial,
                        json.dumps(device.managed, separators=(',', ':'))]
                result = subprocess.run(argv, capture_output=True, timeout=15)
                if result.returncode and not directory.exists():
                    active = subprocess.run(['systemctl', '--user', 'is-active', unit],
                                            capture_output=True, timeout=5)
                    if active.stdout.strip() not in (b'active', b'activating', b'deactivating'):
                        raise AndroidError(f'could not start managed Android device; check journalctl --user -u {unit}')
                # The unit can exit during boot. Do not keep retrying a broken image.
                while time.monotonic() < deadline and not (directory / 'ready').is_socket():
                    if not directory.exists():
                        raise AndroidError(f'Android worker exited; check journalctl --user -u {unit}')
                    time.sleep(.25)
            else:
                time.sleep(.25)
        yield client
    finally:
        client.close()
