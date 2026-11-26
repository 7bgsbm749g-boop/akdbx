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

from .android_route import MANAGED_LINUX_ONLY, AndroidError, Device


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


def _start(device, unit, directory):
    argv = ['systemd-run', '--user', '--quiet', '--collect', '--expand-environment=no', '--service-type=exec',
            '--unit', unit, '-p', f'RuntimeDirectory={unit}', '-p', 'RuntimeDirectoryMode=0700',
            '-p', 'UMask=0077', '-p', 'KillMode=mixed', '-p', 'TimeoutStopSec=45',
            sys.executable, '-I', str(Path(__file__).with_name('android_worker.py').resolve()),
            str(directory), device.adb, str(device.port), device.serial,
            json.dumps(device.managed, separators=(',', ':'))]
    return subprocess.run(argv, capture_output=True, timeout=15).returncode == 0


@contextlib.contextmanager
def use(device: Device):
    """Hold a connection for the operation; closing the last starts the idle period."""
    if device.managed is None:
        yield
        return
    if not sys.platform.startswith('linux'):
        raise AndroidError(MANAGED_LINUX_ONLY)
    unit, directory = runtime(device)
    address = str(directory / 'ready')
    deadline = time.monotonic() + 210
    launched_at = None
    retry_at = 0
    launch_failed = False
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
            now = time.monotonic()
            if not directory.exists() and now >= retry_at:
                if launched_at is not None:
                    if now - launched_at >= 2:
                        raise AndroidError(f'Android worker exited; check journalctl --user -u {unit}')
                elif _start(device, unit, directory):
                    launched_at = time.monotonic()
                else:
                    # A concurrent start can own the unit before systemd creates
                    # RuntimeDirectory. An idle unit can also be pending collection
                    # after the directory disappears. Retry either transition.
                    load = subprocess.run(['systemctl', '--user', 'show', '-p', 'LoadState', '--value', unit],
                                          capture_output=True, timeout=5)
                    if launch_failed and load.stdout.strip() != b'loaded':
                        raise AndroidError(f'could not start managed Android device; check journalctl --user -u {unit}')
                    launch_failed = True
                    retry_at = time.monotonic() + 1
            time.sleep(.25)
        yield
    finally:
        client.close()
