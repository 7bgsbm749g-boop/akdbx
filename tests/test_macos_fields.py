"""Real AppKit controls and the broker's retained AX session on a Darwin runner."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from akdbx.native_fields import NativeFields
from akdbx.target import TargetError, DeliveryError
from akdbx.totp import https_origin

pytestmark = pytest.mark.skipif(sys.platform != 'darwin' or os.environ.get('AKDBX_TEST_APPKIT') != '1',
                                reason='requires an isolated macOS desktop with Accessibility permission')
ORIGIN = 'https://example.test/'


@pytest.fixture(scope='module')
def binary(tmp_path_factory):
    output = tmp_path_factory.mktemp('appkit') / 'AppKitLab'
    source = Path(__file__).with_name('native_appkit_lab.m')
    subprocess.run(['clang', '-fobjc-arc', '-framework', 'Cocoa', '-framework', 'WebKit', str(source), '-o', str(output)],
                   check=True)
    return output


@pytest.fixture
def lab(binary, tmp_path):
    process = subprocess.Popen([binary, tmp_path])
    manager = NativeFields()
    try:
        assert manager.capabilities()['native_field_accessibility_granted']
        def command(cmd):
            result = tmp_path / 'result'
            result.unlink(missing_ok=True)
            pending = tmp_path / 'pending'
            pending.write_text(cmd)
            pending.replace(tmp_path / 'command')
            deadline = time.monotonic() + 8
            while not result.exists():
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(.02)
            return json.loads(result.read_text())

        command('focus0')
        from akdbx.macos_fields import AX, attr
        app = AX.AXUIElementCreateApplication(process.pid)
        deadline = time.monotonic() + 8
        while not attr(app, 'AXFrontmost'):
            assert time.monotonic() < deadline, 'AppKit fixture did not become frontmost'
            time.sleep(.05)
        yield manager, process.pid, command
    finally:
        manager.close()
        process.terminate()
        process.wait(timeout=5)


def listing(manager, pid):
    return manager.discover(dict(action='list-native-fields', native_protocol=1, pid=pid))['windows'][0]


def focused(window):
    return next(f['control'] for f in window['controls'] if f['focused'])


def pin(manager, window, index, mode, **extra):
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=index, mode=mode, service_url=ORIGIN, **extra))
    return manager.take(receipt['target'])


@pytest.mark.parametrize('mode', ['username', 'totp', 'identity', 'card', 'password', 'login', 'read'])
def test_appkit_modes(lab, mode):
    manager, pid, command = lab
    index = 1 if mode == 'password' else 3 if mode == 'read' else 0
    command(f'focus{index}')
    window = listing(manager, pid)
    control = focused(window)
    extra = {}
    if mode == 'login':
        extra['username_control'] = control
        command('focus1')
        control = focused(listing(manager, pid))
    if mode in ('card', 'identity'):
        extra['field'] = 'cc-number' if mode == 'card' else 'address-line1'
    target = pin(manager, window, control, mode, **extra)
    try:
        deadline = time.monotonic() + 5
        origins = {https_origin(ORIGIN)}
        if mode == 'read':
            assert manager.read(target, origins, lambda: True, deadline) == 'invented-read-🐈'
        elif mode in ('username', 'password', 'login'):
            manager.deliver_password(target, mode, 'invented-user', 'fixture-🔑', origins, lambda: True, deadline)
            values = command('inspect')
            if mode in ('username', 'login'):
                assert values[0] == 'invented-user'
            if mode in ('password', 'login'):
                assert values[1] == 'fixture-🔑'
        else:
            value = '123456' if mode == 'totp' else '4111111111111111' if mode == 'card' else 'Example Street'
            if mode == 'totp':
                manager._write(target, (value,), lambda: True, deadline)
            else:
                assert manager.fill(target, value, extra['field'], lambda: True, deadline)['ok']
            assert command('inspect')[0] == value
    finally:
        target.close()


def test_stock_secure_field_refuses_before_either_login_write(lab):
    manager, pid, command = lab
    window = listing(manager, pid)
    command('focus2')
    password = focused(listing(manager, pid))
    target = pin(manager, window, password, 'login', username_control=focused(window))
    try:
        with pytest.raises(DeliveryError) as failure:
            manager.deliver_password(target, 'login', 'fixture-user', 'fixture-key', {https_origin(ORIGIN)},
                                     lambda: True, time.monotonic() + 4)
        assert not failure.value.started and command('inspect') == ['', '', '']
    finally:
        target.close()


def test_replaced_field_and_editable_read_refused(lab):
    manager, pid, command = lab
    window = listing(manager, pid)
    with pytest.raises(TargetError):
        pin(manager, window, focused(window), 'read')
    window = listing(manager, pid)
    target = pin(manager, window, focused(window), 'username')
    try:
        command('replace')
        with pytest.raises(DeliveryError) as failure:
            manager.deliver_password(target, 'username', 'fixture-user', '', {https_origin(ORIGIN)},
                                     lambda: True, time.monotonic() + 4)
        assert not failure.value.started
    finally:
        target.close()
