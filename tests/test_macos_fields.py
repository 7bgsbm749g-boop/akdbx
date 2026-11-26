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


@pytest.mark.parametrize('mode', ['username', 'totp', 'identity', 'card', 'read'])
def test_appkit_modes(lab, mode):
    manager, pid, command = lab
    index = 2 if mode == 'read' else 0
    command(f'focus{index}')
    window = listing(manager, pid)
    control = focused(window)
    extra = {}
    if mode in ('card', 'identity'):
        extra['field'] = 'cc-number' if mode == 'card' else 'address-line1'
    target = pin(manager, window, control, mode, **extra)
    try:
        deadline = time.monotonic() + 5
        origins = {https_origin(ORIGIN)}
        if mode == 'read':
            assert manager.read(target, origins, lambda: True, deadline) == 'invented-read-🐈'
        elif mode == 'username':
            manager.deliver_password(target, mode, 'invented-user', '', origins, lambda: True, deadline)
            assert command('inspect')[0] == 'invented-user'
        else:
            value = '123456' if mode == 'totp' else '4111111111111111' if mode == 'card' else 'Example Street'
            if mode == 'totp':
                manager._write(target, (value,), lambda: True, deadline)
            else:
                assert manager.fill(target, value, extra['field'], lambda: True, deadline)['ok']
            assert command('inspect')[0] == value
    finally:
        target.close()


def test_secure_field_modes_are_refused_before_writing(lab):
    manager, pid, command = lab
    window = listing(manager, pid)
    command('focus1')
    secure = listing(manager, pid)
    password = focused(secure)
    assert secure['controls'][password]['password']
    with pytest.raises(TargetError):
        pin(manager, window, password, 'login', username_control=focused(window))
    with pytest.raises(TargetError):
        pin(manager, secure, password, 'password')
    secure = listing(manager, pid)
    with pytest.raises(TargetError):
        pin(manager, secure, focused(secure), 'card', field='cc-number')
    assert command('inspect') == ['', '']
    assert set(manager.capabilities()['native_field_modes']) == {'username', 'totp', 'identity', 'card', 'read'}


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


def web_children(pid):
    # The fixture window has one group: the WKWebView host.
    from akdbx.macos_fields import AX, attr
    window = attr(AX.AXUIElementCreateApplication(pid), 'AXFocusedWindow')
    hosts = [node for node in attr(window, 'AXChildren') if attr(node, 'AXRole') == 'AXGroup']
    assert len(hosts) == 1
    error, count = AX.AXUIElementGetAttributeValueCount(hosts[0], 'AXChildren', None)
    assert error == AX.kAXErrorSuccess
    return count


def test_embedded_web_area_is_refused(lab):
    from akdbx.macos_fields import EmbeddedWeb, scan
    manager, pid, command = lab
    # One target and one unused listing per state, all taken while the window was native.
    states = []
    for _ in range(2):
        window = listing(manager, pid)
        states.append((pin(manager, window, focused(window), 'username'), listing(manager, pid)))
    try:
        command('web')
        assert web_children(pid) == 0
        for attached, (target, unused) in enumerate(states):
            if attached:
                # The web process attaches its page about a second later.
                deadline = time.monotonic() + 8
                while web_children(pid) == 0:
                    assert time.monotonic() < deadline, 'WKWebView content did not attach'
                    time.sleep(.05)
            with pytest.raises(EmbeddedWeb):
                scan(pid)
            with pytest.raises(EmbeddedWeb):
                pin(manager, unused, focused(unused), 'username')
            with pytest.raises(DeliveryError) as failure:
                manager.deliver_password(target, 'username', 'fixture-user', '', {https_origin(ORIGIN)},
                                         lambda: True, time.monotonic() + 4)
            assert not failure.value.started and isinstance(failure.value.__context__, EmbeddedWeb)
            assert command('inspect')[0] == ''
            if not attached:
                # Refused while WebKit exposed no web content.
                assert web_children(pid) == 0
    finally:
        for target, _ in states:
            target.close()


def test_browser_process_is_refused(binary, tmp_path):
    import shutil
    from akdbx.macos_fields import identity
    browser = tmp_path / 'Google Chrome'
    shutil.copy(binary, browser)
    process = subprocess.Popen([browser, tmp_path])
    try:
        with pytest.raises(TargetError):
            identity(process.pid)
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_missing_permission_has_fixed_response(monkeypatch, lab):
    from akdbx.broker import Broker
    from akdbx.macos_fields import AX
    from akdbx.native_fields import ACCESSIBILITY_ERROR
    manager, pid, _ = lab
    monkeypatch.setattr(AX, 'AXIsProcessTrusted', lambda: False)
    assert manager.capabilities()['native_field_accessibility_granted'] is False
    broker = Broker(type('Vault', (), {'entries': []})(), object())
    response = broker.dispatch(dict(action='list-native-fields', native_protocol=1, pid=pid))
    assert response == dict(ok=False, delivery='not-started', error=ACCESSIBILITY_ERROR)


def test_offscreen_sibling_leaves_focused_field_available(lab):
    manager, pid, command = lab
    before = listing(manager, pid)
    assert any(field['readonly'] for field in before['controls'])
    command('partly-offscreen')
    after = listing(manager, pid)
    assert not any(field['readonly'] for field in after['controls'])
    target = pin(manager, after, focused(after), 'username')
    try:
        manager.deliver_password(target, 'username', 'visible-user', '', {https_origin(ORIGIN)},
                                 lambda: True, time.monotonic() + 4)
        assert command('inspect')[0] == 'visible-user'
    finally:
        target.close()


@pytest.mark.parametrize('attribute', ['AXValue', 'AXSelectedText'])
def test_sibling_without_settable_attribute_is_skipped(monkeypatch, lab, attribute):
    from akdbx.macos_fields import AX, attr
    manager, pid, _ = lab
    original = AX.AXUIElementIsAttributeSettable

    def settable(node, name, output):
        if name == attribute and attr(node, 'AXRole') == 'AXTextArea':
            return AX.kAXErrorAttributeUnsupported, False
        return original(node, name, output)

    monkeypatch.setattr(AX, 'AXUIElementIsAttributeSettable', settable)
    window = listing(manager, pid)
    assert not any(field['readonly'] for field in window['controls'])
    assert window['controls'][focused(window)]['password'] is False
