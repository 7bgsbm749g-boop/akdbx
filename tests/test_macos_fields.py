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
from test_writes import deployed, template  # noqa: F401

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


def test_sms_code_keeps_leading_zero(lab):
    manager, pid, command = lab
    window = listing(manager, pid)
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=focused(window), mode='code', service_url=ORIGIN))
    target = manager.take(receipt['target'], 'code')
    try:
        assert manager.fill(target, '012345', 'one-time-code', lambda: True) == dict(
            ok=True, filled='one-time-code', code_delivery='native-field-v1')
        assert command('inspect')[0] == '012345'
    finally:
        target.close()


def secure(lab):
    manager, pid, command = lab
    command('focus1')
    window = listing(manager, pid)
    assert window['controls'][focused(window)]['password']
    return window, focused(window)


def deliver(manager, target, mode, username, password):
    manager.deliver_password(target, mode, username, password, {https_origin(ORIGIN)}, lambda: True,
                             time.monotonic() + 4)


# AppKit masks each UTF-16 unit: an astral emoji counts twice, a combining
# accent once. Passwords never contain control characters (native text rule).
@pytest.mark.parametrize('value', ['invented-password', 'invented-pássword-✓🐈', 'e\u0301漢字かな', '•x•', 'p' * 512])
def test_secure_field_password_is_verified_by_its_masked_length(lab, value):
    manager, pid, command = lab
    window, control = secure(lab)
    target = pin(manager, window, control, 'password')
    try:
        deliver(manager, target, 'password', '', value)
    finally:
        target.close()
    assert command('inspect') == ['', value]
    assert set(manager.capabilities()['native_field_modes']) == {
        'username', 'password', 'login', 'totp', 'code', 'identity', 'card', 'read'}


def test_secure_field_without_bullets_is_verified_too(lab):
    manager, pid, command = lab
    command('no-bullets')
    window, control = secure(lab)
    target = pin(manager, window, control, 'password')
    try:
        deliver(manager, target, 'password', '', 'invented-pássword-✓🐈')
    finally:
        target.close()
    assert command('inspect') == ['', 'invented-pássword-✓🐈']


@pytest.mark.parametrize('prefilled', [True, False])
def test_secure_field_that_shows_text_is_never_trusted(monkeypatch, lab, prefilled):
    from akdbx.macos_fields import AX
    manager, pid, command = lab
    if prefilled:
        command('prefill')
    window, control = secure(lab)
    target = pin(manager, window, control, 'password')
    original = AX.AXUIElementCopyAttributeValue

    def leaky(node, name, output):
        # An app whose secure field gives text, not mask characters.
        error, value = original(node, name, output)
        if name == 'AXValue' and isinstance(value, str):
            value = value.translate({0xf79a: 'x', 0x200b: 'x'})
        return error, value

    monkeypatch.setattr(AX, 'AXUIElementCopyAttributeValue', leaky)
    try:
        with pytest.raises(DeliveryError) as failure:
            deliver(manager, target, 'password', '', 'invented-password')
        # A filled field is refused before the write; an empty one gives no proof after it.
        assert failure.value.started is not prefilled
    finally:
        monkeypatch.undo()
        target.close()
    assert command('inspect') == ['', 'prefilled' if prefilled else 'invented-password']


def test_secure_login_fills_both_controls(lab):
    manager, pid, command = lab
    window = listing(manager, pid)
    username = focused(window)
    password = next(f['control'] for f in window['controls'] if f['password'])
    command('focus1')
    target = pin(manager, window, password, 'login', username_control=username)
    try:
        deliver(manager, target, 'login', 'invented-user', 'invented-pássword-✓🐈')
    finally:
        target.close()
    assert command('inspect') == ['invented-user', 'invented-pássword-✓🐈']


@pytest.mark.parametrize('mode', ['password', 'login'])
def test_secure_fill_is_refused_when_focus_moves(lab, mode):
    manager, pid, command = lab
    if mode == 'login':
        window = listing(manager, pid)
        extra = dict(username_control=focused(window))
        control = next(f['control'] for f in window['controls'] if f['password'])
        command('focus1')
    else:
        (window, control), extra = secure(lab), {}
    target = pin(manager, window, control, mode, **extra)
    try:
        command('focus0')
        with pytest.raises(DeliveryError) as failure:
            deliver(manager, target, mode, 'invented-user', 'must-not-arrive')
        assert not failure.value.started
    finally:
        target.close()
    assert command('inspect') == ['', '']


@pytest.mark.parametrize('app', ['truncate', 'reject'])
def test_secure_field_that_keeps_less_than_the_password_is_uncertain(lab, app):
    manager, pid, command = lab
    command(app)
    window, control = secure(lab)
    target = pin(manager, window, control, 'password')
    try:
        with pytest.raises(DeliveryError) as failure:
            deliver(manager, target, 'password', '', 'invented-long-password')
        # The field took the write but holds another length: never success.
        assert failure.value.started
    finally:
        target.close()
    assert command('inspect') == ['', 'invented' if app == 'truncate' else '']


@pytest.mark.parametrize('value', ['x' * 65537, '🐈' * 32769])
def test_password_over_the_text_limit_is_refused_before_writing(lab, value):
    manager, pid, command = lab
    window, control = secure(lab)
    target = pin(manager, window, control, 'password')
    try:
        with pytest.raises(DeliveryError) as failure:
            deliver(manager, target, 'password', '', value)
        assert not failure.value.started
    finally:
        target.close()
    assert command('inspect') == ['', '']


def test_masked_card_field_and_unmasked_modes(lab):
    manager, pid, command = lab
    window, control = secure(lab)
    target = pin(manager, window, control, 'card', field='cc-csc')
    try:
        assert manager.fill(target, '123', 'cc-csc', lambda: True)['ok']
    finally:
        target.close()
    assert command('inspect') == ['', '123']
    for mode in ('username', 'totp', 'code'):
        window, control = secure(lab)
        with pytest.raises(TargetError):
            pin(manager, window, control, mode)
    command('focus0')
    plain = listing(manager, pid)
    with pytest.raises(TargetError):
        pin(manager, plain, focused(plain), 'password')
    assert command('inspect') == ['', '123']


def test_generated_password_fills_a_secure_field_and_is_saved(lab, deployed):  # noqa: F811
    from pykeepass import PyKeePass
    from test_writes import MASTER
    from akdbx.writes import metadata
    manager, pid, command = lab
    broker, _, path, _ = deployed
    broker.native = manager
    entry = next(e for e in broker.vault.entries if e.title == 'Synthetic site')
    prepared = broker.dispatch(dict(action='generate-password', handle=broker._new_handle(entry),
                                    metadata=metadata(entry)))
    assert prepared['ok']
    for mode in ('password', 'confirmation'):
        window, control = secure(lab)
        target = broker.dispatch(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                                      control=control, mode='password', service_url=ORIGIN))['target']
        response = broker.dispatch(dict(action='fill-generated', handle=prepared['fill_handles'][mode],
                                        target_url=ORIGIN, target=target, target_protocol=1))
        assert response == dict(ok=True, filled='password', target_delivery='native-field-v1')
    assert broker.dispatch(dict(action='commit-password', write_handle=prepared['write_handle'],
                                site_accepted=True))['ok']
    generated = command('inspect')[1]
    assert len(generated) == 24 and generated not in json.dumps(response)
    assert PyKeePass(path, password=MASTER).find_entries(title='Synthetic site', first=True).password == generated


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


def groups(pid):
    # The fixture window has one native group and, after 'web', the WKWebView host.
    from akdbx.macos_fields import AX, WEBKIT_HOST, attr
    window = attr(AX.AXUIElementCreateApplication(pid), 'AXFocusedWindow')
    found = [node for node in attr(window, 'AXChildren') if attr(node, 'AXRole') == 'AXGroup']
    hosts = [node for node in found
             if WEBKIT_HOST in (AX.AXUIElementCopyParameterizedAttributeNames(node, None)[1] or ())]
    return len(found) - len(hosts), hosts


def web_children(pid):
    from akdbx.macos_fields import AX
    native, hosts = groups(pid)
    assert native == 1 and len(hosts) == 1
    error, count = AX.AXUIElementGetAttributeValueCount(hosts[0], 'AXChildren', None)
    assert error == AX.kAXErrorSuccess
    return count


def test_embedded_web_area_is_refused(lab):
    from akdbx.macos_fields import EmbeddedWeb, scan
    manager, pid, command = lab
    # The pinned field sits in a native group that the web-view check passes.
    assert groups(pid) == (1, [])
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


def settle(pid):
    # AppKit reports a moved frame at once. The WindowServer, which routes the
    # desktop hit test, applies the move later. Wait until both agree.
    from Quartz import CGWindowListCopyWindowInfo, kCGNullWindowID, kCGWindowListOptionOnScreenOnly
    from akdbx.macos_fields import AX, attr
    window = attr(AX.AXUIElementCreateApplication(pid), 'AXFocusedWindow')
    deadline = time.monotonic() + 5
    while True:
        point = AX.AXValueGetValue(attr(window, 'AXPosition'), AX.kAXValueCGPointType, None)[1]
        size = AX.AXValueGetValue(attr(window, 'AXSize'), AX.kAXValueCGSizeType, None)[1]
        frame = tuple(round(v) for v in (point[0], point[1], size[0], size[1]))
        shown = [tuple(round(w['kCGWindowBounds'][k]) for k in ('X', 'Y', 'Width', 'Height'))
                 for w in CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID) or ()
                 if w['kCGWindowOwnerPID'] == pid and w['kCGWindowLayer'] == 0]
        if frame in shown:
            return
        assert time.monotonic() < deadline, 'the WindowServer did not apply the window move'
        time.sleep(.02)


def test_offscreen_sibling_leaves_focused_field_available(lab):
    manager, pid, command = lab
    before = listing(manager, pid)
    assert any(field['readonly'] for field in before['controls'])
    command('partly-offscreen')
    settle(pid)
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
