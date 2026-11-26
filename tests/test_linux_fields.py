"""Real GTK and AT-SPI tests, explicitly admitted inside a fresh D-Bus session."""
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import subprocess
import sys
import time

import pytest

from akdbx.native_fields import NativeFields
from akdbx.target import DeliveryError
from akdbx.totp import https_origin
from test_writes import deployed, template  # noqa: F401

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux') or os.environ.get('AKDBX_TEST_NATIVE_LINUX') != '1',
                                reason='requires the explicit isolated D-Bus native Linux lab')


@pytest.fixture(params=['x11', 'wayland'])
def lab(tmp_path, monkeypatch, request):
    display = request.param.removeprefix('qt-')
    qt = request.param.startswith('qt-')
    assert os.environ.get('DBUS_SESSION_BUS_ADDRESS'), 'run this suite through dbus-run-session'
    for program in ('Xvfb', 'openbox'):
        assert shutil.which(program), f'native Linux lab requires {program}'
    reader, writer = os.pipe()
    children = []
    try:
        children.append(subprocess.Popen(['Xvfb', '-displayfd', str(writer), '-screen', '0', '800x600x24', '-nolisten', 'tcp'],
                                         pass_fds=(writer,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        os.close(writer)
        assert select.select([reader], [], [], 10)[0]
        number = os.read(reader, 32).decode().strip()
        assert number.isdecimal() and number not in {'99', '101', '102', '103', '104'}
        monkeypatch.setenv('DISPLAY', ':' + number)
        monkeypatch.delenv('XAUTHORITY', raising=False)
        monkeypatch.setenv('GTK_MODULES', 'atk-bridge')
        monkeypatch.setenv('NO_AT_BRIDGE', '0')
        # Setting focus before Openbox manages the display can leave the
        # first Qt window inactive between discovery and the pinned read.
        wm_ready = tmp_path / 'openbox-ready'
        wm = subprocess.Popen(['openbox', '--startup', shlex.join(['touch', str(wm_ready)])],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        children.append(wm)
        deadline = time.monotonic() + 10
        while not wm_ready.exists():
            assert wm.poll() is None and time.monotonic() < deadline, 'Openbox did not start'
            time.sleep(.05)
        if display in {'wayland', 'xwayland'}:
            assert shutil.which('weston'), 'native Wayland lab requires Weston'
            runtime = tmp_path / 'runtime'
            runtime.mkdir(mode=0o700)
            monkeypatch.setenv('XDG_RUNTIME_DIR', str(runtime))
            monkeypatch.setenv('WAYLAND_DISPLAY', 'akdbx-test')
            monkeypatch.setenv('GDK_BACKEND', 'wayland' if display == 'wayland' else 'x11')
            options = []
            if display == 'xwayland':
                binary = shutil.which('Xwayland')
                assert binary, 'XWayland lab requires Xwayland'
                config = tmp_path / 'weston.ini'
                config.write_text(f'[xwayland]\npath={binary}\n')
                options = ['--xwayland', '--config=' + str(config)]
            weston_log = tmp_path / 'weston.log'
            weston = subprocess.Popen(['weston', '--backend=x11-backend.so', '--shell=kiosk-shell.so',
                '--socket=akdbx-test', '--idle-time=0', '--log=' + str(weston_log), *options],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(weston)
            deadline = time.monotonic() + 10
            while not (runtime / 'akdbx-test').exists():
                assert weston.poll() is None, (tmp_path / 'weston.log').read_text()
                assert time.monotonic() < deadline
                time.sleep(.05)
            if display == 'xwayland':
                while True:
                    match = re.search(r'listening on display (:\d+)', weston_log.read_text())
                    if match:
                        assert match[1] != os.environ['DISPLAY']
                        (tmp_path / 'outer-display').write_text(os.environ['DISPLAY'])
                        monkeypatch.setenv('DISPLAY', match[1])
                        break
                    assert weston.poll() is None and time.monotonic() < deadline, weston_log.read_text()
                    time.sleep(.05)
        else:
            monkeypatch.setenv('GDK_BACKEND', 'x11')
        executable = os.environ.get('AKDBX_QT_TEST_PYTHON', sys.executable) if qt else sys.executable
        if qt:
            monkeypatch.setenv('QT_QPA_PLATFORM', 'wayland' if display == 'wayland' else 'xcb')
            monkeypatch.setenv('QT_LINUX_ACCESSIBILITY_ALWAYS_ON', '1')
        process = subprocess.Popen([executable, str(Path(__file__).with_name('native_qt_lab.py' if qt else 'native_gtk_lab.py')), str(tmp_path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        children.append(process)
        deadline = time.monotonic() + 10
        while not (tmp_path / 'ready').exists():
            assert process.poll() is None, process.stderr.read().decode()
            assert time.monotonic() < deadline
            time.sleep(.05)
        backend_name = (tmp_path / 'ready').read_text()
        if qt:
            assert backend_name == ('wayland' if display == 'wayland' else 'xcb')
        else:
            assert ('Wayland' if display == 'wayland' else 'X11') in backend_name
        manager = NativeFields()
        yield manager, process.pid, tmp_path
        manager.close()
    finally:
        os.close(reader)
        for process in reversed(children):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def command(directory, **values):
    result = directory / 'result.json'
    result.unlink(missing_ok=True)
    pending = directory / 'command.tmp'
    pending.write_text(json.dumps(values))
    pending.replace(directory / 'command.json')
    deadline = time.monotonic() + 5
    while not result.exists():
        assert time.monotonic() < deadline
        time.sleep(.02)
    return json.loads(result.read_text())


def listing(manager, pid):
    deadline = time.monotonic() + 8
    while True:
        try:
            return manager.discover(dict(action='list-native-fields', native_protocol=1, pid=pid))
        except Exception:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.1)


@pytest.mark.parametrize('lab', ['qt-x11', 'qt-wayland'], indirect=True)
@pytest.mark.parametrize('value', ['abc', 'a\U0001f5ddb'])
def test_real_qt_readonly_capture_handles_reported_range_and_utf16_units(lab, value):
    manager, pid, directory = lab
    command(directory, value=value)
    window = listing(manager, pid)['windows'][0]
    control = next(f['control'] for f in window['controls'] if f['focused'])
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=control, mode='read', service_url='https://example.test/'))
    pin = manager.take(receipt['target'], 'read')
    assert manager.read(pin, {https_origin('https://example.test/')}, lambda: True, time.monotonic() + 4) == value
    pin.close()


@pytest.mark.parametrize('lab', ['x11', 'xwayland'], indirect=True)
def test_window_pin_delivers_to_active_gtk_window(lab):
    from akdbx.broker import Broker
    from akdbx.target import X11Typer
    from test_broker import Entry, Vault
    _, pid, directory = lab
    command(directory, focus=0)
    broker = Broker(Vault([Entry()]), X11Typer())
    assert broker.dispatch({'action': 'ping'})['target_fill_modes'] == ['username', 'totp', 'sms-code']
    # Mapping the GTK window is asynchronous. Wait for the compositor to
    # publish the active XID and focus before dispatching a single fill.
    deadline = time.monotonic() + 5
    while True:
        pin = broker.dispatch(dict(action='pin-target', target_protocol=1, pid=pid,
                                   window=int((directory / 'xid').read_text())))
        if pin['ok']:
            break
        assert time.monotonic() < deadline, pin
        time.sleep(.05)
    handle = broker.dispatch({'action': 'search'})['entries'][0]['handle']
    result = broker.dispatch(dict(action='fill', target_protocol=1, target=pin['target'],
                                  handle=handle, mode='username'))
    assert result['ok'], result
    assert command(directory)[0] == Entry().username


@pytest.mark.parametrize('lab', ['xwayland'], indirect=True)
def test_xwayland_registration_preserves_live_x11_connection(lab):
    from contextlib import closing
    from Xlib.ext import res
    from akdbx.x11_display import TargetDisplay

    _, _, directory = lab
    with closing(TargetDisplay((directory / 'outer-display').read_text())) as x11:
        with closing(TargetDisplay()) as xwayland:
            # Servers are free to assign the same opcode. Check isolation as
            # well as real X-Resource queries on both open connections.
            assert x11.display.extension_major_opcodes is not xwayland.display.extension_major_opcodes
            for connection in (xwayland, x11):
                window = connection.screen().root.create_window(0, 0, 1, 1, 0, 0)
                ids = connection.res_query_client_ids([dict(client=window.id, mask=res.LocalClientPIDMask)]).ids
                assert len(ids) == 1 and list(ids[0].value) == [os.getpid()]


@pytest.mark.parametrize('lab', ['wayland'], indirect=True)
def test_native_wayland_window_pin_refusal(lab, monkeypatch):
    from akdbx.broker import Broker
    from akdbx.target import X11Typer
    from test_broker import Entry, Vault
    manager, pid, _ = lab
    assert listing(manager, pid)['windows']
    monkeypatch.delenv('DISPLAY')
    broker = Broker(Vault([Entry()]), X11Typer())
    result = broker.dispatch(dict(action='pin-target', target_protocol=1, pid=pid, window=42))
    assert result['delivery'] == 'not-started' and 'list-native-fields' in result['error']


def test_real_gtk_login_and_readonly_secret_capture(lab):
    manager, pid, directory = lab
    command(directory, focus=0)
    result = listing(manager, pid)
    window = result['windows'][0]
    assert len(window['controls']) == 4
    username = next(f['control'] for f in window['controls'] if f['focused'])
    command(directory, focus=1)
    assert 'invented-capture-key' not in json.dumps(result)
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=1, username_control=username, mode='login', service_url='https://example.test/'))
    pin = manager.take(receipt['target'], 'password')
    manager.deliver_password(pin, 'login', 'invented-user', 'invented-pássword-✓',
                             {https_origin('https://example.test/')}, lambda: True, time.monotonic() + 4)
    pin.close()
    assert command(directory) == ['invented-user', 'invented-pássword-✓', 'invented-capture-key', '']
    command(directory, focus=2)
    window = listing(manager, pid)['windows'][0]
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=2, mode='read', service_url='https://example.test/'))
    pin = manager.take(receipt['target'], 'read')
    assert manager.read(pin, {https_origin('https://example.test/')}, lambda: True,
                        time.monotonic() + 4) == 'invented-capture-key'
    pin.close()


def test_real_gtk_refuses_password_when_mask_is_removed(lab):
    manager, pid, directory = lab
    window = listing(manager, pid)['windows'][0]
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=1, mode='password', service_url='https://example.test/'))
    pin = manager.take(receipt['target'], 'password')
    command(directory, mask=False)
    with pytest.raises(DeliveryError) as failure:
        manager.deliver_password(pin, 'password', '', 'must-not-arrive', {https_origin('https://example.test/')},
                                 lambda: True, time.monotonic() + 4)
    assert not failure.value.started
    assert command(directory)[1] == ''
    pin.close()


def test_native_vault_workflows_keep_values_out_of_receipts_and_reopen(lab, deployed):  # noqa: F811
    from pykeepass import PyKeePass
    from test_cards import save as save_card
    from test_identities import begin as begin_identity, post as post_identity
    from test_writes import MASTER
    from akdbx.writes import metadata
    manager, pid, directory = lab
    broker, _, path, web = deployed
    broker.native = manager
    broker.card_targets.native = manager
    broker.identity_targets.native = manager

    def pin(mode, control, **fields):
        command(directory, focus=control)
        window = listing(manager, pid)['windows'][0]
        return broker.dispatch(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                                     control=control, mode=mode, service_url='https://example.test/', **fields))['target']

    from akdbx.sms import SmsInbox
    broker.sms = SmsInbox(directory / 'sms.json')
    source = broker.sms.add_source('phone', 'shortcut')
    broker.sms.receive(source, 'Example', 'Your verification code is 012345')
    [message] = broker.dispatch(dict(action='sms-wait', sms_protocol=1))['messages']
    def fill_code(target, **extra):
        return broker.dispatch(dict(action='fill-sms-code', sms_protocol=1, message=message['id'],
                                    target=target, target_protocol=1, **extra))

    wrong_site = pin('code', 0)
    assert not fill_code(wrong_site, target_url='https://other.test/')['ok']
    assert not fill_code(wrong_site)['ok'] and command(directory)[0] == ''
    response = fill_code(pin('code', 0))
    assert response == dict(ok=True, filled='one-time-code', code_delivery='native-field-v1')
    assert command(directory)[0] == '012345'
    assert not fill_code(pin('code', 0))['ok']

    card = save_card(deployed)
    response = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=card['handle'],
                                    target=pin('card', 0, field='cc-number'), field='cc-number'))
    assert response == dict(ok=True, filled='cc-number', card_delivery='native-field-v1')
    assert command(directory)[0] == '4111111111111111'
    assert '4111111111111111' not in json.dumps(response)

    prepared = begin_identity(broker)
    assert post_identity(web, prepared)[0] == 200
    identity = broker.dispatch(dict(action='search-identities', identity_protocol=1, query='Sample shipping'))['entries'][0]
    response = broker.dispatch(dict(action='fill-identity', identity_protocol=1, handle=identity['handle'],
                                    target=pin('identity', 0, field='address-line1'), field='address-line1'))
    assert response == dict(ok=True, filled='address-line1', identity_delivery='native-field-v1')
    assert command(directory)[0] == '12 Synthetic Avenue'
    assert 'Synthetic Avenue' not in json.dumps(response)

    entry = next(e for e in broker.vault.entries if e.title == 'Synthetic site')
    prepared = broker.dispatch(dict(action='generate-password', handle=broker._new_handle(entry), metadata=metadata(entry)))
    assert prepared['ok']
    for mode in ('password', 'confirmation'):
        response = broker.dispatch(dict(action='fill-generated', handle=prepared['fill_handles'][mode],
            target_url='https://example.test/', target=pin('password', 1), target_protocol=1))
        assert response == dict(ok=True, filled='password', target_delivery='native-field-v1')
    assert broker.dispatch(dict(action='commit-password', write_handle=prepared['write_handle'], site_accepted=True))['ok']
    generated = command(directory)[1]
    reopened = PyKeePass(path, password=MASTER)
    assert reopened.find_entries(title='Synthetic site', first=True).password == generated
    assert len(generated) == 24 and generated not in json.dumps(response)

    values = dict(title='Native captured secret', username='client', url='https://example.test/', group='Web')
    response = broker.dispatch(dict(action='capture-secret', capture_protocol=1, target=pin('read', 2),
                                     field='NativeKey', metadata=values, create=True))
    assert response['ok'] and response['capture_delivery'] == 'native-field-read-v1'
    assert 'invented-capture-key' not in json.dumps(response)
    reopened = PyKeePass(path, password=MASTER)
    captured = reopened.find_entries(title='Native captured secret', first=True)
    assert captured.get_custom_property('NativeKey') == 'invented-capture-key'
    assert captured.is_custom_property_protected('NativeKey')

def test_linux_failed_accessibility_init_cannot_abort_on_second_discovery():
    import os
    import subprocess
    import sys
    if not sys.platform.startswith('linux'):
        pytest.skip('Linux libatspi initialization regression')
    script = """
import os
from akdbx.linux_fields import scan
from akdbx.target import TargetError
for attempt in range(2):
    try:
        scan(os.getpid())
    except TargetError:
        continue
    raise AssertionError('unexpected discovery without accessibility bus')
print('both-refused')
"""
    env = dict(os.environ, DBUS_SESSION_BUS_ADDRESS='unix:path=/tmp/akdbx-no-such-accessibility-bus', DISPLAY='', WAYLAND_DISPLAY='')
    result = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True, text=True, timeout=10,
                            preexec_fn=lambda: __import__('resource').setrlimit(__import__('resource').RLIMIT_CORE, (0, 0)))
    assert result.returncode == 0, (result.returncode, result.stderr)
    assert result.stdout.strip() == 'both-refused'
