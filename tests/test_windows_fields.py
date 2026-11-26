"""Real, owned Unicode Edit controls. Invented credentials only."""
import os
import sys
import time

import pytest

if sys.platform != 'win32':
    pytest.skip('requires native Windows', allow_module_level=True)

import win32api
import win32con
import win32gui

from akdbx.native_fields import NativeFields
from akdbx.target import DeliveryError, TargetError
from akdbx.totp import https_origin

SITE = 'https://example.test/'


@pytest.fixture
def lab():
    name = 'AkdbxSyntheticNativeFields' + str(os.getpid())
    cls = win32gui.WNDCLASS()
    cls.lpszClassName = name
    cls.lpfnWndProc = win32gui.DefWindowProc
    cls.hInstance = win32api.GetModuleHandle(None)
    atom = win32gui.RegisterClass(cls)
    window = win32gui.CreateWindowEx(0, atom, 'Synthetic native field lab',
                                     win32con.WS_OVERLAPPEDWINDOW | win32con.WS_VISIBLE,
                                     40, 40, 500, 260, 0, 0, cls.hInstance, None)
    entries = []
    manager = NativeFields()
    try:
        for i, style in enumerate((0, win32con.ES_PASSWORD, win32con.ES_READONLY, 0)):
            entries.append(win32gui.CreateWindowEx(0, 'Edit', 'invented-capture-key' if i == 2 else '',
                win32con.WS_CHILD | win32con.WS_VISIBLE | win32con.WS_BORDER | win32con.WS_TABSTOP | style,
                10, 10 + i * 45, 420, 35, window, 100 + i, cls.hInstance, None))
        win32gui.SetForegroundWindow(window)
        win32gui.SetFocus(entries[1])
        win32gui.PumpWaitingMessages()
        yield manager, entries
    finally:
        manager.close()
        win32gui.DestroyWindow(window)
        win32gui.UnregisterClass(atom, cls.hInstance)


def discover(manager):
    return manager.discover(dict(action='list-native-fields', native_protocol=1, pid=os.getpid()))['windows'][0]


def test_sms_window_pin_delivers_to_focused_edit(lab):
    from types import SimpleNamespace
    from akdbx.broker import Broker
    from akdbx.sms import Message
    from akdbx.windows_target import WindowsTyper

    _, entries = lab
    broker = Broker(SimpleNamespace(entries=[]), WindowsTyper())
    win32gui.SetFocus(entries[0])
    pin = broker.dispatch(dict(action='pin-target', target_protocol=1, pid=os.getpid(),
                               window=win32gui.GetParent(entries[0])))
    assert pin['ok'], pin
    message = Message('1' * 32, 'fixture', 'test', '***', '482913', broker.clock(), broker.wall_clock())
    broker.sms.restore(message)
    result = broker.dispatch(dict(action='fill-sms-code', sms_protocol=1, message=message.id,
                                  target_protocol=1, target=pin['target'], target_url=SITE))
    assert result == dict(ok=True, filled='one-time-code', target_delivery='win32-char-v1')
    assert win32gui.GetWindowText(entries[0]) == message.code


def test_real_win32_login_and_readonly_secret_capture(lab):
    manager, entries = lab
    win32gui.SetFocus(entries[0])
    window = discover(manager)
    fields = window['controls']
    password = next(f['control'] for f in fields if f['password'])
    username = next(f['control'] for f in fields if f['focused'])
    win32gui.SetFocus(entries[1])
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=password, username_control=username, mode='login', service_url=SITE))
    pin = manager.take(receipt['target'], 'password')
    manager.deliver_password(pin, 'login', 'invented-user', 'invented-pássword-✓', {https_origin(SITE)},
                             lambda: True, time.monotonic() + 4)
    pin.close()
    assert win32gui.GetWindowText(entries[0]) == 'invented-user'
    assert win32gui.GetWindowText(entries[1]) == 'invented-pássword-✓'
    win32gui.SetFocus(entries[2])
    window = discover(manager)
    readonly = next(f['control'] for f in window['controls'] if f['readonly'])
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=readonly, mode='read', service_url=SITE))
    pin = manager.take(receipt['target'], 'read')
    assert manager.read(pin, {https_origin(SITE)}, lambda: True, time.monotonic() + 4) == 'invented-capture-key'
    pin.close()


def test_real_win32_refuses_when_focus_or_password_style_changes(lab):
    manager, entries = lab
    window = discover(manager)
    password = next(f['control'] for f in window['controls'] if f['password'])
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=password, mode='password', service_url=SITE))
    pin = manager.take(receipt['target'], 'password')
    win32gui.SetFocus(entries[0])
    with pytest.raises(DeliveryError) as error:
        manager.deliver_password(pin, 'password', '', 'must-not-arrive', {https_origin(SITE)},
                                 lambda: True, time.monotonic() + 4)
    assert not error.value.started and win32gui.GetWindowText(entries[0]) == win32gui.GetWindowText(entries[1]) == ''
    pin.close()


@pytest.mark.parametrize('style', [0x8, 0x10, 0x400])
@pytest.mark.parametrize('member', [0, 1])
def test_case_converting_styles_refuse_before_either_login_field_changes(lab, style, member):
    manager, entries = lab
    win32gui.SetWindowLong(entries[member], -16, win32gui.GetWindowLong(entries[member], -16) | style)
    win32gui.SetFocus(entries[0])
    window = discover(manager)
    username = next(f['control'] for f in window['controls'] if f['focused'])
    password = next(f['control'] for f in window['controls'] if f['password'])
    win32gui.SetFocus(entries[1])
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=password, username_control=username, mode='login', service_url=SITE))
    pin = manager.take(receipt['target'], 'password')
    with pytest.raises(DeliveryError) as error:
        manager.deliver_password(pin, 'login', 'MixedUser', 'MixedPassword', {https_origin(SITE)},
                                 lambda: True, time.monotonic() + 4)
    assert not error.value.started
    assert win32gui.GetWindowText(entries[0]) == win32gui.GetWindowText(entries[1]) == ''
    pin.close()


@pytest.fixture(scope='module')
def managed_exe(tmp_path_factory):
    from pathlib import Path
    import subprocess
    framework = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319'
    exe = tmp_path_factory.mktemp('managed-fields') / 'fields.exe'
    subprocess.run([str(framework / 'csc.exe'), '/nologo', '/target:exe', '/out:' + str(exe),
                    '/r:System.Windows.Forms.dll', '/r:System.Xaml.dll',
                    *('/r:' + str(framework / 'WPF' / (name + '.dll'))
                      for name in ('WindowsBase', 'PresentationCore', 'PresentationFramework')),
                    str(Path(__file__).with_name('windows_managed_fields.cs'))], check=True, timeout=30)
    return exe


@pytest.mark.parametrize('toolkit', ['winforms', 'wpf'])
def test_managed_control_login_read_and_focus_change(managed_exe, toolkit):
    import ctypes
    import queue
    import subprocess
    import threading

    app = subprocess.Popen([str(managed_exe), toolkit], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    messages = queue.Queue()

    def listen():
        for line in app.stdout:
            messages.put(line.strip())

    reader = threading.Thread(target=listen, daemon=True)
    reader.start()
    manager = NativeFields()

    def command(name, expected='focused'):
        app.stdin.write(name + '\n')
        app.stdin.flush()
        assert messages.get(timeout=10) == expected

    def view():
        return manager.discover(dict(action='list-native-fields', native_protocol=1, pid=app.pid))['windows'][0]

    def pin(window, mode, control, **extra):
        receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                                   mode=mode, service_url=SITE, control=control, **extra))
        return manager.take(receipt['target'])

    try:
        assert messages.get(timeout=20) == 'ready'
        ctypes.windll.user32.AllowSetForegroundWindow(app.pid)
        command('user')
        window = view()
        user = next(f['control'] for f in window['controls'] if f['focused'])
        password = next(f['control'] for f in window['controls'] if f['password'])
        command('password')
        target = pin(window, 'login', password, username_control=user)
        try:
            manager.deliver_password(target, 'login', 'invented-user\U0001F600', 'invented-password',
                                     {https_origin(SITE)}, lambda: True, time.monotonic() + 4)
        except DeliveryError as exc:
            # This app has only invented values. Show the exact failing native
            # call on CI, while broker-facing errors remain secret-free.
            if exc.__context__ is not None:
                raise exc.__context__ from None
            raise
        finally:
            target.close()
        command('verify', 'match')

        window = view()
        target = pin(window, 'password', next(f['control'] for f in window['controls'] if f['focused']))
        command('capture')
        try:
            with pytest.raises(DeliveryError) as error:
                manager.deliver_password(target, 'password', '', 'must-not-arrive',
                                         {https_origin(SITE)}, lambda: True, time.monotonic() + 4)
            assert not error.value.started
        finally:
            target.close()
        command('verify', 'match')
        window = view()
        target = pin(window, 'read', next(f['control'] for f in window['controls'] if f['focused']))
        try:
            assert manager.read(target, {https_origin(SITE)}, lambda: True, time.monotonic() + 4) == 'invented-capture'
        finally:
            target.close()

        if toolkit == 'wpf':
            command('user')
            window = view()
            user = next(f['control'] for f in window['controls'] if f['focused'])
            password = next(f['control'] for f in window['controls'] if f['password'])
            command('password')
            target = pin(window, 'login', password, username_control=user)
            # The app replaces the decomposed username with its precomposed
            # form. UI Automation string conditions call the two values equal.
            try:
                manager.deliver_password(target, 'login', '\u0628A\u030A', 'must-not-arrive',
                                         {https_origin(SITE)}, lambda: True, time.monotonic() + 4)
            except DeliveryError as exc:
                error = exc
            else:
                error = None
            finally:
                target.close()
            # First prove that the app changed the username and kept the old password.
            command('verify-normalized', 'match')
            assert error is not None and error.started
    finally:
        manager.close()
        app.stdin.close()
        try:
            app.wait(timeout=3)
        except subprocess.TimeoutExpired:
            app.kill()
            app.wait()
        reader.join(timeout=3)
        app.stdout.close()

def test_higher_integrity_refuses_discovery(lab, monkeypatch):
    from akdbx import windows_fields
    manager, entries = lab
    levels = iter((0x3000, 0x2000))
    monkeypatch.setattr(windows_fields, 'integrity', lambda _: next(levels))
    with pytest.raises(TargetError):
        discover(manager)
    assert win32gui.GetWindowText(entries[1]) == ''


@pytest.mark.parametrize('change', ['secure-desktop', 'embedded-browser'])
def test_changed_desktop_or_browser_host_refuses_before_write(lab, monkeypatch, change):
    import win32service
    manager, entries = lab
    window = discover(manager)
    password = next(f['control'] for f in window['controls'] if f['password'])
    receipt = manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                               control=password, mode='password', service_url=SITE))
    pin = manager.take(receipt['target'])
    browser = atom = None
    try:
        if change == 'secure-desktop':
            monkeypatch.setattr(win32service, 'GetUserObjectInformation', lambda *_: 'Winlogon')
        else:
            cls = win32gui.WNDCLASS()
            cls.lpszClassName = 'Chrome_WidgetWin_AkdbxTest'
            cls.lpfnWndProc = win32gui.DefWindowProc
            cls.hInstance = win32api.GetModuleHandle(None)
            atom = win32gui.RegisterClass(cls)
            browser = win32gui.CreateWindowEx(0, atom, '', win32con.WS_CHILD,
                                              0, 0, 1, 1, win32gui.GetParent(entries[1]),
                                              0, cls.hInstance, None)
        with pytest.raises(DeliveryError) as error:
            manager.deliver_password(pin, 'password', '', 'must-not-arrive', {https_origin(SITE)},
                                     lambda: True, time.monotonic() + 4)
        assert not error.value.started and win32gui.GetWindowText(entries[1]) == ''
    finally:
        pin.close()
        if browser:
            win32gui.DestroyWindow(browser)
        if atom:
            win32gui.UnregisterClass(atom, cls.hInstance)
