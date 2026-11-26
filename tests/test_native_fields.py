"""Native field authorization: metadata only, explicit recipients, one use."""
import json

import pytest

from akdbx.native_fields import NativeFields, DELIVERY, READ_DELIVERY
from akdbx.target import TargetError, DeliveryError
from akdbx.totp import https_origin

SITE = 'https://example.test/'
ORIGINS = {https_origin(SITE)}


class Session:
    def __init__(self):
        self.controls = [0, 1, 2]
        self.facts = [(False, False, False), (True, False, False), (False, True, False)]
        self.focused, self.closed = 1, False
        self.values = {}
        self.reject_after_write = False
        self.preflight_error = False
        self.read_value = 'synthetic-key-only'

    def describe(self, index):
        if self.closed:
            raise TargetError()
        return self.facts[index]

    def focus(self, indices):
        if self.focused not in indices:
            raise TargetError()
        return self.focused

    def check(self, indices, facts, focus):
        if tuple(self.describe(i) for i in indices) != facts or self.focused != focus:
            raise TargetError()

    def prepare(self, index, value):
        if self.preflight_error:
            raise RuntimeError(value)

    def write(self, index, value, before_write):
        before_write()
        self.values[index] = value
        if self.reject_after_write:
            self.focused = 2

    def read(self, index):
        assert index == 2
        return self.read_value

    def close(self):
        self.closed = True


def setup(mode='password', **extra):
    session = Session()
    session.focused = 2 if mode == 'read' else 0 if mode in {'card', 'identity', 'username', 'totp'} else 1
    now = [10.0]
    manager = NativeFields(scan=lambda pid: [session], clock=lambda: now[0])
    if mode == 'login':
        session.focused = 0
    listing = manager.discover(dict(action='list-native-fields', native_protocol=1, pid=123))
    if mode == 'login':
        session.focused = 1
    window = listing['windows'][0]['window']
    args = dict(action='pin-native-target', native_protocol=1, window=window,
                control=session.focused, mode=mode, service_url=SITE, **extra)
    if mode == 'login':
        args['username_control'] = 0
    receipt = manager.pin(args)
    return manager, session, receipt, now


@pytest.mark.parametrize('mode', ['password', 'username', 'login'])
def test_password_login_and_username_set_only_explicit_controls(mode):
    manager, session, receipt, _ = setup(mode)
    pin = manager.take(receipt['target'], 'password')
    manager.deliver_password(pin, mode, 'invented-user', 'invented-password', ORIGINS, lambda: True, 14)
    assert session.values == ({0: 'invented-user', 1: 'invented-password'} if mode == 'login' else
                              {0: 'invented-user'} if mode == 'username' else {1: 'invented-password'})
    assert manager.take(receipt['target']) is None
    assert 'invented' not in json.dumps(receipt)
    pin.close()
    assert session.closed


def test_origin_mismatch_cannot_write():
    manager, session, receipt, _ = setup()
    pin = manager.take(receipt['target'])
    with pytest.raises(DeliveryError) as error:
        manager.deliver_password(pin, 'password', '', 'invented', {https_origin('https://other.test/')}, lambda: True, 14)
    assert not error.value.started and not session.values
    pin.close()


@pytest.mark.parametrize('change', ['focus', 'mask', 'readonly', 'closed', 'deadline', 'caller', 'preflight'])
def test_changed_or_unavailable_target_never_starts(change):
    manager, session, receipt, now = setup()
    pin = manager.take(receipt['target'])
    if change == 'focus': session.focused = 0
    if change == 'mask': session.facts[1] = (False, False, False)
    if change == 'readonly': session.facts[1] = (True, True, False)
    if change == 'closed': session.closed = True
    if change == 'deadline': now[0] = 15
    if change == 'preflight': session.preflight_error = True
    with pytest.raises(DeliveryError) as error:
        manager.deliver_password(pin, 'password', '', 'invented-password', ORIGINS, lambda: change != 'caller', 14)
    assert not error.value.started and not session.values
    assert 'invented' not in str(error.value)
    pin.close()


def test_partial_login_is_uncertain_and_never_redirects_to_another_control():
    manager, session, receipt, _ = setup('login')
    pin = manager.take(receipt['target'])
    session.reject_after_write = True
    with pytest.raises(DeliveryError) as error:
        manager.deliver_password(pin, 'login', 'invented-user', 'invented-password', ORIGINS, lambda: True, 14)
    assert error.value.started and session.values == {0: 'invented-user'}
    pin.close()


@pytest.mark.parametrize('mode,field', [('card', 'cc-number'), ('identity', 'address-line1')])
def test_native_cards_and_addresses_share_existing_value_workflows(mode, field):
    manager, session, receipt, _ = setup(mode, field=field)
    pin = manager.take(receipt['target'], mode)
    result = manager.fill(pin, 'synthetic-value', field, lambda: True, 14)
    assert result == dict(ok=True, filled=field, **{mode + '_delivery': DELIVERY})
    assert session.values == {0: 'synthetic-value'}
    pin.close()


def test_secret_capture_reads_only_explicit_readonly_control():
    manager, session, receipt, _ = setup('read')
    pin = manager.take(receipt['target'], 'read')
    assert manager.read(pin, ORIGINS, lambda: True, 14) == session.read_value
    session.facts[2] = (False, False, False)
    with pytest.raises(TargetError):
        manager.read(pin, ORIGINS, lambda: True, 14)
    pin.close()


@pytest.mark.parametrize('extra', [{}, {'read_kind': 'qr'}])
def test_capture_totp_refuses_and_consumes_native_read_pin(monkeypatch, extra):
    from test_broker import make_broker
    from akdbx.writes import metadata

    broker, _ = make_broker()
    broker.native, session, receipt, now = setup('read')
    broker.clock = lambda: now[0]
    monkeypatch.setattr(session, 'read', lambda index: pytest.fail('native control was read'))
    entry = broker.vault.entries[0]
    entry.url = SITE
    request = dict(action='capture-totp', totp_capture_protocol=1, target=receipt['target'],
                   handle=broker._new_handle(entry), metadata=metadata(entry), start_deadline=14, **extra)
    assert broker.dispatch(request) == dict(
        ok=False, error='authenticator capture refused: native controls cannot verify the site origin; nothing saved')
    assert session.closed and broker.native.take(receipt['target']) is None


def test_wrong_kind_consumes_and_closes_pin():
    manager, session, receipt, _ = setup()
    with pytest.raises(TargetError):
        manager.take(receipt['target'], 'card')
    assert manager.take(receipt['target']) is None and session.closed


def test_listing_and_receipts_never_include_values_or_names():
    session = Session()
    manager = NativeFields(scan=lambda pid: [session])
    result = manager.discover(dict(action='list-native-fields', native_protocol=1, pid=123))
    assert set(result['windows'][0]) == {'window', 'controls'}
    assert result['windows'][0]['controls'] == [
        dict(control=0, password=False, readonly=False, focused=False), dict(control=1, password=True, readonly=False, focused=True),
        dict(control=2, password=False, readonly=True, focused=False)]
    assert session.read_value not in json.dumps(result)
    manager.close()
    assert session.closed and not manager.views


def test_broker_uses_native_password_pin_and_keeps_legacy_window_password_refusal():
    from test_broker import make_broker
    broker, typer = make_broker()
    broker.native, session, receipt, now = setup('login')
    # The test broker's clock must share the native pin's clock.
    broker.clock = lambda: now[0]
    handle = broker._new_handle(broker.vault.entries[0])
    broker.vault.entries[0].url = SITE
    result = broker.dispatch(dict(action='fill', handle=handle, target=receipt['target'], target_protocol=1,
                                  mode='login', start_deadline=14))
    assert result == dict(ok=True, filled='login', target_delivery=DELIVERY)
    assert session.values[1] == broker.vault.entries[0].password
    assert session.closed


def test_native_totp_cli_receipt_coexists_with_browser_routes(monkeypatch, capsys):
    from akdbx import cli
    from test_broker import make_broker
    from totp_vectors import URI
    broker, typer = make_broker()
    broker.native, session, receipt, now = setup('totp')
    broker.clock = lambda: now[0]
    broker.wall_clock = lambda: 1111111111
    entry = broker.vault.entries[0]
    entry.url, entry.otp = SITE, URI
    handle = broker._new_handle(entry)
    monkeypatch.setattr(cli, 'request', lambda path, payload, **kwargs: broker.dispatch(payload))
    assert cli.main(['fill-totp', handle, '--target-url', SITE, '--target', receipt['target']]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == dict(ok=True, filled='totp', target_delivery=DELIVERY)
    assert '050471' not in output.out + output.err
    assert session.values == {0: '050471'} and session.closed and not typer.events


@pytest.mark.parametrize('field,control,mode', [(None, 0, 'password'), (None, 1, 'username'),
                                             (None, 1, 'read'), ('not-a-card-field', 0, 'card')])
def test_pin_refuses_wrong_control_role_or_field_before_delivery(field, control, mode):
    session = Session()
    manager = NativeFields(scan=lambda pid: [session])
    window = manager.discover(dict(action='list-native-fields', native_protocol=1, pid=123))['windows'][0]['window']
    request = dict(action='pin-native-target', native_protocol=1, window=window, control=control, mode=mode, service_url=SITE)
    if field is not None:
        request['field'] = field
    with pytest.raises(TargetError):
        manager.pin(request)
    assert session.closed and not session.values and not manager.views and not manager.pins


def test_expired_discovery_and_pin_are_closed():
    manager, session, receipt, now = setup()
    now[0] += 31
    assert manager.take(receipt['target']) is None
    assert session.closed


@pytest.mark.parametrize('native_protocol', [None, True, 2])
def test_native_cli_never_sends_to_an_incompatible_broker(monkeypatch, capsys, native_protocol):
    from akdbx import cli
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        return dict(ok=True, native_field_protocol=native_protocol, native_field_supported=True,
                    native_field_delivery=DELIVERY)
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['list-native-fields', '--pid', '123']) == 1
    assert calls == [dict(action='ping')]
    assert 'request not sent' in capsys.readouterr().out


def test_native_cli_rejects_extra_values_in_discovery_receipt(monkeypatch, capsys):
    from akdbx import cli
    def request(path, payload, **kwargs):
        if payload['action'] == 'ping':
            return dict(ok=True, native_field_protocol=1, native_field_supported=True, native_field_delivery=DELIVERY)
        return dict(ok=True, pid=123, expires_in=30, windows=[dict(window='a'*64,
                    controls=[dict(control=0, password=False, readonly=False, value='must-not-print')])])
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['list-native-fields', '--pid', '123']) == 2
    assert 'must-not-print' not in str(capsys.readouterr())



@pytest.mark.parametrize('value', ['Shah\u200cr', 'Deva\u200dnagar'])
def test_native_identity_fields_accept_saved_unicode_joiners(value):
    manager, session, receipt, _ = setup('identity', field='address-level2')
    pin = manager.take(receipt['target'])
    assert manager.fill(pin, value, 'address-level2', lambda: True, 14)['ok']
    assert session.values == {0: value}
    pin.close()


@pytest.mark.parametrize('change', ['deadline', 'caller', 'focus'])
def test_authorization_rechecked_inside_backend_before_dispatch(change):
    manager, session, receipt, now = setup()
    pin = manager.take(receipt['target'])
    ready = [True]
    original = session.write
    def delayed_write(index, value, before_write):
        # Models time spent waiting for the backend lock or editable interface.
        if change == 'deadline': now[0] = 15
        if change == 'caller': ready[0] = False
        if change == 'focus': session.focused = 0
        original(index, value, before_write)
    session.write = delayed_write
    with pytest.raises(DeliveryError) as error:
        manager.deliver_password(pin, 'password', '', 'must-not-arrive', ORIGINS, lambda: ready[0], 14)
    assert not error.value.started and not session.values
    pin.close()


def test_login_requires_username_focus_at_discovery_and_password_focus_at_pin():
    session = Session()
    session.controls.append(3)
    session.facts.append((False, False, False))  # Another plain account edit.
    session.focused = 3
    manager = NativeFields(scan=lambda pid: [session])
    window = manager.discover(dict(action='list-native-fields', native_protocol=1, pid=123))['windows'][0]
    assert next(f['control'] for f in window['controls'] if f['focused']) == 3
    session.focused = 1
    with pytest.raises(TargetError):
        manager.pin(dict(action='pin-native-target', native_protocol=1, window=window['window'],
                         control=1, username_control=0, mode='login', service_url=SITE))
    assert not session.values and session.closed


@pytest.mark.parametrize('changed', [False, True])
def test_linux_read_is_bounded_and_refuses_a_growing_field(changed):
    from types import SimpleNamespace
    from akdbx.linux_fields import LinuxFields
    session = object.__new__(LinuxFields)
    session.controls = [1]
    session.describe = lambda index: (False, True)
    counts = iter([3, 7 if changed else 3])
    def call(name, iface):
        assert name == 'text_get_character_count'
        return next(counts)
    def string(name, iface, start, end):
        assert (name, start, end) == ('text_get_text', 0, 3)
        return 'sec' if changed else 'key'
    session.api = SimpleNamespace(accessible_get_text_iface=lambda node: 2, call=call, string=string,
                                  obj=SimpleNamespace(g_object_unref=lambda node: None))
    if changed:
        with pytest.raises(TargetError): session.read(0)
    else:
        assert session.read(0) == 'key'


@pytest.mark.parametrize('changed', [False, True])
def test_windows_read_is_bounded_and_refuses_a_growing_field(changed):
    import ctypes as C
    from akdbx.windows_fields import WindowsFields
    session = object.__new__(WindowsFields)
    session.controls = [1]
    session.describe = lambda index: (False, True)
    lengths = iter([3, 7 if changed else 3])
    def message(hwnd, kind, size=0, pointer=0):
        if kind == 0x000E: return next(lengths)
        assert kind == 0x000D and size == 65538
        value = 'secret!' if changed else 'key'
        C.memmove(pointer, C.create_unicode_buffer(value), (len(value) + 1) * C.sizeof(C.c_wchar))
        return len(value)
    session.message = message
    if changed:
        with pytest.raises(TargetError): session.read(0)
    else:
        assert session.read(0) == 'key'


def test_linux_dispatch_guard_runs_after_editable_interface_acquisition():
    from types import SimpleNamespace
    from akdbx.linux_fields import LinuxFields
    manager, session, receipt, now = setup()
    pin = manager.take(receipt['target'])
    backend = object.__new__(LinuxFields)
    backend.controls = [0, 1, 2]
    def get_iface(node):
        now[0] = 15  # Time expires while acquiring the interface.
        return 42
    def forbidden(*args):
        pytest.fail('expired operation reached the write API')
    backend.api = SimpleNamespace(accessible_get_editable_text_iface=get_iface, call=forbidden,
                                  obj=SimpleNamespace(g_object_unref=lambda node: None))
    session.write = backend.write
    with pytest.raises(DeliveryError) as error:
        manager.deliver_password(pin, 'password', '', 'must-not-arrive', ORIGINS, lambda: True, 14)
    assert not error.value.started and not session.values
    pin.close()



class SlowWin32:
    """The real Win32 write path, with a fake app and one fake clock."""

    def __init__(self, now, delays):
        from akdbx import windows_fields
        self.module, self.now, self.delays = windows_fields, now, delays
        self.calls, self.text = [], {0: '', 1: '', 2: 'invented-capture'}

    def SendMessageTimeoutW(self, hwnd, message, wparam, lparam, flags, timeout, result):
        import ctypes as C
        assert flags == self.module.MESSAGE_FLAGS and type(timeout) is int and timeout >= 1
        self.calls.append((message, timeout))
        delay = self.delays.get(message, 0)
        if delay * 1000 > timeout:
            self.now[0] += timeout / 1000
            return 0  # Timed out. The app may still apply WM_SETTEXT later.
        self.now[0] += delay
        answer = {0x00D5: 30000, 0x000C: 1}.get(message)
        if message == 0x000C:
            self.text[hwnd] = C.wstring_at(lparam)
        elif message in {0x000D, 0x000E}:
            answer = len(self.text[hwnd].encode('utf-16-le')) // 2
            if message == 0x000D:
                C.memmove(lparam, C.create_unicode_buffer(self.text[hwnd]), (answer + 1) * C.sizeof(C.c_wchar))
        result._obj.value = answer
        return 1

    def install(self, session):
        """Keep the fake metadata checks; send the real Win32 messages."""
        backend = object.__new__(self.module.WindowsFields)
        backend.controls, backend.clock = session.controls, lambda: self.now[0]
        backend.native = type('Native', (), {'api': self})()
        # The Win32 facts also carry style, parent and control ID.
        backend.describe = lambda index: session.describe(index) + (0, 0, index)
        session.prepare, session.write, session.read = backend.prepare, backend.write, backend.read
        return backend


def test_windows_probes_keep_the_short_limit():
    manager, session, receipt, now = setup('read')
    app = SlowWin32(now, {})
    app.install(session)
    pin = manager.take(receipt['target'])
    assert manager.read(pin, ORIGINS, lambda: True, 14) == 'invented-capture'
    assert app.calls == [(0x000E, 100), (0x000D, 100), (0x000E, 100)]
    assert app.module.PROBE_TIMEOUT_MS == 100 and app.module.MESSAGE_FLAGS & 0x2  # SMTO_ABORTIFHUNG
    pin.close()


def test_windows_slow_but_responsive_login_succeeds():
    manager, session, receipt, now = setup('login')
    # 250 ms per change handler: more than a probe may wait, less than a write.
    app = SlowWin32(now, {0x000C: 0.25, 0x000E: 0.25})
    app.install(session)
    pin = manager.take(receipt['target'])
    manager.deliver_password(pin, 'login', 'invented-user\U0001F600', 'invented-password', ORIGINS, lambda: True, 14)
    assert app.calls == [(0x00D5, 100), (0x00D5, 100), (0x000C, 1000), (0x000E, 1000), (0x000C, 1000), (0x000E, 1000)]
    assert app.text[0] == 'invented-user\U0001F600' and app.text[1] == 'invented-password' and now[0] == 11
    pin.close()


@pytest.mark.parametrize('case', ['after-length', 'in-settext', 'at-length', 'pin-expiry'])
def test_windows_write_never_waits_past_the_deadline_and_ends_uncertain(case):
    manager, session, receipt, now = setup()
    delays = {'after-length': {0x000C: 0.25, 0x000E: 0.25}, 'in-settext': {0x000C: 0.75},
              'at-length': {0x000C: 0.5}, 'pin-expiry': {0x000C: 0.25, 0x000E: 0.25}}[case]
    app = SlowWin32(now, delays)
    app.install(session)
    pin = manager.take(receipt['target'])
    deadline = 10.5
    if case == 'pin-expiry':
        # The pin expires before the caller's deadline: the pin expiry caps the wait.
        deadline, now[0] = 100, pin.expires - 0.5
    start = now[0]
    with pytest.raises(DeliveryError) as error:
        manager.deliver_password(pin, 'password', '', 'invented-password', ORIGINS, lambda: True, deadline)
    assert error.value.started  # Uncertain: never reported as filled, never retried.
    writes = [call for call in app.calls if call[0] != 0x00D5]
    assert writes == {'after-length': [(0x000C, 500), (0x000E, 250)], 'in-settext': [(0x000C, 500)],
                      'at-length': [(0x000C, 500)], 'pin-expiry': [(0x000C, 500), (0x000E, 250)]}[case]
    assert now[0] == start + 0.5  # Exactly the time left, never a full second.
    pin.close()


@pytest.mark.parametrize('full', [False, True])
def test_discovery_asks_the_app_outside_the_manager_lock(full):
    import threading
    session = Session()
    manager = NativeFields(scan=lambda pid: [session])
    taken = []
    describe = session.describe

    def slow_describe(index):
        if index == 0:
            # Another request takes a pin while this app is still answering.
            other = threading.Thread(target=lambda: taken.append(manager.take('unknown')))
            other.start()
            other.join(timeout=5)
            assert not other.is_alive() and taken == [None]
            if full:
                manager.pins.update({str(n): None for n in range(16)})
        return describe(index)

    session.describe = slow_describe
    request = dict(action='list-native-fields', native_protocol=1, pid=123)
    if full:
        # Pins added meanwhile still count against the limit.
        with pytest.raises(TargetError):
            manager.discover(request)
        assert session.closed and not manager.views
    else:
        assert len(manager.discover(request)['windows']) == 1 and len(manager.views) == 1
