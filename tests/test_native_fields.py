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

    def write(self, index, value):
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
    listing = manager.discover(dict(action='list-native-fields', native_protocol=1, pid=123))
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
        dict(control=0, password=False, readonly=False), dict(control=1, password=True, readonly=False),
        dict(control=2, password=False, readonly=True)]
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
