"""Windows delivery contract with synthetic native snapshots; runs on any OS."""
from dataclasses import replace

import pytest

from akdbx.target import DeliveryError
from akdbx.windows_target import WindowsIdentity, WindowsSession, WindowsTyper


class Native:
    def __init__(self, pid):
        self.identity = WindowsIdentity(pid, 456, 457, 10, ('user', 1, 'start'), 'top', 'edit')
        self.sent, self.closed = [], False
        self.after_send = lambda: None

    def snapshot(self, *_):
        return self.identity

    def send_char(self, focus, value):
        self.sent.append((focus, value))
        self.after_send()

    def close(self):
        self.closed = True


def typer(native):
    return WindowsTyper(lambda pid, window: WindowsSession(pid, window, lambda _: native))


def test_directed_unicode_including_surrogate_pairs():
    native = Native(123)
    typer(native).deliver(native.identity, ['A\u03bb\U0001f600'], lambda: True)
    assert native.sent == [(457, 65), (457, 0x03BB), (457, 0xD83D), (457, 0xDE00)]
    assert native.closed


def test_login_tabs_refused_before_any_secret_prefix():
    native = Native(123)
    with pytest.raises(DeliveryError) as error:
        typer(native).deliver(native.identity, ['synthetic-user', None, 'synthetic-password'], lambda: True)
    assert error.value.started is False and native.sent == [] and native.closed


@pytest.mark.parametrize('field,value', [('pid', 124), ('window', 500), ('focus', 501),
    ('thread', 20), ('process', ('user', 1, 'new-process')), ('window_class', 'new'), ('focus_class', 'new')])
def test_changed_pin_refused(field, value):
    native = Native(123)
    pin = native.identity
    native.identity = replace(pin, **{field: value})
    with pytest.raises(DeliveryError) as error:
        typer(native).deliver(pin, ['synthetic-password'], lambda: True)
    assert error.value.started is False and native.sent == [] and native.closed


def test_focus_change_after_first_character_stops_and_reports_uncertain():
    native = Native(123)
    def switch():
        native.identity = replace(native.identity, focus=999)
    native.after_send = switch
    with pytest.raises(DeliveryError) as error:
        typer(native).deliver(native.identity, ['synthetic-password'], lambda: True)
    assert error.value.started is True and native.sent == [(457, ord('s'))]


def test_disconnect_before_dispatch_sends_nothing():
    native = Native(123)
    with pytest.raises(DeliveryError) as error:
        typer(native).deliver(native.identity, ['synthetic-password'], lambda: False)
    assert not error.value.started and not native.sent and native.closed


def test_totp_guard_expiring_after_send_stops_dispatch():
    native = Native(123)
    with pytest.raises(DeliveryError) as error:
        typer(native).deliver(native.identity, ['123456'], lambda: True, guard=lambda: not native.sent)
    assert error.value.started and native.sent == [(457, ord('1'))]


@pytest.mark.parametrize('text', ['prefix\ud800', 'prefix\udfff'])
def test_lone_surrogate_refused_without_dispatch_or_disclosure(text):
    native = Native(123)
    with pytest.raises(DeliveryError) as error:
        typer(native).deliver(native.identity, [text], lambda: True)
    assert not error.value.started and not native.sent and native.closed
    assert 'prefix' not in str(error.value)


class UnreadPassword:
    uuid, title, username = 'synthetic-uuid', 'Synthetic', 'synthetic-user'
    url, path = 'https://example.test/login', ('Root', 'Synthetic')

    @property
    def password(self):
        raise AssertionError('password must not be read for a Windows HWND pin')


def windows_broker(native):
    from types import SimpleNamespace
    from akdbx.broker import Broker
    broker = Broker(SimpleNamespace(entries=[UnreadPassword()]), typer(native))
    pin = broker.dispatch({'action': 'pin-target', 'pid': 123, 'window': 456, 'target_protocol': 1})
    assert pin['ok']
    handle = broker.dispatch({'action': 'search'})['entries'][0]['handle']
    return broker, handle, dict(target=pin['target'], target_protocol=1)


@pytest.mark.parametrize('mode', ['password', 'login'])
def test_broker_refuses_windows_hwnd_password_fills_before_reading_them(mode):
    # A browser's address bar shares its page's HWND and focus identity, so
    # only verified Chromium DOM pins may receive passwords.
    from akdbx.target import failure
    native = Native(123)
    broker, handle, pin = windows_broker(native)
    result = broker.dispatch({'action': 'fill', 'handle': handle, 'mode': mode, **pin})
    assert result == failure(False) and native.sent == []


def test_broker_still_fills_windows_usernames():
    native = Native(123)
    broker, handle, pin = windows_broker(native)
    result = broker.dispatch({'action': 'fill', 'handle': handle, 'mode': 'username', **pin})
    assert result['ok'] and result['filled'] == 'username'
    assert ''.join(chr(code) for _focus, code in native.sent) == 'synthetic-user'


def test_windows_capabilities_advertise_window_operations(monkeypatch):
    import akdbx.target as target
    monkeypatch.setattr(target.os, 'name', 'nt')
    assert target.capabilities()['target_fill_modes'] == ['username', 'totp', 'sms-code']
