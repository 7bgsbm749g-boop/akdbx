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
