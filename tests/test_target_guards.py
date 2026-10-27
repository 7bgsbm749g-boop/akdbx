"""Additional native ownership and mapping refusals on the synthetic display."""
import os

import pytest

from agentic_kdbx.target import DeliveryError, TargetError, X11Session, X11Typer
from test_target import isolated_x11


def test_native_pid_hint_cannot_override_server_resource_owner(isolated_x11):
    lab = isolated_x11
    from Xlib import Xatom
    lab.windows[0].change_property(lab.display.intern_atom('_NET_WM_PID'), Xatom.CARDINAL, 32, [os.getppid()])
    lab.display.sync()
    with pytest.raises(TargetError):
        X11Typer().capture(os.getppid(), lab.windows[0].id)


def test_native_unmapped_character_preflight_sends_no_prefix(isolated_x11):
    lab = isolated_x11
    pin = X11Typer().capture(os.getpid(), lab.windows[0].id)
    with pytest.raises(DeliveryError) as error:
        X11Typer().deliver(pin, ['safe-prefix\U0001f600'], lambda: True)
    assert not error.value.started
    from test_target import key_events
    assert key_events(lab) == []


def test_native_same_app_focus_window_change_refused(isolated_x11):
    lab = isolated_x11
    pin = X11Typer().capture(os.getpid(), lab.windows[0].id)
    top = lab.windows[0]
    child = top.create_window(0, 0, 20, 20, 0, lab.display.screen().root_depth)
    child.map()
    child.set_input_focus(lab.X.RevertToParent, lab.X.CurrentTime)
    lab.display.sync()
    with pytest.raises(DeliveryError) as error:
        X11Typer().deliver(pin, ['synthetic'], lambda: True)
    assert not error.value.started


def test_native_final_pair_focus_loss_is_uncertain(isolated_x11):
    lab = isolated_x11
    pin = X11Typer().capture(os.getpid(), lab.windows[0].id)
    class LoseFocusAfterSend(X11Session):
        def send_pair(self, code):
            super().send_pair(code)
            lab.activate(lab.windows[1])
    with pytest.raises(DeliveryError) as error:
        X11Typer(LoseFocusAfterSend).deliver(pin, ['x'], lambda: True)
    assert error.value.started


def test_start_deadline_rechecked_after_last_target_preflight():
    from test_target import Session, session_typer
    session = Session(123, 456)
    permitted = [True]
    original = session.check
    def slow_last_check():
        original()
        if session.checks == 2:
            permitted[0] = False
    session.check = slow_last_check
    with pytest.raises(DeliveryError) as error:
        session_typer(session).deliver(session.identity, ['synthetic'], lambda: permitted[0])
    assert not error.value.started and not session.sent
