"""Synthetic-only destination switches; never connect to the managed desktop."""
from dataclasses import replace
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from akdbx import cli
from akdbx.broker import Broker
from akdbx.target import (DELIVERY, DeliveryError, Identity, TargetError,
                                 X11Session, X11Typer, capabilities, failure)
from test_broker import Entry, RecordingTyper, Vault, target_request


def selected(broker):
    return broker.dispatch({'action': 'search'})['entries'][0]['handle']


@pytest.mark.parametrize('changes', [{}, {'target_protocol': True}, {'target_protocol': 2},
                                    {'target': 'unknown', 'target_protocol': 1}])
def test_required_target_cannot_downgrade_and_consumes_credential_handle(changes):
    typer = RecordingTyper()
    broker = Broker(Vault([Entry()]), typer)
    handle = selected(broker)
    result = broker.dispatch(dict(action='fill', handle=handle, **changes))
    assert result == failure()
    assert not broker.dispatch(dict(action='fill', handle=handle, **target_request(broker)))['ok']
    assert typer.events == []


def test_unknown_fields_refused_and_both_pins_consumed():
    broker = Broker(Vault([Entry()]), RecordingTyper())
    pin, handle = target_request(broker), selected(broker)
    assert broker.dispatch(dict(action='fill', handle=handle, **pin, unrestricted=True)) == failure()
    assert broker.dispatch(dict(action='fill', handle=selected(broker), **pin)) == failure()
    assert broker.typer.events == []


def test_expired_pin_and_reused_pin_never_type():
    now = [0]
    broker = Broker(Vault([Entry()]), RecordingTyper(), clock=lambda: now[0])
    pin = target_request(broker)
    now[0] = 30
    assert broker.dispatch(dict(action='fill', handle=selected(broker), **pin)) == failure()
    pin = target_request(broker)
    assert broker.dispatch(dict(action='fill', handle=selected(broker), **pin))['ok']
    broker.typer.events.clear()
    assert broker.dispatch(dict(action='fill', handle=selected(broker), **pin)) == failure()
    assert broker.typer.events == []


@pytest.mark.parametrize('pid,window,protocol', [(True, 456, 1), (0, 456, 1), (123, 1, 1),
                                               (123, 2**32, 1), (123, 456, True)])
def test_pin_identity_must_be_explicit_and_valid(pid, window, protocol):
    broker = Broker(Vault([Entry()]), RecordingTyper())
    assert broker.dispatch(dict(action='pin-target', pid=pid, window=window, target_protocol=protocol)) == failure()


def test_locked_pin_and_fill_have_no_backend_access():
    broker = Broker(None, object())
    for request in [dict(action='pin-target', pid=123, window=456, target_protocol=1),
                    dict(action='fill', handle='unknown', target='unknown', target_protocol=1)]:
        assert broker.dispatch(request) == {'ok': False, 'error': 'vault locked'}


class Session:
    identity = Identity(123, 456, 457, 1, ('start', 1, 2), ('synthetic', 'Synthetic'), 'synthetic-host')
    def __init__(self, pid, window):
        self.sent, self.closed, self.checks = [], False, 0
        self.switch_at = None
        self.after_send = None

    def check(self):
        self.checks += 1
        if self.checks == self.switch_at:
            raise RuntimeError('synthetic secret MUST NOT escape')

    def prepare(self, steps):
        return [c for step in steps for c in ('\t' if step is None else step)]

    def send_pair(self, code):
        self.sent.append((self.identity.focus, code))
        if self.after_send:
            self.after_send(self)

    def close(self):
        self.closed = True


def session_typer(session):
    return X11Typer(lambda pid, window: session)


@pytest.mark.parametrize('change', ['pid', 'window', 'focus', 'root', 'process', 'wm_class', 'machine'])
def test_changed_pinned_identity_refused_before_keys(change):
    session = Session(123, 456)
    pin = session.identity
    session.identity = replace(pin, **{change: 'different'})
    with pytest.raises(DeliveryError) as error:
        session_typer(session).deliver(pin, ['synthetic'], lambda: True)
    assert not error.value.started
    assert session.sent == [] and session.closed


@pytest.mark.parametrize('switch_at,started,count', [(1, False, 0), (2, False, 0), (3, True, 1), (4, True, 1)])
def test_switches_before_and_through_delivery_stop_remaining_keys(switch_at, started, count):
    session = Session(123, 456)
    session.switch_at = switch_at
    with pytest.raises(DeliveryError) as error:
        session_typer(session).deliver(session.identity, ['abc', None, 'xyz'], lambda: True)
    assert error.value.started is started
    assert len(session.sent) == count and session.closed
    assert 'secret' not in str(error.value)


def test_no_keys_when_caller_disconnected_at_delivery_boundary():
    session = Session(123, 456)
    with pytest.raises(DeliveryError) as error:
        session_typer(session).deliver(session.identity, ['synthetic'], lambda: False)
    assert not error.value.started and not session.sent and session.closed


def test_mapping_failure_happens_before_first_key():
    session = Session(123, 456)
    def reject(steps):
        raise RuntimeError(str(steps))
    session.prepare = reject
    with pytest.raises(DeliveryError) as error:
        session_typer(session).deliver(session.identity, ['synthetic-only'], lambda: True)
    assert not error.value.started and not session.sent
    assert 'synthetic-only' not in str(error.value)


def test_budget_stops_long_fills(monkeypatch):
    session = Session(123, 456)
    now = [0]
    monkeypatch.setattr('akdbx.target.time.monotonic', lambda: now[0])
    session.after_send = lambda s: now.__setitem__(0, 4)
    with pytest.raises(DeliveryError) as error:
        session_typer(session).deliver(session.identity, ['abc'], lambda: True)
    assert error.value.started and len(session.sent) == 1


@pytest.mark.parametrize('command', [['pin-target', '--pid', '123', '--window', '0x123'],
                                    ['fill', 'synthetic-handle', '--target', 'synthetic-pin'],
                                    ['fill-generated', 'synthetic-handle', '--target', 'synthetic-pin', '--target-url', 'https://example.test']])
@pytest.mark.parametrize('bad', [{}, {'target_fill_required': False}, {'target_fill_protocol': True},
                                {'target_fill_protocol': 2}, {'target_fill_delivery': 'global'}])
def test_new_cli_never_sends_target_requests_to_old_or_inexact_broker(monkeypatch, capsys, command, bad):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        return dict(ok=True, **{**capabilities(), **bad}) if bad else dict(ok=True, version='0.8.1')
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(command) == 1
    assert calls == [{'action': 'ping'}]
    assert 'not sent' in capsys.readouterr().out


def test_compatible_cli_passes_target_protocol_and_rejects_missing_delivery_receipt(monkeypatch, capsys):
    calls = []
    def request(path, payload, **kwargs):
        calls.append(payload)
        return dict(ok=True, **capabilities()) if payload['action'] == 'ping' else dict(ok=True, filled='password')
    monkeypatch.setattr(cli, 'request', request)
    assert cli.main(['fill', 'synthetic-handle', '--mode', 'password', '--target', 'synthetic-pin']) == 2
    assert calls[1]['target'] == 'synthetic-pin' and calls[1]['target_protocol'] == 1
    assert 'unconfirmed' in capsys.readouterr().err


@pytest.fixture
def isolated_x11(tmp_path, monkeypatch):
    if not shutil.which('Xvfb'):
        pytest.skip('optional synthetic X11 regression requires Xvfb')
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(['Xvfb', '-displayfd', str(write_fd), '-screen', '0', '640x480x24', '-nolisten', 'tcp'],
                               pass_fds=(write_fd,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.close(write_fd)
    try:
        assert select.select([read_fd], [], [], 10)[0], 'isolated test X server startup timed out'
        number = os.read(read_fd, 32).decode().strip()
        assert number.isdecimal() and number != '99'
        monkeypatch.setenv('DISPLAY', ':' + number)
        from Xlib import X, Xatom, display
        d = display.Display()
        root = d.screen().root
        windows = []
        for index in range(2):
            w = root.create_window(10 + index * 150, 10, 100, 100, 0, d.screen().root_depth,
                                   event_mask=X.KeyPressMask | X.KeyReleaseMask)
            w.set_wm_class('synthetic', 'Synthetic')
            w.change_property(d.intern_atom('WM_CLIENT_MACHINE'), Xatom.STRING, 8, os.uname().nodename.encode())
            w.change_property(d.intern_atom('_NET_WM_PID'), Xatom.CARDINAL, 32, [os.getpid()])
            w.map()
            windows.append(w)
        def activate(w):
            root.change_property(d.intern_atom('_NET_ACTIVE_WINDOW'), Xatom.WINDOW, 32, [w.id])
            w.set_input_focus(X.RevertToParent, X.CurrentTime)
            d.sync()
        activate(windows[0])
        yield SimpleNamespace(display=d, windows=windows, activate=activate, X=X)
        d.close()
    finally:
        os.close(read_fd)
        process.terminate()
        process.wait(timeout=5)


def key_events(lab):
    lab.display.sync()
    events = []
    while lab.display.pending_events():
        e = lab.display.next_event()
        if e.type in {lab.X.KeyPress, lab.X.KeyRelease}:
            events.append((e.window.id, e.type, e.detail, e.state))
    return events


def test_native_directed_text_symbols_and_tab_only_reach_pinned_owner(isolated_x11):
    lab = isolated_x11
    typer = X11Typer()
    pin = typer.capture(os.getpid(), lab.windows[0].id)
    typer.deliver(pin, ['aA! $', None, "'`\\"], lambda: True)
    events = key_events(lab)
    assert len(events) == 2 * 9
    assert {e[0] for e in events} == {lab.windows[0].id}
    # Decode real X event keycode/state pairs without a real credential.
    decoded = [lab.display.keycode_to_keysym(code, 1 if state & lab.X.ShiftMask else 0)
               for _, kind, code, state in events if kind == lab.X.KeyPress]
    assert decoded == [ord(c) for c in 'aA! $'] + [0xff09] + [ord(c) for c in "'`\\"]


def test_native_check_send_race_cannot_redirect_keys_to_new_foreground(isolated_x11):
    lab = isolated_x11
    pin = X11Typer().capture(os.getpid(), lab.windows[0].id)
    class SwitchAfterCheck(X11Session):
        def send_pair(self, code):
            lab.activate(lab.windows[1])  # the exact check-then-send race
            super().send_pair(code)
    with pytest.raises(DeliveryError) as error:
        X11Typer(SwitchAfterCheck).deliver(pin, ['synthetic-only'], lambda: True)
    assert error.value.started
    events = key_events(lab)
    assert len(events) == 2 and {e[0] for e in events} == {lab.windows[0].id}


def test_native_transient_focus_loss_is_not_hidden_by_restoration(isolated_x11):
    lab = isolated_x11
    session = X11Session(os.getpid(), lab.windows[0].id)
    try:
        lab.activate(lab.windows[1])
        lab.activate(lab.windows[0])
        with pytest.raises(TargetError):
            session.check()
        assert key_events(lab) == []
    finally:
        session.close()


def test_native_wrong_foreground_refused_without_events(isolated_x11):
    lab = isolated_x11
    pin = X11Typer().capture(os.getpid(), lab.windows[0].id)
    lab.activate(lab.windows[1])
    with pytest.raises(DeliveryError) as error:
        X11Typer().deliver(pin, ['synthetic-only'], lambda: True)
    assert not error.value.started and key_events(lab) == []
