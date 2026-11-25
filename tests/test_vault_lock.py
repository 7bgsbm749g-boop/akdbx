"""Vault lock through the broker, idle deadline and native event transports."""
import os
import socket
import struct
import threading

import pytest

from akdbx import desktop_lock
from akdbx.broker import Broker
from akdbx.vault_lock import timeout_seconds
from test_broker import Entry, RecordingTyper, Vault


def test_idle_lock_does_not_need_a_request(monkeypatch):
    broker = Broker(Vault([Entry()]), RecordingTyper(), lock_timeout=1)
    monkeypatch.setattr(desktop_lock, '_logind', lambda lock, stop, ready: stop.wait())
    monkeypatch.setattr(desktop_lock, '_windows', lambda lock, stop, ready: stop.wait())
    monkeypatch.delenv('WAYLAND_DISPLAY', raising=False)
    with desktop_lock.watch_locks(broker):
        start = broker.session.deadline
        assert broker.dispatch({'action': 'ping'})['lock_timeout_seconds'] == 1
        assert broker.session.deadline == start
        result = broker.dispatch({'action': 'search', 'query': 'Example'})
        assert result['entries'] and broker.session.deadline > start
        with broker.session.condition:
            assert broker.session.condition.wait_for(lambda: broker.session.deadline is None, 4)
        assert broker.vault is None
        assert broker.dispatch({'action': 'search', 'query': 'Example'})['error'] == 'vault locked'
        assert broker.dispatch({'action': 'lock'}) == {'ok': True, 'locked': True}


def test_lock_drains_work_and_refuses_new_operations():
    broker = Broker(Vault([Entry()]), RecordingTyper())
    entered, finish = threading.Event(), threading.Event()

    def pending():
        entered.set()
        assert finish.wait(5)
        return {'ok': True}

    worker = threading.Thread(target=lambda: broker.session.run(pending, pytest.fail))
    worker.start()
    assert entered.wait(5)
    locker = threading.Thread(target=broker.lock)
    locker.start()
    try:
        with broker.session.condition:
            assert broker.session.condition.wait_for(lambda: broker.session.closing, 2)
        assert broker.dispatch({'action': 'search', 'query': ''})['error'] == 'vault locked'
        assert locker.is_alive()
    finally:
        finish.set()
        worker.join(5)
        locker.join(5)
    assert broker.locked


@pytest.mark.parametrize('value', ['0', '-2', '1.5', 'inf', '9999999999999'])
def test_invalid_timeout(value):
    with pytest.raises(ValueError):
        timeout_seconds(value)


@pytest.mark.skipif(os.name == 'nt', reason='Linux desktop notifications')
def test_logind_recognizes_session_owner_and_sleep(monkeypatch):
    from types import SimpleNamespace
    lock = '/org/freedesktop/login1/session/_32: org.freedesktop.login1.Session.Lock ()'
    hint = ("/org/freedesktop/login1/session/_32: org.freedesktop.DBus.Properties.PropertiesChanged "
            "('org.freedesktop.login1.Session', {'LockedHint': <true>}, @as [])")
    result = SimpleNamespace(stdout=f'(<(uint32 {os.getuid()}, objectpath)>,)'.encode())
    monkeypatch.setattr(desktop_lock.subprocess, 'run', lambda *a, **k: result)
    assert desktop_lock._logind_lock(lock)
    assert desktop_lock._logind_lock(hint)
    result.stdout = f'(<(uint32 {os.getuid()+1}, objectpath)>,)'.encode()
    assert not desktop_lock._logind_lock(lock)
    assert not desktop_lock._logind_lock(hint.replace('<true>', '<false>'))
    assert desktop_lock._logind_lock('/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (true,)')


@pytest.mark.skipif(os.name == 'nt', reason='Wayland socket')
def test_hyprland_compositor_lock(tmp_path, monkeypatch):
    path = str(tmp_path / 'display')
    monkeypatch.setenv('WAYLAND_DISPLAY', path)
    ready, stop = threading.Event(), threading.Event()
    broker = Broker(Vault([Entry()]), RecordingTyper())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        server.listen()
        worker = threading.Thread(target=desktop_lock._hyprland, args=(broker.lock, stop, ready.set))
        worker.start()
        with server.accept()[0] as peer:
            try:
                iface = b'hyprland_lock_notifier_v1\0'
                arg = struct.pack('=II', 15, len(iface)) + iface.ljust((len(iface)+3)//4*4, b'\0') + struct.pack('=I', 1)
                desktop_lock._request(peer, 2, 0, arg)
                desktop_lock._request(peer, 5, 0, struct.pack('=I', 42))
                assert ready.wait(3)
                desktop_lock._request(peer, 4, 0, b'')
                with broker.session.condition:
                    assert broker.session.condition.wait_for(lambda: broker.session.deadline is None, 3)
                assert broker.locked
            finally:
                stop.set()
                worker.join(3)
        assert not worker.is_alive()


@pytest.mark.skipif(os.name != 'nt', reason='Windows desktop messages')
def test_windows_receives_session_and_power_messages():
    import win32gui
    ready, stop, locked = threading.Event(), threading.Event(), threading.Event()
    worker = threading.Thread(target=desktop_lock._windows, args=(locked.set, stop, ready.set))
    worker.start()
    try:
        assert ready.wait(8)
        hwnd = win32gui.FindWindow('akdbx-vault-lock-' + str(worker.ident), None)
        for msg, param in [(0x02B1, 7), (0x0218, 4)]:
            locked.clear()
            win32gui.PostMessage(hwnd, msg, param, 0)
            assert locked.wait(3)
    finally:
        stop.set()
        worker.join(4)
    assert not worker.is_alive()
