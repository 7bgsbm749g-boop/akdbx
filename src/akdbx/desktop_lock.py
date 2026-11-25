"""Event-driven lock notifications for desktop brokers."""
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
from contextlib import contextmanager


def _logind_lock(line):
    manager = '/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep '
    # Also lock on resume in case the process was frozen before reading the signal.
    if line.startswith(manager):
        return True
    session = re.match(r'^(/org/freedesktop/login1/session/[A-Za-z0-9_]+): (.*)', line)
    if not session:
        return False
    signal = session[2]
    if not (signal.startswith('org.freedesktop.login1.Session.Lock (')
            or signal.startswith('org.freedesktop.DBus.Properties.PropertiesChanged ')
            and "'org.freedesktop.login1.Session'" in signal and "'LockedHint': <true>" in signal):
        return False
    result = subprocess.run(['/usr/bin/gdbus', 'call', '--system', '--dest', 'org.freedesktop.login1',
                             '--object-path', session[1], '--method', 'org.freedesktop.DBus.Properties.Get',
                             'org.freedesktop.login1.Session', 'User'], capture_output=True, timeout=3,
                            env={**os.environ, 'LC_ALL': 'C'})
    # If the session vanished, err on the side of locking.
    owner = re.search(rb'uint32 (\d+)', result.stdout)
    return owner is None or int(owner[1]) == os.getuid()


def _logind(lock, stop, ready):
    with subprocess.Popen(['/usr/bin/gdbus', 'monitor', '--system', '--dest', 'org.freedesktop.login1'],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={**os.environ, 'LC_ALL': 'C'}) as proc:
        try:
            pending = b''
            while not stop.is_set():
                if not select.select([proc.stdout], [], [], 0.5)[0]:
                    continue
                chunk = os.read(proc.stdout.fileno(), 8192)
                if not chunk:
                    return
                lines = (pending + chunk).split(b'\n')
                pending = lines.pop()
                if len(pending) > 65536:
                    raise ValueError('oversize logind event')
                for line in lines:
                    msg = line.decode('utf-8', 'replace')
                    if ' is owned by ' in msg:
                        ready()
                    elif 'does not have an owner' in msg:
                        return
                    elif _logind_lock(msg):
                        lock()
        finally:
            proc.kill()


def _request(stream, obj, opcode, payload):
    stream.sendall(struct.pack('=II', obj, (8 + len(payload)) << 16 | opcode) + payload)


def _hyprland(lock, stop, ready):
    """Subscribe to hyprland-lock-notify-v1, including compositor-only locks."""
    display = os.environ['WAYLAND_DISPLAY']
    path = display if os.path.isabs(display) else os.path.join(os.environ['XDG_RUNTIME_DIR'], display)
    interface = b'hyprland_lock_notifier_v1\0'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.connect(path)
        _request(stream, 1, 1, struct.pack('=I', 2))  # wl_display.get_registry
        _request(stream, 1, 0, struct.pack('=I', 5))  # sync after initial globals
        data = bytearray()
        bound = False
        while not stop.is_set():
            if not select.select([stream], [], [], 0.5)[0]:
                continue
            part = stream.recv(8192)
            if not part:
                return
            data.extend(part)
            while len(data) >= 8:
                obj, word = struct.unpack_from('=II', data)
                size, opcode = word >> 16, word & 65535
                if size < 8 or size % 4:
                    raise ValueError('invalid Wayland message')
                if len(data) < size:
                    break
                payload = data[8:size]
                del data[:size]
                if obj == 2 and opcode == 0 and not bound:  # wl_registry.global
                    name, length = struct.unpack_from('=II', payload)
                    if payload[8:8 + length] == interface:
                        args = struct.pack('=II', name, length) + interface.ljust((length+3)//4*4, b'\0')
                        _request(stream, 2, 0, args + struct.pack('=II', 1, 3))  # bind v1
                        _request(stream, 3, 1, struct.pack('=I', 4))  # get_lock_notification
                        bound = True
                elif obj == 5 and not bound:
                    raise ValueError('compositor does not advertise lock notifications')
                elif obj == 5:
                    ready()
                elif obj == 4 and opcode == 0:  # locked (also sent for an initially locked screen)
                    lock()


def _windows(lock, stop, ready):
    import win32api
    import win32con
    import win32event
    import win32gui
    import win32ts

    def message(hwnd, msg, param, data):
        if msg == 0x02B1 and param == 7:  # WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK
            lock()
        elif msg == win32con.WM_POWERBROADCAST and param in (4, 7, 18):  # suspend / resume
            lock()
            return 1
        return win32gui.DefWindowProc(hwnd, msg, param, data)

    wc = win32gui.WNDCLASS()
    wc.hInstance = win32api.GetModuleHandle(None)
    wc.lpszClassName = 'akdbx-vault-lock-' + str(threading.get_ident())
    wc.lpfnWndProc = message
    atom = win32gui.RegisterClass(wc)
    try:
        # A hidden top-level window receives power broadcasts; a message-only window does not.
        hwnd = win32gui.CreateWindow(atom, '', 0, 0, 0, 0, 0, 0, 0, wc.hInstance, None)
        try:
            win32ts.WTSRegisterSessionNotification(hwnd, 0)  # this session only
            try:
                ready()
                while not stop.is_set():
                    win32event.MsgWaitForMultipleObjects((), False, 500, win32con.QS_ALLINPUT)
                    if win32gui.PumpWaitingMessages():
                        break
            finally:
                win32ts.WTSUnRegisterSessionNotification(hwnd)
        finally:
            win32gui.DestroyWindow(hwnd)
    finally:
        win32gui.UnregisterClass(atom, wc.hInstance)


@contextmanager
def watch_locks(broker):
    stop = threading.Event()

    def idle():
        while broker.session.monitor(broker.lock):
            pass

    def listen(source):
        name = source.__name__[1:]
        def ready():
            broker.lock_events[name] = 'listening'

        while not stop.is_set():
            try:
                source(broker.lock, stop, ready)
            except Exception:
                # OS errors include pywintypes.error on Windows. Do not log event payloads.
                pass
            if stop.is_set():
                return
            previous = broker.lock_events[name]
            broker.lock_events[name] = 'unavailable'
            if previous == 'listening':
                broker.lock()
            if previous != 'unavailable':
                print(f'akdbx: {name} lock notifications unavailable; retrying in 5 seconds',
                      file=sys.stderr, flush=True)
            stop.wait(5)

    sources = [_windows] if os.name == 'nt' else [_logind]
    if os.name != 'nt' and os.environ.get('WAYLAND_DISPLAY') and (
            os.environ.get('HYPRLAND_INSTANCE_SIGNATURE') or 'hyprland' in os.environ.get('XDG_CURRENT_DESKTOP', '').lower()):
        sources.append(_hyprland)
    broker.lock_events = {source.__name__[1:]: 'starting' for source in sources}
    threads = [threading.Thread(target=idle, daemon=True, name='akdbx-idle-lock')]
    threads.extend(threading.Thread(target=listen, args=(source,), daemon=True,
                                    name='akdbx-lock-' + source.__name__[1:]) for source in sources)
    for thread in threads:
        thread.start()
    try:
        yield
    finally:
        stop.set()
        broker.session.stop()
        for thread in threads:
            thread.join(4)
