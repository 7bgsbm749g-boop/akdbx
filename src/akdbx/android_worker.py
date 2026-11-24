"""Private systemd service process for one AVD. Exits when the last lease has been idle."""
import contextlib
import errno
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time


@contextlib.contextmanager
def child(argv, env):
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def ensure_free(port):
    with socket.socket() as probe:
        # A clean shutdown can leave loopback connections in TIME_WAIT.
        # An existing listener still prevents this probe from listening.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(('127.0.0.1', port))
        probe.listen(1)


def owns_listener(process, port):
    """Check the listening socket belongs to our child before contacting it."""
    if process.poll() is not None:
        return False
    inodes = set()
    for table in ('tcp', 'tcp6'):
        try:
            rows = Path(f'/proc/net/{table}').read_text().splitlines()
        except FileNotFoundError:
            # IPv4-only Linux kernels omit the tcp6 table.
            continue
        for line in rows[1:]:
            cols = line.split()
            if cols[3] == '0A' and int(cols[1].split(':')[1], 16) == port:
                inodes.add(f'socket:[{cols[9]}]')
    for fd in Path(f'/proc/{process.pid}/fd').iterdir():
        try:
            if os.readlink(fd) in inodes:
                return True
        except FileNotFoundError:
            continue
    return False


def serve(listener, idle, healthy):
    clients = set()
    with selectors.DefaultSelector() as events:
        events.register(listener, selectors.EVENT_READ)
        last = time.monotonic()
        try:
            while healthy():
                remaining = idle - (time.monotonic() - last)
                ready = events.select(2 if clients else max(0, min(2, remaining)))
                if not clients and remaining <= 0 and not ready:
                    return
                for key, _ in ready:
                    if key.fileobj is listener:
                        conn, _ = listener.accept()
                        try:
                            conn.sendall(b'1')
                        except OSError:
                            conn.close()
                            continue
                        clients.add(conn)
                        events.register(conn, selectors.EVENT_READ)
                    else:
                        # Clients only hold the socket. Data, EOF or errors release it.
                        conn = key.fileobj
                        events.unregister(conn)
                        clients.remove(conn)
                        conn.close()
                    last = time.monotonic()
            raise RuntimeError('Android emulator or adb exited')
        finally:
            for conn in clients:
                conn.close()


def reserve(stack, port):
    """Bind the legacy adb notification port on both loopback addresses without listening."""
    # No SO_REUSEADDR: with it, another account's socket could bind and listen beside ours.
    stack.enter_context(socket.socket()).bind(('127.0.0.1', port))
    try:
        ipv6 = stack.enter_context(socket.socket(socket.AF_INET6))
        ipv6.bind(('::1', port))
    except OSError as exc:
        # The emulator falls back to [::1] when 127.0.0.1 refuses it. Skip only
        # a host without IPv6 loopback, where that fallback cannot connect.
        if exc.errno not in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            raise


def private_adb(address, process):
    connection = socket.socket(socket.AF_UNIX)
    try:
        connection.settimeout(2)
        connection.connect(str(address))
        pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != process.pid or uid != os.getuid() or process.poll() is not None:
            raise RuntimeError('private adb server changed')
        return connection
    except BaseException:
        connection.close()
        raise


def run(directory, adb, port, serial, managed):
    emulator_port = int(serial.removeprefix('emulator-'))
    for p in (emulator_port, emulator_port + 1):
        ensure_free(p)
    # ADBHOST would make adb register a remote emulator under the local serial.
    env = {k: v for k, v in os.environ.items() if not k.startswith(('ANDROID_', 'ADB_')) and k != 'ADBHOST'}
    address = directory / 'adb'
    endpoint = 'localfilesystem:' + str(address)
    env.update(ANDROID_SDK_ROOT=managed['sdk'], ANDROID_AVD_HOME=managed['avd_home'],
               ADB_SERVER_SOCKET=endpoint, ADB_EMU='0', ADB_USB='0', ADB_MDNS='0',
               ADB_LOCAL_TRANSPORT_MAX_PORT='0')
    emulator = Path(managed['sdk']) / 'emulator' / 'emulator'
    with contextlib.ExitStack() as stack:
        # The emulator also announces itself to a legacy TCP port. Reserve
        # that port without listening so it cannot register with another server.
        reserve(stack, port)
        server = stack.enter_context(child([adb, '-L', endpoint, 'nodaemon', 'server'], env))
        deadline = time.monotonic() + 180
        while True:
            try:
                with private_adb(address, server):
                    break
            except (FileNotFoundError, ConnectionRefusedError):
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('private adb server did not start')
                time.sleep(.1)
        guest = stack.enter_context(child([emulator, '-avd', managed['avd'], '-port', str(emulator_port),
                                          '-no-window', '-no-audio', '-no-boot-anim', '-no-snapshot',
                                          '-gpu', 'swiftshader', '-accel', 'on', '-cores', '2',
                                          '-memory', '2048', '-feature', '-Vulkan', '-no-metrics'],
                                         {**env, 'ANDROID_ADB_SERVER_PORT': str(port)}))

        def alive():
            return guest.poll() is None and server.poll() is None

        def shell(*args):
            if not owns_listener(guest, emulator_port + 1):
                raise RuntimeError('private Android transport changed')
            with private_adb(address, server):
                pass
            return subprocess.run([adb, '-L', endpoint, '-s', serial, 'shell', *args], env=env,
                                  capture_output=True, timeout=8)

        def register():
            # Discovery is off, so only this request attaches the emulator. adb
            # ignores it while the emulator's transport already exists.
            with private_adb(address, server) as connection:
                message = f'host:emulator:{emulator_port + 1}'.encode('ascii')
                connection.sendall(b'%04x' % len(message) + message)
                # adb closes without a reply once it accepts the notification.
                connection.recv(1)

        next_registration = 0
        while alive() and time.monotonic() < deadline:
            if owns_listener(guest, emulator_port + 1):
                if time.monotonic() >= next_registration:
                    register()
                    next_registration = time.monotonic() + 3
                try:
                    boot = shell('getprop', 'sys.boot_completed')
                    if boot.returncode == 0:
                        if boot.stdout.strip() == b'1':
                            break
                        # The transport is online; no further registration is needed
                        # while the guest finishes booting.
                        next_registration = time.monotonic() + 3
                except subprocess.TimeoutExpired:
                    pass
            time.sleep(.5)
        else:
            raise RuntimeError('emulator failed to boot; check KVM, image, AVD and ports')
        shell('settings', 'put', 'secure', 'speak_password', '0').check_returncode()
        if shell('settings', 'get', 'secure', 'speak_password').stdout.strip() != b'0':
            raise RuntimeError('could not verify Android password privacy setting')
        def healthy():
            # A guest reboot or adbd restart drops the transport; attach it again.
            nonlocal next_registration
            if not alive():
                return False
            if time.monotonic() >= next_registration:
                if owns_listener(guest, emulator_port + 1):
                    try:
                        register()
                    except TimeoutError:
                        pass  # A slow adb reply is retried at the next interval.
                next_registration = time.monotonic() + 10
            return True

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            ready = directory / 'ready'
            listener.bind(str(ready))
            listener.listen()
            try:
                serve(listener, managed['idle_seconds'], healthy)
            finally:
                ready.unlink(missing_ok=True)


if __name__ == '__main__':
    def stop(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    directory, adb, port, serial, settings = sys.argv[1:]
    run(Path(directory), adb, int(port), serial, json.loads(settings))
