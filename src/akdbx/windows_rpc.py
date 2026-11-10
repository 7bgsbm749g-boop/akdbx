"""Local-only, same-user/session named pipes with bounded overlapped I/O."""
import ctypes
from ctypes import wintypes as W
from pathlib import Path
import re
import threading
import time

import pywintypes
import win32con
import win32event
import win32file
import win32pipe

from .windows_security import current_identity, private_attributes, verify_process

PREFIX = '\\\\.\\pipe\\'


def default_pipe():
    sid, session = current_identity()
    return Path(PREFIX + f'akdbx-{sid}-{session}')


def pipe_name(path):
    value = str(path)
    if not re.fullmatch(r'\\\\\.\\pipe\\akdbx-[A-Za-z0-9-]{1,160}', value):
        raise ValueError('Windows --socket must be a local \\\\.\\pipe\\akdbx-NAME pipe')
    return value


def verify_peer(handle, *, server):
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    function = getattr(api, 'GetNamedPipeServerProcessId' if server else 'GetNamedPipeClientProcessId')
    function.argtypes, function.restype = [W.HANDLE, ctypes.POINTER(W.ULONG)], W.BOOL
    pid = W.ULONG()
    if not function(int(handle), ctypes.byref(pid)):
        raise PermissionError('Windows pipe peer could not be verified')
    try:
        process, _ = verify_process(pid.value)
        return process
    except Exception:
        raise PermissionError('Windows pipe peer identity could not be verified') from None


def finish_io(handle, overlapped, timeout):
    milliseconds = max(1, int(timeout * 1000))
    if win32event.WaitForSingleObject(overlapped.hEvent, milliseconds) != win32event.WAIT_OBJECT_0:
        win32file.CancelIoEx(handle, overlapped)
        # Drain cancellation before freeing OVERLAPPED or its pinned buffer.
        try:
            win32file.GetOverlappedResult(handle, overlapped, True)
        except pywintypes.error:
            pass
        raise TimeoutError('Windows pipe operation timed out')
    return win32file.GetOverlappedResult(handle, overlapped, False)


class PipeConnection:
    def __init__(self, handle, peer=None):
        self.handle, self.peer = handle, peer
        self.timeout = 5.0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def settimeout(self, timeout):
        self.timeout = timeout

    def _io(self, value, *, writing):
        event = win32event.CreateEvent(None, True, False, None)
        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = event
        try:
            if writing:
                win32file.WriteFile(self.handle, value, overlapped)
            else:
                # Explicitly keep the read buffer alive until cancellation or
                # completion; never let an overlapped call outlive its memory.
                buffer = win32file.AllocateReadBuffer(value)
                win32file.ReadFile(self.handle, buffer, overlapped)
            count = finish_io(self.handle, overlapped, self.timeout)
            return count if writing else bytes(buffer[:count])
        except pywintypes.error as exc:
            if not writing and exc.winerror in {109, 232, 233}:
                return b''
            raise OSError('Windows pipe I/O failed') from None
        finally:
            event.Close()

    def recv(self, size):
        return self._io(size, writing=False)

    def sendall(self, data):
        deadline = time.monotonic() + self.timeout
        offset = 0
        timeout = self.timeout
        try:
            while offset < len(data):
                self.timeout = deadline - time.monotonic()
                if self.timeout <= 0:
                    raise TimeoutError('Windows pipe send timed out')
                count = self._io(data[offset:], writing=True)
                if not count:
                    raise OSError('Windows pipe write incomplete')
                offset += count
        finally:
            self.timeout = timeout

    def is_alive(self):
        try:
            _, available, _ = win32pipe.PeekNamedPipe(self.handle, 0)
            return available == 0
        except pywintypes.error:
            return False

    def close(self):
        if self.handle is not None:
            self.handle.Close()
            self.handle = None
        if self.peer is not None:
            self.peer.Close()
            self.peer = None


def connect(path):
    name = pipe_name(path)
    try:
        handle = win32file.CreateFile(name, win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0,
                                     None, win32con.OPEN_EXISTING,
                                     win32con.FILE_FLAG_OVERLAPPED | 0x00100000 | 0x00010000, None)
        # SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION prevents a pipe
        # squatter from impersonating the connecting user's primary token.
    except pywintypes.error:
        raise OSError('Windows broker pipe unavailable or busy') from None
    try:
        return PipeConnection(handle, verify_peer(handle, server=True))
    except BaseException:
        handle.Close()
        raise


def new_pipe(name, *, first=False):
    return win32pipe.CreateNamedPipe(
        name, win32pipe.PIPE_ACCESS_DUPLEX | win32con.FILE_FLAG_OVERLAPPED
        | (0x00080000 if first else 0),
        win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT | 0x8,
        18, 65540, 65540, 1000, private_attributes())


def serve(path, broker, stop=None):
    from .broker import _serve_connection, MAX_RPC_WORKERS, CONNECTION_TIMEOUT
    name = pipe_name(path)
    # Always retain an instance to pin the namespace. FIRST_PIPE_INSTANCE
    # refuses an already-running or pre-created endpoint at startup.
    pending = new_pipe(name, first=True)
    slots = threading.BoundedSemaphore(MAX_RPC_WORKERS)
    workers, lock = set(), threading.Lock()

    def run(connection):
        try:
            _serve_connection(connection, broker)
        finally:
            with lock:
                workers.discard(threading.current_thread())
            slots.release()

    try:
        while stop is None or not stop.is_set():
            event = win32event.CreateEvent(None, True, False, None)
            overlapped = pywintypes.OVERLAPPED()
            overlapped.hEvent = event
            connected = False
            try:
                try:
                    status = win32pipe.ConnectNamedPipe(pending, overlapped)
                    connected = status in {0, 535}
                except pywintypes.error as exc:
                    if exc.winerror != 535:  # ERROR_PIPE_CONNECTED: raced accept
                        raise
                    connected = True
                while not connected:
                    if stop is not None and stop.is_set():
                        break
                    if win32event.WaitForSingleObject(event, 200) == win32event.WAIT_OBJECT_0:
                        win32file.GetOverlappedResult(pending, overlapped, False)
                        connected = True
                if not connected:
                    break
                connection = PipeConnection(pending)
                # Create the next instance before releasing this one, so the
                # pipe's name cannot be taken between client connections.
                pending = new_pipe(name)
                try:
                    connection.peer = verify_peer(connection.handle, server=False)
                    if not slots.acquire(blocking=False):
                        connection.close()
                        continue
                    worker = threading.Thread(target=run, args=(connection,), daemon=True)
                    with lock:
                        workers.add(worker)
                    try:
                        worker.start()
                    except BaseException:
                        with lock:
                            workers.discard(worker)
                        slots.release()
                        raise
                except Exception:
                    connection.close()
            finally:
                if not connected:
                    win32file.CancelIoEx(pending, overlapped)
                    try:
                        win32file.GetOverlappedResult(pending, overlapped, True)
                    except pywintypes.error:
                        pass
                event.Close()
    finally:
        pending.Close()
        broker.unlock_notifications.close()
        with lock:
            active = list(workers)
        deadline = time.monotonic() + CONNECTION_TIMEOUT + 0.2
        for worker in active:
            worker.join(max(0, deadline - time.monotonic()))
