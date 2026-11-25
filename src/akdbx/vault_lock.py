"""Admission and idle deadline for one unlocked broker session."""
import threading
import time


def timeout_seconds(value):
    seconds = int(value)
    if not 1 <= seconds <= 2_147_483_647:
        raise ValueError('lock timeout must be 1 to 2147483647 seconds')
    return seconds


class VaultSession:
    def __init__(self, timeout, unlocked=False):
        self.timeout = timeout_seconds(timeout)
        self.condition = threading.Condition()
        self.active = 0
        self.active_work = 0
        self.closing = False
        self.stopped = False
        self.deadline = time.monotonic() + self.timeout if unlocked else None

    def opened(self):
        with self.condition:
            self.deadline = time.monotonic() + self.timeout
            self.condition.notify_all()

    def due(self):
        return self.deadline is not None and time.monotonic() >= self.deadline

    def run(self, operation, refused, *, activity=True):
        with self.condition:
            admitted = not self.closing and not self.due() and self.deadline is not None
            if admitted:
                self.active += 1
                if activity:
                    self.active_work += 1
        if not admitted:
            return refused()
        result = None
        try:
            result = operation()
            return result
        finally:
            with self.condition:
                self.active -= 1
                if activity:
                    self.active_work -= 1
                    if not self.closing and result and result.get('ok'):
                        self.deadline = time.monotonic() + self.timeout
                self.condition.notify_all()

    def monitor(self, lock):
        with self.condition:
            while not self.stopped:
                if self.due() and self.active_work:
                    self.condition.wait()
                    continue
                if self.due():
                    # Never acquire the unlock mutex while holding this condition.
                    break
                delay = None if self.deadline is None else max(0, self.deadline - time.monotonic())
                self.condition.wait(None if delay is None else min(delay, threading.TIMEOUT_MAX))
            else:
                return False
        lock(only_if_due=True)
        return True

    def stop(self):
        with self.condition:
            self.stopped = True
            self.condition.notify_all()
