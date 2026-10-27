"""A single monotonic run budget, including an internal shutdown reserve."""
import threading
import time
from pathlib import Path


SHUTDOWN_RESERVE_SECONDS = 10.0


class DeadlineExpired(TimeoutError):
    pass


class Deadline:
    def __init__(self, seconds, clock=None, reserve=SHUTDOWN_RESERVE_SECONDS):
        self.clock = clock or time.monotonic
        self.started = self.clock()
        self.ends = self.started + seconds
        self.reserve = min(float(reserve), float(seconds))

    def remaining(self, cleanup=False):
        return self.ends - self.clock() - (0 if cleanup else self.reserve)

    def check(self, phase, cleanup=False):
        remaining = self.remaining(cleanup)
        if remaining <= 0:
            raise DeadlineExpired('Overall deadline exhausted before ' + phase)
        return remaining

    def timeout(self, cap, phase, cleanup=False):
        return min(float(cap), self.check(phase, cleanup))


def revoke(control):
    """Permanent local revocation; does not call Docker or wait on the gateway."""
    control = Path(control)
    control.mkdir(parents=True, exist_ok=True)
    (control / 'forwarding.closed').touch(exist_ok=True)


def watchdog(deadline, control):
    """Cut admission at the work cutoff even if the orchestration thread stalls."""
    stop = threading.Event()
    def watch():
        remaining = deadline.remaining()
        if remaining <= 0 or not stop.wait(remaining):
            revoke(control)
    thread = threading.Thread(target=watch, name='zap-forwarding-cutoff', daemon=True)
    thread.start()
    return stop
