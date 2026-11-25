"""Login rate limit (fix for weakness O2 and threat T01).

After MAX_FAILURES failed sign-ins for one username within WINDOW_SECONDS, that
username is locked for LOCK_SECONDS: every attempt is refused with HTTP 429
without checking the password, so guessing stops being practical (5 guesses
every 5 minutes is about 1,400 a day, instead of thousands a minute).

The limit is per username, not per address. In the kind cluster every client
reaches the app from the same node address, so a per-address limit would lock
out everyone at once; blocking by address belongs to a proxy or firewall in
front of the app. Unknown usernames are counted the same way as real ones,
so the limit does not reveal which accounts exist.

Trade-off: anyone can lock a known username for five minutes by failing on
purpose. The lock is short and alert DV-A1 fires at the same time, so the
team sees it (playbook P3 in docs/incident-response-plan.md).

Counters are in memory, per process, like the security alerts.
"""

import threading
import time
from collections import deque

MAX_FAILURES = 5
WINDOW_SECONDS = 300
LOCK_SECONDS = 300
MAX_TRACKED = 10_000

_lock = threading.Lock()
_failures: dict[str, deque[float]] = {}
_locked_until: dict[str, float] = {}


def _key(username: str) -> str:
    return username.strip().lower()[:150]


def _prune(now: float) -> None:
    """Drops stale entries, so a flood of made-up usernames cannot fill memory."""
    if len(_failures) + len(_locked_until) <= MAX_TRACKED:
        return
    for key in [k for k, until in _locked_until.items() if until <= now]:
        del _locked_until[key]
    for key in [k for k, times in _failures.items() if not times or now - times[-1] > WINDOW_SECONDS]:
        del _failures[key]


def seconds_locked(username: str, now: float | None = None) -> int:
    """How long the username stays locked; 0 if it is not locked."""
    now = time.monotonic() if now is None else now
    with _lock:
        until = _locked_until.get(_key(username), 0.0)
    return max(0, int(until - now + 0.999))


def record_failure(username: str, now: float | None = None) -> bool:
    """Counts a failed sign-in. Returns True if this failure locks the username."""
    now = time.monotonic() if now is None else now
    key = _key(username)
    with _lock:
        _prune(now)
        times = _failures.setdefault(key, deque())
        times.append(now)
        while times and now - times[0] > WINDOW_SECONDS:
            times.popleft()
        if len(times) >= MAX_FAILURES:
            _locked_until[key] = now + LOCK_SECONDS
            times.clear()
            return True
    return False


def record_success(username: str) -> None:
    with _lock:
        _failures.pop(_key(username), None)


def unlock(username: str) -> None:
    """Lifts a lock early, for an administrator (playbook P3)."""
    with _lock:
        _locked_until.pop(_key(username), None)
        _failures.pop(_key(username), None)


def reset() -> None:
    """Clears everything. For tests."""
    with _lock:
        _failures.clear()
        _locked_until.clear()
