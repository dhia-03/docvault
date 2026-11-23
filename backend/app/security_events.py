"""Security events and alerts: the application side of runtime detection.

Every security-relevant event is written as one JSON line on standard output,
through the "docvault.security" logger. A few rules turn repeated events into
alerts, written the same way with "event": "security_alert", so that
`kubectl logs` or `docker compose logs` shows them, and the incident response
plan (docs/incident-response-plan.md) can start from the rule ID.

Only fields on an allowed list are written, and strings are cut short, so no
password, cookie, token or document content can reach the logs (threat T13).

Counters live in memory, per process. That is enough for the single replica
DocVault runs today; several replicas would need shared counters or detection
on the collected logs instead.
"""

import json
import logging
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime

ALLOWED_FIELDS = (
    "rule",
    "name",
    "severity",
    "user",
    "username",
    "ip",
    "method",
    "path",
    "status",
    "document_id",
    "reason",
    "count",
    "window_seconds",
    "seconds",
)
MAX_TEXT_LENGTH = 100
MAX_TRACKED = 10_000


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    threshold: int
    window_seconds: int


BRUTE_FORCE = Rule("DV-A1", "brute_force_suspected", "medium", threshold=5, window_seconds=60)
FORGED_SESSION = Rule("DV-A2", "forged_session", "high", threshold=1, window_seconds=60)
ACCESS_PROBING = Rule("DV-A3", "access_probing", "medium", threshold=3, window_seconds=60)
PRIVILEGE_PROBE = Rule("DV-A4", "privilege_probe", "low", threshold=1, window_seconds=60)
RULES = (BRUTE_FORCE, FORGED_SESSION, ACCESS_PROBING, PRIVILEGE_PROBE)


class _StdoutHandler(logging.Handler):
    """Writes to whatever sys.stdout is at the time, so tests can capture it."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sys.stdout.write(self.format(record) + "\n")
            sys.stdout.flush()
        except Exception:  # noqa: BLE001 - logging must never break a request
            self.handleError(record)


_logger = logging.getLogger("docvault.security")
_logger.setLevel(logging.INFO)
_logger.propagate = False
if not _logger.handlers:
    _logger.addHandler(_StdoutHandler())

_lock = threading.Lock()
_events: dict[tuple[str, str], deque[float]] = {}
_last_alert: dict[tuple[str, str], float] = {}


def _clean(value: object) -> object:
    if isinstance(value, str):
        return value[:MAX_TEXT_LENGTH]
    return value


def emit(event: str, **fields: object) -> None:
    """Writes one event as a JSON line, keeping only allowed fields."""
    record = {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "event": event,
    }
    for key in ALLOWED_FIELDS:
        if fields.get(key) is not None:
            record[key] = _clean(fields[key])
    # json.dumps escapes newlines and quotes, so a crafted username cannot
    # forge a second log line.
    _logger.info(json.dumps(record, sort_keys=True))


def _observe(rule: Rule, key: str, now: float | None = None) -> int | None:
    """Counts an event for a rule and key; returns the count if it should alert.

    An alert fires when the count within the window reaches the threshold,
    and at most once per window for the same rule and key, so an attack
    produces one alert rather than one per request.
    """
    now = time.monotonic() if now is None else now
    slot = (rule.id, key)
    with _lock:
        _prune(now)
        times = _events.setdefault(slot, deque())
        times.append(now)
        while times and now - times[0] > rule.window_seconds:
            times.popleft()
        count = len(times)
        last = _last_alert.get(slot)
        if count >= rule.threshold and (last is None or now - last > rule.window_seconds):
            _last_alert[slot] = now
            return count
    return None


def _prune(now: float) -> None:
    """Drops stale counters, so a flood of made-up usernames cannot fill memory.

    Called with the lock held.
    """
    if len(_events) <= MAX_TRACKED:
        return
    longest = max(rule.window_seconds for rule in RULES)
    for slot in [s for s, times in _events.items() if not times or now - times[-1] > longest]:
        del _events[slot]
        _last_alert.pop(slot, None)


def _alert(rule: Rule, count: int, **fields: object) -> None:
    emit(
        "security_alert",
        rule=rule.id,
        name=rule.name,
        severity=rule.severity,
        count=count,
        window_seconds=rule.window_seconds,
        **fields,
    )


def login_failed(username: str, ip: str | None) -> None:
    emit("login_failed", username=username, ip=ip)
    for key in (f"username:{username[:MAX_TEXT_LENGTH]}", f"ip:{ip}"):
        count = _observe(BRUTE_FORCE, key)
        if count is not None:
            _alert(BRUTE_FORCE, count, username=username, ip=ip, reason=key.split(":", 1)[0])


def login_succeeded(username: str, ip: str | None) -> None:
    emit("login_succeeded", username=username, ip=ip)


def invalid_session(ip: str | None, path: str, expired: bool) -> None:
    """A session cookie failed its check. Only a bad signature is an alert."""
    emit("invalid_session", ip=ip, path=path, reason="expired" if expired else "bad_signature")
    if not expired:
        count = _observe(FORGED_SESSION, f"ip:{ip}")
        if count is not None:
            _alert(FORGED_SESSION, count, ip=ip, path=path)


def document_denied(
    username: str, ip: str | None, method: str, path: str, status: int, document_id: int
) -> None:
    emit(
        "document_denied",
        username=username,
        ip=ip,
        method=method,
        path=path,
        status=status,
        document_id=document_id,
    )
    count = _observe(ACCESS_PROBING, f"username:{username}")
    if count is not None:
        _alert(ACCESS_PROBING, count, username=username, ip=ip, path=path)


def role_denied(username: str, ip: str | None, method: str, path: str) -> None:
    emit("role_denied", username=username, ip=ip, method=method, path=path, status=403)
    count = _observe(PRIVILEGE_PROBE, f"username:{username}")
    if count is not None:
        _alert(PRIVILEGE_PROBE, count, username=username, ip=ip, path=path)


def login_throttled(username: str, ip: str | None, seconds: int) -> None:
    """A sign-in refused because the username is locked (O2 fix)."""
    emit("login_throttled", username=username, ip=ip, seconds=seconds)


def account_locked(username: str, ip: str | None, seconds: int) -> None:
    """Too many failed sign-ins: the username is now locked (O2 fix)."""
    emit("account_locked", username=username, ip=ip, seconds=seconds)


def csrf_rejected(username: str | None, ip: str | None, path: str) -> None:
    """A POST without a valid CSRF token (O1 fix): a forged form, or a stale page."""
    emit("csrf_rejected", username=username, ip=ip, path=path)


def reset() -> None:
    """Clears all counters. For tests."""
    with _lock:
        _events.clear()
        _last_alert.clear()
