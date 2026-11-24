"""Per-request context: a request ID and the client's address.

A middleware in main.py sets both at the start of every request. The audit
log and the security events read them from here, so every record of one
request carries the same ID, which is also returned to the client in the
X-Request-ID header. Investigators can then join the database audit log, the
JSON security events and a user's report ("it failed with request ID ...").

Context variables are copied into the thread pool that runs FastAPI's sync
routes, so the values are visible there too.
"""

import uuid
from contextvars import ContextVar

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_client_ip: ContextVar[str | None] = ContextVar("client_ip", default=None)


def start(client_ip: str | None) -> str:
    """Starts a new request context and returns its ID."""
    request_id = uuid.uuid4().hex
    _request_id.set(request_id)
    _client_ip.set(client_ip)
    return request_id


def request_id() -> str | None:
    return _request_id.get()


def client_ip() -> str | None:
    return _client_ip.get()
