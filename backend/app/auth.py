"""Password hashing, sessions and role checks."""

from collections.abc import Callable
from functools import cache

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from app import security_events
from app.config import signing_key
from app.db import get_db
from app.models import User

SESSION_COOKIE = "docvault_session"
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60

hasher = PasswordHasher()


@cache
def session_serializer() -> URLSafeTimedSerializer:
    """Signs and checks session cookies.

    Built on first use, so the migration and seeding steps, which import this
    module for password hashing, never need the signing key.
    """
    return URLSafeTimedSerializer(signing_key(), salt="session")


class NotAuthenticated(Exception):
    """Raised when a page requires a signed-in user."""


def hash_password(password: str) -> str:
    return hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return hasher.verify(password_hash, password)
    except VerificationError:
        return False


def create_session(user: User) -> str:
    # "sv" ties the cookie to the user's current session version: raising the
    # version (revoke sessions, password change, disable) invalidates it.
    return session_serializer().dumps({"uid": user.id, "sv": user.session_version})


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise NotAuthenticated
    try:
        data = session_serializer().loads(token, max_age=SESSION_MAX_AGE_SECONDS)
    except BadSignature as exc:
        # An expired session is normal. Any other bad signature means the
        # cookie was not made with our key: forged, or signed with a leaked
        # old key (alert DV-A2).
        security_events.invalid_session(
            client_ip(request),
            request.url.path,
            "expired" if isinstance(exc, SignatureExpired) else "bad_signature",
        )
        raise NotAuthenticated from exc
    user = db.get(User, data.get("uid"))
    reason = None
    if user is None:
        reason = "unknown_user"
    elif user.disabled:
        reason = "disabled"
    elif data.get("sv", 0) != user.session_version:
        reason = "revoked"
    if reason:
        security_events.invalid_session(client_ip(request), request.url.path, reason)
        raise NotAuthenticated
    # Lets the error handler in main.py name the user behind a refused request.
    request.state.user = user
    return user


def client_ip(request: Request) -> str | None:
    """The address the request came from, as seen by the app."""
    return request.client.host if request.client else None


def require_role(*roles: str) -> Callable[[User], User]:
    def check(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return check
