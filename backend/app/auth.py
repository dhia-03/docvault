"""Password hashing, sessions and role checks."""

from collections.abc import Callable

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy.orm import Session

from app.config import SECRET_KEY
from app.db import get_db
from app.models import User

SESSION_COOKIE = "docvault_session"
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60

hasher = PasswordHasher()
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="session")


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
    return serializer.dumps({"uid": user.id})


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise NotAuthenticated
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE_SECONDS)
    except BadSignature as exc:
        raise NotAuthenticated from exc
    user = db.get(User, data["uid"])
    if user is None:
        raise NotAuthenticated
    return user


def require_role(*roles: str) -> Callable[[User], User]:
    def check(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return check
