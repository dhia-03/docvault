"""CSRF protection (fix for weakness O1): a signed double-submit token.

Every visitor gets a random `docvault_csrf` cookie. Every form carries a
hidden `csrf_token` field holding an HMAC of that cookie, made with the
session signing key. A POST is accepted only if the field matches the cookie.

Another site can make a victim's browser send the cookie, but cannot read it,
and cannot compute the matching field without the signing key, so a forged
form submission fails. This also covers the login form, before any session
exists. The cookie is HttpOnly and SameSite=Strict, which adds a second layer
in browsers that honour it.
"""

import hashlib
import hmac
import re
import secrets
from functools import cache

from fastapi import Form, HTTPException, Request

from app import security_events
from app.config import signing_key

CSRF_COOKIE = "docvault_csrf"
CSRF_FIELD = "csrf_token"
_COOKIE_FORMAT = re.compile(r"^[A-Za-z0-9_-]{43}$")


@cache
def _key() -> bytes:
    return signing_key().encode()


def new_cookie_value() -> str:
    return secrets.token_urlsafe(32)


def valid_cookie_value(value: str | None) -> bool:
    return bool(value and _COOKIE_FORMAT.fullmatch(value))


def token_for(cookie_value: str) -> str:
    """The form token that matches a cookie value."""
    return hmac.new(_key(), b"csrf:" + cookie_value.encode(), hashlib.sha256).hexdigest()


def form_token(request: Request) -> str:
    """The token to put in this response's forms (see the middleware in main.py)."""
    return token_for(request.state.csrf_cookie)


def require_csrf(request: Request, csrf_token: str = Form("")) -> None:
    """Dependency for every POST route: refuses a missing or wrong token."""
    cookie = request.cookies.get(CSRF_COOKIE)
    if not valid_cookie_value(cookie) or not hmac.compare_digest(
        csrf_token.encode(), token_for(cookie).encode()
    ):
        user = getattr(request.state, "user", None)
        security_events.csrf_rejected(
            user.username if user else None,
            request.client.host if request.client else None,
            request.url.path,
        )
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")
