"""Application settings."""

import os

from sqlalchemy.engine import URL, make_url


def secret(name: str) -> str:
    """Returns a secret from the file named by NAME_FILE, or else from NAME.

    Files let Kubernetes mount secrets as read-only volumes instead of
    environment variables, which leak more easily (for example into crash
    reports or child processes).
    """
    path = os.environ.get(f"{name}_FILE")
    if path:
        with open(path, encoding="utf-8") as source:
            return source.read().strip()
    return os.environ[name]


def database_url() -> URL:
    """Builds the database URL, adding the password from a secret if given."""
    url = make_url(os.environ["DATABASE_URL"])
    if os.environ.get("DATABASE_PASSWORD_FILE") or os.environ.get("DATABASE_PASSWORD"):
        url = url.set(password=secret("DATABASE_PASSWORD"))
    return url


MIN_SIGNING_KEY_LENGTH = 32


def signing_key() -> str:
    """Returns the key that signs session cookies (F05 fix).

    It is supplied at runtime, never written in the code. A short key could be
    guessed, so start-up fails instead of running with one.
    """
    key = secret("SECRET_KEY")
    if len(key) < MIN_SIGNING_KEY_LENGTH:
        raise RuntimeError(
            f"SECRET_KEY must be at least {MIN_SIGNING_KEY_LENGTH} characters long."
        )
    return key


DATABASE_URL = database_url()
STORAGE_DIR = os.environ.get("STORAGE_DIR", "/data/documents")

# The session cookie is only sent over HTTPS unless this is "false". Local
# Compose, the kind test cluster and the tests use plain HTTP, so they turn it
# off explicitly; any deployment behind HTTPS keeps the default.
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() != "false"

# O3 fix: the largest file one upload may carry, and the total each user may
# store. Both can be changed per environment.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 10 * 1024 * 1024))
UPLOAD_QUOTA_BYTES = int(os.environ.get("UPLOAD_QUOTA_BYTES", 100 * 1024 * 1024))
