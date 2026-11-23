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
