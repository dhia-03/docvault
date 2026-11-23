"""Shared fixtures for the DocVault test suite.

app.config reads its settings when it is imported, and app.main checks the
signing key when it is imported, so the environment is set here, before any
app module is imported.

Database: every test gets its own SQLite file in tmp_path. The app's get_db
dependency is overridden to open sessions on that file. app.db still builds
its own engine at import time, from DATABASE_URL below, but that engine points
at an empty in-memory database with no tables: if some code path ever used it
instead of get_db, the test would fail loudly ("no such table") rather than
silently share data between tests. Overriding the dependency is more reliable
than re-pointing DATABASE_URL per test, because the engine is created only
once, when app.db is first imported.

Storage: STORAGE_DIR is copied into app.main at import time, so each test
patches app.main.STORAGE_DIR (and app.config.STORAGE_DIR) to a fresh folder.
"""

import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

TEST_SECRET_KEY = "test-signing-key-for-pytest-only-0123456789abcdef"
TEST_PASSWORD = "correct-horse-battery-staple"

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["STORAGE_DIR"] = "/nonexistent/docvault-tests"  # Patched per test.
os.environ["SECRET_KEY"] = TEST_SECRET_KEY
os.environ.pop("SECRET_KEY_FILE", None)
os.environ.pop("DATABASE_PASSWORD", None)
os.environ.pop("DATABASE_PASSWORD_FILE", None)
# The test client talks plain http, so it would never send back a cookie
# marked Secure. The F03 fix reads this setting; older code ignores it.
os.environ["SESSION_COOKIE_SECURE"] = "false"

# Make "import app" work whether pytest runs from the repository root or
# from backend/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

import app.config  # noqa: E402
import app.main  # noqa: E402
from app.auth import SESSION_COOKIE, hash_password  # noqa: E402
from app.db import get_db  # noqa: E402
from app.models import Base, User  # noqa: E402

USERS = (
    ("admin", "admin"),
    ("alice", "member"),
    ("bob", "member"),
    ("auditor", "auditor"),
)


@pytest.fixture(scope="session")
def password_hash() -> str:
    """One Argon2 hash shared by all test users, since hashing is slow."""
    return hash_password(TEST_PASSWORD)


@pytest.fixture
def storage_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # Nested two levels deep, so that a "../../" traversal from the storage
    # folder still lands inside tmp_path, where the F04 test can look for it.
    path = tmp_path / "srv" / "data" / "documents"
    path.mkdir(parents=True)
    monkeypatch.setattr(app.main, "STORAGE_DIR", str(path))
    monkeypatch.setattr(app.config, "STORAGE_DIR", str(path))
    return path


@pytest.fixture
def session_factory(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'docvault.sqlite3'}",
        # Sync routes run in a thread pool, not in the test's thread.
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    yield factory
    engine.dispose()


@pytest.fixture
def db(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    """A session for the test itself, to seed data and check results."""
    with session_factory() as session:
        yield session


@pytest.fixture
def users(db: Session, password_hash: str) -> dict[str, User]:
    """The four demo accounts, all with TEST_PASSWORD."""
    created = {}
    for username, role in USERS:
        user = User(username=username, password_hash=password_hash, role=role)
        db.add(user)
        created[username] = user
    db.commit()
    return created


@pytest.fixture
def app_instance(
    session_factory: sessionmaker[Session], storage_dir: Path
) -> Iterator[object]:
    def test_db() -> Iterator[Session]:
        with session_factory() as session:
            yield session

    app.main.app.dependency_overrides[get_db] = test_db
    yield app.main.app
    app.main.app.dependency_overrides.clear()


@pytest.fixture
def make_client(app_instance) -> Iterator[Callable[[], TestClient]]:
    """Builds a new client with its own cookie jar."""
    clients: list[TestClient] = []

    def make() -> TestClient:
        client = TestClient(app_instance, follow_redirects=False)
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.close()


@pytest.fixture
def client(make_client) -> TestClient:
    """An anonymous client."""
    return make_client()


@pytest.fixture
def login(make_client, users) -> Callable[[str], TestClient]:
    """Returns a new client signed in as the given user.

    Each user gets a separate client, so session cookies never mix.
    """

    def sign_in(username: str) -> TestClient:
        client = make_client()
        response = client.post(
            "/login", data={"username": username, "password": TEST_PASSWORD}
        )
        assert response.status_code == 303, response.text
        assert SESSION_COOKIE in client.cookies
        return client

    return sign_in

