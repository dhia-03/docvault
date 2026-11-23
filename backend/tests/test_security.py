"""Regression tests for the planted flaws in docs/vulnerability-register.md.

Each test asserts the secure behaviour, so it fails while its flaw is open.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import Session

import app.config
import app.main
from app.auth import SESSION_COOKIE
from app.models import Document

from conftest import TEST_PASSWORD, TEST_SECRET_KEY

BACKEND_DIR = Path(__file__).resolve().parents[1]
XSS = "<script>alert(1)</script>"
XSS_ESCAPED = "&lt;script&gt;"


def upload(
    client: TestClient,
    title: str,
    content: bytes = b"hello",
    filename: str = "note.txt",
) -> int:
    """Uploads a document and returns its ID."""
    response = client.post(
        "/documents",
        data={"title": title},
        files={"file": (filename, content, "text/plain")},
    )
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith("/documents/")
    return int(location.rsplit("/", 1)[1])


def share(client: TestClient, document_id: int, username: str) -> None:
    response = client.post(
        f"/documents/{document_id}/share", data={"username": username}
    )
    assert response.status_code == 303, response.text


def fetch(db: Session, document_id: int) -> Document:
    """Reads the document again, as the app has changed it in another session."""
    db.expire_all()
    document = db.get(Document, document_id)
    assert document is not None
    return document


# F01: access to any document by ID


def test_f01_other_user_cannot_download_unshared_document(login):
    alice, bob = login("alice"), login("bob")
    document_id = upload(alice, "Alice payroll", b"alice secret contents")

    response = bob.get(f"/documents/{document_id}/download")

    assert response.status_code == 403
    assert b"alice secret contents" not in response.content


def test_f01_owner_can_download_own_document(login):
    alice = login("alice")
    document_id = upload(alice, "Alice payroll", b"alice secret contents")

    response = alice.get(f"/documents/{document_id}/download")

    assert response.status_code == 200
    assert response.content == b"alice secret contents"


def test_f01_other_user_cannot_view_or_preview_unshared_document(login):
    alice, bob = login("alice"), login("bob")
    document_id = upload(alice, "Alice payroll", b"alice secret contents")

    for path in (f"/documents/{document_id}", f"/documents/{document_id}/preview"):
        response = bob.get(path)
        assert response.status_code == 403, path
        assert "alice secret contents" not in response.text, path
        assert "Alice payroll" not in response.text, path


def test_f01_shared_document_is_readable_by_recipient(login):
    alice, bob = login("alice"), login("bob")
    document_id = upload(alice, "Alice payroll", b"alice secret contents")

    share(alice, document_id, "bob")

    download = bob.get(f"/documents/{document_id}/download")
    assert download.status_code == 200
    assert download.content == b"alice secret contents"
    assert bob.get(f"/documents/{document_id}").status_code == 200
    preview = bob.get(f"/documents/{document_id}/preview")
    assert preview.status_code == 200
    assert preview.text == "alice secret contents"


# F02: SQL injection in search


@pytest.fixture
def search_data(login):
    """Alice owns some documents, Bob shares one with her and keeps one private."""
    alice, bob = login("alice"), login("bob")
    for title in ("Alice report", "100% done", "1000 items", "Plan_A", "PlanXA"):
        upload(alice, title)
    shared_id = upload(bob, "Bob shared plan")
    share(bob, shared_id, "alice")
    upload(bob, "Bob private salary")
    return alice


def titles_in(response) -> set[str]:
    candidates = (
        "Alice report",
        "100% done",
        "1000 items",
        "Plan_A",
        "PlanXA",
        "Bob shared plan",
        "Bob private salary",
    )
    return {title for title in candidates if title in response.text}


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "%' UNION SELECT id, id, username, password_hash, password_hash, role,"
        " CURRENT_TIMESTAMP FROM users --",
        "x' UNION SELECT id, owner_id, title, filename, stored_path, tags,"
        " created_at FROM documents --",
    ],
)
def test_f02_injection_payloads_do_not_leak_data(search_data, payload):
    response = search_data.get("/documents", params={"q": payload})

    assert response.status_code == 200
    assert "$argon2" not in response.text
    assert "Bob private salary" not in response.text
    assert titles_in(response) == set()


def test_f02_like_wildcards_match_literally(search_data):
    assert titles_in(search_data.get("/documents", params={"q": "%"})) == {"100% done"}
    assert titles_in(search_data.get("/documents", params={"q": "100%"})) == {
        "100% done"
    }
    assert titles_in(search_data.get("/documents", params={"q": "_"})) == {"Plan_A"}
    assert titles_in(search_data.get("/documents", params={"q": "Plan_A"})) == {
        "Plan_A"
    }


def test_f02_search_returns_own_and_shared_documents_only(search_data):
    everything = search_data.get("/documents")
    assert everything.status_code == 200
    assert titles_in(everything) == {
        "Alice report",
        "100% done",
        "1000 items",
        "Plan_A",
        "PlanXA",
        "Bob shared plan",
    }

    bob_titles = search_data.get("/documents", params={"q": "bob"})
    assert titles_in(bob_titles) == {"Bob shared plan"}


# F03: script injection (XSS) and cookie and header hardening


def test_f03_stored_title_is_escaped(login):
    alice = login("alice")
    document_id = upload(alice, XSS)

    for path in ("/documents", f"/documents/{document_id}"):
        response = alice.get(path)
        assert response.status_code == 200, path
        assert XSS not in response.text, path
        assert XSS_ESCAPED in response.text, path


def test_f03_search_term_is_escaped(login):
    alice = login("alice")

    response = alice.get("/documents", params={"q": XSS})

    assert response.status_code == 200
    assert XSS not in response.text
    assert XSS_ESCAPED in response.text


def test_f03_session_cookie_is_httponly(client, users):
    response = client.post(
        "/login", data={"username": "alice", "password": TEST_PASSWORD}
    )

    assert response.status_code == 303
    cookies = [
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith(f"{SESSION_COOKIE}=")
    ]
    assert len(cookies) == 1
    assert "httponly" in cookies[0].lower()


def test_f03_session_cookie_is_secure_when_enabled(client, users, monkeypatch):
    # The suite turns Secure off (plain-http test client); turn it back on.
    monkeypatch.setattr(app.main, "SESSION_COOKIE_SECURE", True)
    response = client.post(
        "/login", data={"username": "alice", "password": TEST_PASSWORD}
    )

    assert response.status_code == 303
    cookie = next(
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith(f"{SESSION_COOKIE}=")
    )
    assert "; secure" in cookie.lower()


def test_f03_secure_cookie_is_the_default():
    # A fresh interpreter, because app.config is already imported here with
    # SESSION_COOKIE_SECURE=false.
    env = {k: v for k, v in os.environ.items() if k != "SESSION_COOKIE_SECURE"}
    result = subprocess.run(
        [sys.executable, "-c", "import app.config as c; print(c.SESSION_COOKIE_SECURE)"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


@pytest.mark.parametrize("path", ["/login", "/documents", "/healthz"])
def test_f03_security_headers(login, path):
    alice = login("alice")

    response = alice.get(path)

    assert response.status_code == 200
    policy = response.headers.get("content-security-policy", "")
    assert "default-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers.get("x-content-type-options") == "nosniff"


# F04: path traversal


def test_f04_upload_name_cannot_choose_storage_path(
    login, db, storage_dir, tmp_path
):
    alice = login("alice")

    document_id = upload(
        alice, "Traversal", b"traversal contents", filename="../../escaped.txt"
    )

    escaped = [
        path for path in tmp_path.rglob("*escaped*") if storage_dir not in path.parents
    ]
    assert escaped == []
    stored = list(storage_dir.iterdir())
    assert len(stored) == 1
    assert stored[0].read_bytes() == b"traversal contents"
    # The name on disk is chosen by the server, not taken from the client.
    assert "escaped" not in stored[0].name

    document = fetch(db, document_id)
    assert document.filename == "escaped.txt"
    assert Path(document.stored_path).resolve() == stored[0].resolve()
    detail = alice.get(f"/documents/{document_id}")
    assert "<dd>escaped.txt</dd>" in detail.text
    assert "../" not in detail.text


def test_f04_preview_by_path_is_gone(login):
    alice = login("alice")

    response = alice.get("/preview", params={"file": "../../etc/passwd"})

    assert response.status_code == 404
    assert "root:" not in response.text


def test_f04_preview_by_id_works_for_owner(login):
    alice = login("alice")
    document_id = upload(alice, "Notes", b"line one\nline two\n")

    response = alice.get(f"/documents/{document_id}/preview")

    assert response.status_code == 200
    assert response.text == "line one\nline two\n"


def test_f04_delete_removes_the_stored_file(login, storage_dir):
    alice = login("alice")
    document_id = upload(alice, "To delete", b"bye")
    assert len(list(storage_dir.iterdir())) == 1

    response = alice.post(f"/documents/{document_id}/delete")

    assert response.status_code == 303
    assert list(storage_dir.iterdir()) == []
    assert alice.get(f"/documents/{document_id}").status_code == 404


# F05: hard-coded signing key


def forge_session(key: str, user_id: int) -> str:
    return URLSafeTimedSerializer(key, salt="session").dumps({"uid": user_id})


def test_f05_cookie_signed_with_other_key_is_refused(client, users):
    other_key = "an-attacker-chosen-key-that-is-long-enough-123456"
    client.cookies.set(SESSION_COOKIE, forge_session(other_key, users["admin"].id))

    response = client.get("/admin/users")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_f05_cookie_signed_with_configured_key_is_accepted(client, users):
    # Control for the test above: the same cookie, signed with the real key,
    # does open the page, so the refusal really comes from the signature.
    client.cookies.set(SESSION_COOKIE, forge_session(TEST_SECRET_KEY, users["admin"].id))

    assert client.get("/admin/users").status_code == 200


def test_f05_short_signing_key_is_refused(monkeypatch, tmp_path):
    monkeypatch.delenv("SECRET_KEY_FILE", raising=False)

    monkeypatch.setenv("SECRET_KEY", "x" * 31)
    with pytest.raises(RuntimeError):
        app.config.signing_key()

    key_file = tmp_path / "secret_key"
    key_file.write_text("short\n", encoding="utf-8")
    monkeypatch.setenv("SECRET_KEY_FILE", str(key_file))
    with pytest.raises(RuntimeError):
        app.config.signing_key()

    monkeypatch.delenv("SECRET_KEY_FILE")
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    assert app.config.signing_key() == "x" * 32


def test_f05_missing_signing_key_is_refused(monkeypatch):
    monkeypatch.delenv("SECRET_KEY_FILE", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)

    with pytest.raises((KeyError, RuntimeError)):
        app.config.signing_key()


def test_f05_app_does_not_start_with_short_key():
    # A fresh interpreter, because app.main is already imported here.
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("SECRET_KEY", "SECRET_KEY_FILE")
    }
    env["SECRET_KEY"] = "too-short"
    result = subprocess.run(
        [sys.executable, "-c", "import app.main"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode != 0
    assert "SECRET_KEY must be at least" in result.stderr


# F06: unsafe YAML parsing


@pytest.mark.parametrize(
    "payload",
    [
        "tags: !!python/object/apply:os.getuid []",
        # CVE-2020-1747: this form got past FullLoader in PyYAML 5.3, which
        # already refused the one above. It is the payload in run_all.py.
        "tags: !!python/object/new:tuple [!!python/object/new:map"
        " [!!python/name:eval , [\"__import__('os').getuid()\"]]]",
    ],
    ids=["apply", "cve-2020-1747"],
)
def test_f06_yaml_object_tags_are_refused(login, db, payload):
    alice = login("alice")
    document_id = upload(alice, "Quarterly")
    response = alice.post(
        f"/documents/{document_id}/metadata", data={"metadata": "tags: [keep]"}
    )
    assert response.status_code == 303

    response = alice.post(
        f"/documents/{document_id}/metadata", data={"metadata": payload}
    )

    assert response.status_code == 400
    assert fetch(db, document_id).tags == "keep"


def test_f06_plain_yaml_tags_are_stored(login, db):
    alice = login("alice")
    document_id = upload(alice, "Quarterly")

    response = alice.post(
        f"/documents/{document_id}/metadata", data={"metadata": "tags: [finance, q3]"}
    )

    assert response.status_code == 303
    assert fetch(db, document_id).tags == "finance, q3"
    assert '<dd id="tags">finance, q3</dd>' in alice.get(f"/documents/{document_id}").text


# Roles


@pytest.mark.parametrize(
    ("username", "path", "expected"),
    [
        ("alice", "/admin/users", 403),
        ("alice", "/audit", 403),
        ("auditor", "/admin/users", 403),
        ("auditor", "/audit", 200),
        ("admin", "/admin/users", 200),
        ("admin", "/audit", 200),
    ],
)
def test_roles_restrict_admin_and_audit_pages(login, username, path, expected):
    response = login(username).get(path)

    assert response.status_code == expected


def test_anonymous_user_is_sent_to_login(client):
    for path in ("/documents", "/admin/users", "/audit"):
        response = client.get(path)
        assert response.status_code == 303, path
        assert response.headers["location"] == "/login", path
