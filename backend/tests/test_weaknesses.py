"""Fixes for the unplanned weaknesses: O1 (CSRF), O2 (login rate limit), O3 (upload limits)."""

import json

from sqlalchemy.orm import Session

import app.main
from app import login_throttle
from app.csrf import CSRF_COOKIE, token_for
from app.models import Document, Share

from conftest import TEST_PASSWORD
from test_security import upload


# O1: CSRF tokens


def test_o1_every_form_carries_a_csrf_token(login):
    alice = login("alice")
    document_id = upload(alice, "report")

    pages = {
        "/login": alice.get("/login").text,
        "/documents": alice.get("/documents").text,
        f"/documents/{document_id}": alice.get(f"/documents/{document_id}").text,
    }

    expected = token_for(alice.csrf_cookie)
    for path, html in pages.items():
        post_forms = html.count('method="post"')
        assert post_forms > 0, path
        assert html.count(f'name="csrf_token" value="{expected}"') == post_forms, path


def test_o1_new_visitor_gets_a_strict_httponly_csrf_cookie(make_client):
    client = make_client()
    client.cookies.clear()

    response = client.get("/login")

    cookie = next(
        value for value in response.headers.get_list("set-cookie")
        if value.startswith(f"{CSRF_COOKIE}=")
    ).lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie


def test_o1_post_without_token_is_refused(login, db: Session, users):
    alice = login("alice")
    document_id = upload(alice, "private")

    response = alice.post(
        f"/documents/{document_id}/share", data={"username": "bob"}, csrf=False
    )

    assert response.status_code == 403
    assert db.query(Share).count() == 0


def test_o1_token_from_another_visitor_is_refused(login, make_client, db: Session):
    alice = login("alice")
    document_id = upload(alice, "private")
    attacker = make_client()

    # The attacker's page can only embed a token for the attacker's own cookie.
    response = alice.post(
        f"/documents/{document_id}/delete",
        data={"csrf_token": token_for(attacker.csrf_cookie)},
        csrf=False,
    )

    assert response.status_code == 403
    assert db.get(Document, document_id) is not None


def test_o1_login_and_logout_need_the_token(client, users, capsys):
    refused = client.post(
        "/login", data={"username": "alice", "password": TEST_PASSWORD}, csrf=False
    )
    assert refused.status_code == 403
    assert "csrf_rejected" in capsys.readouterr().out

    assert client.post("/login", data={"username": "alice", "password": TEST_PASSWORD}).status_code == 303
    assert client.post("/logout", csrf=False).status_code == 403
    assert client.post("/logout").status_code == 303


# O2: login rate limit


def test_o2_username_is_locked_after_five_failures(client, users, capsys):
    for _ in range(login_throttle.MAX_FAILURES):
        response = client.post("/login", data={"username": "alice", "password": "wrong"})
        assert response.status_code == 401

    # Even the right password is refused while the username is locked.
    locked = client.post("/login", data={"username": "alice", "password": TEST_PASSWORD})

    assert locked.status_code == 429
    assert "Too many failed sign-ins" in locked.text
    events = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")]
    assert [e["event"] for e in events if e["event"] in ("account_locked", "login_throttled")] == [
        "account_locked",
        "login_throttled",
    ]


def test_o2_lock_is_per_username(client, users):
    for _ in range(login_throttle.MAX_FAILURES):
        client.post("/login", data={"username": "alice", "password": "wrong"})

    assert client.post("/login", data={"username": "bob", "password": TEST_PASSWORD}).status_code == 303


def test_o2_unknown_usernames_are_throttled_the_same_way(client, users):
    for _ in range(login_throttle.MAX_FAILURES):
        assert client.post("/login", data={"username": "nobody", "password": "x"}).status_code == 401

    assert client.post("/login", data={"username": "nobody", "password": "x"}).status_code == 429


def test_o2_success_resets_the_failure_count(client, users):
    for _ in range(login_throttle.MAX_FAILURES - 1):
        client.post("/login", data={"username": "alice", "password": "wrong"})
    assert client.post("/login", data={"username": "alice", "password": TEST_PASSWORD}).status_code == 303

    for _ in range(login_throttle.MAX_FAILURES - 1):
        client.post("/login", data={"username": "alice", "password": "wrong"})
    assert client.post("/login", data={"username": "alice", "password": TEST_PASSWORD}).status_code == 303


def test_o2_lock_expires():
    for second in range(login_throttle.MAX_FAILURES):
        login_throttle.record_failure("alice", now=1000.0 + second)

    assert login_throttle.seconds_locked("alice", now=1005.0) > 0
    assert login_throttle.seconds_locked("alice", now=1004.0 + login_throttle.LOCK_SECONDS + 1) == 0


def test_o2_old_failures_fall_out_of_the_window():
    for minute in range(login_throttle.MAX_FAILURES):
        locked = login_throttle.record_failure(
            "alice", now=1000.0 + minute * (login_throttle.WINDOW_SECONDS / 2 + 1)
        )
        assert not locked


# O3: upload size limit and quota


def test_o3_file_over_the_limit_is_refused_and_not_kept(login, storage_dir, monkeypatch):
    monkeypatch.setattr(app.main, "MAX_UPLOAD_BYTES", 1000)
    alice = login("alice")

    response = alice.post(
        "/documents",
        data={"title": "too big"},
        files={"file": ("big.bin", b"x" * 2000, "application/octet-stream")},
    )

    assert response.status_code == 413
    assert "too large" in response.text
    assert list(storage_dir.iterdir()) == []


def test_o3_declared_oversized_body_is_refused_before_reading(login, monkeypatch):
    monkeypatch.setattr(app.main, "MAX_UPLOAD_BYTES", 1000)
    alice = login("alice")

    response = alice.post(
        "/documents",
        data={"title": "huge"},
        files={"file": ("huge.bin", b"x" * (app.main.UPLOAD_OVERHEAD_BYTES + 5000))},
    )

    assert response.status_code == 413
    assert response.text.startswith("File too large")


def test_o3_quota_per_user(login, storage_dir, db: Session, monkeypatch):
    monkeypatch.setattr(app.main, "MAX_UPLOAD_BYTES", 1000)
    monkeypatch.setattr(app.main, "UPLOAD_QUOTA_BYTES", 1500)
    alice, bob = login("alice"), login("bob")

    first = upload(alice, "first", b"a" * 1000)
    refused = alice.post(
        "/documents", data={"title": "second"}, files={"file": ("b.txt", b"b" * 1000)}
    )

    assert db.get(Document, first).size_bytes == 1000
    assert refused.status_code == 413
    assert "quota" in refused.text
    assert len(list(storage_dir.iterdir())) == 1
    # Another user's quota is separate.
    upload(bob, "bob's", b"c" * 1000)
