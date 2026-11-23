"""Application-side detection: security events and alerts DV-A1 to DV-A4."""

import json

import pytest
from itsdangerous import URLSafeTimedSerializer

import app.auth
from app import security_events
from app.auth import SESSION_COOKIE

from conftest import TEST_PASSWORD
from test_security import upload


def events(capsys) -> list[dict]:
    """The JSON security events printed so far."""
    lines = capsys.readouterr().out.splitlines()
    return [json.loads(line) for line in lines if line.startswith("{")]


def alerts(found: list[dict], rule: str) -> list[dict]:
    return [e for e in found if e["event"] == "security_alert" and e["rule"] == rule]


def fail_login(client, username: str = "alice") -> None:
    response = client.post("/login", data={"username": username, "password": "wrong-password"})
    # 429 once the login throttle (O2 fix) has locked the username.
    assert response.status_code in (401, 429)


# DV-A1: brute force


def test_dv_a1_fires_at_five_failed_logins(client, users, capsys):
    for _ in range(4):
        fail_login(client)
    assert alerts(events(capsys), "DV-A1") == []

    fail_login(client)
    found = alerts(events(capsys), "DV-A1")

    by_username = [a for a in found if a["reason"] == "username"]
    assert len(by_username) == 1
    assert by_username[0]["username"] == "alice"
    assert by_username[0]["severity"] == "medium"
    assert by_username[0]["count"] == 5


def test_dv_a1_fires_once_per_window(client, users, capsys):
    for _ in range(8):
        fail_login(client)

    found = alerts(events(capsys), "DV-A1")
    assert len([a for a in found if a["reason"] == "username"]) == 1


def test_failed_login_never_logs_the_password(client, users, capsys):
    client.post("/login", data={"username": "alice", "password": "hunter2-secret"})

    output = capsys.readouterr().out
    assert "login_failed" in output
    assert "hunter2-secret" not in output


# DV-A2: forged session


def test_dv_a2_fires_on_cookie_signed_with_another_key(client, users, capsys):
    forged = URLSafeTimedSerializer("not-the-real-key-" * 3, salt="session").dumps(
        {"uid": users["admin"].id}
    )
    client.cookies.set(SESSION_COOKIE, forged)

    response = client.get("/admin/users")

    assert response.status_code == 303
    found = events(capsys)
    assert [e["reason"] for e in found if e["event"] == "invalid_session"] == ["bad_signature"]
    [alert] = alerts(found, "DV-A2")
    assert alert["severity"] == "high"
    assert alert["path"] == "/admin/users"


def test_expired_session_is_logged_but_not_an_alert(login, monkeypatch, capsys):
    alice = login("alice")
    capsys.readouterr()
    monkeypatch.setattr(app.auth, "SESSION_MAX_AGE_SECONDS", -1)

    response = alice.get("/documents")

    assert response.status_code == 303
    found = events(capsys)
    assert [e["reason"] for e in found if e["event"] == "invalid_session"] == ["expired"]
    assert alerts(found, "DV-A2") == []


# DV-A3: document access probing


def test_dv_a3_fires_at_three_refused_documents(login, capsys):
    alice, bob = login("alice"), login("bob")
    private = [upload(alice, f"private {i}") for i in range(2)]
    capsys.readouterr()

    bob.get(f"/documents/{private[0]}/download")
    bob.get(f"/documents/{private[1]}")
    assert alerts(events(capsys), "DV-A3") == []

    bob.get("/documents/999999/preview")
    found = events(capsys)

    denied = [e for e in found if e["event"] == "document_denied"]
    assert [e["status"] for e in denied] == [404]
    [alert] = alerts(found, "DV-A3")
    assert alert["username"] == "bob"
    assert alert["count"] == 3


def test_reading_own_and_shared_documents_is_not_probing(login, capsys):
    alice, bob = login("alice"), login("bob")
    document_id = upload(alice, "shared")
    alice.post(f"/documents/{document_id}/share", data={"username": "bob"})
    capsys.readouterr()

    for _ in range(5):
        assert bob.get(f"/documents/{document_id}/download").status_code == 200

    found = events(capsys)
    assert [e for e in found if e["event"] == "document_denied"] == []
    assert alerts(found, "DV-A3") == []


# DV-A4: privilege probing


def test_dv_a4_fires_when_a_member_opens_admin_pages(login, capsys):
    alice = login("alice")
    capsys.readouterr()

    assert alice.get("/admin/users").status_code == 403
    assert alice.get("/audit").status_code == 403

    found = events(capsys)
    assert [e["path"] for e in found if e["event"] == "role_denied"] == ["/admin/users", "/audit"]
    [alert] = alerts(found, "DV-A4")
    assert alert["username"] == "alice"
    assert alert["severity"] == "low"


# Normal use and log hygiene


def test_normal_use_raises_no_alert(login, capsys):
    alice, admin, auditor = login("alice"), login("admin"), login("auditor")
    document_id = upload(alice, "report")
    alice.get("/documents", params={"q": "report"})
    alice.get(f"/documents/{document_id}")
    alice.get(f"/documents/{document_id}/preview")
    admin.get("/admin/users")
    auditor.get("/audit")

    found = events(capsys)
    assert [e for e in found if e["event"] == "security_alert"] == []
    assert len([e for e in found if e["event"] == "login_succeeded"]) == 3


def test_only_allowed_fields_are_logged(capsys):
    security_events.emit(
        "login_failed",
        username="eve\n{\"event\": \"fake\"}" + "x" * 500,
        password=TEST_PASSWORD,
        cookie="secret-cookie",
    )

    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert set(record) == {"ts", "event", "username"}
    assert len(record["username"]) == security_events.MAX_TEXT_LENGTH
    assert TEST_PASSWORD not in lines[0]
