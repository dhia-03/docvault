"""Account controls and the richer audit log (gaps found by the incident response plan)."""

import csv
import io
import json
import re

from sqlalchemy.orm import Session

from app import login_throttle
from app.models import AuditLog, User

from conftest import TEST_PASSWORD
from test_security import upload

NEW_PASSWORD = "a-brand-new-password-42"


def signed_in(client) -> bool:
    return client.get("/documents").status_code == 200


def events(capsys) -> list[dict]:
    return [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")]


# Per-user session revocation


def test_revoke_signs_out_only_that_user(login, users, capsys):
    alice, bob, admin = login("alice"), login("bob"), login("admin")
    capsys.readouterr()

    assert admin.post(f"/admin/users/{users['alice'].id}/revoke-sessions").status_code == 303

    assert not signed_in(alice)
    assert signed_in(bob)
    assert [e["reason"] for e in events(capsys) if e["event"] == "invalid_session"] == ["revoked"]
    # Alice can simply sign in again.
    assert signed_in(login("alice"))


def test_members_cannot_use_account_actions(login, users):
    bob = login("bob")
    target = users["alice"].id
    for action in ("revoke-sessions", "disable", "enable"):
        assert bob.post(f"/admin/users/{target}/{action}").status_code == 403
    assert bob.post(f"/admin/users/{target}/password", data={"new_password": NEW_PASSWORD}).status_code == 403


# Password reset by an administrator


def test_admin_reset_password(login, make_client, users):
    alice, admin = login("alice"), login("admin")

    response = admin.post(
        f"/admin/users/{users['alice'].id}/password", data={"new_password": NEW_PASSWORD}
    )

    assert response.status_code == 303
    assert not signed_in(alice)
    fresh = make_client()
    assert fresh.post("/login", data={"username": "alice", "password": TEST_PASSWORD}).status_code == 401
    assert fresh.post("/login", data={"username": "alice", "password": NEW_PASSWORD}).status_code == 303


def test_admin_reset_rejects_a_short_password(login, users):
    admin = login("admin")
    response = admin.post(f"/admin/users/{users['alice'].id}/password", data={"new_password": "short"})
    assert response.status_code == 422


def test_admin_reset_lifts_a_login_lock(login, client, users):
    for _ in range(login_throttle.MAX_FAILURES):
        client.post("/login", data={"username": "alice", "password": "wrong"})
    assert login_throttle.seconds_locked("alice") > 0

    login("admin").post(f"/admin/users/{users['alice'].id}/password", data={"new_password": NEW_PASSWORD})

    assert client.post("/login", data={"username": "alice", "password": NEW_PASSWORD}).status_code == 303


# Disabling an account


def test_disabled_account_is_signed_out_and_cannot_sign_in(login, make_client, users, db: Session):
    bob, admin = login("bob"), login("admin")

    assert admin.post(f"/admin/users/{users['bob'].id}/disable").status_code == 303

    assert not signed_in(bob)
    fresh = make_client()
    refused = fresh.post("/login", data={"username": "bob", "password": TEST_PASSWORD})
    assert refused.status_code == 401
    # Same message as a wrong password: the form does not reveal the state.
    assert "Invalid username or password." in refused.text
    actions = [e.action for e in db.query(AuditLog).order_by(AuditLog.id)]
    assert "disable_account" in actions and "login_disabled" in actions

    assert admin.post(f"/admin/users/{users['bob'].id}/enable").status_code == 303
    assert fresh.post("/login", data={"username": "bob", "password": TEST_PASSWORD}).status_code == 303


def test_admin_cannot_disable_own_account(login, users):
    admin = login("admin")
    assert admin.post(f"/admin/users/{users['admin'].id}/disable").status_code == 400


# Changing one's own password


def test_change_own_password_signs_out_other_sessions(login):
    alice_here, alice_elsewhere = login("alice"), login("alice")

    response = alice_here.post(
        "/account/password",
        data={"current_password": TEST_PASSWORD, "new_password": NEW_PASSWORD},
    )

    assert response.status_code == 200
    assert "Password changed" in response.text
    assert signed_in(alice_here)
    assert not signed_in(alice_elsewhere)


def test_change_own_password_checks_the_current_one(login):
    alice = login("alice")

    wrong = alice.post(
        "/account/password", data={"current_password": "wrong", "new_password": NEW_PASSWORD}
    )
    short = alice.post(
        "/account/password", data={"current_password": TEST_PASSWORD, "new_password": "short"}
    )

    assert wrong.status_code == 400 and "current password is wrong" in wrong.text
    assert short.status_code == 400 and "at least 12" in short.text
    assert signed_in(alice)


def test_guessing_through_the_password_form_is_throttled(login):
    alice = login("alice")
    for _ in range(login_throttle.MAX_FAILURES):
        alice.post("/account/password", data={"current_password": "wrong", "new_password": NEW_PASSWORD})

    locked = alice.post(
        "/account/password", data={"current_password": TEST_PASSWORD, "new_password": NEW_PASSWORD}
    )

    assert locked.status_code == 400 and "Try again later" in locked.text


# Request IDs and the audit log


def test_every_response_has_a_request_id(client):
    first = client.get("/login").headers["x-request-id"]
    second = client.get("/login").headers["x-request-id"]
    assert re.fullmatch(r"[0-9a-f]{32}", first)
    assert first != second


def test_audit_entry_and_security_event_share_the_request_id(login, db: Session, capsys):
    alice = login("alice")
    capsys.readouterr()

    response = alice.post("/documents", data={"title": "report"}, files={"file": ("r.txt", b"x")})
    failed = alice.post("/login", data={"username": "bob", "password": "wrong"})

    entry = db.query(AuditLog).filter_by(action="upload").one()
    assert entry.request_id == response.headers["x-request-id"]
    assert entry.ip == "testclient"
    [event] = [e for e in events(capsys) if e["event"] == "login_failed"]
    assert event["request_id"] == failed.headers["x-request-id"]


def test_preview_is_audited(login, db: Session):
    alice = login("alice")
    document_id = upload(alice, "notes")

    alice.get(f"/documents/{document_id}/preview")

    assert db.query(AuditLog).filter_by(action="preview", target=f"document:{document_id}").count() == 1


def test_audit_export_for_auditors_only(login, users):
    admin, auditor, alice = login("admin"), login("auditor"), login("alice")
    admin.post(
        "/admin/users",
        data={"username": "=HYPERLINK(\"x\")", "password": NEW_PASSWORD, "role": "member"},
    )

    response = auditor.get("/audit/export.csv")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0] == ["id", "created_at", "actor", "action", "target", "ip", "request_id"]
    created = [r for r in rows if r[3] == "create_user"]
    # A value that a spreadsheet would run as a formula is neutralised.
    assert created[0][4].startswith("'=")
    assert alice.get("/audit/export.csv").status_code == 403


def test_new_users_need_a_long_password(login):
    admin = login("admin")
    response = admin.post("/admin/users", data={"username": "carol", "password": "short-pw", "role": "member"})
    assert response.status_code == 422
