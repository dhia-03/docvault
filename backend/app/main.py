"""DocVault web application.

This is the deliberately vulnerable baseline. Each planted flaw is marked with
a "VULN" comment and described in docs/vulnerability-register.md. Run it only
on localhost or in a dedicated test environment.
"""

import csv
import io
import os
import re
import uuid
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app import csrf, login_throttle, request_context, security_events
from app.auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE_SECONDS,
    NotAuthenticated,
    client_ip,
    create_session,
    current_user,
    hash_password,
    require_role,
    session_serializer,
    verify_password,
)
from app.config import MAX_UPLOAD_BYTES, SESSION_COOKIE_SECURE, STORAGE_DIR, UPLOAD_QUOTA_BYTES
from app.db import get_db
from app.csrf import require_csrf
from app.models import ROLES, AuditLog, Document, Share, User

BASE_DIR = Path(__file__).resolve().parent

# Fail at start-up, not at the first sign-in, if the signing key is missing
# or too short.
session_serializer()

app = FastAPI(title="DocVault", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# F03 fix, defense in depth: even if a script were injected, the browser
# would refuse to run it, because only files from this site are allowed and
# the pages have no inline scripts or styles.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


# Room for the form fields and multipart framing around the file itself.
UPLOAD_OVERHEAD_BYTES = 64 * 1024


@app.middleware("http")
async def csrf_cookie_and_upload_limit(request: Request, call_next) -> Response:
    # O3 fix: refuse an oversized upload from its declared length, before the
    # body is read and buffered in /tmp. upload_document checks again while
    # writing, in case the declared length is missing or wrong.
    if request.method == "POST" and request.url.path == "/documents":
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES + UPLOAD_OVERHEAD_BYTES:
            return PlainTextResponse(
                f"File too large: the limit is {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB.",
                status_code=413,
            )

    # O1 fix: every visitor gets a CSRF cookie; see app/csrf.py.
    cookie = request.cookies.get(csrf.CSRF_COOKIE)
    new_cookie = None
    if not csrf.valid_cookie_value(cookie):
        cookie = new_cookie = csrf.new_cookie_value()
    request.state.csrf_cookie = cookie
    response = await call_next(request)
    if new_cookie:
        response.set_cookie(
            csrf.CSRF_COOKIE,
            new_cookie,
            httponly=True,
            secure=SESSION_COOKIE_SECURE,
            samesite="strict",
        )
    return response


# Defined last, so it wraps the other middleware and every log line of the
# request, including theirs, carries the same ID.
@app.middleware("http")
async def assign_request_id(request: Request, call_next) -> Response:
    request_id = request_context.start(request.client.host if request.client else None)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def render(request: Request, name: str, status_code: int = 200, **context) -> Response:
    # Every form needs the CSRF token (O1 fix); base.html's sign-out form too.
    context.setdefault("csrf_token", csrf.form_token(request))
    return templates.TemplateResponse(
        request, name, context, status_code=status_code
    )


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def audit(db: Session, actor: str, action: str, target: str = "") -> None:
    # The address and request ID come from the request being handled.
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            target=target[:255],
            ip=request_context.client_ip(),
            request_id=request_context.request_id(),
        )
    )
    db.commit()


MIN_PASSWORD_LENGTH = 12


def get_document(db: Session, document_id: int) -> Document:
    document = db.get(Document, document_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Not found")
    return document


def can_read(db: Session, document: Document, user: User) -> bool:
    if document.owner_id == user.id:
        return True
    share = db.scalar(
        select(Share).where(
            Share.document_id == document.id, Share.user_id == user.id
        )
    )
    return share is not None


def contained_file(document: Document) -> Path | None:
    """Returns the document's file if it exists inside the storage folder.

    Files are stored under server-generated names (F04 fix), so this only
    guards against rows written before the fix, or a future mistake.
    """
    path = Path(document.stored_path).resolve()
    if path.is_relative_to(Path(STORAGE_DIR).resolve()) and path.is_file():
        return path
    return None


def stored_file(document: Document) -> Path:
    """Returns the document's file for reading, or answers 404."""
    path = contained_file(document)
    if path is None:
        raise HTTPException(status_code=404, detail="Not found")
    return path


def get_readable_document(db: Session, document_id: int, user: User) -> Document:
    """Returns a document the user may read: their own, or one shared with them.

    F01 fix: every route that shows or serves a document goes through this
    one function, so a new route cannot forget the access check.
    """
    document = get_document(db, document_id)
    if not can_read(db, document, user):
        raise HTTPException(status_code=403, detail="Forbidden")
    return document


def get_owned_document(db: Session, document_id: int, user: User) -> Document:
    document = get_document(db, document_id)
    if document.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return document


@app.exception_handler(NotAuthenticated)
def handle_not_authenticated(_request: Request, _exc: NotAuthenticated) -> Response:
    return redirect("/login")


DOCUMENT_PATH = re.compile(r"^/documents/(\d+)(?:/|$)")


@app.exception_handler(StarletteHTTPException)
async def record_refusals(request: Request, exc: StarletteHTTPException) -> Response:
    """Records refused requests by signed-in users as security events.

    One place for every route: a 403 or 404 on a document (alert DV-A3 when
    repeated) and a 403 on an admin or audit page (alert DV-A4). The access
    checks themselves stay in get_readable_document and require_role.
    """
    user = getattr(request.state, "user", None)
    path = request.url.path
    if user is not None and exc.status_code in (403, 404):
        match = DOCUMENT_PATH.match(path)
        if match:
            security_events.document_denied(
                user.username, client_ip(request), request.method, path,
                exc.status_code, int(match.group(1)),
            )
        elif exc.status_code == 403 and (path == "/audit" or path.startswith("/admin")):
            security_events.role_denied(user.username, client_ip(request), request.method, path)
    return await http_exception_handler(request, exc)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/")
def index() -> Response:
    return redirect("/documents")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> Response:
    return render(request, "login.html", user=None, error=None)


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    # O2 fix: a locked username is refused before its password is checked.
    locked = login_throttle.seconds_locked(username)
    if locked:
        security_events.login_throttled(username, client_ip(request), locked)
        return render(
            request,
            "login.html",
            status_code=429,
            user=None,
            error=f"Too many failed sign-ins. Try again in {max(1, locked // 60)} minute(s).",
        )

    user = db.scalar(select(User).where(User.username == username))
    if user is not None and user.disabled and verify_password(user.password_hash, password):
        # Same answer as a wrong password, so the form does not reveal which
        # accounts are disabled; the audit log records the real reason.
        audit(db, user.username, "login_disabled")
        security_events.login_failed(username, client_ip(request))
        return render(
            request,
            "login.html",
            status_code=401,
            user=None,
            error="Invalid username or password.",
        )
    if user is None or not verify_password(user.password_hash, password):
        audit(db, username[:64], "login_failed")
        security_events.login_failed(username, client_ip(request))
        if login_throttle.record_failure(username):
            security_events.account_locked(
                username, client_ip(request), login_throttle.LOCK_SECONDS
            )
        return render(
            request,
            "login.html",
            status_code=401,
            user=None,
            error="Invalid username or password.",
        )

    login_throttle.record_success(username)
    audit(db, user.username, "login")
    security_events.login_succeeded(user.username, client_ip(request))
    response = redirect("/documents")
    # F03 fix: HttpOnly keeps the cookie away from page scripts, and Secure
    # keeps it off plain HTTP (see SESSION_COOKIE_SECURE).
    response.set_cookie(
        SESSION_COOKIE,
        create_session(user),
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="lax",
    )
    return response


@app.post("/logout")
def logout(_csrf: None = Depends(require_csrf)) -> Response:
    response = redirect("/login")
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/documents", response_class=HTMLResponse)
def list_documents(
    request: Request,
    q: str = "",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    # F02 fix: the query is built by SQLAlchemy, so the search term is sent as
    # a bound parameter and never becomes part of the SQL text. LIKE's own
    # wildcards are escaped too, so "%" or "_" only match themselves.
    pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    query = (
        select(Document)
        .outerjoin(Share, and_(Share.document_id == Document.id, Share.user_id == user.id))
        .where(or_(Document.owner_id == user.id, Share.user_id.is_not(None)))
        .where(Document.title.ilike(pattern, escape="\\"))
        .order_by(Document.id)
    )
    documents = db.scalars(query).all()
    return render(request, "documents.html", user=user, documents=documents, q=q)


COPY_CHUNK_BYTES = 1024 * 1024


@app.post("/documents")
def upload_document(
    title: str = Form(...),
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    # F04 fix: the file is stored under a random name chosen by the server.
    # The client's file name is kept only for display and download, without
    # any directory part, so it can never select where the file is written.
    display_name = Path(file.filename or "").name[:255] or "upload"
    path = os.path.join(STORAGE_DIR, uuid.uuid4().hex)

    # O3 fix: stop writing as soon as the file passes the size limit or the
    # owner's quota, and leave nothing behind.
    used = db.scalar(
        select(func.coalesce(func.sum(Document.size_bytes), 0)).where(Document.owner_id == user.id)
    )
    allowed = min(MAX_UPLOAD_BYTES, max(0, UPLOAD_QUOTA_BYTES - used))
    size = 0
    with open(path, "xb") as output:
        while chunk := file.file.read(COPY_CHUNK_BYTES):
            size += len(chunk)
            if size > allowed:
                break
            output.write(chunk)
    if size > allowed:
        os.remove(path)
        if size > MAX_UPLOAD_BYTES:
            reason = f"File too large: the limit is {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB."
        else:
            reason = f"Storage quota reached: {UPLOAD_QUOTA_BYTES // (1024 * 1024)} MiB per user."
        raise HTTPException(status_code=413, detail=reason)

    document = Document(
        owner_id=user.id,
        title=title,
        filename=display_name,
        stored_path=path,
        size_bytes=size,
    )
    db.add(document)
    db.commit()
    audit(db, user.username, "upload", f"document:{document.id}")
    return redirect(f"/documents/{document.id}")


@app.get("/documents/{document_id}", response_class=HTMLResponse)
def document_detail(
    request: Request,
    document_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    document = get_readable_document(db, document_id, user)
    return render(request, "document.html", user=user, document=document)


@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    # F01 fix: the download now has the same access check as the detail page.
    document = get_readable_document(db, document_id, user)
    audit(db, user.username, "download", f"document:{document.id}")
    return FileResponse(stored_file(document), filename=os.path.basename(document.filename))


@app.get("/documents/{document_id}/preview", response_class=PlainTextResponse)
def preview_document(
    document_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> str:
    # F04 fix: the preview is chosen by document ID, after an access check,
    # instead of by a file path from the request.
    document = get_readable_document(db, document_id, user)
    audit(db, user.username, "preview", f"document:{document.id}")
    with open(stored_file(document), encoding="utf-8", errors="replace") as source:
        return source.read()


@app.post("/documents/{document_id}/share")
def share_document(
    document_id: int,
    username: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    document = get_owned_document(db, document_id, user)
    recipient = db.scalar(select(User).where(User.username == username))
    if recipient is None:
        raise HTTPException(status_code=404, detail="User not found")
    existing = db.scalar(
        select(Share).where(
            Share.document_id == document.id, Share.user_id == recipient.id
        )
    )
    if existing is None and recipient.id != user.id:
        db.add(Share(document_id=document.id, user_id=recipient.id))
        db.commit()
        audit(db, user.username, "share", f"document:{document.id}:{username}")
    return redirect(f"/documents/{document.id}")


@app.post("/documents/{document_id}/metadata")
def update_metadata(
    document_id: int,
    metadata: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    document = get_owned_document(db, document_id, user)
    try:
        # F06 fix: safe_load only builds plain data (strings, numbers, lists,
        # mappings). Tags such as !!python/object are refused as YAMLError.
        data = yaml.safe_load(metadata)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail="Invalid metadata") from exc

    tags = data.get("tags", []) if isinstance(data, dict) else []
    if not isinstance(tags, (list, tuple)):
        tags = [tags]
    document.tags = ", ".join(str(tag) for tag in tags)
    db.commit()
    audit(db, user.username, "update_metadata", f"document:{document.id}")
    return redirect(f"/documents/{document.id}")


@app.post("/documents/{document_id}/delete")
def delete_document(
    document_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    document = get_owned_document(db, document_id, user)
    # Only a file inside the storage folder is deleted; a row written before
    # the F04 fix could point elsewhere.
    path = contained_file(document)
    if path is not None:
        path.unlink()
    db.delete(document)
    db.commit()
    audit(db, user.username, "delete", f"document:{document_id}")
    return redirect("/documents")


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(
    request: Request,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> Response:
    users = db.scalars(select(User).order_by(User.id)).all()
    return render(request, "admin_users.html", user=user, users=users, roles=ROLES)


@app.post("/admin/users")
def create_user(
    username: str = Form(..., min_length=3, max_length=64),
    password: str = Form(..., min_length=MIN_PASSWORD_LENGTH),
    role: str = Form(...),
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    if role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    if db.scalar(select(User).where(User.username == username)) is not None:
        raise HTTPException(status_code=409, detail="Username already exists")
    db.add(User(username=username, password_hash=hash_password(password), role=role))
    db.commit()
    audit(db, user.username, "create_user", username)
    return redirect("/admin/users")


@app.post("/admin/users/{user_id}/role")
def change_role(
    user_id: int,
    role: str = Form(...),
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    if role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Not found")
    target.role = role
    db.commit()
    audit(db, user.username, "change_role", f"{target.username}:{role}")
    return redirect("/admin/users")


def get_account(db: Session, user_id: int) -> User:
    account = db.get(User, user_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Not found")
    return account


@app.post("/admin/users/{user_id}/password")
def reset_password(
    user_id: int,
    new_password: str = Form(..., min_length=MIN_PASSWORD_LENGTH),
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    """Sets a new password and signs the user out everywhere (playbook P3)."""
    account = get_account(db, user_id)
    account.password_hash = hash_password(new_password)
    account.session_version += 1
    db.commit()
    login_throttle.unlock(account.username)
    audit(db, user.username, "reset_password", account.username)
    return redirect("/admin/users")


@app.post("/admin/users/{user_id}/revoke-sessions")
def revoke_sessions(
    user_id: int,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    """Signs one user out everywhere, without rotating the key for everyone."""
    account = get_account(db, user_id)
    account.session_version += 1
    db.commit()
    audit(db, user.username, "revoke_sessions", account.username)
    return redirect("/admin/users")


@app.post("/admin/users/{user_id}/disable")
def disable_account(
    user_id: int,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    account = get_account(db, user_id)
    if account.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot disable your own account")
    account.disabled = True
    account.session_version += 1
    db.commit()
    audit(db, user.username, "disable_account", account.username)
    return redirect("/admin/users")


@app.post("/admin/users/{user_id}/enable")
def enable_account(
    user_id: int,
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    account = get_account(db, user_id)
    account.disabled = False
    db.commit()
    audit(db, user.username, "enable_account", account.username)
    return redirect("/admin/users")


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request, user: User = Depends(current_user)) -> Response:
    return render(request, "account.html", user=user, error=None, done=False)


@app.post("/account/password")
def change_own_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    _csrf: None = Depends(require_csrf),
) -> Response:
    """Changes one's own password, and signs out every other session."""
    error = None
    if login_throttle.seconds_locked(user.username):
        error = "Too many failed attempts. Try again later."
    elif not verify_password(user.password_hash, current_password):
        # Guessing through this form counts like failed sign-ins (O2).
        login_throttle.record_failure(user.username)
        audit(db, user.username, "change_password_failed")
        error = "The current password is wrong."
    elif len(new_password) < MIN_PASSWORD_LENGTH:
        error = f"The new password must have at least {MIN_PASSWORD_LENGTH} characters."
    if error:
        return render(request, "account.html", status_code=400, user=user, error=error, done=False)

    user.password_hash = hash_password(new_password)
    user.session_version += 1
    db.commit()
    audit(db, user.username, "change_password")
    response = render(request, "account.html", user=user, error=None, done=True)
    # This browser stays signed in with a cookie for the new version.
    response.set_cookie(
        SESSION_COOKIE,
        create_session(user),
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="lax",
    )
    return response


@app.get("/audit", response_class=HTMLResponse)
def audit_log(
    request: Request,
    user: User = Depends(require_role("admin", "auditor")),
    db: Session = Depends(get_db),
) -> Response:
    entries = db.scalars(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(200)
    ).all()
    return render(request, "audit.html", user=user, entries=entries)


def _csv_cell(value: object) -> str:
    """Text for a CSV cell that a spreadsheet will not run as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@app.get("/audit/export.csv")
def export_audit_log(
    user: User = Depends(require_role("admin", "auditor")),
    db: Session = Depends(get_db),
) -> Response:
    """The whole audit log as CSV, for an investigation (playbook P4)."""
    audit(db, user.username, "export_audit")
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "created_at", "actor", "action", "target", "ip", "request_id"])
    for entry in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        writer.writerow(
            _csv_cell(v)
            for v in (entry.id, entry.created_at, entry.actor, entry.action,
                      entry.target, entry.ip, entry.request_id)
        )
    return Response(
        buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="docvault-audit.csv"'},
    )
