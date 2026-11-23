"""DocVault web application.

This is the deliberately vulnerable baseline. Each planted flaw is marked with
a "VULN" comment and described in docs/vulnerability-register.md. Run it only
on localhost or in a dedicated test environment.
"""

import os
import shutil
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE_SECONDS,
    NotAuthenticated,
    create_session,
    current_user,
    hash_password,
    require_role,
    session_serializer,
    verify_password,
)
from app.config import STORAGE_DIR
from app.db import get_db
from app.models import ROLES, AuditLog, Document, Share, User

BASE_DIR = Path(__file__).resolve().parent

# Fail at start-up, not at the first sign-in, if the signing key is missing
# or too short.
session_serializer()

app = FastAPI(title="DocVault", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def render(request: Request, name: str, status_code: int = 200, **context) -> Response:
    return templates.TemplateResponse(
        request, name, context, status_code=status_code
    )


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def audit(db: Session, actor: str, action: str, target: str = "") -> None:
    db.add(AuditLog(actor=actor, action=action, target=target))
    db.commit()


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


def get_owned_document(db: Session, document_id: int, user: User) -> Document:
    document = get_document(db, document_id)
    if document.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return document


@app.exception_handler(NotAuthenticated)
def handle_not_authenticated(_request: Request, _exc: NotAuthenticated) -> Response:
    return redirect("/login")


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
) -> Response:
    user = db.scalar(select(User).where(User.username == username))
    if user is None or not verify_password(user.password_hash, password):
        audit(db, username[:64], "login_failed")
        return render(
            request,
            "login.html",
            status_code=401,
            user=None,
            error="Invalid username or password.",
        )

    audit(db, user.username, "login")
    response = redirect("/documents")
    # VULN F03: without HttpOnly, injected scripts can read the session cookie.
    response.set_cookie(
        SESSION_COOKIE,
        create_session(user),
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=False,
        samesite="lax",
    )
    return response


@app.post("/logout")
def logout() -> Response:
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
    # VULN F02: the search term is concatenated into the SQL statement.
    query = (
        "SELECT d.id, d.title, d.filename, d.created_at FROM documents d "
        f"LEFT JOIN shares s ON s.document_id = d.id AND s.user_id = {user.id} "
        f"WHERE (d.owner_id = {user.id} OR s.user_id IS NOT NULL) "
        f"AND d.title ILIKE '%{q}%' ORDER BY d.id"
    )
    documents = db.execute(text(query)).mappings().all()
    return render(request, "documents.html", user=user, documents=documents, q=q)


@app.post("/documents")
def upload_document(
    title: str = Form(...),
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    # VULN F04: the client-supplied file name is used to build the storage path.
    path = os.path.join(STORAGE_DIR, file.filename or "upload")
    with open(path, "wb") as output:
        shutil.copyfileobj(file.file, output)

    document = Document(
        owner_id=user.id,
        title=title,
        filename=file.filename or "upload",
        stored_path=path,
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
    document = get_document(db, document_id)
    if not can_read(db, document, user):
        raise HTTPException(status_code=403, detail="Forbidden")
    return render(request, "document.html", user=user, document=document)


@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    # VULN F01: any signed-in user can download any document; no access check.
    document = get_document(db, document_id)
    audit(db, user.username, "download", f"document:{document.id}")
    return FileResponse(
        document.stored_path, filename=os.path.basename(document.filename)
    )


@app.get("/preview", response_class=PlainTextResponse)
def preview_document(
    file: str,
    _user: User = Depends(current_user),
) -> str:
    # VULN F04: the requested path is not confined to the storage folder.
    path = os.path.join(STORAGE_DIR, file)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Not found")
    with open(path, encoding="utf-8", errors="replace") as source:
        return source.read()


@app.post("/documents/{document_id}/share")
def share_document(
    document_id: int,
    username: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
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
) -> Response:
    document = get_owned_document(db, document_id, user)
    if os.path.isfile(document.stored_path):
        os.remove(document.stored_path)
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
    password: str = Form(..., min_length=8),
    role: str = Form(...),
    user: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
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
