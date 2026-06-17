import time
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import hash_password, verify_password
from app.core.totp import decrypted_totp_secret, encrypted_totp_secret, generate_totp_secret, provisioning_uri, qr_code_data_uri, verify_totp
from app.db.session import get_db
from app.models.models import User
from app.services.audit import write_audit
from app.services.sessions import end_user_session, start_user_session, touch_user_session

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_FAILURES: dict[str, list[float]] = {}
DUMMY_PASSWORD_HASH = hash_password("not-the-real-password")


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def login_is_limited(key: str) -> bool:
    now = time.monotonic()
    attempts = [attempt for attempt in LOGIN_FAILURES.get(key, []) if now - attempt < LOGIN_WINDOW_SECONDS]
    LOGIN_FAILURES[key] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def record_login_failure(key: str) -> None:
    now = time.monotonic()
    attempts = [attempt for attempt in LOGIN_FAILURES.get(key, []) if now - attempt < LOGIN_WINDOW_SECONDS]
    attempts.append(now)
    LOGIN_FAILURES[key] = attempts


def current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if user:
        touch_user_session(db, request, user)
    return user


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = current_user(request, db)
    if not user:
        raise PermissionError("Authentication required")
    return user


def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    user = require_user(request, db)
    if user.role != "admin":
        raise PermissionError("Admin access required")
    return user


def require_editor(request: Request, db: Session = Depends(get_db)) -> User:
    user = require_user(request, db)
    if user.role not in ["admin", "editor"]:
        raise PermissionError("Editor access required")
    return user


@router.get("/login")
def login_page(request: Request):
    request.session.pop("pending_2fa_user_id", None)
    return templates.TemplateResponse(request, "login.html", {"error": None, **csrf_context(request, include_version=False)})


@router.post("/login")
def login(request: Request, email: str = Form(""), password: str = Form(""), totp_code: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf_token(request, csrf_token)
    key = client_key(request)
    if login_is_limited(key):
        return templates.TemplateResponse(request, "login.html", {"error": "Too many failed sign-in attempts. Try again later.", **csrf_context(request, include_version=False)}, status_code=429)

    pending_user_id = request.session.get("pending_2fa_user_id")
    if pending_user_id:
        user = db.query(User).filter(User.id == pending_user_id, User.is_active == True).first()
        if not user or not user.totp_enabled or not verify_totp(decrypted_totp_secret(user.totp_secret), totp_code):
            record_login_failure(key)
            return templates.TemplateResponse(request, "login.html", {"error": "Invalid authentication code", "requires_2fa": True, **csrf_context(request, include_version=False)}, status_code=401)
        request.session.clear()
        request.session["user_id"] = user.id
        start_user_session(db, request, user)
        LOGIN_FAILURES.pop(key, None)
        write_audit(db, user, "login", "user", str(user.id), request.client.host if request.client else None, detail="2FA verified")
        return RedirectResponse("/dashboard", status_code=303)

    user = db.query(User).filter(User.email == email.strip().lower(), User.is_active == True).first()
    password_hash = user.password_hash if user else DUMMY_PASSWORD_HASH
    if not verify_password(password, password_hash) or not user:
        record_login_failure(key)
        return templates.TemplateResponse(request, "login.html", {"error": "Invalid email or password", **csrf_context(request, include_version=False)}, status_code=401)
    if user.totp_enabled:
        request.session.clear()
        request.session["pending_2fa_user_id"] = user.id
        return templates.TemplateResponse(request, "login.html", {"error": None, "requires_2fa": True, **csrf_context(request, include_version=False)})
    request.session.clear()
    request.session["user_id"] = user.id
    start_user_session(db, request, user)
    LOGIN_FAILURES.pop(key, None)
    write_audit(db, user, "login", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/dashboard", status_code=303)


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf_token(request, csrf_token)
    end_user_session(db, request)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/profile")
def profile(request: Request, user=Depends(require_user)):
    secret = decrypted_totp_secret(user.totp_secret) if user.totp_secret and not user.totp_enabled else None
    uri = provisioning_uri(user.email, secret) if secret else None
    qr_code = qr_code_data_uri(uri) if uri else None
    return templates.TemplateResponse(request, "profile.html", {"user": user, "setup_secret": secret, "setup_uri": uri, "setup_qr_code": qr_code, "error": None, "success": None, **csrf_context(request)})


@router.post("/profile/name")
def update_profile_name(request: Request, first_name: str = Form("", max_length=120), last_name: str = Form("", max_length=120), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    user.first_name = first_name.strip() or None
    user.last_name = last_name.strip() or None
    db.commit()
    write_audit(db, user, "update_profile", "user", str(user.id), request.client.host if request.client else None, detail="Updated profile name")
    return RedirectResponse("/profile", status_code=303)


@router.post("/profile/password")
def update_profile_password(request: Request, current_password: str = Form("", max_length=255), new_password: str = Form("", max_length=255), confirm_password: str = Form("", max_length=255), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    if not verify_password(current_password, user.password_hash):
        return templates.TemplateResponse(request, "profile.html", {"user": user, "setup_secret": None, "setup_uri": None, "setup_qr_code": None, "error": "Current password is incorrect.", "success": None, **csrf_context(request)}, status_code=400)
    if len(new_password) < 12:
        return templates.TemplateResponse(request, "profile.html", {"user": user, "setup_secret": None, "setup_uri": None, "setup_qr_code": None, "error": "New password must be at least 12 characters.", "success": None, **csrf_context(request)}, status_code=400)
    if new_password != confirm_password:
        return templates.TemplateResponse(request, "profile.html", {"user": user, "setup_secret": None, "setup_uri": None, "setup_qr_code": None, "error": "New passwords do not match.", "success": None, **csrf_context(request)}, status_code=400)
    user.password_hash = hash_password(new_password)
    db.commit()
    write_audit(db, user, "change_password", "user", str(user.id), request.client.host if request.client else None)
    return templates.TemplateResponse(request, "profile.html", {"user": user, "setup_secret": None, "setup_uri": None, "setup_qr_code": None, "error": None, "success": "Password updated.", **csrf_context(request)})


@router.post("/profile/2fa/start")
def start_profile_2fa(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    secret = generate_totp_secret()
    user.totp_secret = encrypted_totp_secret(secret)
    user.totp_enabled = False
    db.commit()
    write_audit(db, user, "start_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/profile", status_code=303)


@router.post("/profile/2fa/enable")
def enable_profile_2fa(request: Request, code: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    secret = decrypted_totp_secret(user.totp_secret)
    if not secret or not verify_totp(secret, code):
        uri = provisioning_uri(user.email, secret) if secret else None
        qr_code = qr_code_data_uri(uri) if uri else None
        return templates.TemplateResponse(request, "profile.html", {"user": user, "setup_secret": secret, "setup_uri": uri, "setup_qr_code": qr_code, "error": "Invalid authentication code.", "success": None, **csrf_context(request)}, status_code=400)
    user.totp_enabled = True
    db.commit()
    write_audit(db, user, "enable_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/profile", status_code=303)


@router.post("/profile/2fa/disable")
def disable_profile_2fa(request: Request, current_password: str = Form("", max_length=255), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    if not verify_password(current_password, user.password_hash):
        return templates.TemplateResponse(request, "profile.html", {"user": user, "setup_secret": None, "setup_uri": None, "setup_qr_code": None, "error": "Current password is required to disable 2FA.", "success": None, **csrf_context(request)}, status_code=400)
    user.totp_secret = None
    user.totp_enabled = False
    db.commit()
    write_audit(db, user, "disable_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/profile", status_code=303)
