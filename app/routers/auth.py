import hashlib
import secrets
import smtplib
import time
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.demo import DEMO_ACCOUNTS, demo_generation, demo_login_email
from app.core.security import decrypt_secret, hash_password, verify_password
from app.core.totp import decrypted_totp_secret, encrypted_totp_secret, generate_totp_secret, provisioning_uri, qr_code_data_uri, verify_totp
from app.db.session import get_db
from app.models.models import AppSession, AuditLog, ExternalIdentity, OIDCProvider, PasswordResetToken, User, VaultSession
from app.services.audit import write_audit
from app.services.mail import MailConfigurationError, render_email_template, send_mail
from app.services.sessions import end_user_session, start_user_session, touch_user_session
from app.services.site_settings import get_site_setting
from app.services.oidc_client import safe_return_path
from app.services.authentication_policy import get_authentication_policy, normal_local_login_allowed

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_FAILURES: dict[str, list[float]] = {}
DUMMY_PASSWORD_HASH = hash_password("not-the-real-password")
settings = get_settings()
PASSWORD_RESET_TOKEN_HOURS = 1
PASSWORD_RESET_MESSAGE = "If that email matches an active account and mail is configured, a reset link will be sent shortly."
MAX_PASSWORD_RESET_ATTEMPTS = 5
PASSWORD_RESET_WINDOW_SECONDS = 60 * 60
PASSWORD_RESET_ATTEMPTS: dict[str, list[float]] = {}


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def recent_attempts(cache: dict[str, list[float]], key: str, window_seconds: int) -> list[float]:
    now = time.monotonic()
    attempts = [attempt for attempt in cache.get(key, []) if now - attempt < window_seconds]
    cache[key] = attempts
    return attempts


def login_is_limited(db: Session, key: str, attempted_email: str) -> bool:
    attempts = recent_attempts(LOGIN_FAILURES, key, LOGIN_WINDOW_SECONDS)
    since = datetime.utcnow() - timedelta(seconds=LOGIN_WINDOW_SECONDS)
    metadata_match = f'"attempted_email":"{attempted_email[:255]}"'
    audit_identity_filters = [AuditLog.ip_address == key]
    if attempted_email:
        audit_identity_filters.append(AuditLog.metadata_json.contains(metadata_match))
    audit_count = (
        db.query(AuditLog)
        .filter(
            AuditLog.action.in_(["login_failed", "login_blocked", "2fa_failed"]),
            AuditLog.created_at >= since,
            or_(*audit_identity_filters),
        )
        .count()
    )
    return max(len(attempts), audit_count) >= MAX_LOGIN_ATTEMPTS


def password_reset_is_limited(db: Session, user: User | None, email: str, key: str) -> bool:
    cache_keys = [f"ip:{key}", f"email:{email[:255]}"]
    cached = max(
        len(recent_attempts(PASSWORD_RESET_ATTEMPTS, cache_key, PASSWORD_RESET_WINDOW_SECONDS))
        for cache_key in cache_keys
    )
    if cached >= MAX_PASSWORD_RESET_ATTEMPTS:
        return True
    if not user:
        return False
    since = datetime.utcnow() - timedelta(seconds=PASSWORD_RESET_WINDOW_SECONDS)
    token_count = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == user.id, PasswordResetToken.created_at >= since)
        .count()
    )
    return token_count >= MAX_PASSWORD_RESET_ATTEMPTS


def record_password_reset_attempt(email: str, key: str) -> None:
    now = time.monotonic()
    for cache_key in [f"ip:{key}", f"email:{email[:255]}"]:
        attempts = recent_attempts(PASSWORD_RESET_ATTEMPTS, cache_key, PASSWORD_RESET_WINDOW_SECONDS)
        attempts.append(now)
        PASSWORD_RESET_ATTEMPTS[cache_key] = attempts


def record_login_failure(key: str) -> None:
    now = time.monotonic()
    attempts = recent_attempts(LOGIN_FAILURES, key, LOGIN_WINDOW_SECONDS)
    attempts.append(now)
    LOGIN_FAILURES[key] = attempts


def password_reset_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def password_reset_link(request: Request, db: Session, token: str) -> str:
    base_url = get_site_setting(db, "base_url").strip() or str(request.base_url)
    return f"{base_url.rstrip('/')}/reset-password?token={token}"


def find_valid_reset_token(db: Session, token: str) -> PasswordResetToken | None:
    if not token:
        return None
    return (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash == password_reset_hash(token),
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at >= datetime.utcnow(),
        )
        .first()
    )


def login_template_context(request: Request, db: Session, **overrides) -> dict:
    """Build one consistent login context for initial, error and 2FA renders."""
    policy = get_authentication_policy(db)
    context = {
        "error": None,
        "success": None,
        "setup_complete": False,
        "requires_2fa": False,
        "demo_accounts": DEMO_ACCOUNTS if settings.demo_mode else None,
        "authentication_mode": policy.authentication_mode,
        "oidc_available": policy.oidc_available,
        "oidc_button_label": policy.oidc_button_label,
        "show_local_login": policy.show_local_login,
        "auto_redirect_oidc": policy.auto_redirect_oidc,
        "provider_display_name": policy.provider_display_name,
        "local_login_disabled": policy.local_login_disabled,
        "oidc_provider": policy.provider,
        **csrf_context(request, include_version=False),
    }
    context.update(overrides)
    return context


def current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    if settings.demo_mode and request.session.get("demo_generation") != demo_generation():
        request.session.clear()
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
def login_page(
    request: Request,
    setup_complete: str = "",
    logged_out: str = "",
    db: Session = Depends(get_db)
):
    admin = db.query(User).filter(User.role == "admin").first()

    if not admin:
        return RedirectResponse("/setup", status_code=303)

    request.session.pop("pending_2fa_user_id", None)

    policy = get_authentication_policy(db)
    if policy.authentication_mode == "oidc_required" and not policy.oidc_available:
        return templates.TemplateResponse(
            request,
            "oidc_error.html",
            {
                "message": "Single sign-on is currently unavailable. Please contact your Kaya administrator.",
                "authentication_mode": policy.authentication_mode,
                **csrf_context(request, include_version=False),
            },
            status_code=503,
        )
    if policy.auto_redirect_oidc and logged_out != "1" and not settings.demo_mode:
        write_audit(db, None, "oidc_automatic_redirect_initiated", "oidc", ip_address=request.client.host if request.client else None)
        return RedirectResponse("/auth/oidc/login", status_code=303)

    return templates.TemplateResponse(
        request,
        "login.html",
        login_template_context(request, db, setup_complete=setup_complete == "1"),
    )


@router.get("/setup")
def setup_page(
    request: Request,
    db: Session = Depends(get_db)
):
    admin = db.query(User).filter(User.role == "admin").first()

    if admin:
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request,
        "setup.html",
        {
            "error": None,
            **csrf_context(request, include_version=False)
        }
    )


@router.get("/forgot-password")
def forgot_password_page(request: Request):
    if settings.demo_mode:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {
            "error": None,
            "message": None,
            **csrf_context(request, include_version=False),
        },
    )


@router.post("/forgot-password")
def forgot_password_submit(
    request: Request,
    email: str = Form("", max_length=255),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf_token(request, csrf_token)
    if settings.demo_mode:
        return RedirectResponse("/login", status_code=303)

    clean_email = email.strip().lower()
    user = db.query(User).filter(User.email == clean_email, User.is_active == True).first()
    key = client_key(request)
    limited = password_reset_is_limited(db, user, clean_email, key)
    record_password_reset_attempt(clean_email, key)
    if user and user.password_hash and user.authentication_type != "oidc" and not limited:
        raw_token = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        ).update({PasswordResetToken.used_at: now}, synchronize_session=False)
        db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=password_reset_hash(raw_token),
                expires_at=now + timedelta(hours=PASSWORD_RESET_TOKEN_HOURS),
            )
        )
        try:
            reset_link = password_reset_link(request, db, raw_token)
            template_values = {
                "app_name": get_site_setting(db, "app_name"),
                "expiry_hours": str(PASSWORD_RESET_TOKEN_HOURS),
                "reset_link": reset_link,
                "user_email": user.email,
            }
            send_mail(
                db,
                user.email,
                render_email_template(get_site_setting(db, "email_template_password_reset_subject"), **template_values),
                render_email_template(get_site_setting(db, "email_template_password_reset_body"), **template_values),
            )
            db.commit()
            write_audit(
                db,
                user,
                "password_reset_requested",
                "user",
                str(user.id),
                request.client.host if request.client else None,
                detail="Password reset email sent",
            )
        except (MailConfigurationError, OSError, ValueError, smtplib.SMTPException):
            db.rollback()
            write_audit(
                db,
                user,
                "password_reset_email_failed",
                "user",
                str(user.id),
                request.client.host if request.client else None,
                detail="Password reset email could not be sent",
                severity="warning",
            )
    elif limited:
        write_audit(
            db,
            user,
            "password_reset_blocked",
            "user",
            str(user.id) if user else None,
            request.client.host if request.client else None,
            detail="Password reset blocked by rate limit",
            severity="warning",
            status_code=429,
            metadata={"attempted_email": clean_email[:255]},
        )

    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {
            "error": None,
            "message": PASSWORD_RESET_MESSAGE,
            **csrf_context(request, include_version=False),
        },
    )


@router.get("/reset-password")
def reset_password_page(request: Request, token: str = "", db: Session = Depends(get_db)):
    if settings.demo_mode:
        return RedirectResponse("/login", status_code=303)
    row = find_valid_reset_token(db, token)
    if row and (not row.user.password_hash or row.user.authentication_type == "oidc"):
        row = None
    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {
            "token": token if row else "",
            "error": None if row else "This reset link is invalid or has expired.",
            **csrf_context(request, include_version=False),
        },
        status_code=200 if row else 400,
    )


@router.post("/reset-password")
def reset_password_submit(
    request: Request,
    token: str = Form(""),
    password: str = Form("", max_length=255),
    confirm_password: str = Form("", max_length=255),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf_token(request, csrf_token)
    if settings.demo_mode:
        return RedirectResponse("/login", status_code=303)

    row = find_valid_reset_token(db, token)
    if row and (not row.user.password_hash or row.user.authentication_type == "oidc"):
        row = None
    if not row:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {
                "token": "",
                "error": "This reset link is invalid or has expired.",
                **csrf_context(request, include_version=False),
            },
            status_code=400,
        )
    if len(password) < 12:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {
                "token": token,
                "error": "Password must be at least 12 characters.",
                **csrf_context(request, include_version=False),
            },
            status_code=400,
        )
    if password != confirm_password:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {
                "token": token,
                "error": "Passwords do not match.",
                **csrf_context(request, include_version=False),
            },
            status_code=400,
        )

    user = row.user
    user.password_hash = hash_password(password)
    db.query(VaultSession).filter(VaultSession.user_id == user.id, VaultSession.revoked_at.is_(None)).update({VaultSession.revoked_at: datetime.utcnow()}, synchronize_session=False)
    row.used_at = datetime.utcnow()
    db.commit()
    write_audit(
        db,
        user,
        "password_reset_completed",
        "user",
        str(user.id),
        request.client.host if request.client else None,
    )
    request.session.clear()
    return templates.TemplateResponse(
        request,
        "login.html",
        login_template_context(request, db, success="Password updated. You can sign in now.", demo_accounts=None),
    )


@router.post("/setup")
def setup_submit(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(""),
    password: str = Form(""),
    confirm_password: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    validate_csrf_token(request, csrf_token)

    admin = db.query(User).filter(User.role == "admin").first()

    if admin:
        return RedirectResponse("/login", status_code=303)

    email = email.strip().lower()

    if not email:
        return templates.TemplateResponse(
            request,
            "setup.html",
            {
                "error": "Email is required.",
                **csrf_context(request, include_version=False)
            },
            status_code=400
        )

    if len(password) < 12:
        return templates.TemplateResponse(
            request,
            "setup.html",
            {
                "error": "Password must be at least 12 characters.",
                **csrf_context(request, include_version=False)
            },
            status_code=400
        )

    if password != confirm_password:
        return templates.TemplateResponse(
            request,
            "setup.html",
            {
                "error": "Passwords do not match.",
                **csrf_context(request, include_version=False)
            },
            status_code=400
        )

    user = User(
        email=email,
        first_name=first_name.strip() or None,
        last_name=last_name.strip() or None,
        password_hash=hash_password(password),
        role="admin",
        is_active=True
    )

    db.add(user)
    db.commit()
    write_audit(
        db,
        user,
        "create_initial_admin",
        "user",
        str(user.id),
        request.client.host if request.client else None,
        detail="Created the initial administrator account",
    )

    return RedirectResponse("/login?setup_complete=1", status_code=303)

@router.post("/login")
def login(request: Request, email: str = Form(""), password: str = Form(""), totp_code: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf_token(request, csrf_token)
    if not normal_local_login_allowed(db) and not settings.demo_mode:
        write_audit(
            db, None, "local_login_rejected_disabled", "user",
            ip_address=request.client.host if request.client else None,
            detail="Normal email/password sign-in is disabled by authentication policy",
            severity="warning", status_code=403,
        )
        return templates.TemplateResponse(
            request, "login.html",
            login_template_context(request, db, error="Email and password sign-in is disabled. Please use single sign-on."),
            status_code=403,
        )
    key = client_key(request)
    attempted_email = email.strip().lower()
    if login_is_limited(db, key, attempted_email):
        write_audit(
            db,
            None,
            "login_blocked",
            "user",
            ip_address=request.client.host if request.client else None,
            detail="Login blocked by rate limit",
            severity="warning",
            status_code=429,
            metadata={"attempted_email": attempted_email[:255]},
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            login_template_context(request, db, error="Too many failed sign-in attempts. Try again later."),
            status_code=429,
        )

    pending_user_id = request.session.get("pending_2fa_user_id")
    if pending_user_id:
        user = db.query(User).filter(User.id == pending_user_id, User.is_active == True).first()
        if not user or not user.totp_enabled or not verify_totp(decrypted_totp_secret(user.totp_secret), totp_code):
            record_login_failure(key)
            write_audit(
                db,
                user,
                "2fa_failed",
                "user",
                str(user.id) if user else None,
                request.client.host if request.client else None,
                detail="Invalid authentication code",
                severity="warning",
                status_code=401,
            )
            return templates.TemplateResponse(
                request,
                "login.html",
                login_template_context(request, db, error="Invalid authentication code", requires_2fa=True),
                status_code=401,
            )
        request.session.clear()
        request.session["user_id"] = user.id
        start_user_session(db, request, user)
        LOGIN_FAILURES.pop(key, None)
        write_audit(db, user, "login", "user", str(user.id), request.client.host if request.client else None, detail="2FA verified")
        return RedirectResponse("/dashboard", status_code=303)

    login_email = demo_login_email(email) if settings.demo_mode else email.strip().lower()
    user = db.query(User).filter(User.email == login_email, User.is_active == True).first()
    password_hash = user.password_hash if user and user.authentication_type != "oidc" else DUMMY_PASSWORD_HASH
    if not verify_password(password, password_hash) or not user or not user.password_hash or user.authentication_type == "oidc":
        record_login_failure(key)
        write_audit(
            db,
            None,
            "login_failed",
            "user",
            ip_address=request.client.host if request.client else None,
            detail="Invalid email or password",
            severity="warning",
            status_code=401,
            metadata={"attempted_email": email.strip().lower()[:255]},
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            login_template_context(request, db, error="Invalid email or password"),
            status_code=401,
        )
    if user.totp_enabled:
        request.session.clear()
        request.session["pending_2fa_user_id"] = user.id
        write_audit(
            db,
            user,
            "2fa_challenge",
            "user",
            str(user.id),
            request.client.host if request.client else None,
            detail="Password verified; awaiting authentication code",
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            login_template_context(request, db, requires_2fa=True),
        )
    request.session.clear()
    request.session["user_id"] = user.id
    if settings.demo_mode:
        request.session["demo_generation"] = demo_generation()
    start_user_session(db, request, user)
    LOGIN_FAILURES.pop(key, None)
    write_audit(db, user, "login", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/dashboard", status_code=303)


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf_token(request, csrf_token)
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if user_id else None
    authentication_method = request.session.get("authentication_method")
    session_id = request.session.get("session_id")
    app_session = db.query(AppSession).filter_by(session_id=session_id).first() if session_id else None
    id_token_hint = decrypt_secret(app_session.encrypted_oidc_id_token) if app_session and app_session.encrypted_oidc_id_token else None
    if user:
        from app.models.models import Vault
        from app.services.secret_vault import lock_vault
        if db.query(Vault.id).filter_by(owner_id=user.id).first():
            lock_vault(db, request, user)
    end_user_session(db, request)
    write_audit(
        db,
        user,
        "logout",
        "user",
        str(user.id) if user else None,
        request.client.host if request.client else None,
    )
    request.session.clear()
    if authentication_method == "oidc":
        from app.services.oidc_client import provider_logout_redirect
        redirect = provider_logout_redirect(db, id_token_hint=id_token_hint)
        if redirect:
            write_audit(db, user, "oidc_logout_started", "oidc", ip_address=request.client.host if request.client else None)
            return RedirectResponse(redirect, status_code=303)
        post_logout_path = safe_return_path(get_site_setting(db, "oidc_post_logout_path"), "/login")
        if post_logout_path == "/login":
            post_logout_path = "/login?logged_out=1"
        return RedirectResponse(post_logout_path, status_code=303)
    return RedirectResponse("/login", status_code=303)


@router.get("/profile")
def profile(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    secret = decrypted_totp_secret(user.totp_secret) if user.totp_secret and not user.totp_enabled else None
    uri = provisioning_uri(user.email, secret) if secret else None
    qr_code = qr_code_data_uri(uri) if uri else None
    identity = db.query(ExternalIdentity).filter_by(user_id=user.id).first()
    provider = db.get(OIDCProvider, identity.provider_id) if identity else db.query(OIDCProvider).filter_by(is_enabled=True).first()
    identity_errors = {
        "unavailable": "OpenID Connect is not currently enabled.",
        "configuration_not_ready": "OpenID Connect must pass its configuration test before an account can be linked.",
        "incomplete_provider": "The OpenID Connect provider is missing its client ID or client secret.",
        "local_password_required": "A local password is required for this action.",
        "no_remaining_login_method": "Set a local password before unlinking your OpenID Connect identity.",
        "identity_conflict": "That OpenID Connect identity is already linked to another Kaya account.",
        "user_identity_conflict": "This Kaya account is already linked to a different OpenID Connect identity.",
    }
    identity_error = request.query_params.get("identity_error", "")
    success = None
    if request.query_params.get("identity_linked") == "1":
        success = "OpenID Connect account linked successfully."
    elif request.query_params.get("identity_unlinked") == "1":
        success = "OpenID Connect account unlinked successfully."
    return templates.TemplateResponse(request, "profile.html", {
        "user": user, "identity": identity, "oidc_provider": provider,
        "setup_secret": secret, "setup_uri": uri, "setup_qr_code": qr_code,
        "error": identity_errors.get(identity_error, "The sign-in method could not be updated." if identity_error else None),
        "success": success, **csrf_context(request),
    })


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
    db.query(VaultSession).filter(VaultSession.user_id == user.id, VaultSession.revoked_at.is_(None)).update({VaultSession.revoked_at: datetime.utcnow()}, synchronize_session=False)
    db.commit()
    write_audit(db, user, "change_password", "user", str(user.id), request.client.host if request.client else None)
    return templates.TemplateResponse(request, "profile.html", {"user": user, "setup_secret": None, "setup_uri": None, "setup_qr_code": None, "error": None, "success": "Password updated.", **csrf_context(request)})


@router.post("/profile/2fa/start")
def start_profile_2fa(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    if not user.password_hash or user.authentication_type == "oidc":
        return RedirectResponse("/profile?identity_error=local_password_required", status_code=303)
    secret = generate_totp_secret()
    user.totp_secret = encrypted_totp_secret(secret)
    user.totp_enabled = False
    db.commit()
    write_audit(db, user, "start_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/profile", status_code=303)


@router.post("/profile/2fa/enable")
def enable_profile_2fa(request: Request, code: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    if not user.password_hash or user.authentication_type == "oidc":
        return RedirectResponse("/profile?identity_error=local_password_required", status_code=303)
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
    db.query(VaultSession).filter(VaultSession.user_id == user.id, VaultSession.revoked_at.is_(None)).update({VaultSession.revoked_at: datetime.utcnow()}, synchronize_session=False)
    db.commit()
    write_audit(db, user, "disable_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/profile", status_code=303)
