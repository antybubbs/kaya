"""Minimal public-facing Secure Send recipient application."""
from __future__ import annotations

import hashlib
import secrets
import smtplib
import time
from datetime import datetime, timedelta
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.core.branding import BRAND_CONTEXT
from app.core.config import get_settings
from app.db.session import get_db
from app.models.models import SecureSendFile, SecureSendPackage
from app.services.audit import write_audit
from app.services.client_ip import client_ip
from app.services.mail import MailConfigurationError, send_mail
from app.services.secure_send import (
    SESSION_COOKIE, SecureSendError, active_recipient_session, authenticate_package, build_zip, decode_note,
    decode_summary, decoded_files, package_accessible, package_for_token, package_key_from_application, read_file,
    record_activity, revoke_recipient_sessions, start_recipient_session, verify_session_csrf,
)
from app.services.site_settings import get_site_setting

settings = get_settings()
app = FastAPI(title="Kaya Secure Send", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory="app/templates")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="secure_send_state", same_site="strict", https_only=settings.session_cookie_secure, max_age=1800)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
ATTEMPTS: dict[str, list[float]] = {}


@app.middleware("http")
async def gateway_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({
        "Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store",
    })
    request_is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip() == "https"
    if request_is_https:
        for index, (name, value) in enumerate(response.raw_headers):
            if name.lower() == b"set-cookie" and b" secure" not in value.lower():
                response.raw_headers[index] = (name, value + b"; Secure")
    return response


def public_context(request: Request, **values):
    return {"brand": BRAND_CONTEXT, "csrf_token": request.session.get("recipient_csrf", ""), **values}


def safe_state(row: SecureSendPackage | None) -> str:
    if not row: return "missing"
    if row.revoked_at or row.status == "revoked": return "revoked"
    if row.deleted_at or row.status == "deleted": return "missing"
    if row.one_download_only and row.download_count >= 1: return "expired"
    if row.expires_at <= datetime.utcnow() or row.expired_at or row.status == "expired": return "expired"
    return "active"


def package_or_error(db: Session, token: str) -> SecureSendPackage:
    row = package_for_token(db, token); state = safe_state(row)
    if state == "missing": raise HTTPException(404, "This secure package could not be found.")
    if state == "expired": raise HTTPException(410, "This secure package has expired and is no longer available.")
    if state == "revoked": raise HTTPException(410, "This secure package has been withdrawn by the sender.")
    return row


@app.exception_handler(HTTPException)
async def public_error(request: Request, exc: HTTPException):
    message = str(exc.detail) if exc.status_code in {404, 410, 429} else "Secure Send is temporarily unavailable. Please try again later."
    return templates.TemplateResponse(request, "secure_send_gateway_error.html", public_context(request, message=message), status_code=exc.status_code)


@app.get("/healthz", include_in_schema=False)
def healthz(): return {"status": "ok"}


def demo_or_disabled(db: Session) -> None:
    if settings.demo_mode or get_site_setting(db, "secure_send_enabled") != "1": raise HTTPException(404, "This secure package could not be found.")


def attempt_limited(request: Request, row: SecureSendPackage) -> bool:
    now = time.monotonic(); key = f"{client_ip(request)}:{row.id}"
    ATTEMPTS[key] = [value for value in ATTEMPTS.get(key, []) if now - value < 900]
    return len(ATTEMPTS[key]) >= 10 or bool(row.locked_until and row.locked_until > datetime.utcnow())


def notify_sender(db: Session, row: SecureSendPackage, event: str) -> None:
    if get_site_setting(db, "secure_send_email_notifications") != "1": return
    try: send_mail(db, row.sender.email, f"Secure Send package {event}", f"One of your Secure Send packages was {event}. Open Kaya to review its activity.")
    except (MailConfigurationError, OSError, ValueError, smtplib.SMTPException): pass


@app.get("/{access_token}")
def recipient(access_token: str, request: Request, db: Session = Depends(get_db)):
    demo_or_disabled(db); row = package_or_error(db, access_token)
    if not row.opened_at:
        row.opened_at = datetime.utcnow(); row.status = "opened"; record_activity(db, row, "opened", commit=False); db.commit()
        write_audit(db, row.sender, "secure_send_opened", "secure_send_package", str(row.id), client_ip(request), category="security")
        if row.notify_when_opened: notify_sender(db, row, "opened")
    session = active_recipient_session(db, row, request.cookies.get(SESSION_COOKIE))
    if not session:
        return templates.TemplateResponse(request, "secure_send_gateway_unlock.html", public_context(request, error=None, access_token=access_token))
    key = package_key_from_application(row); summary = decode_summary(row, key); files = decoded_files(db, row, key); note = decode_note(row, key)
    return templates.TemplateResponse(request, "secure_send_gateway_package.html", public_context(
        request, package=row, files=files, note=note, access_token=access_token,
        expires_at=row.expires_at, allow_vault_save=row.allow_vault_save and row.internal_recipient_id,
        save_url=f"{(get_site_setting(db, 'base_url') or '').rstrip('/')}/security/secure-send/receive/{quote(access_token, safe='')}",
    ))


@app.post("/{access_token}/unlock")
def unlock(access_token: str, request: Request, pin: str = Form(""), passphrase: str = Form(""), db: Session = Depends(get_db)):
    demo_or_disabled(db); row = package_or_error(db, access_token)
    if attempt_limited(request, row): raise HTTPException(429, "Too many attempts. Please try again later.")
    try: authenticate_package(row, access_token, pin, passphrase)
    except SecureSendError:
        key = f"{client_ip(request)}:{row.id}"; ATTEMPTS.setdefault(key, []).append(time.monotonic()); row.failed_attempts += 1
        if row.failed_attempts >= 10: row.locked_until = datetime.utcnow() + timedelta(minutes=30)
        elif row.failed_attempts >= 5: row.locked_until = datetime.utcnow() + timedelta(minutes=5)
        db.commit(); record_activity(db, row, "authentication_failed")
        write_audit(db, row.sender, "secure_send_authentication_failed", "secure_send_package", str(row.id), client_ip(request), category="security", severity="warning")
        return templates.TemplateResponse(request, "secure_send_gateway_unlock.html", public_context(request, error="The information entered is incorrect. Please check your PIN and passphrase and try again.", access_token=access_token), status_code=400)
    row.failed_attempts = 0; row.locked_until = None; row.authenticated_at = datetime.utcnow(); db.commit()
    token, csrf, _ = start_recipient_session(db, row); request.session["recipient_csrf"] = csrf
    record_activity(db, row, "authenticated"); write_audit(db, row.sender, "secure_send_authenticated", "secure_send_package", str(row.id), client_ip(request), category="security")
    response = RedirectResponse(f"/{quote(access_token, safe='')}", status_code=303)
    response.set_cookie(SESSION_COOKIE, token, max_age=900, httponly=True, secure=request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https", samesite="strict", path="/")
    return response


def authorised_download(db: Session, request: Request, access_token: str, csrf_token: str) -> tuple[SecureSendPackage, bytes]:
    row = package_or_error(db, access_token); session = active_recipient_session(db, row, request.cookies.get(SESSION_COOKIE))
    if not session or not verify_session_csrf(session, csrf_token): raise HTTPException(403, "Secure Send is temporarily unavailable. Please try again later.")
    if row.one_download_only and row.download_count >= 1: raise HTTPException(410, "This secure package is no longer available for download.")
    return row, package_key_from_application(row)


def mark_download(db: Session, request: Request, row: SecureSendPackage) -> None:
    row.download_count += 1; row.downloaded_at = datetime.utcnow(); row.status = "downloaded"
    record_activity(db, row, "downloaded", commit=False)
    if row.one_download_only: revoke_recipient_sessions(db, row.id, commit=False)
    db.commit(); write_audit(db, row.sender, "secure_send_downloaded", "secure_send_package", str(row.id), client_ip(request), category="security", metadata={"download_count": row.download_count})
    notify_sender(db, row, "downloaded")


@app.post("/{access_token}/files/{file_id}")
def download_file(access_token: str, file_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    demo_or_disabled(db); row, key = authorised_download(db, request, access_token, csrf_token)
    item = db.query(SecureSendFile).filter_by(id=file_id, package_id=row.id).first()
    if not item: raise HTTPException(404, "This secure package could not be found.")
    metadata = next((value for value in decoded_files(db, row, key) if value["row"].id == item.id), None)
    if not metadata: raise HTTPException(404, "This secure package could not be found.")
    content = read_file(row, item, key); item.downloaded_at = datetime.utcnow(); mark_download(db, request, row)
    filename = str(metadata["name"]).replace('"', "")
    return Response(content, media_type=metadata["content_type"], headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}", "Cache-Control": "no-store"})


@app.post("/{access_token}/download-package")
def download_package(access_token: str, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    demo_or_disabled(db); row, key = authorised_download(db, request, access_token, csrf_token); content = build_zip(db, row, key); mark_download(db, request, row)
    return Response(content, media_type="application/zip", headers={"Content-Disposition": "attachment; filename=secure-package.zip", "Cache-Control": "no-store"})


@app.post("/{access_token}/logout")
def logout(access_token: str, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    row = package_for_token(db, access_token); session = active_recipient_session(db, row, request.cookies.get(SESSION_COOKIE)) if row else None
    if session and verify_session_csrf(session, csrf_token): session.revoked_at = datetime.utcnow(); db.commit()
    request.session.clear(); response = RedirectResponse(f"/{quote(access_token, safe='')}", status_code=303); response.delete_cookie(SESSION_COOKIE, path="/"); return response
