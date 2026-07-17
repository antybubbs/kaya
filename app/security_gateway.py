"""Minimal public-facing Secure Send recipient application."""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import smtplib
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.core.branding import BRAND_CONTEXT
from app.core.config import get_settings
from app.db.session import SessionLocal, get_db
from app.models.models import SecureSendFile, SecureSendPackage
from app.services.audit import write_audit
from app.services.client_ip import client_ip
from app.services.mail import MailConfigurationError, send_mail
from app.services.secure_send import (
    SESSION_COOKIE, SecureSendError, active_recipient_session, authenticate_package, build_zip, decode_note,
    decode_summary, decoded_files, package_accessible, package_for_token, package_key_from_application, read_file,
    gateway_health_token, record_activity, revoke_recipient_sessions, start_recipient_session, verify_session_csrf,
)
from app.services.site_settings import get_site_setting

settings = get_settings()
logger = logging.getLogger("kaya.secure_send.gateway")
app = FastAPI(title="Kaya Secure Send", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory="app/templates")
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="secure_send_state", same_site="strict", https_only=settings.session_cookie_secure, max_age=1800)
ATTEMPTS: dict[str, list[float]] = {}
PUBLIC_REQUESTS: dict[str, list[float]] = {}
GATEWAY_HOST_CACHE: dict[str, object] = {"expires": 0.0, "hostname": ""}
ACCESS_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{64}$")
RECIPIENT_PATH_RE = re.compile(r"^/[A-Za-z0-9_-]{64}(?:/unlock|/download-package|/logout|/files/[1-9][0-9]*)?$")
STATIC_FILES = {
    "/assets/gateway.css": (Path("app/static/css/secure-send-gateway.css"), "text/css; charset=utf-8"),
    "/assets/logo.png": (Path("app/static/brand/kaya-favicon-192-transparent.png"), "image/png"),
    "/favicon.svg": (Path("app/static/brand/kaya-favicon.svg"), "image/svg+xml"),
}


def security_headers(response: Response, *, https: bool) -> Response:
    response.headers.update({
        "Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        # Edge can serialize the Origin header as "null" for a form POST when
        # the document policy is no-referrer. Keep the bearer-token path out of
        # referrers while preserving a usable same-origin CSRF signal.
        "Referrer-Policy": "strict-origin", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()", "Cache-Control": "no-store, max-age=0",
        "Pragma": "no-cache", "Expires": "0", "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin", "X-Permitted-Cross-Domain-Policies": "none",
    })
    if https:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def forbidden(*, https: bool = False) -> Response:
    return security_headers(PlainTextResponse("Forbidden", status_code=403), https=https)


def rejected(request: Request, reason: str, *, https: bool = False) -> Response:
    # Never log the request path: it contains the bearer access token. Reasons
    # are fixed internal labels and deliberately exclude headers, form values,
    # client addresses, and other recipient data.
    logger.warning("Secure Send request rejected method=%s reason=%s", request.method.upper(), reason)
    return forbidden(https=https)


def request_is_https(request: Request) -> bool:
    # Uvicorn updates ASGI scope.scheme only for forwarding proxies explicitly
    # trusted by --forwarded-allow-ips; never trust the raw browser header here.
    return request.url.scheme == "https"


def health_authorised(request: Request) -> bool:
    supplied = request.headers.get("x-kaya-health", "")
    return bool(supplied and hmac.compare_digest(supplied, gateway_health_token()))


def configured_gateway_hostname() -> str:
    now = time.monotonic()
    if float(GATEWAY_HOST_CACHE.get("expires") or 0) > now:
        return str(GATEWAY_HOST_CACHE.get("hostname") or "")
    hostname = ""
    db = SessionLocal()
    try:
        hostname = (urlparse(get_site_setting(db, "secure_send_gateway_hostname") or "").hostname or "").lower()
    except (SQLAlchemyError, OSError, ValueError):
        hostname = ""
    finally:
        db.close()
    GATEWAY_HOST_CACHE.update({"expires": now + 15.0, "hostname": hostname})
    return hostname


def host_allowed(request: Request) -> bool:
    if request.url.path == "/healthz" and health_authorised(request):
        return True
    supplied = (urlparse(f"//{request.headers.get('host', '')}").hostname or "").lower()
    expected = configured_gateway_hostname()
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def origin_allowed(request: Request) -> bool:
    origin = request.headers.get("origin", "")
    parsed = urlparse(origin)
    expected = configured_gateway_hostname()
    if not origin or not parsed.scheme or not parsed.hostname or not expected:
        return False
    if request.headers.get("sec-fetch-site", "same-origin") not in {"same-origin", "none"}:
        return False
    if request_is_https(request) and parsed.scheme.lower() != "https":
        return False
    return hmac.compare_digest(parsed.hostname.lower(), expected)


def route_shape_allowed(request: Request) -> bool:
    path, method = request.url.path, request.method.upper()
    if request.url.query or len(path) > 240:
        return False
    if path == "/healthz":
        return method == "GET" and health_authorised(request)
    if path in STATIC_FILES:
        return method in {"GET", "HEAD"}
    if not RECIPIENT_PATH_RE.fullmatch(path):
        return False
    suffix = path.split("/", 2)[2] if path.count("/") > 1 else ""
    if not suffix:
        return method == "GET"
    return method == "POST"


def public_rate_limited(request: Request) -> bool:
    now = time.monotonic(); key = client_ip(request) or "unknown"
    recent = [value for value in PUBLIC_REQUESTS.get(key, []) if now - value < 60]
    recent.append(now); PUBLIC_REQUESTS[key] = recent
    if len(PUBLIC_REQUESTS) > 10000:
        for stale_key in list(PUBLIC_REQUESTS)[:1000]:
            if not PUBLIC_REQUESTS[stale_key] or now - PUBLIC_REQUESTS[stale_key][-1] >= 60:
                PUBLIC_REQUESTS.pop(stale_key, None)
    return len(recent) > 120


@app.middleware("http")
async def gateway_headers(request: Request, call_next):
    https = request_is_https(request)
    if not route_shape_allowed(request):
        return rejected(request, "route_shape", https=https)
    if not host_allowed(request):
        return rejected(request, "host", https=https)
    if request.url.path != "/healthz" and public_rate_limited(request):
        logger.warning("Secure Send request rejected method=%s reason=public_rate_limit", request.method.upper())
        return security_headers(PlainTextResponse("Too Many Requests", status_code=429), https=https)
    if request.method == "POST":
        if not origin_allowed(request):
            return rejected(request, "origin", https=https)
        try: content_length = int(request.headers.get("content-length", "0"))
        except ValueError: return rejected(request, "content_length_invalid", https=https)
        if content_length < 1 or content_length > 8192:
            return rejected(request, "content_length_bounds", https=https)
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
            return rejected(request, "content_type", https=https)
    response = await call_next(request)
    if response.status_code == 404:
        return forbidden(https=https)
    security_headers(response, https=https)
    if https:
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
    if not ACCESS_TOKEN_RE.fullmatch(token):
        logger.warning("Secure Send request rejected reason=access_token_shape")
        raise HTTPException(403, "Forbidden")
    row = package_for_token(db, token); state = safe_state(row)
    if state != "active":
        logger.warning("Secure Send request rejected reason=package_state state=%s", state)
        raise HTTPException(403, "Forbidden")
    return row


@app.exception_handler(HTTPException)
async def public_error(request: Request, exc: HTTPException):
    if exc.status_code == 429:
        return security_headers(PlainTextResponse("Too Many Requests", status_code=429), https=request_is_https(request))
    endpoint = getattr(request.scope.get("endpoint"), "__name__", "unmatched")
    logger.warning(
        "Secure Send endpoint rejected method=%s endpoint=%s status=%s",
        request.method.upper(), endpoint, exc.status_code,
    )
    return forbidden(https=request_is_https(request))


@app.get("/healthz", include_in_schema=False)
def healthz(): return {"status": "ok"}


@app.get("/assets/gateway.css", include_in_schema=False)
@app.head("/assets/gateway.css", include_in_schema=False)
def gateway_css(): return FileResponse(STATIC_FILES["/assets/gateway.css"][0], media_type="text/css")


@app.get("/assets/logo.png", include_in_schema=False)
@app.head("/assets/logo.png", include_in_schema=False)
def gateway_logo(): return FileResponse(STATIC_FILES["/assets/logo.png"][0], media_type="image/png")


@app.get("/favicon.svg", include_in_schema=False)
@app.head("/favicon.svg", include_in_schema=False)
def gateway_favicon(): return FileResponse(STATIC_FILES["/favicon.svg"][0], media_type="image/svg+xml")


def demo_or_disabled(db: Session) -> None:
    if settings.demo_mode or get_site_setting(db, "secure_send_enabled") != "1":
        logger.warning("Secure Send request rejected reason=demo_or_disabled")
        raise HTTPException(403, "Forbidden")


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
        save_url=f"{(get_site_setting(db, 'base_url') or '').rstrip('/')}/security/secure-send/receive/{row.id}",
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
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, token, max_age=900, httponly=True, secure=request_is_https(request), samesite="strict", path="/")
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
    demo_or_disabled(db); row = package_or_error(db, access_token)
    session = active_recipient_session(db, row, request.cookies.get(SESSION_COOKIE))
    if not session or not verify_session_csrf(session, csrf_token): raise HTTPException(403, "Forbidden")
    session.revoked_at = datetime.utcnow(); db.commit()
    request.session.clear(); response = RedirectResponse("/", status_code=303); response.delete_cookie(SESSION_COOKIE, path="/"); response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'; return response
