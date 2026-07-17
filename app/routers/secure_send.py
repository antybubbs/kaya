from __future__ import annotations

import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import (
    SecureSendActivity, SecureSendFile, SecureSendPackage, User, Vault, VaultAttachment, VaultItem, VaultItemVersion,
)
from app.routers.auth import require_user
from app.services.audit import write_audit
from app.services.mail import MailConfigurationError, render_email_template, send_mail
from app.services.secure_send import (
    SecureSendError, authenticate_package, clean_package_content, create_package, decode_note, decode_summary,
    decoded_files, decrypted_access_token, expire_and_cleanup, gateway_health,
    package_accessible, package_key_from_application, read_file, record_activity,
    revoke_recipient_sessions, validate_pin,
)
from app.services.site_settings import get_site_setting

router = APIRouter(prefix="/security/secure-send")


def person_name(first_name: str | None, last_name: str | None, fallback: str) -> str:
    """Return a clean display name when a full name was stored as first name."""
    first = " ".join((first_name or "").split())
    last = " ".join((last_name or "").split())
    if first and last:
        folded_first, folded_last = first.casefold(), last.casefold()
        if folded_first == folded_last or folded_first.endswith(f" {folded_last}"):
            return first
    return " ".join(value for value in (first, last) if value) or fallback
templates = Jinja2Templates(directory="app/templates")
settings = get_settings()
EXPIRY_CHOICES = {"15m": 15, "1h": 60, "4h": 240, "24h": 1440, "3d": 4320, "7d": 10080}


def module_enabled(db: Session) -> bool:
    return not settings.demo_mode and get_site_setting(db, "secure_send_enabled") == "1"


def require_module(db: Session, *, creation: bool = False) -> None:
    if settings.demo_mode and creation:
        raise HTTPException(403, "Secure Send package creation is disabled in the public demo.")
    if not module_enabled(db):
        raise HTTPException(404, "Secure Send is not available")


def can_create(user: User) -> bool:
    return user.role in {"admin", "editor"}


def gateway_base(db: Session) -> str:
    return (get_site_setting(db, "secure_send_gateway_hostname") or "http://localhost:8999").strip().rstrip("/")


def secure_url(db: Session, row: SecureSendPackage) -> str:
    return f"{gateway_base(db)}/{quote(decrypted_access_token(row), safe='')}"


def safe_summary(row: SecureSendPackage) -> dict:
    try: return decode_summary(row)
    except SecureSendError: return {"title": "Secure package", "recipient_name": "Unavailable", "recipient_email": ""}


def current_status(row: SecureSendPackage) -> str:
    if row.deleted_at: return "deleted"
    if row.revoked_at: return "revoked"
    if row.expires_at <= datetime.utcnow(): return "expired"
    if row.downloaded_at: return "downloaded"
    if row.opened_at: return "opened"
    return "active"


def page_context(request: Request, user: User, **values):
    return {"user": user, "expiry_choices": EXPIRY_CHOICES, **csrf_context(request), **values}


@router.get("/gateway-status", include_in_schema=False)
def gateway_status(db: Session = Depends(get_db), user: User = Depends(require_user)):
    require_module(db)
    return JSONResponse(gateway_health(), headers={"Cache-Control": "no-store"})


@router.get("")
def home(request: Request, view: str = Query("dashboard"), db: Session = Depends(get_db), user: User = Depends(require_user)):
    if settings.demo_mode:
        return templates.TemplateResponse(request, "secure_send_disabled.html", page_context(request, user))
    require_module(db); expire_and_cleanup(db)
    sent = db.query(SecureSendPackage).filter_by(sender_id=user.id).order_by(SecureSendPackage.created_at.desc()).all()
    received = db.query(SecureSendPackage).filter_by(internal_recipient_id=user.id).order_by(SecureSendPackage.created_at.desc()).all()
    managed = db.query(SecureSendPackage).order_by(SecureSendPackage.created_at.desc()).all() if user.role == "admin" else []
    sent_rows = [{"row": row, "summary": safe_summary(row), "status": current_status(row)} for row in sent if not row.deleted_at]
    received_rows = [{"row": row, "summary": safe_summary(row), "status": current_status(row), "url": secure_url(db, row)} for row in received if package_accessible(row)]
    today = datetime.utcnow().date()
    activity = (
        db.query(SecureSendActivity).join(SecureSendPackage).filter(SecureSendPackage.sender_id == user.id)
        .order_by(SecureSendActivity.created_at.desc()).limit(12).all()
    )
    metrics = {
        "active": sum(1 for item in sent_rows if item["status"] in {"active", "opened", "downloaded"}),
        "opened_today": sum(1 for item in sent_rows if item["row"].opened_at and item["row"].opened_at.date() == today),
        "expiring_today": sum(1 for item in sent_rows if item["row"].expires_at.date() == today and item["status"] not in {"expired", "revoked"}),
        "expired": sum(1 for item in sent_rows if item["status"] == "expired"),
    }
    return templates.TemplateResponse(request, "secure_send.html", page_context(
        request, user, view=view if view in {"dashboard", "sent", "received", "manage"} and (view != "manage" or user.role == "admin") else "dashboard",
        sent=sent_rows, received=received_rows, managed=managed, activity=activity, metrics=metrics,
        can_create=can_create(user), gateway_status=gateway_health(),
    ))


def vault_source(db: Session, request: Request, user: User, item_id: int) -> dict | None:
    if not item_id: return None
    from app.routers.secret_vault import item_payload
    from app.services.secret_vault import decrypt_file as decrypt_vault_file, decrypt_payload, master_key_from_application, require_unlocked
    item = db.get(VaultItem, item_id); vault = db.get(Vault, item.vault_id) if item else None
    if not item or not vault or vault.owner_id != user.id or item.deleted_at: raise HTTPException(404, "Vault item not found")
    require_unlocked(db, request, user); key = master_key_from_application(vault); payload = item_payload(key, item)
    files = []
    for attachment in db.query(VaultAttachment).filter_by(item_id=item.id).all():
        metadata = decrypt_payload(key, vault.id, f"attachment-meta:{attachment.storage_id}", attachment.encrypted_metadata)
        path = Path("data/secret-vault") / attachment.storage_id
        from app.services.secret_vault import ensure_storage as ensure_vault_storage
        path = ensure_vault_storage() / attachment.storage_id
        files.append((Path(str(metadata.get("name") or "vault-file")).name, str(metadata.get("content_type") or "application/octet-stream"), decrypt_vault_file(key, vault.id, attachment.storage_id, path.read_bytes())))
    note_parts = [str(payload.get("body") or "")]
    for field in payload.get("fields") or []:
        if isinstance(field, dict): note_parts.append(f"{field.get('label', 'Field')}: {field.get('value', '')}")
    return {"title": str(payload.get("title") or "Secure Vault item"), "note": "\n\n".join(filter(None, note_parts)), "files": files}


@router.get("/new")
def new_package(request: Request, vault_item_id: int = Query(0), db: Session = Depends(get_db), user: User = Depends(require_user)):
    require_module(db, creation=True)
    if not can_create(user): raise HTTPException(403, "Secure Send creation permission required")
    source = vault_source(db, request, user, vault_item_id) if vault_item_id else None
    users = db.query(User).filter(User.is_active == True, User.id != user.id).order_by(User.email).all()  # noqa: E712
    return templates.TemplateResponse(request, "secure_send_new.html", page_context(
        request, user, users=users, source=source, vault_item_id=vault_item_id, error=None,
        default_expiry=get_site_setting(db, "secure_send_default_expiry") or "24h",
        one_download_allowed=get_site_setting(db, "secure_send_allow_one_download") == "1",
        vault_integration=get_site_setting(db, "secure_send_vault_integration") == "1",
    ))


def expiry_from_form(db: Session, choice: str, custom: str) -> datetime:
    now = datetime.utcnow()
    if choice == "custom":
        try: result = datetime.fromisoformat(custom)
        except ValueError: raise HTTPException(400, "Choose a valid expiry date and time.")
    else:
        minutes = EXPIRY_CHOICES.get(choice)
        if not minutes: raise HTTPException(400, "Choose a valid expiry.")
        result = now + timedelta(minutes=minutes)
    try: maximum_days = max(1, min(int(get_site_setting(db, "secure_send_max_expiry_days") or 7), 30))
    except ValueError: maximum_days = 7
    maximum = now + timedelta(days=maximum_days)
    try: valid = result > now and result <= maximum
    except TypeError: valid = False
    if not valid: raise HTTPException(400, "Expiry must be in the future and within the site maximum.")
    return result


@router.post("/new")
async def create(
    request: Request, recipient_type: str = Form("external"), internal_recipient_id: int = Form(0),
    recipient_name: str = Form("", max_length=255), recipient_email: str = Form("", max_length=255),
    description: str = Form("", max_length=500), secure_note: str = Form("", max_length=200000),
    pin: str = Form("", max_length=32), pin_confirm: str = Form("", max_length=32), expiry: str = Form("24h"),
    custom_expiry: str = Form(""), notify_when_opened: str = Form(""), one_download_only: str = Form(""),
    allow_vault_save: str = Form(""), vault_item_id: int = Form(0), csrf_token: str = Form(...),
    files: list[UploadFile] = File(default=[]), db: Session = Depends(get_db), user: User = Depends(require_user),
):
    validate_csrf_token(request, csrf_token); require_module(db, creation=True)
    if not can_create(user): raise HTTPException(403, "Secure Send creation permission required")
    error = validate_pin(pin)
    if pin != pin_confirm: error = "The PIN confirmation does not match."
    source = vault_source(db, request, user, vault_item_id) if vault_item_id else None
    internal = db.get(User, internal_recipient_id) if recipient_type == "internal" and internal_recipient_id else None
    if recipient_type == "internal":
        if not internal or not internal.is_active or internal.id == user.id: error = "Choose a valid Kaya recipient."
        else:
            recipient_email = internal.email; recipient_name = person_name(internal.first_name, internal.last_name, internal.email)
    elif not recipient_name.strip() or "@" not in recipient_email:
        error = "Enter the external recipient's name and email address."
    try: upload_mb = max(1, min(int(get_site_setting(db, "secure_send_max_upload_mb") or 25), 250))
    except ValueError: upload_mb = 25
    upload_limit = upload_mb * 1024 * 1024
    payload_files = list(source["files"] if source else [])
    total = sum(len(value[2]) for value in payload_files)
    for upload in files:
        content = await upload.read(upload_limit + 1)
        total += len(content)
        if total > upload_limit: error = f"The package exceeds the {upload_limit // 1024 // 1024} MB site limit."; break
        if upload.filename: payload_files.append((Path(upload.filename).name[:255], (upload.content_type or "application/octet-stream")[:120], content))
    note = source["note"] if source else secure_note.strip()
    title = (source["title"] if source else description.strip()) or "Secure package"
    if not payload_files and not note: error = "Add at least one file or a secure note."
    if error:
        users = db.query(User).filter(User.is_active == True, User.id != user.id).order_by(User.email).all()  # noqa: E712
        return templates.TemplateResponse(request, "secure_send_new.html", page_context(request, user, users=users, source=source, vault_item_id=vault_item_id, error=error, default_expiry=expiry, one_download_allowed=get_site_setting(db, "secure_send_allow_one_download") == "1", vault_integration=get_site_setting(db, "secure_send_vault_integration") == "1"), status_code=400)
    expires_at = expiry_from_form(db, expiry, custom_expiry)
    row, token, passphrase = create_package(
        db, user, recipient_type=recipient_type, internal_recipient_id=internal.id if internal else None,
        summary={"title": title, "recipient_name": recipient_name.strip(), "recipient_email": recipient_email.strip().lower(), "description": description.strip(), "file_names": [x[0] for x in payload_files]},
        note=note, pin=pin, expires_at=expires_at,
        one_download_only=bool(one_download_only) and get_site_setting(db, "secure_send_allow_one_download") == "1",
        allow_vault_save=bool(allow_vault_save) and bool(internal) and get_site_setting(db, "secure_send_vault_integration") == "1",
        notify_when_opened=bool(notify_when_opened), files=payload_files,
    )
    write_audit(db, user, "secure_send_created", "secure_send_package", str(row.id), category="security", metadata={"recipient_type": recipient_type, "expires_at": expires_at.isoformat(), "file_count": len(payload_files)})
    url = f"{gateway_base(db)}/{quote(token, safe='')}"
    if get_site_setting(db, "secure_send_email_notifications") == "1":
        try:
            sender_name = person_name(user.first_name, user.last_name, user.email)
            template_values = {
                "app_name": get_site_setting(db, "app_name") or "Kaya",
                "sender_name": sender_name,
                "sender_email": user.email,
                "recipient_name": recipient_name.strip(),
                "package_title": title.strip() or "Secure package",
                "secure_link": url,
                "expiry_utc": f"{expires_at:%Y-%m-%d %H:%M} UTC",
            }
            subject = render_email_template(
                get_site_setting(db, "email_template_secure_send_subject"), **template_values
            )
            body = render_email_template(
                get_site_setting(db, "email_template_secure_send_body"), **template_values
            )
            send_mail(db, recipient_email, subject, body, action_url=url, action_label="Open secure package")
            record_activity(db, row, "shared", actor_user_id=user.id)
        except (MailConfigurationError, OSError, ValueError, smtplib.SMTPException):
            record_activity(db, row, "email_failed", actor_user_id=user.id)
    return templates.TemplateResponse(request, "secure_send_created.html", page_context(request, user, package=row, url=url, passphrase=passphrase))


@router.get("/packages/{package_id}")
def details(package_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    require_module(db); expire_and_cleanup(db)
    row = db.get(SecureSendPackage, package_id)
    if not row or (row.sender_id != user.id and user.role != "admin"): raise HTTPException(404, "Secure package not found")
    is_sender = row.sender_id == user.id
    summary = safe_summary(row) if is_sender else {"title": "Secure package", "recipient_name": "Protected", "recipient_email": ""}
    key = package_key_from_application(row) if is_sender and not row.cleaned_at else None
    files = decoded_files(db, row, key) if key else []
    activities = db.query(SecureSendActivity).filter_by(package_id=row.id).order_by(SecureSendActivity.created_at).all()
    return templates.TemplateResponse(request, "secure_send_detail.html", page_context(request, user, package=row, summary=summary, files=files, activities=activities, status=current_status(row), url=secure_url(db, row) if is_sender else "", is_sender=is_sender))


@router.post("/packages/{package_id}/revoke")
def revoke(package_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); require_module(db)
    row = db.get(SecureSendPackage, package_id)
    if not row or (row.sender_id != user.id and user.role != "admin"): raise HTTPException(404, "Secure package not found")
    if package_accessible(row):
        row.revoked_at = datetime.utcnow(); row.status = "revoked"; revoke_recipient_sessions(db, row.id, commit=False); record_activity(db, row, "revoked", actor_user_id=user.id, commit=False); db.commit()
        write_audit(db, user, "secure_send_revoked", "secure_send_package", str(row.id), category="security", severity="warning")
    return RedirectResponse(f"/security/secure-send/packages/{row.id}", status_code=303)


@router.post("/packages/{package_id}/extend")
def extend(package_id: int, request: Request, expiry: str = Form("24h"), custom_expiry: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); require_module(db)
    row = db.get(SecureSendPackage, package_id)
    if not row or row.sender_id != user.id or row.revoked_at or row.deleted_at: raise HTTPException(404, "Secure package not found")
    row.expires_at = expiry_from_form(db, expiry, custom_expiry); row.expired_at = None; row.status = current_status(row); record_activity(db, row, "expiry_extended", actor_user_id=user.id, commit=False); db.commit()
    write_audit(db, user, "secure_send_expiry_extended", "secure_send_package", str(row.id), category="security", metadata={"expires_at": row.expires_at.isoformat()})
    return RedirectResponse(f"/security/secure-send/packages/{row.id}", status_code=303)


@router.post("/packages/{package_id}/delete")
def delete(package_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); require_module(db)
    row = db.get(SecureSendPackage, package_id)
    if not row or (row.sender_id != user.id and user.role != "admin"): raise HTTPException(404, "Secure package not found")
    record_activity(db, row, "deleted", actor_user_id=user.id, commit=False); clean_package_content(db, row, status="deleted")
    write_audit(db, user, "secure_send_deleted", "secure_send_package", str(row.id), category="security", severity="warning")
    return RedirectResponse("/security/secure-send?view=sent", status_code=303)


@router.get("/receive/{package_id}")
def receive_page(package_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    require_module(db); row = db.get(SecureSendPackage, package_id)
    if not row or row.internal_recipient_id != user.id or not row.allow_vault_save or not package_accessible(row): raise HTTPException(404, "Secure package not found")
    return templates.TemplateResponse(request, "secure_send_save_to_vault.html", page_context(request, user, package_id=package_id, error=None))


@router.post("/receive/{package_id}/save")
def save_to_vault(package_id: int, request: Request, pin: str = Form(""), passphrase: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); require_module(db); row = db.get(SecureSendPackage, package_id)
    if not row or row.internal_recipient_id != user.id or not row.allow_vault_save or not package_accessible(row): raise HTTPException(404, "Secure package not found")
    try: key = authenticate_package(row, decrypted_access_token(row), pin, passphrase)
    except SecureSendError:
        return templates.TemplateResponse(request, "secure_send_save_to_vault.html", page_context(request, user, package_id=package_id, error="The information entered is incorrect."), status_code=400)
    from app.services.secret_vault import encrypt_file as encrypt_vault_file, encrypt_payload, ensure_storage as ensure_vault_storage, require_unlocked
    try: vault, vault_key = require_unlocked(db, request, user)
    except HTTPException:
        return templates.TemplateResponse(request, "secure_send_save_to_vault.html", page_context(request, user, package_id=package_id, error="Unlock your Secret Vault first, then return here to save the package."), status_code=403)
    summary = decode_summary(row, key); note = decode_note(row, key)
    item = VaultItem(vault_id=vault.id, item_type="secure_document" if db.query(SecureSendFile.id).filter_by(package_id=row.id).first() else "secure_note", encrypted_payload="pending", created_by_id=user.id, updated_by_id=user.id)
    db.add(item); db.flush(); payload = {"title": summary.get("title") or "Received secure package", "body": note, "fields": [], "tags": ["secure-send"], "classification": "confidential", "expiry_date": "", "review_date": ""}
    item.encrypted_payload = encrypt_payload(vault_key, vault.id, f"item:{item.id}", payload)
    db.add(VaultItemVersion(item_id=item.id, version=1, encrypted_payload=item.encrypted_payload, saved_by_id=user.id))
    for source in decoded_files(db, row, key):
        content = read_file(row, source["row"], key); storage_id = secrets.token_hex(24); encrypted = encrypt_vault_file(vault_key, vault.id, storage_id, content); (ensure_vault_storage() / storage_id).write_bytes(encrypted)
        db.add(VaultAttachment(item_id=item.id, storage_id=storage_id, encrypted_metadata=encrypt_payload(vault_key, vault.id, f"attachment-meta:{storage_id}", {"name": source["name"], "content_type": source["content_type"]}), size_bytes=len(content), ciphertext_size=len(encrypted), integrity_hash=hashlib.sha256(encrypted).hexdigest()))
    db.commit(); record_activity(db, row, "saved_to_vault", actor_user_id=user.id)
    write_audit(db, user, "secure_send_saved_to_vault", "vault_item", str(item.id), category="security", metadata={"package_id": row.id})
    return RedirectResponse(f"/security/secret-vault/items/{item.id}", status_code=303)
