from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.csrf import csrf_context, validate_csrf_token
from app.core.config import get_settings
from app.core.security import verify_password
from app.db.session import get_db
from app.models.models import (
    AuditLog, ExternalIdentity, OIDCProvider, User, Vault, VaultAttachment, VaultBackupRecord, VaultCollection,
    VaultCollectionMember, VaultItem, VaultItemVersion,
)
from app.routers.auth import require_user
from app.services.audit import write_audit
from app.services.oidc_client import safe_return_path
from app.services.secret_vault import (
    VaultCryptoError, active_vault_session, clear_failed_unlock, create_vault,
    decrypt_file, decrypt_payload, encrypt_file, encrypt_payload,
    ensure_storage, lock_vault, master_key_from_application, master_key_from_pin,
    master_key_from_recovery, record_failed_unlock, require_unlocked,
    reset_pin, rotate_recovery_key, safe_reference, start_vault_session, validate_pin,
    verify_fresh_totp, encrypt_portable_package, decrypt_portable_package,
)
from app.services.site_settings import get_site_setting

router = APIRouter(prefix="/security/secret-vault")
templates = Jinja2Templates(directory="app/templates")
settings = get_settings()
ITEM_TYPES = {
    "secure_note": "Secure Note", "secure_document": "Secure Document",
    "recovery_record": "Recovery Record", "sensitive_data": "Sensitive Data Record",
    "certificate": "Certificate Record", "recovery_kit": "Recovery Kit",
}
MEMBER_LEVELS = {"viewer", "viewer_downloader", "contributor", "manager", "owner"}


def has_access(user: User) -> bool:
    # Kaya currently has role-based module permissions. All active roles may own
    # a private vault; collection and item mutations remain role/ownership bound.
    return user.role in {"admin", "editor", "viewer"}


def base_context(request: Request, user: User, **values):
    return {"user": user, "item_types": ITEM_TYPES, **csrf_context(request), **values}


def oidc_vault_context(db: Session, request: Request, user: User, purpose: str) -> dict:
    identity = db.query(ExternalIdentity).filter_by(user_id=user.id).first()
    provider = db.get(OIDCProvider, identity.provider_id) if identity else None
    policy = get_site_setting(db, "secret_vault_oidc_mfa_policy") or "either"
    approval = request.session.get("vault_oidc_approval") or {}
    try:
        age = int(datetime.now(timezone.utc).timestamp()) - int(approval.get("issued_at"))
        fresh = 0 <= age <= 300
    except (TypeError, ValueError):
        fresh = False
    approved = bool(
        fresh and approval.get("user_id") == user.id and approval.get("purpose") == purpose
        and approval.get("method") == "oidc_mfa"
    )
    return {
        "oidc_provider": provider,
        "oidc_allowed": bool(provider and provider.is_enabled and policy in {"idp_mfa", "either"}),
        "oidc_approved": approved,
        "totp_allowed": bool(user.totp_enabled and (not identity or policy in {"kaya_totp", "either"})),
        "vault_mfa_policy": policy,
    }


def consume_oidc_approval(request: Request, user: User, purpose: str) -> bool:
    approval = request.session.pop("vault_oidc_approval", None) or {}
    try:
        age = int(datetime.now(timezone.utc).timestamp()) - int(approval.get("issued_at"))
    except (TypeError, ValueError):
        return False
    return bool(
        0 <= age <= 300 and approval.get("user_id") == user.id
        and approval.get("purpose") == purpose and approval.get("method") == "oidc_mfa"
    )


def vault_for_user(db: Session, user: User) -> Vault | None:
    return db.query(Vault).filter_by(owner_id=user.id).first()


def require_access(user: User) -> None:
    if not has_access(user):
        raise HTTPException(status_code=403, detail="Secret Vault permission required")


def safe_audit(db: Session, user: User, action: str, entity: str, entity_id: int | str | None = None, **metadata):
    return write_audit(
        db, user, action, entity, str(entity_id) if entity_id is not None else None,
        detail="Secret Vault security operation", category="security", metadata=metadata or None,
    )


def item_payload(master_key: bytes, item: VaultItem) -> dict:
    return decrypt_payload(master_key, item.vault_id, f"item:{item.id}", item.encrypted_payload)


def collection_payload(master_key: bytes, row: VaultCollection) -> dict:
    return decrypt_payload(master_key, row.vault_id, f"collection:{row.id}", row.encrypted_payload)


def accessible_item(db: Session, user: User, item_id: int) -> tuple[VaultItem, Vault, bytes, str]:
    item = db.get(VaultItem, item_id)
    if not item or item.deleted_at:
        raise HTTPException(404, "Vault item not found")
    owner_vault = db.get(Vault, item.vault_id)
    permission = "owner" if owner_vault and owner_vault.owner_id == user.id else ""
    if not permission and item.collection_id:
        member = db.query(VaultCollectionMember).filter_by(collection_id=item.collection_id, user_id=user.id).first()
        permission = member.permission if member else ""
    if not owner_vault or not permission:
        raise HTTPException(404, "Vault item not found")
    return item, owner_vault, master_key_from_application(owner_vault), permission


def parse_fields(raw: str) -> list[dict]:
    try:
        rows = json.loads(raw or "[]")
    except json.JSONDecodeError:
        rows = []
    result = []
    if isinstance(rows, list):
        for row in rows[:50]:
            if not isinstance(row, dict) or not str(row.get("label", "")).strip():
                continue
            sensitivity = str(row.get("sensitivity", "normal")).lower()
            result.append({
                "id": secrets.token_hex(8), "label": str(row["label"]).strip()[:120],
                "value": str(row.get("value", ""))[:20000],
                "sensitivity": sensitivity if sensitivity in {"normal", "masked", "highly_sensitive"} else "normal",
            })
    return result


@router.get("")
def home(request: Request, view: str = Query("vault"), db: Session = Depends(get_db), user: User = Depends(require_user)):
    require_access(user)
    vault = vault_for_user(db, user)
    if not vault:
        return templates.TemplateResponse(request, "secret_vault_setup.html", base_context(request, user, error=None, **oidc_vault_context(db, request, user, "setup")))
    if not vault.recovery_confirmed_at:
        return templates.TemplateResponse(request, "secret_vault_setup_incomplete.html", base_context(request, user))
    session = active_vault_session(db, request, user, touch=False)
    if not session:
        return templates.TemplateResponse(request, "secret_vault_unlock.html", base_context(
            request, user, vault=vault, error=None, locked_until=vault.locked_until,
            **oidc_vault_context(db, request, user, "unlock"),
        ))
    vault, key = require_unlocked(db, request, user)
    rows = db.query(VaultItem).filter(VaultItem.vault_id == vault.id, VaultItem.deleted_at.is_(None)).order_by(VaultItem.updated_at.desc()).all()
    decoded = []
    for row in rows:
        try:
            payload = item_payload(key, row)
        except VaultCryptoError:
            continue
        expiry = payload.get("expiry_date")
        if view == "favourites" and not row.is_favourite:
            continue
        if view == "expiring" and (not expiry or expiry > (date.today() + timedelta(days=30)).isoformat()):
            continue
        decoded.append({"row": row, "payload": payload})
    collections = []
    for row in db.query(VaultCollection).filter_by(vault_id=vault.id).order_by(VaultCollection.updated_at.desc()).all():
        try:
            collections.append({"row": row, "payload": collection_payload(key, row)})
        except VaultCryptoError:
            pass
    shared = []
    for member in db.query(VaultCollectionMember).filter_by(user_id=user.id).all():
        row = db.get(VaultCollection, member.collection_id)
        owner_vault = db.get(Vault, row.vault_id) if row else None
        if row and owner_vault and owner_vault.owner_id != user.id:
            try:
                shared.append({"row": row, "payload": collection_payload(master_key_from_application(owner_vault), row), "permission": member.permission})
            except VaultCryptoError:
                pass
    activity = db.query(AuditLog).filter(AuditLog.user_id == user.id, AuditLog.entity.like("vault%")) .order_by(AuditLog.created_at.desc()).limit(100).all()
    backups = db.query(VaultBackupRecord).filter_by(vault_id=vault.id).order_by(VaultBackupRecord.created_at.desc()).limit(20).all()
    storage_path = ensure_storage()
    sensitive_auth = oidc_vault_context(db, request, user, "sensitive")
    vault_health = {"application_key": True, "storage_writable": os.access(storage_path, os.W_OK), "mfa": sensitive_auth["totp_allowed"] or sensitive_auth["oidc_allowed"], "portable_backup_verified": any(row.status == "verified" for row in backups)}
    return templates.TemplateResponse(request, "secret_vault.html", base_context(
        request, user, vault=vault, session=session, items=decoded, collections=collections,
        activity=activity, backups=backups, vault_health=vault_health, shared=shared,
        sharing_enabled=get_site_setting(db, "secret_vault_sharing_enabled") == "1",
        view=view, today=date.today().isoformat(), **sensitive_auth,
    ))


@router.post("/setup")
def setup(request: Request, password: str = Form(""), totp_code: str = Form(""), pin: str = Form(""), pin_confirm: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); require_access(user)
    if vault_for_user(db, user):
        raise HTTPException(409, "Vault already exists")
    error = validate_pin(pin, int(get_site_setting(db, "secret_vault_min_pin_length") or 8))
    oidc_approved = consume_oidc_approval(request, user, "setup")
    auth_context = oidc_vault_context(db, request, user, "setup")
    local_approved = bool(user.password_hash and auth_context["totp_allowed"] and verify_password(password, user.password_hash) and verify_fresh_totp(db, user, totp_code))
    if pin != pin_confirm:
        error = "The vault PIN or passphrase confirmation does not match."
    elif not oidc_approved and not local_approved:
        error = "Complete fresh identity verification before creating the vault."
    if error:
        safe_audit(db, user, "vault_setup_failed", "vault")
        return templates.TemplateResponse(request, "secret_vault_setup.html", base_context(request, user, error=error, **oidc_vault_context(db, request, user, "setup")), status_code=400)
    vault, recovery_key = create_vault(db, user, pin)
    safe_audit(db, user, "vault_created", "vault", vault.id, authentication_method="oidc_mfa" if oidc_approved else "password_totp")
    return templates.TemplateResponse(request, "secret_vault_recovery_kit.html", base_context(request, user, vault=vault, recovery_key=recovery_key))


@router.post("/setup/confirm")
def confirm_setup(request: Request, recovery_key: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    vault = vault_for_user(db, user)
    if not vault or vault.recovery_confirmed_at:
        raise HTTPException(404, "Pending vault setup not found")
    try:
        master_key_from_recovery(vault, recovery_key)
    except VaultCryptoError:
        return templates.TemplateResponse(request, "secret_vault_setup_incomplete.html", base_context(request, user, error="Recovery key confirmation did not match."), status_code=400)
    vault.recovery_confirmed_at = datetime.utcnow(); db.commit()
    safe_audit(db, user, "recovery_kit_confirmed", "vault", vault.id)
    return RedirectResponse("/security/secret-vault", status_code=303)


@router.post("/unlock")
def unlock(request: Request, pin: str = Form(""), totp_code: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); require_access(user)
    vault = vault_for_user(db, user)
    if not vault or not vault.recovery_confirmed_at:
        raise HTTPException(404, "Vault not enrolled")
    now = datetime.utcnow()
    valid = not vault.locked_until or vault.locked_until <= now
    oidc_approved = consume_oidc_approval(request, user, "unlock")
    try:
        if valid:
            master_key_from_pin(vault, pin)
            valid = oidc_approved or (oidc_vault_context(db, request, user, "unlock")["totp_allowed"] and verify_fresh_totp(db, user, totp_code))
    except VaultCryptoError:
        valid = False
    if not valid:
        record_failed_unlock(db, vault)
        safe_audit(db, user, "vault_unlock_failed", "vault", vault.id, failure_count=vault.failed_attempts)
        return templates.TemplateResponse(request, "secret_vault_unlock.html", base_context(request, user, vault=vault, locked_until=vault.locked_until, error="The vault could not be unlocked. Check your details and try again.", **oidc_vault_context(db, request, user, "unlock")), status_code=400)
    method = "pin_oidc_mfa" if oidc_approved else "pin_totp"
    clear_failed_unlock(db, vault); start_vault_session(db, request, vault, user, method=method)
    safe_audit(db, user, "vault_unlocked", "vault", vault.id, authentication_method=method)
    return RedirectResponse("/security/secret-vault", status_code=303)


@router.post("/oidc/verify")
async def begin_oidc_verification(request: Request, purpose: str = Form(...), return_to: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); require_access(user)
    if purpose not in {"setup", "unlock", "recovery", "sensitive"}:
        raise HTTPException(400, "Invalid verification purpose")
    context = oidc_vault_context(db, request, user, purpose)
    provider = context["oidc_provider"]
    if not context["oidc_allowed"] or not provider:
        raise HTTPException(403, "Identity-provider MFA is not enabled for Secret Vault")
    acr_values = get_site_setting(db, "secret_vault_oidc_accepted_acr")
    from app.routers.oidc import _begin
    requested_return = safe_return_path(return_to, "/security/secret-vault")
    if not (requested_return == "/security/secret-vault" or requested_return.startswith("/security/secret-vault/") or requested_return.startswith("/security/secret-vault?")):
        requested_return = "/security/secret-vault"
    return await _begin(
        request, db, provider, flow_type=f"vault_{purpose}", target_user_id=user.id,
        initiated_by_user_id=user.id,
        return_path="/security/secret-vault/recover-authenticator" if purpose == "recovery" else requested_return,
        authorization_params={"prompt": "login", "max_age": "0", "acr_values": acr_values},
    )


@router.post("/lock")
def lock(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault = vault_for_user(db, user)
    lock_vault(db, request, user)
    if vault: safe_audit(db, user, "vault_locked", "vault", vault.id)
    return RedirectResponse("/security/secret-vault", status_code=303)


@router.get("/items/new")
def new_item(request: Request, item_type: str = "secure_note", db: Session = Depends(get_db), user: User = Depends(require_user)):
    vault, _ = require_unlocked(db, request, user)
    collections = db.query(VaultCollection).filter_by(vault_id=vault.id).all()
    key = master_key_from_application(vault)
    choices = [{"row": x, "payload": collection_payload(key, x)} for x in collections]
    return templates.TemplateResponse(request, "secret_vault_item_form.html", base_context(request, user, item=None, payload=None, selected_type=item_type if item_type in ITEM_TYPES else "secure_note", collections=choices))


@router.post("/items")
async def create_item(request: Request, title: str = Form(..., max_length=255), item_type: str = Form("secure_note"), body: str = Form("", max_length=200000), fields_json: str = Form("[]"), tags: str = Form(""), classification: str = Form("confidential"), expiry_date: str = Form(""), review_date: str = Form(""), collection_id: str = Form(""), attachment: UploadFile | None = File(None), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault, key = require_unlocked(db, request, user)
    if item_type not in ITEM_TYPES or not title.strip(): raise HTTPException(400, "Invalid vault item")
    collection = int(collection_id) if collection_id.isdigit() else None
    if collection and not db.query(VaultCollection).filter_by(id=collection, vault_id=vault.id).first(): raise HTTPException(400, "Invalid collection")
    row = VaultItem(vault_id=vault.id, collection_id=collection, item_type=item_type, encrypted_payload="pending", created_by_id=user.id, updated_by_id=user.id)
    db.add(row); db.flush()
    payload = {"title": title.strip(), "body": body, "fields": parse_fields(fields_json), "tags": [x.strip()[:40] for x in tags.split(",") if x.strip()][:30], "classification": classification[:40], "expiry_date": expiry_date or None, "review_date": review_date or None}
    row.encrypted_payload = encrypt_payload(key, vault.id, f"item:{row.id}", payload); db.commit()
    if attachment and attachment.filename:
        await _save_attachment(db, vault, key, row, attachment)
    safe_audit(db, user, "vault_item_created", "vault_item", row.id, item_type=item_type)
    return RedirectResponse(f"/security/secret-vault/items/{row.id}", status_code=303)


async def _save_attachment(db: Session, vault: Vault, key: bytes, item: VaultItem, upload: UploadFile):
    maximum = min(100, int(get_site_setting(db, "max_upload_mb") or 25)) * 1024 * 1024
    content = await upload.read(maximum + 1)
    if len(content) > maximum: raise HTTPException(413, "Attachment is too large")
    storage_id = uuid4().hex; encrypted = encrypt_file(key, vault.id, storage_id, content)
    path = ensure_storage() / storage_id
    path.write_bytes(encrypted)
    metadata = {"name": Path(upload.filename or "attachment").name[:255], "content_type": (upload.content_type or "application/octet-stream")[:120]}
    row = VaultAttachment(item_id=item.id, storage_id=storage_id, encrypted_metadata=encrypt_payload(key, vault.id, f"attachment-meta:{storage_id}", metadata), size_bytes=len(content), ciphertext_size=len(encrypted), integrity_hash=hashlib.sha256(encrypted).hexdigest())
    db.add(row); db.commit()


@router.get("/items/{item_id}")
def item_detail(item_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    require_unlocked(db, request, user)
    item, owner_vault, key, permission = accessible_item(db, user, item_id)
    payload = item_payload(key, item)
    attachments = []
    for row in db.query(VaultAttachment).filter_by(item_id=item.id).all():
        attachments.append({"row": row, "metadata": decrypt_payload(key, item.vault_id, f"attachment-meta:{row.storage_id}", row.encrypted_metadata)})
    versions = db.query(VaultItemVersion).filter_by(item_id=item.id).order_by(VaultItemVersion.version.desc()).all()
    return templates.TemplateResponse(request, "secret_vault_item.html", base_context(request, user, item=item, payload=payload, attachments=attachments, versions=versions, permission=permission, secure_send_enabled=get_site_setting(db, "secure_send_enabled") == "1" and not settings.demo_mode, **oidc_vault_context(db, request, user, "sensitive")))


@router.get("/items/{item_id}/edit")
def edit_item(item_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    require_unlocked(db, request, user)
    item, owner_vault, key, permission = accessible_item(db, user, item_id)
    if permission not in {"owner", "contributor", "manager"}:
        raise HTTPException(403, "Edit permission required")
    choices = [{"row": row, "payload": collection_payload(key, row)} for row in db.query(VaultCollection).filter_by(vault_id=owner_vault.id).all()]
    return templates.TemplateResponse(request, "secret_vault_item_form.html", base_context(request, user, item=item, payload=item_payload(key, item), selected_type=item.item_type, collections=choices))


@router.post("/items/{item_id}")
async def update_item(item_id: int, request: Request, title: str = Form(..., max_length=255), item_type: str = Form("secure_note"), body: str = Form("", max_length=200000), fields_json: str = Form("[]"), tags: str = Form(""), classification: str = Form("confidential"), expiry_date: str = Form(""), review_date: str = Form(""), collection_id: str = Form(""), attachment: UploadFile | None = File(None), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); require_unlocked(db, request, user)
    item, vault, key, permission = accessible_item(db, user, item_id)
    if permission not in {"owner", "contributor", "manager"}: raise HTTPException(403, "Edit permission required")
    if item_type not in ITEM_TYPES or not title.strip(): raise HTTPException(400, "Invalid vault item")
    version = db.query(VaultItemVersion).filter_by(item_id=item.id).count() + 1
    db.add(VaultItemVersion(item_id=item.id, version=version, encrypted_payload=item.encrypted_payload, key_version=item.key_version, saved_by_id=user.id))
    collection = int(collection_id) if collection_id.isdigit() else None
    if collection and not db.query(VaultCollection).filter_by(id=collection, vault_id=vault.id).first(): raise HTTPException(400, "Invalid collection")
    payload = {"title": title.strip(), "body": body, "fields": parse_fields(fields_json), "tags": [x.strip()[:40] for x in tags.split(",") if x.strip()][:30], "classification": classification[:40], "expiry_date": expiry_date or None, "review_date": review_date or None}
    item.item_type = item_type; item.collection_id = collection; item.encrypted_payload = encrypt_payload(key, vault.id, f"item:{item.id}", payload); item.updated_by_id = user.id; item.updated_at = datetime.utcnow(); db.commit()
    if attachment and attachment.filename: await _save_attachment(db, vault, key, item, attachment)
    safe_audit(db, user, "vault_item_updated", "vault_item", item.id, item_type=item_type, version=version)
    return RedirectResponse(f"/security/secret-vault/items/{item.id}", status_code=303)


@router.post("/items/{item_id}/delete")
def delete_item(item_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault, _ = require_unlocked(db, request, user)
    item = db.query(VaultItem).filter_by(id=item_id, vault_id=vault.id).first()
    if not item: raise HTTPException(404, "Vault item not found")
    item.deleted_at = datetime.utcnow(); db.commit(); safe_audit(db, user, "vault_item_deleted", "vault_item", item.id)
    return RedirectResponse("/security/secret-vault", status_code=303)


@router.post("/items/{item_id}/reveal/{field_id}")
def reveal_field(item_id: int, field_id: str, request: Request, pin: str = Form(""), totp_code: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); require_unlocked(db, request, user)
    item, _vault, key, _permission = accessible_item(db, user, item_id); payload = item_payload(key, item)
    field = next((x for x in payload.get("fields", []) if x.get("id") == field_id), None)
    if not field or field.get("sensitivity") == "normal": raise HTTPException(404, "Protected field not found")
    if field.get("sensitivity") == "highly_sensitive":
        own_vault = vault_for_user(db, user)
        try: valid = bool(own_vault and master_key_from_pin(own_vault, pin) and (consume_oidc_approval(request, user, "sensitive") or (oidc_vault_context(db, request, user, "sensitive")["totp_allowed"] and verify_fresh_totp(db, user, totp_code))))
        except VaultCryptoError: valid = False
        if not valid:
            safe_audit(db, user, "vault_reveal_failed", "vault_item", item.id)
            return JSONResponse({"error": "Fresh authentication failed"}, status_code=403)
    safe_audit(db, user, "vault_field_revealed", "vault_item", item.id, sensitivity=field.get("sensitivity"))
    return JSONResponse({"value": field.get("value", ""), "hide_after_seconds": 30})


@router.post("/items/{item_id}/favourite")
def favourite(item_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault, _ = require_unlocked(db, request, user)
    item = db.query(VaultItem).filter_by(id=item_id, vault_id=vault.id).first()
    if not item: raise HTTPException(404, "Vault item not found")
    item.is_favourite = not item.is_favourite; db.commit(); safe_audit(db, user, "vault_favourite_changed", "vault_item", item.id)
    return RedirectResponse(f"/security/secret-vault/items/{item.id}", status_code=303)


@router.get("/attachments/{attachment_id}")
def download_attachment(attachment_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    require_unlocked(db, request, user); attachment = db.get(VaultAttachment, attachment_id)
    if not attachment: raise HTTPException(404, "Attachment not found")
    item, vault, key, permission = accessible_item(db, user, attachment.item_id)
    if permission == "viewer": raise HTTPException(403, "Download permission required")
    path = ensure_storage() / attachment.storage_id
    encrypted = path.read_bytes()
    if not secrets.compare_digest(hashlib.sha256(encrypted).hexdigest(), attachment.integrity_hash): raise HTTPException(409, f"Attachment integrity check failed. Reference: {safe_reference()}")
    metadata = decrypt_payload(key, vault.id, f"attachment-meta:{attachment.storage_id}", attachment.encrypted_metadata)
    content = decrypt_file(key, vault.id, attachment.storage_id, encrypted)
    safe_audit(db, user, "vault_attachment_downloaded", "vault_attachment", attachment.id)
    filename = metadata.get("name", "attachment").replace('"', "")
    return Response(content, media_type=metadata.get("content_type") or "application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})


@router.post("/collections")
def create_collection(request: Request, name: str = Form(..., max_length=255), description: str = Form("", max_length=5000), classification: str = Form("confidential"), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault, key = require_unlocked(db, request, user)
    row = VaultCollection(vault_id=vault.id, encrypted_payload="pending"); db.add(row); db.flush()
    row.encrypted_payload = encrypt_payload(key, vault.id, f"collection:{row.id}", {"name": name.strip(), "description": description, "classification": classification})
    db.commit(); safe_audit(db, user, "vault_collection_created", "vault_collection", row.id)
    return RedirectResponse("/security/secret-vault?view=collections", status_code=303)


@router.post("/collections/{collection_id}/share")
def share_collection(collection_id: int, request: Request, email: str = Form(""), permission: str = Form("viewer"), pin: str = Form(""), totp_code: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault, _ = require_unlocked(db, request, user)
    if get_site_setting(db, "secret_vault_sharing_enabled") != "1": raise HTTPException(403, "Vault sharing is disabled")
    row = db.query(VaultCollection).filter_by(id=collection_id, vault_id=vault.id).first()
    recipient = db.query(User).filter(User.email == email.strip().lower(), User.is_active == True).first()
    try:
        valid = bool(row and recipient and recipient.id != user.id and permission in MEMBER_LEVELS and master_key_from_pin(vault, pin) and (consume_oidc_approval(request, user, "sensitive") or (oidc_vault_context(db, request, user, "sensitive")["totp_allowed"] and verify_fresh_totp(db, user, totp_code))))
    except VaultCryptoError:
        valid = False
    if not valid:
        safe_audit(db, user, "vault_share_failed", "vault_collection", collection_id)
        raise HTTPException(400, "Collection access could not be granted")
    member = db.query(VaultCollectionMember).filter_by(collection_id=row.id, user_id=recipient.id).first()
    if not member:
        member = VaultCollectionMember(collection_id=row.id, user_id=recipient.id); db.add(member)
    member.permission = permission; row.is_private = False; db.commit()
    safe_audit(db, user, "vault_collection_shared", "vault_collection", row.id, recipient_id=recipient.id, permission=permission)
    return RedirectResponse("/security/secret-vault?view=collections", status_code=303)


def portable_export(db: Session, vault: Vault, key: bytes) -> dict:
    items = []
    for row in db.query(VaultItem).filter_by(vault_id=vault.id).all():
        item = {"id": row.id, "collection_id": row.collection_id, "type": row.item_type, "favourite": row.is_favourite, "payload": item_payload(key, row), "versions": [], "attachments": []}
        for version in db.query(VaultItemVersion).filter_by(item_id=row.id).order_by(VaultItemVersion.version.asc()).all():
            item["versions"].append({"version": version.version, "payload": decrypt_payload(key, vault.id, f"item:{row.id}", version.encrypted_payload)})
        for attachment in db.query(VaultAttachment).filter_by(item_id=row.id).all():
            encrypted = (ensure_storage() / attachment.storage_id).read_bytes()
            content = decrypt_file(key, vault.id, attachment.storage_id, encrypted)
            item["attachments"].append({"metadata": decrypt_payload(key, vault.id, f"attachment-meta:{attachment.storage_id}", attachment.encrypted_metadata), "content": base64.b64encode(content).decode(), "sha256": hashlib.sha256(content).hexdigest()})
        items.append(item)
    collections = [{"id": row.id, "payload": collection_payload(key, row)} for row in db.query(VaultCollection).filter_by(vault_id=vault.id).all()]
    return {"format": "kayavault", "version": 1, "created_at": datetime.utcnow().isoformat() + "Z", "items": items, "collections": collections}


@router.post("/export")
def export_vault(request: Request, pin: str = Form(""), totp_code: str = Form(""), export_passphrase: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault, _ = require_unlocked(db, request, user)
    if len(export_passphrase) < 12: raise HTTPException(400, "Export passphrase must contain at least 12 characters")
    try: key = master_key_from_pin(vault, pin); valid = consume_oidc_approval(request, user, "sensitive") or (oidc_vault_context(db, request, user, "sensitive")["totp_allowed"] and verify_fresh_totp(db, user, totp_code))
    except VaultCryptoError: valid = False
    if not valid:
        safe_audit(db, user, "vault_export_failed", "vault", vault.id); raise HTTPException(403, "Fresh authentication failed")
    package = encrypt_portable_package(portable_export(db, vault, key), export_passphrase)
    # Verification is a real authenticated decrypt, not a file-exists check.
    decrypt_portable_package(package, export_passphrase)
    record = VaultBackupRecord(vault_id=vault.id, operation="export", status="verified", size_bytes=len(package), verified_at=datetime.utcnow(), created_by_id=user.id); db.add(record); db.commit()
    safe_audit(db, user, "vault_exported", "vault_backup", record.id, format_version=1, size_bytes=len(package))
    return Response(package, media_type="application/vnd.kaya.vault+json", headers={"Content-Disposition": f'attachment; filename="kaya-vault-{datetime.utcnow():%Y%m%d}.kayavault"', "Cache-Control": "no-store"})


@router.post("/restore")
async def restore_vault(request: Request, package: UploadFile = File(...), export_passphrase: str = Form(""), pin: str = Form(""), totp_code: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault, _ = require_unlocked(db, request, user)
    try: key = master_key_from_pin(vault, pin); valid = consume_oidc_approval(request, user, "sensitive") or (oidc_vault_context(db, request, user, "sensitive")["totp_allowed"] and verify_fresh_totp(db, user, totp_code))
    except VaultCryptoError: valid = False
    if not valid:
        safe_audit(db, user, "vault_restore_failed", "vault", vault.id, reason="reauthentication")
        raise HTTPException(403, "Fresh authentication failed")
    raw = await package.read(250 * 1024 * 1024 + 1)
    if len(raw) > 250 * 1024 * 1024: raise HTTPException(413, "Vault package is too large")
    created_paths: list[Path] = []
    try:
        decoded = decrypt_portable_package(raw, export_passphrase)
        collection_map = {}
        for source in decoded.get("collections", []):
            payload = source.get("payload")
            if not isinstance(payload, dict): raise VaultCryptoError("Collection payload is invalid")
            row = VaultCollection(vault_id=vault.id, encrypted_payload="pending"); db.add(row); db.flush()
            row.encrypted_payload = encrypt_payload(key, vault.id, f"collection:{row.id}", payload)
            collection_map[source.get("id")] = row.id
        for source in decoded.get("items", []):
            payload = source.get("payload"); item_type = source.get("type")
            if not isinstance(payload, dict) or item_type not in ITEM_TYPES: raise VaultCryptoError("Item payload is invalid")
            row = VaultItem(vault_id=vault.id, collection_id=collection_map.get(source.get("collection_id")), item_type=item_type, encrypted_payload="pending", is_favourite=bool(source.get("favourite")), created_by_id=user.id, updated_by_id=user.id)
            db.add(row); db.flush(); row.encrypted_payload = encrypt_payload(key, vault.id, f"item:{row.id}", payload)
            for source_version in source.get("versions", []):
                version_payload = source_version.get("payload")
                if not isinstance(version_payload, dict): raise VaultCryptoError("Item version payload is invalid")
                db.add(VaultItemVersion(item_id=row.id, version=int(source_version.get("version") or 1), encrypted_payload=encrypt_payload(key, vault.id, f"item:{row.id}", version_payload), saved_by_id=user.id))
            for source_attachment in source.get("attachments", []):
                content = base64.b64decode(source_attachment.get("content", ""), validate=True)
                if not secrets.compare_digest(hashlib.sha256(content).hexdigest(), source_attachment.get("sha256", "")): raise VaultCryptoError("Attachment hash validation failed")
                storage_id = uuid4().hex; encrypted = encrypt_file(key, vault.id, storage_id, content); attachment_path = ensure_storage() / storage_id; attachment_path.write_bytes(encrypted); created_paths.append(attachment_path)
                metadata = source_attachment.get("metadata", {})
                attachment = VaultAttachment(item_id=row.id, storage_id=storage_id, encrypted_metadata=encrypt_payload(key, vault.id, f"attachment-meta:{storage_id}", metadata), size_bytes=len(content), ciphertext_size=len(encrypted), integrity_hash=hashlib.sha256(encrypted).hexdigest()); db.add(attachment)
        record = VaultBackupRecord(vault_id=vault.id, operation="restore", status="verified", size_bytes=len(raw), verified_at=datetime.utcnow(), created_by_id=user.id); db.add(record); db.commit()
    except (VaultCryptoError, ValueError, TypeError) as exc:
        db.rollback()
        for path in created_paths:
            try: path.unlink(missing_ok=True)
            except OSError: pass
        safe_audit(db, user, "vault_restore_failed", "vault", vault.id, reason=type(exc).__name__)
        raise HTTPException(400, f"Restore stopped because package authentication or integrity validation failed. Reference: {safe_reference()}")
    safe_audit(db, user, "vault_restored", "vault_backup", record.id, format_version=1)
    return RedirectResponse("/security/secret-vault?view=backup", status_code=303)


@router.get("/recover-authenticator")
def recover_authenticator_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    require_access(user); vault = vault_for_user(db, user)
    if not vault or not vault.recovery_confirmed_at:
        raise HTTPException(404, "Vault not enrolled")
    return templates.TemplateResponse(request, "secret_vault_authenticator_recovery.html", base_context(
        request, user, vault=vault, error=None, **oidc_vault_context(db, request, user, "recovery")
    ))


@router.post("/recover")
def recover(request: Request, recovery_key: str = Form(""), password: str = Form(""), new_pin: str = Form(""), new_pin_confirm: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault = vault_for_user(db, user)
    error = validate_pin(new_pin, int(get_site_setting(db, "secret_vault_min_pin_length") or 8))
    try: key = master_key_from_recovery(vault, recovery_key) if vault else None
    except VaultCryptoError: key = None
    oidc_approved = consume_oidc_approval(request, user, "recovery")
    local_approved = bool(user.password_hash and verify_password(password, user.password_hash))
    if error or new_pin != new_pin_confirm or not key or not (oidc_approved or local_approved):
        safe_audit(db, user, "vault_authenticator_recovery_failed", "vault", vault.id if vault else None)
        return templates.TemplateResponse(request, "secret_vault_authenticator_recovery.html", base_context(
            request, user, vault=vault, error="Recovery could not be completed. Check the recovery key and identity verification.",
            **oidc_vault_context(db, request, user, "recovery")
        ), status_code=400)
    reset_pin(db, vault, key, new_pin)
    replacement_recovery_key = rotate_recovery_key(db, vault, key)
    method = "recovery_key_oidc_mfa" if oidc_approved else "recovery_key_password"
    safe_audit(db, user, "vault_authenticator_recovered", "vault", vault.id, authentication_method=method, recovery_key_rotated=True)
    return templates.TemplateResponse(request, "secret_vault_recovery_kit.html", base_context(
        request, user, vault=vault, recovery_key=replacement_recovery_key, recovery_completed=True
    ))


@router.post("/settings")
def update_settings(request: Request, auto_lock_minutes: int = Form(10), csrf_token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_user)):
    validate_csrf_token(request, csrf_token); vault, _ = require_unlocked(db, request, user)
    if auto_lock_minutes not in {5, 10, 15, 30, 60}: raise HTTPException(400, "Invalid auto-lock interval")
    maximum = int(get_site_setting(db, "secret_vault_max_auto_lock_minutes") or 60)
    vault.auto_lock_minutes = min(auto_lock_minutes, maximum); db.commit(); safe_audit(db, user, "vault_settings_changed", "vault", vault.id)
    return RedirectResponse("/security/secret-vault?view=settings", status_code=303)
