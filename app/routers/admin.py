from pathlib import Path
import tempfile
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status
from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import hash_password
from app.core.totp import decrypted_totp_secret, encrypted_totp_secret, generate_totp_secret, provisioning_uri, verify_totp
from app.db.session import get_db
from app.models.models import AuditLog, User
from app.routers.auth import require_admin
from app.services.audit import write_audit
from app.services.exporter import export_ip_addresses_csv, export_licences_csv
from app.services.importer import ImportCSVError, import_csv, import_ip_addresses_csv

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="app/templates")
ROLES = {"admin", "editor", "viewer"}


@router.get("")
def admin_home(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    users = db.query(User).count()
    enabled_2fa = db.query(User).filter(User.totp_enabled == True).count()
    audit_events = db.query(AuditLog).count()
    return templates.TemplateResponse(request, "admin.html", {"user": user, "users": users, "enabled_2fa": enabled_2fa, "audit_events": audit_events, **csrf_context(request)})


@router.get("/users")
def users(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    rows = db.query(User).order_by(User.email.asc()).all()
    return templates.TemplateResponse(request, "users.html", {"user": user, "rows": rows, **csrf_context(request)})


@router.get("/users/new")
def new_user(request: Request, user=Depends(require_admin)):
    return templates.TemplateResponse(request, "user_form.html", {"user": user, "target": None, "roles": sorted(ROLES), "error": None, **csrf_context(request)})


@router.post("/users/new")
def create_user(request: Request, email: str = Form(..., max_length=255), password: str = Form(..., min_length=12, max_length=255), role: str = Form("viewer"), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    role = role if role in ROLES else "viewer"
    email = email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(request, "user_form.html", {"user": user, "target": None, "roles": sorted(ROLES), "error": "A user with that email already exists.", **csrf_context(request)}, status_code=400)
    row = User(email=email, password_hash=hash_password(password), role=role, is_active=True)
    db.add(row)
    db.commit()
    write_audit(db, user, "create", "user", str(row.id), request.client.host if request.client else None, detail=email)
    return RedirectResponse("/admin/users", status_code=303)


@router.get("/users/{user_id}/edit")
def edit_user(request: Request, user_id: int, db: Session = Depends(get_db), user=Depends(require_admin)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return templates.TemplateResponse(request, "user_form.html", {"user": user, "target": target, "roles": sorted(ROLES), "error": None, **csrf_context(request)})


@router.post("/users/{user_id}/edit")
def update_user(request: Request, user_id: int, email: str = Form(..., max_length=255), password: str = Form("", max_length=255), role: str = Form("viewer"), is_active: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.id == user.id and (role != "admin" or not is_active):
        return templates.TemplateResponse(request, "user_form.html", {"user": user, "target": target, "roles": sorted(ROLES), "error": "You cannot remove your own admin access or deactivate yourself.", **csrf_context(request)}, status_code=400)
    role = role if role in ROLES else "viewer"
    target.email = email.strip().lower()
    target.role = role
    target.is_active = bool(is_active)
    if password:
        if len(password) < 12:
            return templates.TemplateResponse(request, "user_form.html", {"user": user, "target": target, "roles": sorted(ROLES), "error": "New passwords must be at least 12 characters.", **csrf_context(request)}, status_code=400)
        target.password_hash = hash_password(password)
    db.commit()
    write_audit(db, user, "update", "user", str(target.id), request.client.host if request.client else None, detail=target.email)
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/users/{user_id}/reset-2fa")
def reset_user_2fa(request: Request, user_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    target.totp_secret = None
    target.totp_enabled = False
    db.commit()
    write_audit(db, user, "reset_2fa", "user", str(target.id), request.client.host if request.client else None, detail=target.email)
    return RedirectResponse("/admin/users", status_code=303)


@router.get("/import")
def import_page(request: Request, module: str = "licences", user=Depends(require_admin)):
    return templates.TemplateResponse(request, "import.html", {"user": user, "active_module": module if module in {"licences", "ip-addresses"} else "licences", "message": None, "error": None, **csrf_context(request)})


@router.post("/import/{module}")
async def import_upload(request: Request, module: str, file: UploadFile = File(...), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    active_module = module if module in {"licences", "ip-addresses"} else "licences"
    filename = file.filename or ""
    if not filename.lower().endswith(".csv"):
        return templates.TemplateResponse(request, "import.html", {"user": user, "active_module": active_module, "message": None, "error": "Only CSV files are currently supported.", **csrf_context(request)}, status_code=400)
    max_bytes = get_settings().max_upload_mb * 1024 * 1024
    contents = await file.read(max_bytes + 1)
    if len(contents) > max_bytes:
        return templates.TemplateResponse(request, "import.html", {"user": user, "active_module": active_module, "message": None, "error": f"CSV file is larger than {get_settings().max_upload_mb} MB.", **csrf_context(request)}, status_code=413)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        tmp.write(contents)
        tmp_path = tmp.name
    try:
        if active_module == "ip-addresses":
            count = import_ip_addresses_csv(db, user, tmp_path, request.client.host if request.client else None)
            label = "IP address"
        else:
            count = import_csv(db, user, tmp_path, request.client.host if request.client else None)
            label = "licence"
    except ImportCSVError as exc:
        return templates.TemplateResponse(request, "import.html", {"user": user, "active_module": active_module, "message": None, "error": str(exc), **csrf_context(request)}, status_code=400)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return templates.TemplateResponse(request, "import.html", {"user": user, "active_module": active_module, "message": f"Imported or updated {count} {label} records.", "error": None, **csrf_context(request)})


@router.post("/export/{module}")
def export_csv(request: Request, module: str, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    if module == "ip-addresses":
        csv_data = export_ip_addresses_csv(db)
        entity = "ip_address"
        filename = "homelab-ip-addresses.csv"
        detail = "Exported IP address CSV"
    else:
        csv_data = export_licences_csv(db)
        entity = "licence"
        filename = "homelab-licences.csv"
        detail = "Exported licence CSV"
    write_audit(db, user, "export", entity, ip_address=request.client.host if request.client else None, detail=detail)
    return PlainTextResponse(
        csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/security")
def security(request: Request, user=Depends(require_admin)):
    secret = decrypted_totp_secret(user.totp_secret) if user.totp_secret and not user.totp_enabled else None
    uri = provisioning_uri(user.email, secret) if secret else None
    return templates.TemplateResponse(request, "security.html", {"user": user, "setup_secret": secret, "setup_uri": uri, "error": None, **csrf_context(request)})


@router.post("/security/2fa/start")
def start_2fa(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    secret = generate_totp_secret()
    user.totp_secret = encrypted_totp_secret(secret)
    user.totp_enabled = False
    db.commit()
    write_audit(db, user, "start_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/admin/security", status_code=303)


@router.post("/security/2fa/enable")
def enable_2fa(request: Request, code: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    secret = decrypted_totp_secret(user.totp_secret)
    if not secret or not verify_totp(secret, code):
        uri = provisioning_uri(user.email, secret) if secret else None
        return templates.TemplateResponse(request, "security.html", {"user": user, "setup_secret": secret, "setup_uri": uri, "error": "Invalid authentication code.", **csrf_context(request)}, status_code=400)
    user.totp_enabled = True
    db.commit()
    write_audit(db, user, "enable_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/admin/security", status_code=303)


@router.post("/security/2fa/disable")
def disable_2fa(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    user.totp_secret = None
    user.totp_enabled = False
    db.commit()
    write_audit(db, user, "disable_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/admin/security", status_code=303)


@router.get("/audit")
def audit(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(200).all()
    return templates.TemplateResponse(request, "audit.html", {"user": user, "logs": logs, **csrf_context(request)})
