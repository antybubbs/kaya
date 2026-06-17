from pathlib import Path
import tempfile
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy.orm import selectinload
from starlette import status
from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import hash_password, verify_password
from app.core.totp import decrypted_totp_secret, encrypted_totp_secret, generate_totp_secret, provisioning_uri, qr_code_data_uri, verify_totp
from app.db.session import get_db
from app.models.models import AppSession, AuditLog, CustomField, ManagedListItem, User
from app.routers.auth import require_admin
from app.services.audit import write_audit
from app.services.about import collect_about
from app.services.custom_fields import FIELD_TYPES, make_field_key
from app.services.exporter import export_ip_addresses_csv, export_licences_csv
from app.services.importer import ImportCSVError, import_csv, import_ip_addresses_csv
from app.services.managed_lists import MANAGED_LIST_MODULES, MANAGED_LISTS, list_label
from app.services.sessions import active_since

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="app/templates")
ROLES = {"admin", "editor", "viewer"}
CUSTOM_FIELD_MODULES = {"ip_addresses": "IP Addresses", "hardware_assets": "Hardware Assets", "licences": "License Keys"}


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
def create_user(request: Request, email: str = Form(..., max_length=255), first_name: str = Form("", max_length=120), last_name: str = Form("", max_length=120), password: str = Form(..., min_length=12, max_length=255), role: str = Form("viewer"), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    role = role if role in ROLES else "viewer"
    email = email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(request, "user_form.html", {"user": user, "target": None, "roles": sorted(ROLES), "error": "A user with that email already exists.", **csrf_context(request)}, status_code=400)
    row = User(email=email, first_name=first_name.strip() or None, last_name=last_name.strip() or None, password_hash=hash_password(password), role=role, is_active=True)
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
def update_user(request: Request, user_id: int, email: str = Form(..., max_length=255), first_name: str = Form("", max_length=120), last_name: str = Form("", max_length=120), password: str = Form("", max_length=255), role: str = Form("viewer"), is_active: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.id == user.id and (role != "admin" or not is_active):
        return templates.TemplateResponse(request, "user_form.html", {"user": user, "target": target, "roles": sorted(ROLES), "error": "You cannot remove your own admin access or deactivate yourself.", **csrf_context(request)}, status_code=400)
    role = role if role in ROLES else "viewer"
    target.email = email.strip().lower()
    target.first_name = first_name.strip() or None
    target.last_name = last_name.strip() or None
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


@router.get("/custom-fields")
def custom_fields(request: Request, module: str = "ip_addresses", db: Session = Depends(get_db), user=Depends(require_admin)):
    active_module = module if module in CUSTOM_FIELD_MODULES else "ip_addresses"
    rows = db.query(CustomField).filter(CustomField.module == active_module).order_by(CustomField.sort_order.asc(), CustomField.label.asc()).all()
    return templates.TemplateResponse(request, "custom_fields.html", {"user": user, "modules": CUSTOM_FIELD_MODULES, "active_module": active_module, "rows": rows, "field_types": FIELD_TYPES, "error": None, **csrf_context(request)})


@router.post("/custom-fields")
def create_custom_field(request: Request, module: str = Form("ip_addresses"), label: str = Form(..., max_length=120), field_type: str = Form("text"), options: str = Form("", max_length=5000), is_required: str = Form(""), sort_order: int = Form(0), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    active_module = module if module in CUSTOM_FIELD_MODULES else "ip_addresses"
    clean_label = label.strip()
    clean_type = field_type if field_type in FIELD_TYPES else "text"
    clean_options = options.strip()
    rows = db.query(CustomField).filter(CustomField.module == active_module).order_by(CustomField.sort_order.asc(), CustomField.label.asc()).all()
    if not clean_label:
        return templates.TemplateResponse(request, "custom_fields.html", {"user": user, "modules": CUSTOM_FIELD_MODULES, "active_module": active_module, "rows": rows, "field_types": FIELD_TYPES, "error": "Field name is required.", **csrf_context(request)}, status_code=400)
    if clean_type in {"radio", "select"} and not clean_options:
        return templates.TemplateResponse(request, "custom_fields.html", {"user": user, "modules": CUSTOM_FIELD_MODULES, "active_module": active_module, "rows": rows, "field_types": FIELD_TYPES, "error": "List fields need one option per line.", **csrf_context(request)}, status_code=400)
    field_key = make_field_key(clean_label)
    if db.query(CustomField).filter(CustomField.module == active_module, CustomField.field_key == field_key).first():
        return templates.TemplateResponse(request, "custom_fields.html", {"user": user, "modules": CUSTOM_FIELD_MODULES, "active_module": active_module, "rows": rows, "field_types": FIELD_TYPES, "error": "A field with that name already exists for this module.", **csrf_context(request)}, status_code=400)
    row = CustomField(module=active_module, label=clean_label, field_key=field_key, field_type=clean_type, options=clean_options or None, is_required=bool(is_required), is_active=True, sort_order=sort_order)
    db.add(row)
    db.commit()
    write_audit(db, user, "create", "custom_field", str(row.id), request.client.host if request.client else None, detail=f"{CUSTOM_FIELD_MODULES[active_module]}: {clean_label}")
    return RedirectResponse(f"/admin/custom-fields?module={active_module}", status_code=303)


@router.post("/custom-fields/{field_id}/toggle")
def toggle_custom_field(request: Request, field_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    row = db.get(CustomField, field_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Custom field not found")
    row.is_active = not row.is_active
    db.commit()
    write_audit(db, user, "update", "custom_field", str(row.id), request.client.host if request.client else None, detail=f"{row.label}: {'active' if row.is_active else 'inactive'}")
    return RedirectResponse(f"/admin/custom-fields?module={row.module}", status_code=303)


@router.get("/categories")
def categories(request: Request, module: str = "hardware_assets", list_key: str = "category", db: Session = Depends(get_db), user=Depends(require_admin)):
    active_module = module if module in MANAGED_LIST_MODULES else "hardware_assets"
    lists = MANAGED_LISTS.get(active_module, {})
    active_list = list_key if list_key in lists else next(iter(lists))
    rows = db.query(ManagedListItem).filter(ManagedListItem.module == active_module, ManagedListItem.list_key == active_list).order_by(ManagedListItem.sort_order.asc(), ManagedListItem.value.asc()).all()
    return templates.TemplateResponse(request, "categories.html", {"user": user, "modules": MANAGED_LIST_MODULES, "lists": lists, "active_module": active_module, "active_list": active_list, "active_list_label": list_label(active_module, active_list), "rows": rows, "error": None, **csrf_context(request)})


@router.post("/categories")
def create_category(request: Request, module: str = Form("hardware_assets"), list_key: str = Form("category"), value: str = Form(..., max_length=120), sort_order: int = Form(0), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    active_module = module if module in MANAGED_LIST_MODULES else "hardware_assets"
    lists = MANAGED_LISTS.get(active_module, {})
    active_list = list_key if list_key in lists else next(iter(lists))
    clean_value = value.strip()
    rows = db.query(ManagedListItem).filter(ManagedListItem.module == active_module, ManagedListItem.list_key == active_list).order_by(ManagedListItem.sort_order.asc(), ManagedListItem.value.asc()).all()
    if not clean_value:
        return templates.TemplateResponse(request, "categories.html", {"user": user, "modules": MANAGED_LIST_MODULES, "lists": lists, "active_module": active_module, "active_list": active_list, "active_list_label": list_label(active_module, active_list), "rows": rows, "error": "Name is required.", **csrf_context(request)}, status_code=400)
    if db.query(ManagedListItem).filter(ManagedListItem.module == active_module, ManagedListItem.list_key == active_list, ManagedListItem.value == clean_value).first():
        return templates.TemplateResponse(request, "categories.html", {"user": user, "modules": MANAGED_LIST_MODULES, "lists": lists, "active_module": active_module, "active_list": active_list, "active_list_label": list_label(active_module, active_list), "rows": rows, "error": "That value already exists.", **csrf_context(request)}, status_code=400)
    row = ManagedListItem(module=active_module, list_key=active_list, value=clean_value, is_active=True, sort_order=sort_order)
    db.add(row)
    db.commit()
    write_audit(db, user, "create", "category", str(row.id), request.client.host if request.client else None, detail=f"{MANAGED_LIST_MODULES[active_module]} {list_label(active_module, active_list)}: {clean_value}")
    return RedirectResponse(f"/admin/categories?module={active_module}&list_key={active_list}", status_code=303)


@router.post("/categories/{item_id}/toggle")
def toggle_category(request: Request, item_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    row = db.get(ManagedListItem, item_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")
    row.is_active = not row.is_active
    db.commit()
    write_audit(db, user, "update", "category", str(row.id), request.client.host if request.client else None, detail=f"{row.value}: {'active' if row.is_active else 'inactive'}")
    return RedirectResponse(f"/admin/categories?module={row.module}&list_key={row.list_key}", status_code=303)


@router.post("/categories/{item_id}/edit")
def edit_category(request: Request, item_id: int, value: str = Form(..., max_length=120), sort_order: int = Form(0), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    row = db.get(ManagedListItem, item_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")
    clean_value = value.strip()
    if not clean_value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Name is required.")
    duplicate = db.query(ManagedListItem).filter(
        ManagedListItem.module == row.module,
        ManagedListItem.list_key == row.list_key,
        ManagedListItem.value == clean_value,
        ManagedListItem.id != row.id,
    ).first()
    if duplicate:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="That value already exists.")
    old_value = row.value
    row.value = clean_value
    row.sort_order = sort_order
    db.commit()
    write_audit(db, user, "update", "category", str(row.id), request.client.host if request.client else None, detail=f"{old_value} -> {row.value}")
    return RedirectResponse(f"/admin/categories?module={row.module}&list_key={row.list_key}", status_code=303)


@router.get("/security")
def security(request: Request, user=Depends(require_admin)):
    secret = decrypted_totp_secret(user.totp_secret) if user.totp_secret and not user.totp_enabled else None
    uri = provisioning_uri(user.email, secret) if secret else None
    qr_code = qr_code_data_uri(uri) if uri else None
    return templates.TemplateResponse(request, "security.html", {"user": user, "setup_secret": secret, "setup_uri": uri, "setup_qr_code": qr_code, "error": None, **csrf_context(request)})


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
        qr_code = qr_code_data_uri(uri) if uri else None
        return templates.TemplateResponse(request, "security.html", {"user": user, "setup_secret": secret, "setup_uri": uri, "setup_qr_code": qr_code, "error": "Invalid authentication code.", **csrf_context(request)}, status_code=400)
    user.totp_enabled = True
    db.commit()
    write_audit(db, user, "enable_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/admin/security", status_code=303)


@router.post("/security/2fa/disable")
def disable_2fa(request: Request, current_password: str = Form("", max_length=255), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    if not verify_password(current_password, user.password_hash):
        return templates.TemplateResponse(request, "security.html", {"user": user, "setup_secret": None, "setup_uri": None, "setup_qr_code": None, "error": "Current password is required to disable 2FA.", **csrf_context(request)}, status_code=400)
    user.totp_secret = None
    user.totp_enabled = False
    db.commit()
    write_audit(db, user, "disable_2fa", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/admin/security", status_code=303)


@router.get("/audit")
def audit(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(200).all()
    return templates.TemplateResponse(request, "audit.html", {"user": user, "logs": logs, **csrf_context(request)})


@router.get("/about")
def about(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    sessions = db.query(AppSession).filter(
        AppSession.ended_at.is_(None),
        AppSession.last_seen_at >= active_since(),
    ).options(selectinload(AppSession.user)).order_by(AppSession.last_seen_at.desc()).limit(100).all()
    current_session_id = request.session.get("session_id")
    return templates.TemplateResponse(request, "about.html", {
        "user": user,
        "about": collect_about(db),
        "sessions": sessions,
        "current_session_id": current_session_id,
        **csrf_context(request),
    })
