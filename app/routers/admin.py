from pathlib import Path
import io
import tempfile
import json
import socket
import smtplib
from ftplib import FTP
from datetime import datetime, timedelta
from urllib.request import urlopen
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_
from sqlalchemy.orm import Session
from sqlalchemy.orm import selectinload
from starlette import status
from urllib.parse import urlencode
import smbclient

from app.core.config import get_settings
from app.core.branding import APP_BRAND_NAME
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import decrypt_secret, encrypt_secret, hash_password, verify_password
from app.core.totp import (
    decrypted_totp_secret,
    encrypted_totp_secret,
    generate_totp_secret,
    provisioning_uri,
    qr_code_data_uri,
    verify_totp,
)
from app.db.session import get_db
from app.models.models import (
    AppSession,
    AuditLog,
    CustomField,
    ManagedListItem,
    RemoteManagerSetting,
    User,
)
from app.routers.auth import require_admin
from app.services.about import collect_about
from app.services.audit import write_audit
from app.services.custom_fields import FIELD_TYPES, make_field_key
from app.services.exporter import export_ip_addresses_csv, export_licences_csv
from app.services.importer import ImportCSVError, import_csv, import_ip_addresses_csv
from app.services.managed_lists import MANAGED_LIST_MODULES, MANAGED_LISTS, list_label
from app.services.mail import MailConfigurationError, render_email_template, send_mail
from app.services.sessions import active_since
from app.services.site_settings import (
    effective_allowed_hosts,
    frame_ancestor_directive,
    get_site_setting,
    host_without_port,
    host_is_allowed,
    hsts_header_value,
    load_security_settings,
)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

ROLES = {"admin", "editor", "viewer"}

CUSTOM_FIELD_MODULES = {
    "ip_addresses": "VLAN/IP Manager",
    "hardware_assets": "Asset Manager",
    "licences": "License Keys",
}

SITE_SETTING_KEYS = {
    "app_name": APP_BRAND_NAME,
    "base_url": "http://localhost:8080",
    "max_upload_mb": "25",
    "trusted_hosts_enabled": "",
    "allowed_hosts": "",
    "csp_frame_ancestors": "self",
    "csp_frame_ancestor_sources": "",
    "hsts_enabled": "",
    "hsts_include_subdomains": "",
    "hsts_max_age": "31536000",
    "rdp_token_ttl_minutes": "10",
    "backup_storage_type": "local",
    "backup_storage_path": "/mnt/backups",
    "backup_remote_host": "",
    "backup_remote_share": "",
    "backup_remote_username": "",
    "backup_remote_password": "",
    "backup_targets_json": "[]",
    "backup_default_target_name": "",
    "guacd_host": "",
    "guacd_port": "4822",
    "smtp_enabled": "",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_use_tls": "1",
    "smtp_use_ssl": "",
    "smtp_username": "",
    "smtp_password": "",
    "smtp_from_email": "",
    "smtp_from_name": APP_BRAND_NAME,
    "email_template_password_reset_subject": "Reset your {app_name} password",
    "email_template_password_reset_body": (
        "A password reset was requested for your {app_name} account.\n\n"
        "Use this link within {expiry_hours} hour to set a new password:\n"
        "{reset_link}\n\n"
        "If you did not request this, you can ignore this email."
    ),
}


def load_site_settings(db: Session) -> dict[str, str]:
    settings = SITE_SETTING_KEYS.copy()

    rows = (
        db.query(RemoteManagerSetting)
        .filter(RemoteManagerSetting.key.in_(SITE_SETTING_KEYS.keys()))
        .all()
    )

    for row in rows:
        if row.key in {"smtp_password", "backup_remote_password"}:
            settings[row.key] = ""
            settings[f"{row.key}_set"] = "1" if row.value else ""
        else:
            settings[row.key] = row.value or ""

    return settings


def save_site_setting(db: Session, key: str, value: str) -> None:
    if key not in SITE_SETTING_KEYS:
        return

    row = (
        db.query(RemoteManagerSetting)
        .filter(RemoteManagerSetting.key == key)
        .first()
    )

    if not row:
        row = RemoteManagerSetting(key=key)
        db.add(row)

    row.value = value.strip()


def save_smtp_password(db: Session, password: str) -> None:
    if not password:
        return
    save_site_setting(db, "smtp_password", encrypt_secret(password))


def save_backup_remote_password(db: Session, password: str) -> None:
    if not password:
        return
    save_site_setting(db, "backup_remote_password", encrypt_secret(password))


def normalize_backup_targets_json(value: str) -> str:
    try:
        payload = json.loads(value or "[]")
    except (TypeError, ValueError):
        payload = []
    if not isinstance(payload, list):
        payload = []

    cleaned: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        target_type = str(item.get("type") or "local").strip().lower()
        if target_type not in {"local", "smb", "ftp", "sftp"}:
            target_type = "local"
        password = str(item.get("remote_password") or "").strip()
        password_enc = str(item.get("remote_password_enc") or "").strip()
        if password:
            password_enc = encrypt_secret(password)
        cleaned.append(
            {
                "name": name,
                "type": target_type,
                "path": str(item.get("path") or "").strip(),
                "remote_host": str(item.get("remote_host") or "").strip(),
                "remote_share": str(item.get("remote_share") or "").strip(),
                "remote_username": str(item.get("remote_username") or "").strip(),
                "remote_password_enc": password_enc,
            }
        )
    return json.dumps(cleaned, separators=(",", ":"), ensure_ascii=True)


def save_backup_settings(
    db: Session,
    *,
    backup_storage_type: str,
    backup_storage_path: str,
    backup_remote_host: str,
    backup_remote_share: str,
    backup_remote_username: str,
    backup_remote_password: str,
) -> None:
    if backup_storage_type not in {"local", "smb", "ftp", "sftp"}:
        backup_storage_type = "local"
    settings_to_save = {
        "backup_storage_type": backup_storage_type,
        "backup_storage_path": backup_storage_path,
        "backup_remote_host": backup_remote_host,
        "backup_remote_share": backup_remote_share,
        "backup_remote_username": backup_remote_username,
    }
    for key, value in settings_to_save.items():
        save_site_setting(db, key, value)
    save_backup_remote_password(db, backup_remote_password)


def read_saved_backup_password(db: Session, fallback_password: str = "") -> str:
    if fallback_password:
        return fallback_password.strip()
    return decrypt_secret(get_site_setting(db, "backup_remote_password")).strip()


def test_directory_read_write(path_value: str) -> tuple[bool, str]:
    target = Path(path_value.strip() or "/mnt/backups")
    if not target.exists():
        return False, f"{target} does not exist from inside Kaya."
    if not target.is_dir():
        return False, f"{target} is not a directory."

    test_file = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=target,
            prefix=".kaya-storage-test-",
            suffix=".txt",
            encoding="utf-8",
        ) as handle:
            test_file = Path(handle.name)
            handle.write("kaya storage test")

        if test_file.read_text(encoding="utf-8") != "kaya storage test":
            return False, f"Kaya wrote to {target}, but could not read the same data back."
        test_file.unlink()
    except OSError as exc:
        return False, f"Kaya could not write, read and delete a test file in {target}: {exc}"
    finally:
        if test_file and test_file.exists():
            try:
                test_file.unlink()
            except OSError:
                pass

    return True, f"Kaya can write, read and delete files in {target}."


def test_tcp_connection(host: str, port: int) -> tuple[bool, str]:
    if not host.strip():
        return False, "Remote host is required for this storage type."
    try:
        with socket.create_connection((host.strip(), port), timeout=8):
            return True, f"Kaya can reach {host.strip()} on port {port}."
    except OSError as exc:
        return False, f"Kaya cannot reach {host.strip()} on port {port}: {exc}"


def test_ftp_storage(
    *,
    host: str,
    remote_path: str,
    username: str,
    password: str,
) -> tuple[bool, str]:
    host = host.strip()
    if not host:
        return False, "Remote host is required for FTP storage."

    marker = ".kaya-storage-test.txt"
    payload = b"kaya storage test"
    ftp = FTP()
    try:
        ftp.connect(host, 21, timeout=8)
        ftp.login(username.strip() or "anonymous", password or "anonymous@")
        if remote_path.strip():
            ftp.cwd(remote_path.strip())
        ftp.storbinary(f"STOR {marker}", io.BytesIO(payload))
        downloaded = io.BytesIO()
        ftp.retrbinary(f"RETR {marker}", downloaded.write)
        ftp.delete(marker)
        ftp.quit()
    except OSError as exc:
        return False, f"Kaya could not reach the FTP server: {exc}"
    except Exception as exc:
        try:
            ftp.quit()
        except Exception:
            pass
        return False, f"Kaya could not write, read and delete a test file over FTP: {exc}"

    if downloaded.getvalue() != payload:
        return False, "Kaya uploaded a test file over FTP, but the downloaded data did not match."
    return True, f"Kaya can write, read and delete files on FTP storage at {host}."


def smb_unc_path(host: str, remote_share: str, *children: str) -> str:
    host = host.strip().strip("\\/")
    share_path = remote_share.strip().strip("\\/")
    if not host:
        raise ValueError("Remote host is required for SMB storage.")
    if not share_path:
        raise ValueError("Remote share/path is required for SMB storage.")
    parts = [part for part in share_path.replace("\\", "/").split("/") if part]
    share = parts[0]
    path_parts = parts[1:]
    for child in children:
        path_parts.extend(part for part in str(child).replace("\\", "/").split("/") if part)
    suffix = ("\\" + "\\".join(path_parts)) if path_parts else ""
    return f"\\\\{host}\\{share}{suffix}"


def test_smb_storage(
    *,
    host: str,
    remote_share: str,
    username: str,
    password: str,
) -> tuple[bool, str]:
    try:
        target = smb_unc_path(host, remote_share)
    except ValueError as exc:
        return False, str(exc)

    marker = f".kaya-storage-test-{uuid4().hex}.txt"
    payload = b"kaya storage test"
    test_path = smb_unc_path(host, remote_share, marker)
    try:
        smbclient.register_session(host.strip(), username=username.strip() or None, password=password or None)
        with smbclient.open_file(test_path, mode="wb") as handle:
            handle.write(payload)
        with smbclient.open_file(test_path, mode="rb") as handle:
            downloaded = handle.read()
        smbclient.remove(test_path)
    except Exception as exc:
        return False, f"Kaya could not write, read and delete a test file on SMB target {target}: {exc}"
    finally:
        try:
            smbclient.delete_session(host.strip())
        except Exception:
            pass

    if downloaded != payload:
        return False, f"Kaya wrote to SMB target {target}, but the downloaded data did not match."
    return True, f"Kaya can write, read and delete files on SMB target {target}."


def test_backup_storage_target(
    db: Session,
    *,
    storage_type: str,
    storage_path: str,
    remote_host: str,
    remote_share: str,
    remote_username: str,
    remote_password: str,
) -> tuple[bool, str]:
    storage_type = storage_type if storage_type in {"local", "smb", "ftp", "sftp"} else "local"

    if storage_type == "local":
        return test_directory_read_write(storage_path)

    mounted_ok, mounted_detail = test_directory_read_write(storage_path)
    if mounted_ok:
        return True, f"{mounted_detail} This is the path Kaya will use for {storage_type.upper()} storage."

    if storage_type == "ftp":
        password = read_saved_backup_password(db, remote_password)
        return test_ftp_storage(
            host=remote_host,
            remote_path=remote_share,
            username=remote_username,
            password=password,
        )

    if storage_type == "smb":
        password = read_saved_backup_password(db, remote_password)
        return test_smb_storage(
            host=remote_host,
            remote_share=remote_share,
            username=remote_username,
            password=password,
        )

    port = 445 if storage_type == "smb" else 22
    reachable, reachable_detail = test_tcp_connection(remote_host, port)
    if reachable:
        return (
            False,
            f"{reachable_detail} Read/write was not verified because {storage_type.upper()} must be mounted at "
            f"{storage_path.strip() or '/mnt/backups'} for Kaya to test file access directly. Mount the share there, "
            "or test it from the backup agent when agent-side remote storage is enabled.",
        )
    return False, f"{mounted_detail} {reachable_detail}"


def save_email_settings(
    db: Session,
    *,
    app_name: str,
    base_url: str,
    github_repo: str,
    version_check_interval_seconds: str,
    guacd_host: str,
    guacd_port: str,
    max_upload_mb: str,
    smtp_enabled: str,
    smtp_host: str,
    smtp_port: str,
    smtp_use_tls: str,
    smtp_use_ssl: str,
    smtp_username: str,
    smtp_password: str,
    smtp_from_email: str,
    smtp_from_name: str,
    email_template_password_reset_subject: str,
    email_template_password_reset_body: str,
) -> None:
    settings_to_save = {
        "app_name": app_name,
        "base_url": base_url,
        "github_repo": github_repo,
        "version_check_interval_seconds": version_check_interval_seconds,
        "guacd_host": guacd_host,
        "guacd_port": guacd_port,
        "max_upload_mb": max_upload_mb,
        "smtp_enabled": "1" if smtp_enabled else "",
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_use_tls": "1" if smtp_use_tls else "",
        "smtp_use_ssl": "1" if smtp_use_ssl else "",
        "smtp_username": smtp_username,
        "smtp_from_email": smtp_from_email,
        "smtp_from_name": smtp_from_name,
        "email_template_password_reset_subject": email_template_password_reset_subject,
        "email_template_password_reset_body": email_template_password_reset_body,
    }

    for key, value in settings_to_save.items():
        save_site_setting(db, key, value)
    save_smtp_password(db, smtp_password)


def save_security_settings(
    db: Session,
    *,
    trusted_hosts_enabled: str,
    allowed_hosts: str,
    csp_frame_ancestors: str,
    csp_frame_ancestor_sources: str,
    hsts_enabled: str,
    hsts_include_subdomains: str,
    hsts_max_age: str,
    rdp_token_ttl_minutes: str,
) -> None:
    if csp_frame_ancestors not in {"none", "self", "custom"}:
        csp_frame_ancestors = "self"
    try:
        clean_hsts_max_age = str(max(300, min(int(hsts_max_age or 31536000), 63072000)))
    except ValueError:
        clean_hsts_max_age = "31536000"
    try:
        clean_rdp_ttl = str(max(5, min(int(rdp_token_ttl_minutes or 10), 60)))
    except ValueError:
        clean_rdp_ttl = "10"

    settings_to_save = {
        "trusted_hosts_enabled": "1" if trusted_hosts_enabled else "",
        "allowed_hosts": allowed_hosts,
        "csp_frame_ancestors": csp_frame_ancestors,
        "csp_frame_ancestor_sources": csp_frame_ancestor_sources,
        "hsts_enabled": "1" if hsts_enabled else "",
        "hsts_include_subdomains": "1" if hsts_include_subdomains else "",
        "hsts_max_age": clean_hsts_max_age,
        "rdp_token_ttl_minutes": clean_rdp_ttl,
    }
    for key, value in settings_to_save.items():
        save_site_setting(db, key, value)


def include_current_host(allowed_hosts: str, request: Request) -> str:
    current_host = request.headers.get("host", "").strip()
    if not current_host:
        return allowed_hosts
    existing = {
        part.strip().lower()
        for part in str(allowed_hosts or "").replace("\r", "\n").replace(",", "\n").split("\n")
        if part.strip()
    }
    if current_host.lower() in existing:
        return allowed_hosts
    separator = "\n" if allowed_hosts.strip() else ""
    return f"{allowed_hosts.strip()}{separator}{current_host}"


def security_check_context(request: Request, db: Session) -> dict[str, object]:
    app_settings = get_settings()
    security = load_security_settings(db)
    allowed_hosts = effective_allowed_hosts(security, app_settings)
    current_host = request.headers.get("host", "")
    host_filter_enabled = security.get("trusted_hosts_enabled") == "1" or bool(app_settings.allowed_hosts.strip())
    request_is_https = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip() == "https"
    )
    hsts_enabled = security.get("hsts_enabled") == "1" or app_settings.session_cookie_secure
    return {
        "current_host": current_host,
        "host_filter_enabled": host_filter_enabled,
        "host_allowed": (not host_filter_enabled) or host_is_allowed(current_host, allowed_hosts),
        "allowed_hosts": allowed_hosts,
        "frame_ancestors": frame_ancestor_directive(security),
        "hsts_enabled": hsts_enabled,
        "hsts_active": request_is_https and hsts_enabled,
        "hsts_header": hsts_header_value(security) if hsts_enabled else "",
        "request_is_https": request_is_https,
        "rdp_token_ttl_minutes": security.get("rdp_token_ttl_minutes") or "10",
    }


def lookup_public_ip() -> tuple[str, str]:
    services = [
        ("ipify", "https://api.ipify.org?format=json"),
        ("ifconfig.me", "https://ifconfig.me/ip"),
    ]
    last_error = "Public IP check failed"
    for name, url in services:
        try:
            with urlopen(url, timeout=5) as response:
                body = response.read(512).decode("utf-8", errors="replace").strip()
            if name == "ipify":
                payload = json.loads(body)
                ip_address = str(payload.get("ip", "")).strip()
            else:
                ip_address = body
            if ip_address:
                return ip_address, name
        except Exception as exc:
            last_error = f"{name}: {type(exc).__name__}"
    raise RuntimeError(last_error)


def lookup_inbound_addresses(host: str) -> list[str]:
    addresses = {
        result[4][0]
        for result in socket.getaddrinfo(host, None)
        if result[4] and result[4][0]
    }
    return sorted(addresses)


@router.get("/admin")
def admin_home(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    users = db.query(User).count()
    enabled_2fa = db.query(User).filter(User.totp_enabled == True).count()
    audit_events = db.query(AuditLog).count()

    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "user": user,
            "users": users,
            "enabled_2fa": enabled_2fa,
            "audit_events": audit_events,
            **csrf_context(request),
        },
    )


@router.get("/team/users")
def users(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    rows = db.query(User).order_by(User.email.asc()).all()

    return templates.TemplateResponse(
        request,
        "users.html",
        {
            "user": user,
            "rows": rows,
            **csrf_context(request),
        },
    )


@router.get("/team/users/new")
def new_user(
    request: Request,
    user=Depends(require_admin),
):
    return templates.TemplateResponse(
        request,
        "user_form.html",
        {
            "user": user,
            "target": None,
            "roles": sorted(ROLES),
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/team/users/new")
def create_user(
    request: Request,
    email: str = Form(..., max_length=255),
    first_name: str = Form("", max_length=120),
    last_name: str = Form("", max_length=120),
    password: str = Form(..., min_length=12, max_length=255),
    role: str = Form("viewer"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    role = role if role in ROLES else "viewer"
    email = email.strip().lower()

    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(
            request,
            "user_form.html",
            {
                "user": user,
                "target": None,
                "roles": sorted(ROLES),
                "error": "A user with that email already exists.",
                **csrf_context(request),
            },
            status_code=400,
        )

    row = User(
        email=email,
        first_name=first_name.strip() or None,
        last_name=last_name.strip() or None,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )

    db.add(row)
    db.commit()

    write_audit(
        db,
        user,
        "create",
        "user",
        str(row.id),
        request.client.host if request.client else None,
        detail=email,
    )

    return RedirectResponse("/team/users", status_code=303)


@router.get("/team/users/{user_id}/edit")
def edit_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    target = db.get(User, user_id)

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return templates.TemplateResponse(
        request,
        "user_form.html",
        {
            "user": user,
            "target": target,
            "roles": sorted(ROLES),
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/team/users/{user_id}/edit")
def update_user(
    request: Request,
    user_id: int,
    email: str = Form(..., max_length=255),
    first_name: str = Form("", max_length=120),
    last_name: str = Form("", max_length=120),
    password: str = Form("", max_length=255),
    role: str = Form("viewer"),
    is_active: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    target = db.get(User, user_id)

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if target.id == user.id and (role != "admin" or not is_active):
        return templates.TemplateResponse(
            request,
            "user_form.html",
            {
                "user": user,
                "target": target,
                "roles": sorted(ROLES),
                "error": "You cannot remove your own admin access or deactivate yourself.",
                **csrf_context(request),
            },
            status_code=400,
        )

    role = role if role in ROLES else "viewer"

    target.email = email.strip().lower()
    target.first_name = first_name.strip() or None
    target.last_name = last_name.strip() or None
    target.role = role
    target.is_active = bool(is_active)

    if password:
        if len(password) < 12:
            return templates.TemplateResponse(
                request,
                "user_form.html",
                {
                    "user": user,
                    "target": target,
                    "roles": sorted(ROLES),
                    "error": "New passwords must be at least 12 characters.",
                    **csrf_context(request),
                },
                status_code=400,
            )

        target.password_hash = hash_password(password)

    db.commit()

    write_audit(
        db,
        user,
        "update",
        "user",
        str(target.id),
        request.client.host if request.client else None,
        detail=target.email,
    )

    return RedirectResponse("/team/users", status_code=303)


@router.post("/team/users/{user_id}/reset-2fa")
def reset_user_2fa(
    request: Request,
    user_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    target = db.get(User, user_id)

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    target.totp_secret = None
    target.totp_enabled = False

    db.commit()

    write_audit(
        db,
        user,
        "reset_2fa",
        "user",
        str(target.id),
        request.client.host if request.client else None,
        detail=target.email,
    )

    return RedirectResponse("/team/users", status_code=303)


@router.get("/data/import-export")
def import_page(
    request: Request,
    module: str = "licences",
    user=Depends(require_admin),
):
    return templates.TemplateResponse(
        request,
        "import.html",
        {
            "user": user,
            "active_module": module if module in {"licences", "ip-addresses"} else "licences",
            "message": None,
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/data/import-export/import/{module}")
async def import_upload(
    request: Request,
    module: str,
    file: UploadFile = File(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    active_module = module if module in {"licences", "ip-addresses"} else "licences"
    filename = file.filename or ""

    if not filename.lower().endswith(".csv"):
        return templates.TemplateResponse(
            request,
            "import.html",
            {
                "user": user,
                "active_module": active_module,
                "message": None,
                "error": "Only CSV files are currently supported.",
                **csrf_context(request),
            },
            status_code=400,
        )

    max_upload_mb = int(get_site_setting(db, "max_upload_mb"))
    max_bytes = max_upload_mb * 1024 * 1024
    contents = await file.read(max_bytes + 1)

    if len(contents) > max_bytes:
        return templates.TemplateResponse(
            request,
            "import.html",
            {
                "user": user,
                "active_module": active_module,
                "message": None,
                "error": f"CSV file is larger than {max_upload_mb} MB.",
                **csrf_context(request),
            },
            status_code=413,
        )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        if active_module == "ip-addresses":
            count = import_ip_addresses_csv(
                db,
                user,
                tmp_path,
                request.client.host if request.client else None,
            )
            label = "IP address"
        else:
            count = import_csv(
                db,
                user,
                tmp_path,
                request.client.host if request.client else None,
            )
            label = "licence"
    except ImportCSVError as exc:
        return templates.TemplateResponse(
            request,
            "import.html",
            {
                "user": user,
                "active_module": active_module,
                "message": None,
                "error": str(exc),
                **csrf_context(request),
            },
            status_code=400,
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return templates.TemplateResponse(
        request,
        "import.html",
        {
            "user": user,
            "active_module": active_module,
            "message": f"Imported or updated {count} {label} records.",
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/data/import-export/export/{module}")
def export_csv(
    request: Request,
    module: str,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    if module == "ip-addresses":
        csv_data = export_ip_addresses_csv(db)
        entity = "ip_address"
        filename = "kaya-ip-addresses.csv"
        detail = "Exported IP address CSV"
    else:
        csv_data = export_licences_csv(db)
        entity = "licence"
        filename = "kaya-licences.csv"
        detail = "Exported licence CSV"

    write_audit(
        db,
        user,
        "export",
        entity,
        None,
        request.client.host if request.client else None,
        detail=detail,
    )

    return PlainTextResponse(
        csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/data/custom-fields")
def custom_fields(
    request: Request,
    module: str = "ip_addresses",
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    active_module = module if module in CUSTOM_FIELD_MODULES else "ip_addresses"

    rows = (
        db.query(CustomField)
        .filter(CustomField.module == active_module)
        .order_by(CustomField.sort_order.asc(), CustomField.label.asc())
        .all()
    )

    return templates.TemplateResponse(
        request,
        "custom_fields.html",
        {
            "user": user,
            "modules": CUSTOM_FIELD_MODULES,
            "active_module": active_module,
            "rows": rows,
            "field_types": FIELD_TYPES,
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/data/custom-fields")
def create_custom_field(
    request: Request,
    module: str = Form("ip_addresses"),
    label: str = Form(..., max_length=120),
    field_type: str = Form("text"),
    options: str = Form("", max_length=5000),
    is_required: str = Form(""),
    sort_order: int = Form(0),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    active_module = module if module in CUSTOM_FIELD_MODULES else "ip_addresses"
    clean_label = label.strip()
    clean_type = field_type if field_type in FIELD_TYPES else "text"
    clean_options = options.strip()

    rows = (
        db.query(CustomField)
        .filter(CustomField.module == active_module)
        .order_by(CustomField.sort_order.asc(), CustomField.label.asc())
        .all()
    )

    if not clean_label:
        return templates.TemplateResponse(
            request,
            "custom_fields.html",
            {
                "user": user,
                "modules": CUSTOM_FIELD_MODULES,
                "active_module": active_module,
                "rows": rows,
                "field_types": FIELD_TYPES,
                "error": "Field name is required.",
                **csrf_context(request),
            },
            status_code=400,
        )

    if clean_type in {"radio", "select"} and not clean_options:
        return templates.TemplateResponse(
            request,
            "custom_fields.html",
            {
                "user": user,
                "modules": CUSTOM_FIELD_MODULES,
                "active_module": active_module,
                "rows": rows,
                "field_types": FIELD_TYPES,
                "error": "List fields need one option per line.",
                **csrf_context(request),
            },
            status_code=400,
        )

    field_key = make_field_key(clean_label)

    if (
        db.query(CustomField)
        .filter(
            CustomField.module == active_module,
            CustomField.field_key == field_key,
        )
        .first()
    ):
        return templates.TemplateResponse(
            request,
            "custom_fields.html",
            {
                "user": user,
                "modules": CUSTOM_FIELD_MODULES,
                "active_module": active_module,
                "rows": rows,
                "field_types": FIELD_TYPES,
                "error": "A field with that name already exists for this module.",
                **csrf_context(request),
            },
            status_code=400,
        )

    row = CustomField(
        module=active_module,
        label=clean_label,
        field_key=field_key,
        field_type=clean_type,
        options=clean_options or None,
        is_required=bool(is_required),
        is_active=True,
        sort_order=sort_order,
    )

    db.add(row)
    db.commit()

    write_audit(
        db,
        user,
        "create",
        "custom_field",
        str(row.id),
        request.client.host if request.client else None,
        detail=f"{CUSTOM_FIELD_MODULES[active_module]}: {clean_label}",
    )

    params = urlencode({"module": active_module})

    return RedirectResponse(
        f"/data/custom-fields?{params}",
        status_code=303,
    )

@router.post("/data/custom-fields/{field_id}/toggle")
def toggle_custom_field(
    request: Request,
    field_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    row = db.get(CustomField, field_id)

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Custom field not found",
        )

    row.is_active = not row.is_active
    db.commit()

    write_audit(
        db,
        user,
        "update",
        "custom_field",
        str(row.id),
        request.client.host if request.client else None,
        detail=f"{row.label}: {'active' if row.is_active else 'inactive'}",
    )

    return RedirectResponse(
        f"/data/custom-fields?module={row.module}",
        status_code=303,
    )


@router.get("/data/categories")
def categories(
    request: Request,
    module: str = "hardware_assets",
    list_key: str = "category",
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    active_module = module if module in MANAGED_LIST_MODULES else "hardware_assets"
    lists = MANAGED_LISTS.get(active_module, {})
    active_list = list_key if list_key in lists else next(iter(lists))

    rows = (
        db.query(ManagedListItem)
        .filter(
            ManagedListItem.module == active_module,
            ManagedListItem.list_key == active_list,
        )
        .order_by(ManagedListItem.sort_order.asc(), ManagedListItem.value.asc())
        .all()
    )

    return templates.TemplateResponse(
        request,
        "categories.html",
        {
            "user": user,
            "modules": MANAGED_LIST_MODULES,
            "lists": lists,
            "active_module": active_module,
            "active_list": active_list,
            "active_list_label": list_label(active_module, active_list),
            "rows": rows,
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/data/categories")
def create_category(
    request: Request,
    module: str = Form("hardware_assets"),
    list_key: str = Form("category"),
    value: str = Form(..., max_length=120),
    sort_order: int = Form(0),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    active_module = module if module in MANAGED_LIST_MODULES else "hardware_assets"
    lists = MANAGED_LISTS.get(active_module, {})
    active_list = list_key if list_key in lists else next(iter(lists))
    clean_value = value.strip()

    rows = (
        db.query(ManagedListItem)
        .filter(
            ManagedListItem.module == active_module,
            ManagedListItem.list_key == active_list,
        )
        .order_by(ManagedListItem.sort_order.asc(), ManagedListItem.value.asc())
        .all()
    )

    if not clean_value:
        return templates.TemplateResponse(
            request,
            "categories.html",
            {
                "user": user,
                "modules": MANAGED_LIST_MODULES,
                "lists": lists,
                "active_module": active_module,
                "active_list": active_list,
                "active_list_label": list_label(active_module, active_list),
                "rows": rows,
                "error": "Name is required.",
                **csrf_context(request),
            },
            status_code=400,
        )

    if (
        db.query(ManagedListItem)
        .filter(
            ManagedListItem.module == active_module,
            ManagedListItem.list_key == active_list,
            ManagedListItem.value == clean_value,
        )
        .first()
    ):
        return templates.TemplateResponse(
            request,
            "categories.html",
            {
                "user": user,
                "modules": MANAGED_LIST_MODULES,
                "lists": lists,
                "active_module": active_module,
                "active_list": active_list,
                "active_list_label": list_label(active_module, active_list),
                "rows": rows,
                "error": "That value already exists.",
                **csrf_context(request),
            },
            status_code=400,
        )

    row = ManagedListItem(
        module=active_module,
        list_key=active_list,
        value=clean_value,
        is_active=True,
        sort_order=sort_order,
    )

    db.add(row)
    db.commit()

    write_audit(
        db,
        user,
        "create",
        "category",
        str(row.id),
        request.client.host if request.client else None,
        detail=f"{MANAGED_LIST_MODULES[active_module]} {list_label(active_module, active_list)}: {clean_value}",
    )

    return RedirectResponse(
        f"/data/categories?module={active_module}&list_key={active_list}",
        status_code=303,
    )


@router.post("/data/categories/{item_id}/toggle")
def toggle_category(
    request: Request,
    item_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    row = db.get(ManagedListItem, item_id)

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found",
        )

    row.is_active = not row.is_active
    db.commit()

    write_audit(
        db,
        user,
        "update",
        "category",
        str(row.id),
        request.client.host if request.client else None,
        detail=f"{row.value}: {'active' if row.is_active else 'inactive'}",
    )

    return RedirectResponse(
        f"/data/categories?module={row.module}&list_key={row.list_key}",
        status_code=303,
    )


@router.post("/data/categories/{item_id}/edit")
def edit_category(
    request: Request,
    item_id: int,
    value: str = Form(..., max_length=120),
    sort_order: int = Form(0),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    row = db.get(ManagedListItem, item_id)

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Category not found",
        )

    clean_value = value.strip()

    if not clean_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Name is required.",
        )

    duplicate = (
        db.query(ManagedListItem)
        .filter(
            ManagedListItem.module == row.module,
            ManagedListItem.list_key == row.list_key,
            ManagedListItem.value == clean_value,
            ManagedListItem.id != row.id,
        )
        .first()
    )

    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That value already exists.",
        )

    old_value = row.value
    row.value = clean_value
    row.sort_order = sort_order

    db.commit()

    write_audit(
        db,
        user,
        "update",
        "category",
        str(row.id),
        request.client.host if request.client else None,
        detail=f"{old_value} -> {row.value}",
    )

    return RedirectResponse(
        f"/data/categories?module={row.module}&list_key={row.list_key}",
        status_code=303,
    )


@router.get("/admin/security")
def security(
    request: Request,
    user=Depends(require_admin),
):
    secret = (
        decrypted_totp_secret(user.totp_secret)
        if user.totp_secret and not user.totp_enabled
        else None
    )

    uri = provisioning_uri(user.email, secret) if secret else None
    qr_code = qr_code_data_uri(uri) if uri else None

    return templates.TemplateResponse(
        request,
        "security.html",
        {
            "user": user,
            "setup_secret": secret,
            "setup_uri": uri,
            "setup_qr_code": qr_code,
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/admin/security/2fa/start")
def start_2fa(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    secret = generate_totp_secret()
    user.totp_secret = encrypted_totp_secret(secret)
    user.totp_enabled = False

    db.commit()

    write_audit(
        db,
        user,
        "start_2fa",
        "user",
        str(user.id),
        request.client.host if request.client else None,
    )

    return RedirectResponse("/admin/security", status_code=303)


@router.post("/admin/security/2fa/enable")
def enable_2fa(
    request: Request,
    code: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    secret = decrypted_totp_secret(user.totp_secret)

    if not secret or not verify_totp(secret, code):
        uri = provisioning_uri(user.email, secret) if secret else None
        qr_code = qr_code_data_uri(uri) if uri else None

        return templates.TemplateResponse(
            request,
            "security.html",
            {
                "user": user,
                "setup_secret": secret,
                "setup_uri": uri,
                "setup_qr_code": qr_code,
                "error": "Invalid authentication code.",
                **csrf_context(request),
            },
            status_code=400,
        )

    user.totp_enabled = True

    db.commit()

    write_audit(
        db,
        user,
        "enable_2fa",
        "user",
        str(user.id),
        request.client.host if request.client else None,
    )

    return RedirectResponse("/admin/security", status_code=303)


@router.post("/admin/security/2fa/disable")
def disable_2fa(
    request: Request,
    current_password: str = Form("", max_length=255),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    if not verify_password(current_password, user.password_hash):
        return templates.TemplateResponse(
            request,
            "security.html",
            {
                "user": user,
                "setup_secret": None,
                "setup_uri": None,
                "setup_qr_code": None,
                "error": "Current password is required to disable 2FA.",
                **csrf_context(request),
            },
            status_code=400,
        )

    user.totp_secret = None
    user.totp_enabled = False

    db.commit()

    write_audit(
        db,
        user,
        "disable_2fa",
        "user",
        str(user.id),
        request.client.host if request.client else None,
    )

    return RedirectResponse("/admin/security", status_code=303)


@router.get("/admin/audit")
def legacy_audit(user=Depends(require_admin)):
    return RedirectResponse("/system/audit-logs", status_code=302)


@router.get("/system/audit-logs")
def audit_logs(
    request: Request,
    q: str = Query("", max_length=200),
    category: str = Query("", max_length=40),
    severity: str = Query("", max_length=20),
    action: str = Query("", max_length=80),
    entity: str = Query("", max_length=80),
    actor: str = Query("", max_length=255),
    date_from: str = Query("", max_length=10),
    date_to: str = Query("", max_length=10),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=25, le=100),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    if per_page not in {25, 50, 100}:
        per_page = 50
    query = db.query(AuditLog)
    settings = get_settings()
    clean_q = q.strip()
    if clean_q:
        like = f"%{clean_q}%"
        search_fields = [
            AuditLog.action.ilike(like),
            AuditLog.entity.ilike(like),
            AuditLog.entity_id.ilike(like),
            AuditLog.detail.ilike(like),
            AuditLog.request_path.ilike(like),
            AuditLog.request_id.ilike(like),
            AuditLog.user.has(User.email.ilike(like)),
        ]
        if not settings.demo_mode:
            search_fields.append(AuditLog.ip_address.ilike(like))
        query = query.filter(or_(*search_fields))
    if category:
        query = query.filter(AuditLog.category == category)
    if severity:
        query = query.filter(AuditLog.severity == severity)
    if action:
        query = query.filter(AuditLog.action == action)
    if entity:
        query = query.filter(AuditLog.entity == entity)
    if actor:
        query = query.filter(AuditLog.user.has(User.email == actor))
    if date_from:
        try:
            query = query.filter(AuditLog.created_at >= datetime.strptime(date_from, "%Y-%m-%d"))
        except ValueError:
            date_from = ""
    if date_to:
        try:
            query = query.filter(AuditLog.created_at < datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1))
        except ValueError:
            date_to = ""

    filtered_total = query.count()
    pages = max(1, (filtered_total + per_page - 1) // per_page)
    page = min(page, pages)
    logs = (
        query
        .options(selectinload(AuditLog.user))
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    for log in logs:
        try:
            parsed_metadata = json.loads(log.metadata_json or "{}")
            log.metadata_data = parsed_metadata if isinstance(parsed_metadata, dict) else {"value": parsed_metadata}
        except json.JSONDecodeError:
            log.metadata_data = {"raw": log.metadata_json}

    now = datetime.utcnow()
    summary = {
        "total": db.query(func.count(AuditLog.id)).scalar() or 0,
        "last_24h": db.query(func.count(AuditLog.id)).filter(AuditLog.created_at >= now - timedelta(days=1)).scalar() or 0,
        "attention": db.query(func.count(AuditLog.id)).filter(AuditLog.severity.in_(["warning", "error", "critical"])).scalar() or 0,
        "actors": db.query(func.count(func.distinct(AuditLog.user_id))).filter(AuditLog.user_id.is_not(None)).scalar() or 0,
    }
    categories = [value for value, in db.query(AuditLog.category).distinct().order_by(AuditLog.category) if value]
    actions = [value for value, in db.query(AuditLog.action).distinct().order_by(AuditLog.action) if value]
    entities = [value for value, in db.query(AuditLog.entity).distinct().order_by(AuditLog.entity) if value]
    actors = [email for email, in db.query(User.email).join(AuditLog, AuditLog.user_id == User.id).distinct().order_by(User.email)]
    params = {
        "q": clean_q,
        "category": category,
        "severity": severity,
        "action": action,
        "entity": entity,
        "actor": actor,
        "date_from": date_from,
        "date_to": date_to,
        "per_page": per_page,
    }
    params = {key: value for key, value in params.items() if value not in ("", None)}
    page_url = lambda target: "/system/audit-logs?" + urlencode({**params, "page": target})
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "user": user,
            "logs": logs,
            "summary": summary,
            "filtered_total": filtered_total,
            "categories": categories,
            "actions": actions,
            "entities": entities,
            "actors": actors,
            "q": clean_q,
            "active_category": category,
            "active_severity": severity,
            "active_action": action,
            "active_entity": entity,
            "active_actor": actor,
            "date_from": date_from,
            "date_to": date_to,
            "page": page,
            "pages": pages,
            "per_page": per_page,
            "previous_url": page_url(page - 1) if page > 1 else None,
            "next_url": page_url(page + 1) if page < pages else None,
            **csrf_context(request),
        },
    )


@router.get("/system/about")
def about(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    if get_settings().demo_mode:
        sessions = []
        current_session_id = None
    else:
        sessions = (
            db.query(AppSession)
            .filter(
                AppSession.ended_at.is_(None),
                AppSession.last_seen_at >= active_since(),
            )
            .options(selectinload(AppSession.user))
            .order_by(AppSession.last_seen_at.desc())
            .limit(100)
            .all()
        )
        current_session_id = request.session.get("session_id")

    return templates.TemplateResponse(
        request,
        "about.html",
        {
            "user": user,
            "about": collect_about(db),
            "sessions": sessions,
            "current_session_id": current_session_id,
            **csrf_context(request),
        },
    )


@router.get("/system/site-administration")
def settings_page(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "settings": load_site_settings(db),
            "security_check": security_check_context(request, db),
            "message": None,
            "error": None,
            **csrf_context(request),
        },
    )


@router.get("/system/site-administration/security/public-ip")
def public_ip_check(user=Depends(require_admin)):
    try:
        ip_address, source = lookup_public_ip()
    except RuntimeError as exc:
        return JSONResponse(
            {"ok": False, "error": str(exc)},
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
    return {"ok": True, "ip": ip_address, "source": source}


@router.get("/system/site-administration/security/inbound")
def inbound_check(request: Request, user=Depends(require_admin)):
    host = host_without_port(request.headers.get("host", ""))
    if not host:
        return JSONResponse(
            {"ok": False, "error": "Kaya could not read a Host header from this request."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    try:
        addresses = lookup_inbound_addresses(host)
    except OSError as exc:
        return JSONResponse(
            {"ok": False, "host": host, "error": f"DNS lookup failed: {type(exc).__name__}"},
            status_code=status.HTTP_502_BAD_GATEWAY,
        )

    if not addresses:
        return JSONResponse(
            {"ok": False, "host": host, "error": "DNS lookup returned no addresses."},
            status_code=status.HTTP_502_BAD_GATEWAY,
        )

    return {"ok": True, "host": host, "addresses": addresses}


@router.post("/system/site-administration")
def save_settings(
    request: Request,
    app_name: str = Form(APP_BRAND_NAME),
    base_url: str = Form("http://localhost:8080"),
    github_repo: str = Form("antybubbs/Kaya"),
    version_check_interval_seconds: str = Form("1800"),
    guacd_host: str = Form(""),
    guacd_port: str = Form(""),
    max_upload_mb: str = Form("25"),
    trusted_hosts_enabled: str = Form(""),
    allowed_hosts: str = Form(""),
    csp_frame_ancestors: str = Form("self"),
    csp_frame_ancestor_sources: str = Form(""),
    hsts_enabled: str = Form(""),
    hsts_include_subdomains: str = Form(""),
    hsts_max_age: str = Form("31536000"),
    rdp_token_ttl_minutes: str = Form("10"),
    backup_storage_type: str = Form("local"),
    backup_storage_path: str = Form("/mnt/backups"),
    backup_remote_host: str = Form(""),
    backup_remote_share: str = Form(""),
    backup_remote_username: str = Form(""),
    backup_remote_password: str = Form(""),
    backup_targets_json: str = Form("[]"),
    backup_default_target_name: str = Form(""),
    smtp_enabled: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: str = Form("587"),
    smtp_use_tls: str = Form(""),
    smtp_use_ssl: str = Form(""),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from_email: str = Form(""),
    smtp_from_name: str = Form(APP_BRAND_NAME),
    email_template_password_reset_subject: str = Form(""),
    email_template_password_reset_body: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    save_email_settings(
        db,
        app_name=app_name,
        base_url=base_url,
        github_repo=github_repo,
        version_check_interval_seconds=version_check_interval_seconds,
        guacd_host=guacd_host,
        guacd_port=guacd_port,
        max_upload_mb=max_upload_mb,
        smtp_enabled=smtp_enabled,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_use_tls=smtp_use_tls,
        smtp_use_ssl=smtp_use_ssl,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        smtp_from_email=smtp_from_email,
        smtp_from_name=smtp_from_name,
        email_template_password_reset_subject=email_template_password_reset_subject,
        email_template_password_reset_body=email_template_password_reset_body,
    )
    if trusted_hosts_enabled:
        allowed_hosts = include_current_host(allowed_hosts, request)
    save_security_settings(
        db,
        trusted_hosts_enabled=trusted_hosts_enabled,
        allowed_hosts=allowed_hosts,
        csp_frame_ancestors=csp_frame_ancestors,
        csp_frame_ancestor_sources=csp_frame_ancestor_sources,
        hsts_enabled=hsts_enabled,
        hsts_include_subdomains=hsts_include_subdomains,
        hsts_max_age=hsts_max_age,
        rdp_token_ttl_minutes=rdp_token_ttl_minutes,
    )
    save_backup_settings(
        db,
        backup_storage_type=backup_storage_type,
        backup_storage_path=backup_storage_path,
        backup_remote_host=backup_remote_host,
        backup_remote_share=backup_remote_share,
        backup_remote_username=backup_remote_username,
        backup_remote_password=backup_remote_password,
    )
    normalized_targets = normalize_backup_targets_json(backup_targets_json)
    save_site_setting(db, "backup_targets_json", normalized_targets)
    default_name = backup_default_target_name.strip()
    if default_name:
        save_site_setting(db, "backup_default_target_name", default_name)
    else:
        save_site_setting(db, "backup_default_target_name", "")

    db.commit()

    write_audit(
        db,
        user,
        "update",
        "settings",
        None,
        request.client.host if request.client else None,
        detail="Updated application settings",
    )

    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "settings": load_site_settings(db),
            "security_check": security_check_context(request, db),
            "message": "Settings saved successfully.",
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/system/site-administration/test-backup-storage")
def test_backup_storage(
    request: Request,
    backup_storage_type: str = Form("local"),
    backup_storage_path: str = Form("/mnt/backups"),
    backup_remote_host: str = Form(""),
    backup_remote_share: str = Form(""),
    backup_remote_username: str = Form(""),
    backup_remote_password: str = Form(""),
    backup_remote_password_enc: str = Form(""),
    backup_targets_json: str = Form("[]"),
    backup_default_target_name: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    effective_remote_password = backup_remote_password.strip()
    if not effective_remote_password and backup_remote_password_enc.strip():
        effective_remote_password = decrypt_secret(backup_remote_password_enc).strip()

    save_backup_settings(
        db,
        backup_storage_type=backup_storage_type,
        backup_storage_path=backup_storage_path,
        backup_remote_host=backup_remote_host,
        backup_remote_share=backup_remote_share,
        backup_remote_username=backup_remote_username,
        backup_remote_password=effective_remote_password,
    )
    save_site_setting(db, "backup_targets_json", normalize_backup_targets_json(backup_targets_json))
    save_site_setting(db, "backup_default_target_name", backup_default_target_name.strip())
    db.commit()

    passed, detail = test_backup_storage_target(
        db,
        storage_type=backup_storage_type,
        storage_path=backup_storage_path,
        remote_host=backup_remote_host,
        remote_share=backup_remote_share,
        remote_username=backup_remote_username,
        remote_password=effective_remote_password,
    )
    write_audit(
        db,
        user,
        "test_backup_storage",
        "settings",
        None,
        request.client.host if request.client else None,
        detail=detail,
        severity="info" if passed else "warning",
    )
    db.commit()

    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "settings": load_site_settings(db),
            "security_check": security_check_context(request, db),
            "message": f"Backup storage test passed: {detail}" if passed else None,
            "error": None if passed else f"Backup storage test failed: {detail}",
            **csrf_context(request),
        },
    )


@router.post("/system/site-administration/test-email")
def send_test_email(
    request: Request,
    app_name: str = Form(APP_BRAND_NAME),
    base_url: str = Form("http://localhost:8080"),
    github_repo: str = Form("antybubbs/Kaya"),
    version_check_interval_seconds: str = Form("1800"),
    guacd_host: str = Form(""),
    guacd_port: str = Form(""),
    max_upload_mb: str = Form("25"),
    trusted_hosts_enabled: str = Form(""),
    allowed_hosts: str = Form(""),
    csp_frame_ancestors: str = Form("self"),
    csp_frame_ancestor_sources: str = Form(""),
    hsts_enabled: str = Form(""),
    hsts_include_subdomains: str = Form(""),
    hsts_max_age: str = Form("31536000"),
    rdp_token_ttl_minutes: str = Form("10"),
    smtp_enabled: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: str = Form("587"),
    smtp_use_tls: str = Form(""),
    smtp_use_ssl: str = Form(""),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from_email: str = Form(""),
    smtp_from_name: str = Form(APP_BRAND_NAME),
    email_template_password_reset_subject: str = Form(""),
    email_template_password_reset_body: str = Form(""),
    test_email_to: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)

    save_email_settings(
        db,
        app_name=app_name,
        base_url=base_url,
        github_repo=github_repo,
        version_check_interval_seconds=version_check_interval_seconds,
        guacd_host=guacd_host,
        guacd_port=guacd_port,
        max_upload_mb=max_upload_mb,
        smtp_enabled=smtp_enabled,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_use_tls=smtp_use_tls,
        smtp_use_ssl=smtp_use_ssl,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        smtp_from_email=smtp_from_email,
        smtp_from_name=smtp_from_name,
        email_template_password_reset_subject=email_template_password_reset_subject,
        email_template_password_reset_body=email_template_password_reset_body,
    )
    if trusted_hosts_enabled:
        allowed_hosts = include_current_host(allowed_hosts, request)
    save_security_settings(
        db,
        trusted_hosts_enabled=trusted_hosts_enabled,
        allowed_hosts=allowed_hosts,
        csp_frame_ancestors=csp_frame_ancestors,
        csp_frame_ancestor_sources=csp_frame_ancestor_sources,
        hsts_enabled=hsts_enabled,
        hsts_include_subdomains=hsts_include_subdomains,
        hsts_max_age=hsts_max_age,
        rdp_token_ttl_minutes=rdp_token_ttl_minutes,
    )
    db.commit()

    recipient = (test_email_to or user.email).strip()
    template_values = {
        "app_name": app_name.strip() or APP_BRAND_NAME,
        "expiry_hours": "1",
        "reset_link": f"{(base_url.strip() or 'http://localhost:8080').rstrip('/')}/reset-password?token=example-test-token",
        "user_email": recipient,
    }
    subject = render_email_template(email_template_password_reset_subject or SITE_SETTING_KEYS["email_template_password_reset_subject"], **template_values)
    body = render_email_template(email_template_password_reset_body or SITE_SETTING_KEYS["email_template_password_reset_body"], **template_values)

    try:
        send_mail(db, recipient, f"[Test] {subject}", body)
        write_audit(
            db,
            user,
            "test_email_sent",
            "settings",
            None,
            request.client.host if request.client else None,
            detail=f"Sent test email to {recipient}",
        )
        message = f"Test email sent to {recipient}."
        error = None
    except (MailConfigurationError, OSError, ValueError, smtplib.SMTPException) as exc:
        write_audit(
            db,
            user,
            "test_email_failed",
            "settings",
            None,
            request.client.host if request.client else None,
            detail=type(exc).__name__,
            severity="warning",
        )
        message = None
        error = f"Test email failed: {exc}"

    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "settings": load_site_settings(db),
            "security_check": security_check_context(request, db),
            "message": message,
            "error": error,
            "test_email_to": recipient,
            **csrf_context(request),
        },
    )
