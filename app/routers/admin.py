from pathlib import Path
import io
import tempfile
import json
import re
import socket
import smtplib
from ftplib import FTP
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
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
from app.core.performance import external_call
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
    BackupJob,
    BackupRecord,
    CustomField,
    CustomFieldValue,
    DNSProviderConfig,
    HACluster,
    DHCPRange,
    ExternalIdentity,
    ManagedListItem,
    IPAddress,
    RemoteManagerSetting,
    User,
    VLAN,
    VaultSession,
)
from app.routers.auth import require_admin
from app.services.about import collect_about
from app.services.audit import write_audit
from app.services.user_names import clean_name_part, first_name_contains_last_name
from app.services.client_ip import client_ip_details, validate_trusted_proxies
from app.services.custom_fields import FIELD_TYPES, make_field_key
from app.services.exporter import export_ip_addresses_csv, export_licences_csv
from app.services.importer import ImportCSVError, import_csv, import_ip_addresses_csv
from app.services.managed_lists import MANAGED_LIST_MODULES, MANAGED_LISTS, list_label
from app.services.mail import MailConfigurationError, render_email_template, send_mail
from app.services.sessions import active_since
from app.services.dns_providers import provider_for
from app.services.guacamole_bridge import restart_guacamole_bridge
from app.services.site_settings import (
    effective_allowed_hosts,
    frame_ancestor_directive,
    get_site_setting,
    host_without_port,
    host_is_allowed,
    hsts_header_value,
    load_security_settings,
    split_hosts,
    validate_allowed_hosts,
)
from app.routers.remote_manager import (
    RDP_SETTING_KEYS,
    SETTINGS as REMOTE_MANAGER_SETTINGS,
    TERMINAL_SETTING_KEYS,
    clean_global_setting,
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
    "timezone_region": "UTC",
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
    "dashboard_customisation_enabled": "1",
    "dashboard_monitor_mode_enabled": "1",
    "dashboard_poll_interval_seconds": "10",
    "dashboard_recent_activity_limit": "10",
    "dashboard_show_source_age": "1",
    "dashboard_attention_required": "1",
    "dashboard_globally_disabled_widgets": "",
    "high_availability_enabled": "",
    "backup_manager_enabled": "1",
    "dns_manager_enabled": "",
    "dns_collector_enabled": "1",
    "dns_default_provider_id": "",
    "dns_refresh_interval_seconds": "300",
    "dns_cache_enabled": "1",
    "dns_vlan_integration_enabled": "1",
    "dns_match_suggestions_enabled": "1",
    "dns_auto_link_exact_mac": "",
    "dns_auto_update_dynamic_ip": "",
    "dns_stale_client_days": "30",
    "dns_retain_client_history": "1",
    "dns_client_history_days": "365",
    "dns_traffic_history_days": "30",
    "dns_vlan_enrichment_enabled": "1",
    "dns_update_empty_managed_hostname": "",
    "secret_vault_min_pin_length": "8",
    "secret_vault_max_auto_lock_minutes": "60",
    "secret_vault_sharing_enabled": "1",
    "secret_vault_oidc_mfa_policy": "either",
    "secret_vault_oidc_accepted_acr": "",
    "secure_send_enabled": "1",
    "secure_send_default_expiry": "24h",
    "secure_send_max_expiry_days": "7",
    "secure_send_max_upload_mb": "25",
    "secure_send_allow_one_download": "1",
    "secure_send_vault_integration": "1",
    "secure_send_gateway_hostname": "http://localhost:8999",
    "secure_send_email_notifications": "1",
    "smtp_enabled": "",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_use_tls": "1",
    "smtp_use_ssl": "",
    "smtp_username": "",
    "smtp_password": "",
    "smtp_from_email": "",
    "smtp_from_name": APP_BRAND_NAME,
    "email_include_branding": "1",
    "email_template_password_reset_subject": "Reset your {app_name} password",
    "email_template_password_reset_body": (
        "A password reset was requested for your {app_name} account.\n\n"
        "Use this link within {expiry_hours} hour to set a new password:\n"
        "{reset_link}\n\n"
        "If you did not request this, you can ignore this email."
    ),
    "email_template_secure_send_subject": "{sender_name} sent you a secure package",
    "email_template_secure_send_body": (
        "Hello {recipient_name},\n\n"
        "{sender_name} has sent you a secure package using {app_name}.\n\n"
        "Open secure package:\n"
        "{secure_link}\n\n"
        "Package: {package_title}\n"
        "Expires: {expiry_utc}\n\n"
        "For your security, obtain the PIN and passphrase from the sender separately."
    ),
}
SITE_SETTING_KEYS.update(REMOTE_MANAGER_SETTINGS)


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

    row = next(
        (
            obj for obj in db.new
            if isinstance(obj, RemoteManagerSetting) and obj.key == key
        ),
        None,
    )

    if not row:
        with db.no_autoflush:
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


def dns_providers_for_admin(db: Session) -> list[DNSProviderConfig]:
    return db.query(DNSProviderConfig).order_by(DNSProviderConfig.name.asc()).all()


def vlan_ip_admin_context(db: Session) -> dict:
    return {
        "vlan_options": db.query(VLAN).order_by(VLAN.name.asc()).all(),
        "vlan_ip_categories": db.query(ManagedListItem).filter_by(module="ip_addresses", list_key="category").order_by(ManagedListItem.sort_order.asc(), ManagedListItem.value.asc()).all(),
        "dhcp_ranges": db.query(DHCPRange).order_by(DHCPRange.name.asc()).all(),
    }


def save_dns_manager_settings(
    db: Session,
    *,
    dns_manager_enabled: str,
    dns_collector_enabled: str,
    dns_default_provider_id: str,
    dns_refresh_interval_seconds: str,
    dns_cache_enabled: str,
    dns_vlan_integration_enabled: str,
    dns_match_suggestions_enabled: str,
    dns_auto_link_exact_mac: str,
    dns_auto_update_dynamic_ip: str,
    dns_stale_client_days: str,
    dns_retain_client_history: str,
    dns_client_history_days: str,
    dns_traffic_history_days: str,
    dns_vlan_enrichment_enabled: str,
    dns_update_empty_managed_hostname: str,
    dns_provider_id: str,
    dns_provider_name: str,
    dns_provider_type: str,
    dns_provider_base_url: str,
    dns_provider_auth_method: str,
    dns_provider_secret: str,
    dns_provider_ssl_verify: str,
    dns_provider_timeout_seconds: str,
    dns_provider_enabled: str,
    dns_provider_description: str,
) -> None:
    save_site_setting(db, "dns_manager_enabled", "1" if dns_manager_enabled else "")
    save_site_setting(db, "dns_collector_enabled", "1" if dns_collector_enabled else "")
    save_site_setting(db, "dns_cache_enabled", "1" if dns_cache_enabled else "")
    for key, value in {
        "dns_vlan_integration_enabled": dns_vlan_integration_enabled,
        "dns_match_suggestions_enabled": dns_match_suggestions_enabled,
        "dns_auto_link_exact_mac": dns_auto_link_exact_mac,
        "dns_auto_update_dynamic_ip": dns_auto_update_dynamic_ip,
        "dns_retain_client_history": dns_retain_client_history,
        "dns_vlan_enrichment_enabled": dns_vlan_enrichment_enabled,
        "dns_update_empty_managed_hostname": dns_update_empty_managed_hostname,
    }.items():
        save_site_setting(db, key, "1" if value else "")
    try:
        stale_days = max(1, min(int(dns_stale_client_days or "30"), 3650))
    except ValueError:
        stale_days = 30
    try:
        history_days = max(1, min(int(dns_client_history_days or "365"), 3650))
    except ValueError:
        history_days = 365
    save_site_setting(db, "dns_stale_client_days", str(stale_days))
    save_site_setting(db, "dns_client_history_days", str(history_days))
    try:
        traffic_history_days = max(1, min(int(dns_traffic_history_days or "30"), 3650))
    except ValueError:
        traffic_history_days = 30
    save_site_setting(db, "dns_traffic_history_days", str(traffic_history_days))
    try:
        refresh = max(30, min(int(dns_refresh_interval_seconds or "300"), 86400))
    except ValueError:
        refresh = 300
    save_site_setting(db, "dns_refresh_interval_seconds", str(refresh))

    name = dns_provider_name.strip()
    base_url = dns_provider_base_url.strip().rstrip("/")
    if not name or not base_url:
        save_site_setting(db, "dns_default_provider_id", dns_default_provider_id.strip())
        return

    provider = None
    if dns_provider_id.strip().isdigit():
        provider = db.get(DNSProviderConfig, int(dns_provider_id.strip()))
    if not provider:
        provider = DNSProviderConfig(name=name, provider_type="pihole", base_url=base_url)
        db.add(provider)
        db.flush()

    provider.name = name
    provider.provider_type = dns_provider_type if dns_provider_type in {"pihole"} else "pihole"
    provider.base_url = base_url
    provider.auth_method = dns_provider_auth_method if dns_provider_auth_method in {"password", "api_token"} else "password"
    if dns_provider_secret.strip():
        provider.encrypted_secret = encrypt_secret(dns_provider_secret.strip())
    provider.ssl_verify = bool(dns_provider_ssl_verify)
    try:
        provider.timeout_seconds = max(1, min(int(dns_provider_timeout_seconds or "10"), 60))
    except ValueError:
        provider.timeout_seconds = 10
    provider.is_enabled = bool(dns_provider_enabled)
    provider.description = dns_provider_description.strip() or None
    provider.updated_at = datetime.utcnow()
    save_site_setting(db, "dns_default_provider_id", str(provider.id))


def save_remote_manager_settings(db: Session, form) -> bool:
    previous_bridge_settings = {
        key: get_site_setting(db, key)
        for key in ("guacamole_enabled", "guacd_host", "guacd_port")
    }
    guacamole_enabled = "1" if form.get("guacamole_enabled") else "0"
    guacd_host = str(form.get("guacd_host", "")).strip()
    try:
        guacd_port = max(1, min(int(str(form.get("guacd_port", "4822")) or "4822"), 65535))
    except ValueError:
        guacd_port = 4822

    save_site_setting(db, "guacamole_enabled", guacamole_enabled)
    save_site_setting(db, "split_screen_enabled", "1" if form.get("split_screen_enabled") else "0")
    save_site_setting(db, "guacd_host", guacd_host)
    save_site_setting(db, "guacd_port", str(guacd_port))
    for key in (
        "session_idle_timeout_minutes",
        "recording_mode",
        "recording_categories",
        "recording_pause_idle_minutes",
        *TERMINAL_SETTING_KEYS,
        *RDP_SETTING_KEYS,
    ):
        save_site_setting(db, key, clean_global_setting(key, str(form.get(key, ""))))
    return previous_bridge_settings != {
        "guacamole_enabled": guacamole_enabled,
        "guacd_host": guacd_host,
        "guacd_port": str(guacd_port),
    }


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


def _resolve_backup_path(path_value: str, base_dir: str = "/mnt/backups") -> Path:
    base = Path(base_dir).resolve()
    raw_path = (path_value or "").strip()

    if not raw_path:
        candidate = base
    else:
        # Force user input to remain relative to base, even if an absolute
        # path is supplied.
        relative_input = raw_path.lstrip("/\\")
        candidate = base / Path(relative_input)

    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(base)
    except ValueError:
        raise ValueError(f"Path must stay within {base}.")
    return resolved


def resolve_backup_storage_path(path_value: str) -> tuple[Path | None, str | None]:
    try:
        target = _resolve_backup_path(path_value)
    except ValueError as exc:
        return None, str(exc)
    return target, None


def test_directory_read_write(path_value: str) -> tuple[bool, str]:
    target, validation_error = resolve_backup_storage_path(path_value)
    if validation_error:
        return False, validation_error
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
        with external_call():
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
    email_include_branding: str,
    email_template_password_reset_subject: str,
    email_template_password_reset_body: str,
    email_template_secure_send_subject: str,
    email_template_secure_send_body: str,
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
        "email_include_branding": "1" if email_include_branding else "",
        "email_template_password_reset_subject": email_template_password_reset_subject,
        "email_template_password_reset_body": email_template_password_reset_body,
        "email_template_secure_send_subject": email_template_secure_send_subject,
        "email_template_secure_send_body": email_template_secure_send_body,
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


def security_check_context(request: Request, db: Session) -> dict[str, object]:
    app_settings = get_settings()
    security = load_security_settings(db)
    allowed_hosts = effective_allowed_hosts(security, app_settings)
    current_host = host_without_port(request.headers.get("host", ""))
    host_filter_enabled = security.get("trusted_hosts_enabled") == "1" or bool(app_settings.allowed_hosts.strip())
    request_is_https = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip() == "https"
    )
    hsts_enabled = security.get("hsts_enabled") == "1" or app_settings.session_cookie_secure
    proxy = client_ip_details(request)
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
        "client_ip": proxy.client_ip,
        "immediate_ip": proxy.immediate_ip,
        "forwarded_for": proxy.forwarded_for,
        "trusted_proxy": proxy.trusted_proxy,
        "trusted_proxy_config": proxy.trusted_proxy_config,
        "trusted_proxy_config_errors": validate_trusted_proxies(proxy.trusted_proxy_config),
        "client_ip_source": proxy.source,
    }


def lookup_public_ip() -> tuple[str, str]:
    services = [
        ("ipify", "https://api.ipify.org?format=json"),
        ("ifconfig.me", "https://ifconfig.me/ip"),
    ]
    last_error = "Public IP check failed"
    for name, url in services:
        try:
            with external_call():
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
    with external_call():
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
            "field_errors": {},
            "form_values": {},
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
    first_name = clean_name_part(first_name)
    last_name = clean_name_part(last_name)

    if first_name_contains_last_name(first_name, last_name):
        return templates.TemplateResponse(
            request, "user_form.html",
            {
                "user": user, "target": None, "roles": sorted(ROLES), "error": None,
                "field_errors": {"first_name": "Enter only the given name here; the surname is already in the last name field."},
                "form_values": {"email": email, "first_name": first_name, "last_name": last_name, "role": role},
                **csrf_context(request),
            },
            status_code=400,
        )

    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse(
            request,
            "user_form.html",
            {
                "user": user,
                "target": None,
                "roles": sorted(ROLES),
                "error": "A user with that email already exists.",
                "field_errors": {"email": "This email address is already in use."},
                "form_values": {"email": email, "first_name": first_name, "last_name": last_name, "role": role},
                **csrf_context(request),
            },
            status_code=400,
        )

    row = User(
        email=email,
        first_name=first_name,
        last_name=last_name,
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
            "field_errors": {},
            "form_values": {},
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
    is_break_glass: str = Form(""),
    role_source: str = Form("local"),
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
    clean_first_name = clean_name_part(first_name)
    clean_last_name = clean_name_part(last_name)
    if first_name_contains_last_name(clean_first_name, clean_last_name):
        return templates.TemplateResponse(
            request, "user_form.html",
            {
                "user": user, "target": target, "roles": sorted(ROLES), "error": None,
                "field_errors": {"first_name": "Enter only the given name here; the surname is already in the last name field."},
                "form_values": {
                    "email": email.strip().lower(), "first_name": clean_first_name, "last_name": clean_last_name,
                    "role": role, "is_active": bool(is_active), "is_break_glass": is_break_glass == "1", "role_source": role_source,
                },
                **csrf_context(request),
            },
            status_code=400,
        )

    target.email = email.strip().lower()
    target.first_name = clean_first_name
    target.last_name = clean_last_name
    target.role = role
    target.is_active = bool(is_active)
    requested_break_glass = is_break_glass == "1"
    if requested_break_glass and (role != "admin" or not target.is_active or not (password or target.password_hash)):
        return templates.TemplateResponse(
            request, "user_form.html",
            {"user": user, "target": target, "roles": sorted(ROLES), "error": "Break-glass access requires an active administrator with a local password.", **csrf_context(request)},
            status_code=400,
        )
    target.is_break_glass = requested_break_glass
    target.role_source = role_source if role_source in {"local", "oidc"} else "local"
    identity = db.query(ExternalIdentity).filter_by(user_id=target.id).first()
    if identity:
        identity.role_management = target.role_source

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
        target.authentication_type = "local_and_oidc" if identity else "local"

    db.query(VaultSession).filter(VaultSession.user_id == target.id, VaultSession.revoked_at.is_(None)).update({VaultSession.revoked_at: datetime.utcnow()}, synchronize_session=False)
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
    db.query(VaultSession).filter(VaultSession.user_id == target.id, VaultSession.revoked_at.is_(None)).update({VaultSession.revoked_at: datetime.utcnow()}, synchronize_session=False)
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


@router.post("/data/custom-fields/{field_id}/delete")
def delete_custom_field(request: Request, field_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    row = db.get(CustomField, field_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Custom field not found")
    module = row.module
    label = row.label
    db.query(CustomFieldValue).filter(CustomFieldValue.field_id == row.id).delete(synchronize_session=False)
    db.delete(row)
    db.commit()
    write_audit(db, user, "delete", "custom_field", str(field_id), request.client.host if request.client else None, detail=label)
    return RedirectResponse(f"/data/custom-fields?module={module}", status_code=303)


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


@router.post("/data/categories/{item_id}/delete")
def delete_category(request: Request, item_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    row = db.get(ManagedListItem, item_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Category not found")
    module = row.module
    list_key = row.list_key
    value = row.value
    db.delete(row)
    db.commit()
    write_audit(db, user, "delete", "category", str(item_id), request.client.host if request.client else None, detail=value)
    return RedirectResponse(f"/data/categories?module={module}&list_key={list_key}", status_code=303)


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
            "ha_active_cluster_count": db.query(HACluster).filter(HACluster.deleted_at.is_(None)).count(),
            "backup_preserved_item_count": db.query(BackupRecord).count() + db.query(BackupJob).count(),
            "backup_inflight_job_count": db.query(BackupJob).filter(BackupJob.status.in_(["queued", "dispatched", "running"])).count(),
            "dns_providers": dns_providers_for_admin(db),
            **vlan_ip_admin_context(db),
            "security_check": security_check_context(request, db),
            "message": None,
            "error": None,
            **csrf_context(request),
        },
    )


@router.post("/system/site-administration/experimental-features/high-availability")
async def set_high_availability_feature(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    enabled = str(form.get("enabled") or "") == "1"
    previous = get_site_setting(db, "high_availability_enabled") == "1"
    active_clusters = db.query(HACluster).filter(HACluster.deleted_at.is_(None)).count()
    acknowledged = str(form.get("acknowledge_ha_disable") or "") == "1"
    if not enabled and active_clusters and not acknowledged:
        return RedirectResponse(
            "/system/site-administration?tab=experimental-features&feature_error=acknowledgement-required",
            status_code=303,
        )
    save_site_setting(db, "high_availability_enabled", "1" if enabled else "")
    db.commit()
    write_audit(
        db,
        user,
        "feature_enabled" if enabled else "feature_disabled",
        "experimental_feature",
        entity_id="high_availability",
        detail=f"High Availability {'enabled' if enabled else 'disabled'}.",
        metadata={"feature": "high_availability", "previous_enabled": previous, "enabled": enabled, "preserved_cluster_count": active_clusters},
    )
    state = "enabled" if enabled else "disabled"
    return RedirectResponse(
        f"/system/site-administration?tab=experimental-features&feature_status={state}",
        status_code=303,
    )


@router.post("/system/site-administration/experimental-features/backup-manager")
async def set_backup_manager_feature(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    enabled = str(form.get("enabled") or "") == "1"
    previous = get_site_setting(db, "backup_manager_enabled") == "1"
    preserved_items = db.query(BackupRecord).count() + db.query(BackupJob).count()
    inflight_jobs = db.query(BackupJob).filter(BackupJob.status.in_(["queued", "dispatched", "running"])).count()
    acknowledged = str(form.get("acknowledge_backup_disable") or "") == "1"
    if not enabled and preserved_items and not acknowledged:
        return RedirectResponse(
            "/system/site-administration?tab=experimental-features&feature_error=backup-acknowledgement-required",
            status_code=303,
        )
    save_site_setting(db, "backup_manager_enabled", "1" if enabled else "")
    db.commit()
    write_audit(
        db,
        user,
        "feature_enabled" if enabled else "feature_disabled",
        "experimental_feature",
        entity_id="backup_manager",
        detail=f"Backup Manager {'enabled' if enabled else 'disabled'}.",
        metadata={"feature": "backup_manager", "previous_enabled": previous, "enabled": enabled, "preserved_item_count": preserved_items, "inflight_job_count": inflight_jobs},
    )
    state = "enabled" if enabled else "disabled"
    return RedirectResponse(
        f"/system/site-administration?tab=experimental-features&feature=backup-manager&feature_status={state}",
        status_code=303,
    )


@router.post("/system/site-administration/vlan-ip-manager")
async def manage_vlan_ip_options(request: Request, db: Session = Depends(get_db), user=Depends(require_admin)):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    action = str(form.get("admin_action") or "")

    def clean_vlan_fields(suffix: str = "") -> tuple[str, str, str | None]:
        name = str(form.get(f"vlan_name{suffix}") or "").strip()
        description = str(form.get(f"vlan_description{suffix}") or "").strip()
        subnet = str(form.get(f"vlan_subnet{suffix}") or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="VLAN name is required.")
        if subnet:
            try:
                subnet = str(ip_network(subnet, strict=False))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Enter a valid VLAN subnet in CIDR notation.") from exc
        return name, description, subnet or None

    def clean_scope_fields(suffix: str = "") -> tuple[str, str, str, int | None, str, bool]:
        name = str(form.get(f"scope_name{suffix}") or "").strip()
        start_raw = str(form.get(f"scope_start{suffix}") or "").strip()
        end_raw = str(form.get(f"scope_end{suffix}") or "").strip()
        description = str(form.get(f"scope_description{suffix}") or "").strip()
        vlan_raw = str(form.get(f"scope_vlan_id{suffix}") or "").strip()
        if not name or not start_raw or not end_raw:
            raise HTTPException(status_code=400, detail="DHCP range name, start address, and end address are required.")
        try:
            start, end = ip_address(start_raw), ip_address(end_raw)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Enter valid DHCP start and end addresses.") from exc
        if start.version != end.version or int(start) > int(end):
            raise HTTPException(status_code=400, detail="The DHCP range end must be after its start and use the same IP version.")
        vlan_id = int(vlan_raw) if vlan_raw.isdigit() else None
        if vlan_id and not db.get(VLAN, vlan_id):
            raise HTTPException(status_code=400, detail="Choose a valid VLAN for this DHCP range.")
        enabled = str(form.get(f"scope_enabled{suffix}") or "") == "1"
        return name, str(start), str(end), vlan_id, description, enabled

    def validate_scope_bounds(start_raw: str, end_raw: str, vlan_id: int | None, enabled: bool, exclude_id: int | None = None) -> None:
        start, end = ip_address(start_raw), ip_address(end_raw)
        vlan = db.get(VLAN, vlan_id) if vlan_id else None
        if vlan and vlan.subnet_cidr:
            network = ip_network(vlan.subnet_cidr, strict=False)
            if start not in network or end not in network:
                raise HTTPException(status_code=400, detail=f"The DHCP range must fit inside {vlan.name} ({network}).")
        if not enabled:
            return
        for existing in db.query(DHCPRange).filter(DHCPRange.is_enabled == True).all():  # noqa: E712
            if exclude_id and existing.id == exclude_id:
                continue
            try:
                existing_start, existing_end = ip_address(existing.start_address), ip_address(existing.end_address)
            except ValueError:
                continue
            if existing_start.version == start.version and start <= existing_end and existing_start <= end:
                raise HTTPException(status_code=409, detail=f"This range overlaps the enabled DHCP range {existing.name}.")

    detail = action
    if action == "create_vlan":
        name, description, subnet = clean_vlan_fields()
        if db.query(VLAN).filter(func.lower(VLAN.name) == name.lower()).first():
            raise HTTPException(status_code=409, detail="That VLAN already exists.")
        db.add(VLAN(name=name, description=description or None, subnet_cidr=subnet))
    elif action.startswith("update_vlan:"):
        row_id = int(action.split(":", 1)[1])
        row = db.get(VLAN, row_id)
        if not row:
            raise HTTPException(status_code=404, detail="VLAN not found.")
        name, description, subnet = clean_vlan_fields(f"_{row_id}")
        duplicate = db.query(VLAN).filter(func.lower(VLAN.name) == name.lower(), VLAN.id != row.id).first()
        if duplicate:
            raise HTTPException(status_code=409, detail="That VLAN already exists.")
        row.name, row.description, row.subnet_cidr = name, description or None, subnet
    elif action.startswith("delete_vlan:"):
        row_id = int(action.split(":", 1)[1])
        row = db.get(VLAN, row_id)
        if not row:
            raise HTTPException(status_code=404, detail="VLAN not found.")
        if db.query(IPAddress).filter_by(vlan_id=row.id).first() or db.query(DHCPRange).filter_by(vlan_id=row.id).first():
            raise HTTPException(status_code=409, detail="Move its IP records and DHCP ranges before deleting this VLAN.")
        db.delete(row)
    elif action == "create_category":
        value = str(form.get("category_value") or "").strip()
        if not value:
            raise HTTPException(status_code=400, detail="Category name is required.")
        if db.query(ManagedListItem).filter(ManagedListItem.module == "ip_addresses", ManagedListItem.list_key == "category", func.lower(ManagedListItem.value) == value.lower()).first():
            raise HTTPException(status_code=409, detail="That Category already exists.")
        order = db.query(func.max(ManagedListItem.sort_order)).filter_by(module="ip_addresses", list_key="category").scalar() or 0
        db.add(ManagedListItem(module="ip_addresses", list_key="category", value=value, sort_order=order + 10, is_active=True))
    elif action.startswith("update_category:"):
        row_id = int(action.split(":", 1)[1])
        row = db.get(ManagedListItem, row_id)
        if not row or row.module != "ip_addresses" or row.list_key != "category":
            raise HTTPException(status_code=404, detail="Category not found.")
        value = str(form.get(f"category_value_{row_id}") or "").strip()
        if not value:
            raise HTTPException(status_code=400, detail="Category name is required.")
        duplicate = db.query(ManagedListItem).filter(ManagedListItem.module == "ip_addresses", ManagedListItem.list_key == "category", func.lower(ManagedListItem.value) == value.lower(), ManagedListItem.id != row.id).first()
        if duplicate:
            raise HTTPException(status_code=409, detail="That Category already exists.")
        old = row.value
        row.value = value
        row.is_active = str(form.get(f"category_enabled_{row_id}") or "") == "1"
        if old != value:
            db.query(IPAddress).filter(IPAddress.category == old).update({IPAddress.category: value}, synchronize_session=False)
    elif action.startswith("delete_category:"):
        row_id = int(action.split(":", 1)[1])
        row = db.get(ManagedListItem, row_id)
        if not row or row.module != "ip_addresses" or row.list_key != "category":
            raise HTTPException(status_code=404, detail="Category not found.")
        if db.query(IPAddress).filter_by(category=row.value).first():
            raise HTTPException(status_code=409, detail="Reassign records before deleting this Category. You can disable it instead.")
        db.delete(row)
    elif action == "create_scope":
        name, start, end, vlan_id, description, enabled = clean_scope_fields()
        validate_scope_bounds(start, end, vlan_id, enabled)
        if db.query(DHCPRange).filter(func.lower(DHCPRange.name) == name.lower()).first():
            raise HTTPException(status_code=409, detail="That DHCP range already exists.")
        db.add(DHCPRange(name=name, start_address=start, end_address=end, vlan_id=vlan_id, description=description or None, is_enabled=enabled))
    elif action.startswith("update_scope:"):
        row_id = int(action.split(":", 1)[1])
        row = db.get(DHCPRange, row_id)
        if not row:
            raise HTTPException(status_code=404, detail="DHCP range not found.")
        name, start, end, vlan_id, description, enabled = clean_scope_fields(f"_{row_id}")
        validate_scope_bounds(start, end, vlan_id, enabled, row_id)
        duplicate = db.query(DHCPRange).filter(func.lower(DHCPRange.name) == name.lower(), DHCPRange.id != row.id).first()
        if duplicate:
            raise HTTPException(status_code=409, detail="That DHCP range already exists.")
        row.name, row.start_address, row.end_address = name, start, end
        row.vlan_id, row.description, row.is_enabled = vlan_id, description or None, enabled
    elif action.startswith("delete_scope:"):
        row = db.get(DHCPRange, int(action.split(":", 1)[1]))
        if not row:
            raise HTTPException(status_code=404, detail="DHCP range not found.")
        db.delete(row)
    else:
        raise HTTPException(status_code=400, detail="Choose a VLAN/IP Manager action.")

    db.commit()
    write_audit(db, user, "update", "vlan_ip_settings", None, request.client.host if request.client else None, detail=detail)
    return RedirectResponse("/system/site-administration?tab=module-vlan-ip-manager", status_code=303)


@router.get("/system/site-administration/security/public-ip")
def public_ip_check(user=Depends(require_admin)):
    try:
        ip_address, source = lookup_public_ip()
    except RuntimeError:
        return JSONResponse(
            {"ok": False, "error": "Public IP lookup failed."},
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
async def save_settings(
    request: Request,
    app_name: str = Form(APP_BRAND_NAME),
    base_url: str = Form("http://localhost:8080"),
    timezone_region: str = Form("UTC"),
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
    dashboard_customisation_enabled: str = Form(""),
    dashboard_monitor_mode_enabled: str = Form(""),
    dashboard_poll_interval_seconds: str = Form("10"),
    dashboard_recent_activity_limit: str = Form("10"),
    dashboard_show_source_age: str = Form(""),
    dashboard_attention_required: str = Form(""),
    dashboard_globally_disabled_widgets: str = Form(""),
    secret_vault_min_pin_length: str = Form("8"),
    secret_vault_max_auto_lock_minutes: str = Form("60"),
    secret_vault_sharing_enabled: str = Form(""),
    secret_vault_oidc_mfa_policy: str = Form("either"),
    secret_vault_oidc_accepted_acr: str = Form(""),
    secure_send_enabled: str = Form(""),
    secure_send_default_expiry: str = Form("24h"),
    secure_send_max_expiry_days: str = Form("7"),
    secure_send_max_upload_mb: str = Form("25"),
    secure_send_allow_one_download: str = Form(""),
    secure_send_vault_integration: str = Form(""),
    secure_send_gateway_hostname: str = Form("http://localhost:8999"),
    secure_send_email_notifications: str = Form(""),
    dns_manager_enabled: str = Form(""),
    dns_collector_enabled: str = Form(""),
    dns_default_provider_id: str = Form(""),
    dns_refresh_interval_seconds: str = Form("300"),
    dns_cache_enabled: str = Form(""),
    dns_vlan_integration_enabled: str = Form(""),
    dns_match_suggestions_enabled: str = Form(""),
    dns_auto_link_exact_mac: str = Form(""),
    dns_auto_update_dynamic_ip: str = Form(""),
    dns_stale_client_days: str = Form("30"),
    dns_retain_client_history: str = Form(""),
    dns_client_history_days: str = Form("365"),
    dns_traffic_history_days: str = Form("30"),
    dns_vlan_enrichment_enabled: str = Form(""),
    dns_update_empty_managed_hostname: str = Form(""),
    dns_provider_id: str = Form(""),
    dns_provider_name: str = Form(""),
    dns_provider_type: str = Form("pihole"),
    dns_provider_base_url: str = Form(""),
    dns_provider_auth_method: str = Form("password"),
    dns_provider_secret: str = Form(""),
    dns_provider_ssl_verify: str = Form(""),
    dns_provider_timeout_seconds: str = Form("10"),
    dns_provider_enabled: str = Form(""),
    dns_provider_description: str = Form(""),
    smtp_enabled: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: str = Form("587"),
    smtp_use_tls: str = Form(""),
    smtp_use_ssl: str = Form(""),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from_email: str = Form(""),
    smtp_from_name: str = Form(APP_BRAND_NAME),
    email_include_branding: str = Form(""),
    email_template_password_reset_subject: str = Form(""),
    email_template_password_reset_body: str = Form(""),
    email_template_secure_send_subject: str = Form(""),
    email_template_secure_send_body: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)
    form = await request.form()
    timezone_region = timezone_region.strip()
    if not timezone_region or len(timezone_region) > 100 or not re.fullmatch(r"[A-Za-z0-9_+\-/]+", timezone_region):
        timezone_region = "UTC"
    save_site_setting(db, "timezone_region", timezone_region)

    allowed_host_errors = validate_allowed_hosts(allowed_hosts)
    if trusted_hosts_enabled and not split_hosts(allowed_hosts):
        allowed_host_errors.insert(
            0,
            {
                "line": None,
                "value": "",
                "message": (
                    "Host restriction is enabled but no allowed hosts have been configured. "
                    "At least one hostname or IP address must be added before this setting can be enabled."
                ),
            },
        )
    if allowed_host_errors:
        submitted_settings = load_site_settings(db)
        for key, value in form.items():
            if key in submitted_settings and key not in {"csrf_token", "smtp_password"}:
                submitted_settings[key] = str(value)
        submitted_settings["trusted_hosts_enabled"] = "1" if trusted_hosts_enabled else ""
        submitted_settings["allowed_hosts"] = allowed_hosts
        return templates.TemplateResponse(
            request,
            "settings.html",
            {
                "user": user,
                "settings": submitted_settings,
                "dns_providers": dns_providers_for_admin(db),
                **vlan_ip_admin_context(db),
                "security_check": security_check_context(request, db),
                "allowed_host_errors": allowed_host_errors,
                "message": None,
                "error": "Review the highlighted allowed-host entries before saving.",
                **csrf_context(request),
            },
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

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
        email_include_branding=email_include_branding,
        email_template_password_reset_subject=email_template_password_reset_subject,
        email_template_password_reset_body=email_template_password_reset_body,
        email_template_secure_send_subject=email_template_secure_send_subject,
        email_template_secure_send_body=email_template_secure_send_body,
    )
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
    save_site_setting(db, "dashboard_customisation_enabled", "1" if dashboard_customisation_enabled else "")
    save_site_setting(db, "dashboard_monitor_mode_enabled", "1" if dashboard_monitor_mode_enabled else "")
    save_site_setting(db, "dashboard_show_source_age", "1" if dashboard_show_source_age else "")
    save_site_setting(db, "dashboard_attention_required", "1" if dashboard_attention_required else "")
    disabled_widget_keys = ",".join(sorted({key.strip() for key in dashboard_globally_disabled_widgets.split(",") if re.fullmatch(r"[a-z0-9_]+", key.strip())}))
    save_site_setting(db, "dashboard_globally_disabled_widgets", disabled_widget_keys)
    try:
        dashboard_poll_interval_seconds = str(int(dashboard_poll_interval_seconds))
    except ValueError:
        dashboard_poll_interval_seconds = "10"
    if dashboard_poll_interval_seconds not in {"10", "30", "60", "300"}:
        dashboard_poll_interval_seconds = "10"
    try:
        dashboard_recent_activity_limit = str(max(1, min(int(dashboard_recent_activity_limit), 20)))
    except ValueError:
        dashboard_recent_activity_limit = "10"
    save_site_setting(db, "dashboard_poll_interval_seconds", dashboard_poll_interval_seconds)
    save_site_setting(db, "dashboard_recent_activity_limit", dashboard_recent_activity_limit)
    try:
        vault_min_pin = str(max(6, min(int(secret_vault_min_pin_length), 20)))
    except ValueError:
        vault_min_pin = "8"
    if secret_vault_max_auto_lock_minutes not in {"5", "10", "15", "30", "60"}:
        secret_vault_max_auto_lock_minutes = "60"
    save_site_setting(db, "secret_vault_min_pin_length", vault_min_pin)
    save_site_setting(db, "secret_vault_max_auto_lock_minutes", secret_vault_max_auto_lock_minutes)
    save_site_setting(db, "secret_vault_sharing_enabled", "1" if secret_vault_sharing_enabled else "")
    if secret_vault_oidc_mfa_policy not in {"kaya_totp", "idp_mfa", "either"}:
        secret_vault_oidc_mfa_policy = "either"
    save_site_setting(db, "secret_vault_oidc_mfa_policy", secret_vault_oidc_mfa_policy)
    save_site_setting(db, "secret_vault_oidc_accepted_acr", secret_vault_oidc_accepted_acr.strip()[:500])
    save_site_setting(db, "secure_send_enabled", "1" if secure_send_enabled else "")
    save_site_setting(db, "secure_send_default_expiry", secure_send_default_expiry if secure_send_default_expiry in {"15m", "1h", "4h", "24h", "3d", "7d"} else "24h")
    try:
        secure_send_max_expiry_days = str(max(1, min(int(secure_send_max_expiry_days), 30)))
    except ValueError:
        secure_send_max_expiry_days = "7"
    try:
        secure_send_max_upload_mb = str(max(1, min(int(secure_send_max_upload_mb), 250)))
    except ValueError:
        secure_send_max_upload_mb = "25"
    save_site_setting(db, "secure_send_max_expiry_days", secure_send_max_expiry_days)
    save_site_setting(db, "secure_send_max_upload_mb", secure_send_max_upload_mb)
    save_site_setting(db, "secure_send_allow_one_download", "1" if secure_send_allow_one_download else "")
    save_site_setting(db, "secure_send_vault_integration", "1" if secure_send_vault_integration else "")
    save_site_setting(db, "secure_send_email_notifications", "1" if secure_send_email_notifications else "")
    gateway_hostname = secure_send_gateway_hostname.strip().rstrip("/")[:500]
    if not re.fullmatch(r"https?://[^\s/]+(?::\d+)?", gateway_hostname):
        gateway_hostname = "http://localhost:8999"
    save_site_setting(db, "secure_send_gateway_hostname", gateway_hostname)
    save_dns_manager_settings(
        db,
        dns_manager_enabled=dns_manager_enabled,
        dns_collector_enabled=dns_collector_enabled,
        dns_default_provider_id=dns_default_provider_id,
        dns_refresh_interval_seconds=dns_refresh_interval_seconds,
        dns_cache_enabled=dns_cache_enabled,
        dns_vlan_integration_enabled=dns_vlan_integration_enabled,
        dns_match_suggestions_enabled=dns_match_suggestions_enabled,
        dns_auto_link_exact_mac=dns_auto_link_exact_mac,
        dns_auto_update_dynamic_ip=dns_auto_update_dynamic_ip,
        dns_stale_client_days=dns_stale_client_days,
        dns_retain_client_history=dns_retain_client_history,
        dns_client_history_days=dns_client_history_days,
        dns_traffic_history_days=dns_traffic_history_days,
        dns_vlan_enrichment_enabled=dns_vlan_enrichment_enabled,
        dns_update_empty_managed_hostname=dns_update_empty_managed_hostname,
        dns_provider_id=dns_provider_id,
        dns_provider_name=dns_provider_name,
        dns_provider_type=dns_provider_type,
        dns_provider_base_url=dns_provider_base_url,
        dns_provider_auth_method=dns_provider_auth_method,
        dns_provider_secret=dns_provider_secret,
        dns_provider_ssl_verify=dns_provider_ssl_verify,
        dns_provider_timeout_seconds=dns_provider_timeout_seconds,
        dns_provider_enabled=dns_provider_enabled,
        dns_provider_description=dns_provider_description,
    )
    guacamole_bridge_changed = save_remote_manager_settings(db, form)

    db.commit()
    if guacamole_bridge_changed:
        restart_guacamole_bridge()

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
            "dns_providers": dns_providers_for_admin(db),
            **vlan_ip_admin_context(db),
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
        backup_remote_password="",
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
            "dns_providers": dns_providers_for_admin(db),
            **vlan_ip_admin_context(db),
            "security_check": security_check_context(request, db),
            "message": f"Backup storage test passed: {detail}" if passed else None,
            "error": None if passed else f"Backup storage test failed: {detail}",
            **csrf_context(request),
        },
    )


@router.post("/system/site-administration/test-dns-provider")
def test_dns_provider(
    request: Request,
    dns_manager_enabled: str = Form(""),
    dns_collector_enabled: str = Form(""),
    dns_default_provider_id: str = Form(""),
    dns_refresh_interval_seconds: str = Form("300"),
    dns_cache_enabled: str = Form(""),
    dns_vlan_integration_enabled: str = Form(""),
    dns_match_suggestions_enabled: str = Form(""),
    dns_auto_link_exact_mac: str = Form(""),
    dns_auto_update_dynamic_ip: str = Form(""),
    dns_stale_client_days: str = Form("30"),
    dns_retain_client_history: str = Form(""),
    dns_client_history_days: str = Form("365"),
    dns_traffic_history_days: str = Form("30"),
    dns_vlan_enrichment_enabled: str = Form(""),
    dns_update_empty_managed_hostname: str = Form(""),
    dns_provider_id: str = Form(""),
    dns_provider_name: str = Form(""),
    dns_provider_type: str = Form("pihole"),
    dns_provider_base_url: str = Form(""),
    dns_provider_auth_method: str = Form("password"),
    dns_provider_secret: str = Form(""),
    dns_provider_ssl_verify: str = Form(""),
    dns_provider_timeout_seconds: str = Form("10"),
    dns_provider_enabled: str = Form(""),
    dns_provider_description: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)
    save_dns_manager_settings(
        db,
        dns_manager_enabled=dns_manager_enabled,
        dns_collector_enabled=dns_collector_enabled,
        dns_default_provider_id=dns_default_provider_id,
        dns_refresh_interval_seconds=dns_refresh_interval_seconds,
        dns_cache_enabled=dns_cache_enabled,
        dns_vlan_integration_enabled=dns_vlan_integration_enabled,
        dns_match_suggestions_enabled=dns_match_suggestions_enabled,
        dns_auto_link_exact_mac=dns_auto_link_exact_mac,
        dns_auto_update_dynamic_ip=dns_auto_update_dynamic_ip,
        dns_stale_client_days=dns_stale_client_days,
        dns_retain_client_history=dns_retain_client_history,
        dns_client_history_days=dns_client_history_days,
        dns_traffic_history_days=dns_traffic_history_days,
        dns_vlan_enrichment_enabled=dns_vlan_enrichment_enabled,
        dns_update_empty_managed_hostname=dns_update_empty_managed_hostname,
        dns_provider_id=dns_provider_id,
        dns_provider_name=dns_provider_name,
        dns_provider_type=dns_provider_type,
        dns_provider_base_url=dns_provider_base_url,
        dns_provider_auth_method=dns_provider_auth_method,
        dns_provider_secret=dns_provider_secret,
        dns_provider_ssl_verify=dns_provider_ssl_verify,
        dns_provider_timeout_seconds=dns_provider_timeout_seconds,
        dns_provider_enabled=dns_provider_enabled,
        dns_provider_description=dns_provider_description,
    )
    db.commit()

    provider_id = (get_site_setting(db, "dns_default_provider_id") or "").strip()
    provider = db.get(DNSProviderConfig, int(provider_id)) if provider_id.isdigit() else None
    if not provider:
        passed = False
        detail = "DNS provider settings were saved, but no provider is configured to test."
    else:
        result = provider_for(provider).test_connection()
        passed = result.ok
        detail = result.message
        provider.last_status = "online" if passed else "error"
        provider.last_error = "" if passed else detail
        provider.last_checked_at = datetime.utcnow()
        db.commit()

    write_audit(
        db,
        user,
        "test_connection",
        "dns_provider",
        str(provider.id) if provider else None,
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
            "dns_providers": dns_providers_for_admin(db),
            **vlan_ip_admin_context(db),
            "security_check": security_check_context(request, db),
            "message": detail if passed else None,
            "error": None if passed else detail,
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
    email_include_branding: str = Form(""),
    email_template_password_reset_subject: str = Form(""),
    email_template_password_reset_body: str = Form(""),
    email_template_secure_send_subject: str = Form(""),
    email_template_secure_send_body: str = Form(""),
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
        email_include_branding=email_include_branding,
        email_template_password_reset_subject=email_template_password_reset_subject,
        email_template_password_reset_body=email_template_password_reset_body,
        email_template_secure_send_subject=email_template_secure_send_subject,
        email_template_secure_send_body=email_template_secure_send_body,
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
            "dns_providers": dns_providers_for_admin(db),
            **vlan_ip_admin_context(db),
            "security_check": security_check_context(request, db),
            "message": message,
            "error": error,
            "test_email_to": recipient,
            **csrf_context(request),
        },
    )
