from fnmatch import fnmatch
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.branding import APP_BRAND_NAME
from app.models.models import RemoteManagerSetting


DEFAULT_SITE_SETTINGS = {
    "app_name": APP_BRAND_NAME,
    "base_url": "http://localhost:8080",
    "github_repo": "antybubbs/Kaya",
    "version_check_interval_seconds": "1800",
    "guacd_host": "",
    "guacd_port": "",
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

SECURITY_SETTING_KEYS = {
    "base_url",
    "trusted_hosts_enabled",
    "allowed_hosts",
    "csp_frame_ancestors",
    "csp_frame_ancestor_sources",
    "hsts_enabled",
    "hsts_include_subdomains",
    "hsts_max_age",
    "rdp_token_ttl_minutes",
}


def get_site_setting(db: Session, key: str) -> str:
    row = (
        db.query(RemoteManagerSetting)
        .filter(RemoteManagerSetting.key == key)
        .first()
    )

    if row and row.value is not None:
        return row.value

    if key in DEFAULT_SITE_SETTINGS:
        return DEFAULT_SITE_SETTINGS[key]

    return str(getattr(get_settings(), key, ""))


def load_security_settings(db: Session) -> dict[str, str]:
    return {key: get_site_setting(db, key) for key in SECURITY_SETTING_KEYS}


def split_hosts(value: str) -> list[str]:
    return [
        part.strip().lower()
        for part in str(value or "").replace("\r", "\n").replace(",", "\n").split("\n")
        if part.strip()
    ]


def host_without_port(value: str) -> str:
    host = str(value or "").strip().lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host


def effective_allowed_hosts(security: dict[str, str], settings: Settings | None = None) -> list[str]:
    app_settings = settings or get_settings()
    hosts = {"localhost", "127.0.0.1", "::1", "kaya", "homelab"}
    base_url_host = urlparse(security.get("base_url") or app_settings.base_url).hostname
    if base_url_host:
        hosts.add(base_url_host.lower())
    hosts.update(split_hosts(security.get("allowed_hosts", "")))
    hosts.update(split_hosts(app_settings.allowed_hosts))
    return sorted(hosts)


def host_is_allowed(host: str, allowed_hosts: list[str]) -> bool:
    clean_host = host_without_port(host)
    for pattern in allowed_hosts:
        clean_pattern = host_without_port(pattern)
        if clean_pattern == "*":
            return True
        if clean_pattern.startswith("*."):
            suffix = clean_pattern[1:]
            if clean_host.endswith(suffix) and clean_host != clean_pattern[2:]:
                return True
        if fnmatch(clean_host, clean_pattern):
            return True
    return False


def frame_ancestor_directive(security: dict[str, str]) -> str:
    mode = (security.get("csp_frame_ancestors") or "self").strip().lower()
    if mode == "none":
        return "'none'"
    if mode == "custom":
        sources = [
            source
            for source in str(security.get("csp_frame_ancestor_sources") or "").replace("\r", "\n").replace(",", "\n").split("\n")
            if source.strip()
            for source in [source.strip()]
        ]
        return " ".join(["'self'", *sources]) if sources else "'self'"
    return "'self'"


def hsts_header_value(security: dict[str, str]) -> str:
    try:
        max_age = max(300, min(int(security.get("hsts_max_age") or 31536000), 63072000))
    except ValueError:
        max_age = 31536000
    value = f"max-age={max_age}"
    if security.get("hsts_include_subdomains") == "1":
        value += "; includeSubDomains"
    return value
