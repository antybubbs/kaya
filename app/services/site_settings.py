from sqlalchemy.orm import Session

from app.core.config import get_settings
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
