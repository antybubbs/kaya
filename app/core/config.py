from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings
from sqlalchemy.engine import make_url

from app.core.branding import APP_BRAND_NAME
from app.core.paths import DEFAULT_DATA_DIR, DEFAULT_RECORDING_DIR, DEFAULT_UPLOAD_DIR


class InvalidConfigurationError(RuntimeError):
    pass


class Settings(BaseSettings):
    app_name: str = APP_BRAND_NAME
    app_version: str = "dev"
    app_env: str = "production"
    base_url: str = "http://localhost:8080"
    root_path: str = ""
    database_url: str = f"sqlite:///{DEFAULT_DATA_DIR / 'kaya.db'}"
    data_dir: str = str(DEFAULT_DATA_DIR)
    migration_backup_dir: str = str(DEFAULT_DATA_DIR / "backups")
    migration_backups_enabled: bool = True
    migration_backup_retention_count: int = 10
    secret_key: str = ""
    encryption_key: str = ""
    setup_token: str = ""
    session_cookie_secure: bool = False
    upload_dir: str = str(DEFAULT_UPLOAD_DIR)
    recording_dir: str = str(DEFAULT_RECORDING_DIR)
    max_upload_mb: int = 25
    max_recording_upload_mb: int = 1024
    min_recording_free_mb: int = 256
    allowed_hosts: str = ""
    forwarded_allow_ips: str = "127.0.0.1"
    github_repo: str = "antybubbs/Kaya"
    guacd_host: str = ""
    guacd_port: str = ""
    version_check_interval_seconds: int = 1800
    performance_diagnostics: bool = False
    vapid_public_key: str = ""
    vapid_private_key: str = ""
    vapid_subject: str = "mailto:admin@example.invalid"

    model_config = {"extra": "ignore"}


def trusted_hosts(settings: Settings) -> list[str]:
    if not settings.allowed_hosts.strip():
        return []

    hosts = {"localhost", "127.0.0.1", "::1", "kaya", "homelab"}

    parsed_host = urlparse(settings.base_url).hostname
    if parsed_host:
        hosts.add(parsed_host)

    hosts.update(
        host.strip() for host in settings.allowed_hosts.split(",") if host.strip()
    )
    return sorted(hosts)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()

    if settings.app_env == "production":
        if not settings.secret_key or len(settings.secret_key) < 32:
            raise InvalidConfigurationError(
                "SECRET_KEY must be set to a strong random value."
            )
        if "*" in {entry.strip() for entry in settings.forwarded_allow_ips.split(",")}:
            raise InvalidConfigurationError(
                "FORWARDED_ALLOW_IPS cannot trust every address in production. Configure the exact proxy IP or CIDR."
            )

    try:
        Fernet(settings.encryption_key.encode())
    except (TypeError, ValueError) as exc:
        raise InvalidConfigurationError(
            "ENCRYPTION_KEY must be a valid Fernet key."
        ) from exc

    return settings


def sqlite_database_path(database_url: str) -> Path | None:
    """Return the local path for a SQLite URL without exposing URL credentials."""
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite":
        return None
    if url.host:
        raise InvalidConfigurationError(
            "SQLite database URLs must reference a local file."
        )
    if url.database in {None, "", ":memory:"}:
        return None
    return Path(url.database).resolve()
