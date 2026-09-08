from functools import lru_cache
import os
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
    security_contact: str = ""
    root_path: str = ""
    database_url: str = f"sqlite:///{DEFAULT_DATA_DIR / 'kaya.db'}"
    database_password_file: str = ""
    database_pool_size: int = 5
    database_max_overflow: int = 5
    database_pool_recycle_seconds: int = 1800
    database_connect_timeout_seconds: int = 10
    database_pool_timeout_seconds: int = 10
    data_dir: str = str(DEFAULT_DATA_DIR)
    migration_backup_dir: str = str(DEFAULT_DATA_DIR / "backups")
    postgres_backup_dir: str = str(DEFAULT_DATA_DIR / "postgres-backups")
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


def resolve_database_password(database_url: str, password_file: str = "") -> str:
    """Resolve a PostgreSQL password from a protected file without logging it."""
    if not password_file or not database_url.startswith("postgresql"):
        return database_url
    url = make_url(database_url)
    if url.password:
        return database_url
    try:
        password = Path(password_file).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise InvalidConfigurationError("DATABASE_PASSWORD_FILE could not be read.") from exc
    if not password:
        raise InvalidConfigurationError("DATABASE_PASSWORD_FILE is empty.")
    return url.set(password=password).render_as_string(hide_password=False)


def postgres_engine_options(settings: Settings) -> dict:
    """Return bounded SQLAlchemy/psycopg options for PostgreSQL connections."""
    return {
        "connect_args": {
            "connect_timeout": max(1, int(settings.database_connect_timeout_seconds)),
        },
        "pool_pre_ping": True,
        "pool_timeout": max(1, int(settings.database_pool_timeout_seconds)),
    }


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

    configured_failpoint = os.environ.get("KAYA_TEST_FAILPOINT", "").strip()
    if configured_failpoint and settings.app_env == "production":
        raise InvalidConfigurationError(
            "Phase 6 test failpoints are unavailable in production."
        )

    settings.database_url = resolve_database_password(
        settings.database_url, settings.database_password_file
    )

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


def redact_database_url(database_url: str) -> str:
    """Render a database URL without its password or query parameters."""
    url = make_url(database_url)
    return url.set(password=None, query={}).render_as_string(hide_password=True)


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
