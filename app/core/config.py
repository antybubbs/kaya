from functools import lru_cache
from urllib.parse import urlparse
from pydantic_settings import BaseSettings
import cryptography.fernet


class InvalidConfigurationError(RuntimeError):
    pass


class Settings(BaseSettings):
    app_name: str = "HomeLab"
    app_version: str = "dev"
    app_env: str = "production"
    base_url: str = "http://localhost:8080"
    root_path: str = ""
    database_url: str = "sqlite:////app/data/homelab.db"
    secret_key: str = ""
    encryption_key: str = ""
    admin_email: str = "admin@example.local"
    admin_password: str = "change-me-now"
    session_cookie_secure: bool = False
    upload_dir: str = "/app/uploads"
    max_upload_mb: int = 25
    allowed_hosts: str = ""
    github_repo: str = "antybubbs/HomeLab"
    guacd_host: str = ""
    guacd_port: str = ""
    version_check_interval_seconds: int = 1800

    class Config:
        env_file = ".env"
        extra = "ignore"


def trusted_hosts(settings: Settings) -> list[str]:
    hosts = {"localhost", "127.0.0.1", "::1", "homelab"}
    parsed_host = urlparse(settings.base_url).hostname
    if parsed_host:
        hosts.add(parsed_host)
    hosts.update(host.strip() for host in settings.allowed_hosts.split(",") if host.strip())
    return sorted(hosts)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.app_env == "production":
        if settings.secret_key == "change-this-secret-key" or len(settings.secret_key) < 32:
            raise InvalidConfigurationError(
                "SECRET_KEY must be set to a strong random value. Generate one with: "
                "python scripts/generate_secrets.py"
            )
        if settings.admin_password == "change-me-now" or len(settings.admin_password) < 12:
            raise InvalidConfigurationError(
                "ADMIN_PASSWORD must be changed before production startup."
            )
    if not settings.encryption_key or settings.encryption_key == "change-this-fernet-key":
        if settings.app_env == "production":
            raise InvalidConfigurationError(
                "ENCRYPTION_KEY must be set to a valid Fernet key. Generate one with: "
                "python scripts/generate_secrets.py"
            )
        settings.encryption_key = cryptography.fernet.Fernet.generate_key().decode()
    try:
        cryptography.fernet.Fernet(settings.encryption_key.encode())
    except Exception as exc:
        raise InvalidConfigurationError(
            "ENCRYPTION_KEY must be 32 url-safe base64-encoded bytes. Generate one with: "
            "python scripts/generate_secrets.py"
        ) from exc
    return settings
