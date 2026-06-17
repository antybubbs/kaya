from functools import lru_cache
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings


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
    hosts = {"*"}

    parsed_host = urlparse(settings.base_url).hostname
    if parsed_host:
        hosts.add(parsed_host)

    hosts.update(
        host.strip()
        for host in settings.allowed_hosts.split(",")
        if host.strip()
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

    try:
        Fernet(settings.encryption_key.encode())
    except Exception as exc:
        raise InvalidConfigurationError(
            "ENCRYPTION_KEY must be a valid Fernet key."
        ) from exc

    return settings
