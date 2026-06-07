from functools import lru_cache
from pydantic_settings import BaseSettings
from cryptography.fernet import Fernet


class Settings(BaseSettings):
    app_name: str = "KeyVault"
    app_env: str = "production"
    base_url: str = "http://localhost:8080"
    database_url: str = "sqlite:////app/data/keyvault.db"
    secret_key: str = "change-this-secret-key"
    encryption_key: str = ""
    admin_email: str = "admin@example.local"
    admin_password: str = "change-me-now"
    session_cookie_secure: bool = False
    upload_dir: str = "/app/uploads"
    max_upload_mb: int = 25

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.encryption_key or settings.encryption_key == "change-this-fernet-key":
        # Development fallback only. Production should set ENCRYPTION_KEY explicitly.
        settings.encryption_key = Fernet.generate_key().decode()
    return settings
