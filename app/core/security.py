from cryptography.fernet import Fernet, InvalidToken
from passlib.context import CryptContext
from app.core.config import get_settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False
    return pwd_context.verify(password, password_hash)


def fernet() -> Fernet:
    return Fernet(get_settings().encryption_key.encode())


def encrypt_secret(value: str | None) -> str:
    if not value:
        return ""
    return fernet().encrypt(value.encode()).decode()


def decrypt_secret(value: str | None) -> str:
    if not value:
        return ""
    try:
        return fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return "[decryption failed]"


def mask_key(value: str | None) -> str:
    if not value:
        return ""
    clean = value.strip()
    if len(clean) <= 8:
        return "*" * len(clean)
    return "*" * max(0, len(clean) - 5) + clean[-5:]
