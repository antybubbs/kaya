import secrets
from cryptography.fernet import Fernet

print('SECRET_KEY=' + secrets.token_urlsafe(64))
print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())
