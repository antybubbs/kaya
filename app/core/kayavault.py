"""Configuration-free codec for portable .kayavault packages."""
from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class KayaVaultError(ValueError):
    pass


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _derive(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def encrypt_package(payload: dict[str, Any], passphrase: str) -> bytes:
    if len(passphrase) < 12:
        raise KayaVaultError("Export passphrase must contain at least 12 characters")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ciphertext = AESGCM(_derive(passphrase, salt)).encrypt(nonce, plaintext, b"kayavault:v1")
    package = {"format": "kayavault", "version": 1, "kdf": {"name": "scrypt", "n": 32768, "r": 8, "p": 1, "salt": _b64(salt)}, "cipher": {"name": "AES-256-GCM", "nonce": _b64(nonce)}, "ciphertext": _b64(ciphertext)}
    return json.dumps(package, separators=(",", ":"), sort_keys=True).encode("utf-8")


def decrypt_package(package_bytes: bytes, passphrase: str) -> dict[str, Any]:
    try:
        outer = json.loads(package_bytes)
        if outer.get("format") != "kayavault" or outer.get("version") != 1:
            raise KayaVaultError("Unsupported .kayavault format")
        if outer.get("kdf", {}).get("name") != "scrypt" or outer.get("cipher", {}).get("name") != "AES-256-GCM":
            raise KayaVaultError("Unsupported .kayavault cryptography")
        plaintext = AESGCM(_derive(passphrase, _unb64(outer["kdf"]["salt"]))).decrypt(_unb64(outer["cipher"]["nonce"]), _unb64(outer["ciphertext"]), b"kayavault:v1")
        payload = json.loads(plaintext)
    except KayaVaultError:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, InvalidTag) as exc:
        raise KayaVaultError("Backup authentication or integrity validation failed") from exc
    if not isinstance(payload, dict) or payload.get("format") != "kayavault" or payload.get("version") != 1:
        raise KayaVaultError("Decrypted backup payload is invalid")
    return payload
