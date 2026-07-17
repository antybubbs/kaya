import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.core.kayavault import KayaVaultError, decrypt_package, encrypt_package


def fixture_payload():
    return {"format": "kayavault", "version": 1, "created_at": "2026-07-16T12:00:00Z", "items": [{"type": "secure_note", "payload": {"title": "DC01", "body": "recovery"}}], "collections": []}


def test_round_trip_has_no_plaintext_and_is_versioned():
    payload = fixture_payload()
    package = encrypt_package(payload, "a sufficiently long export passphrase")
    assert b"DC01" not in package and b"recovery" not in package
    assert decrypt_package(package, "a sufficiently long export passphrase") == payload


def test_incorrect_passphrase_and_modified_ciphertext_fail_closed():
    package = encrypt_package(fixture_payload(), "a sufficiently long export passphrase")
    with pytest.raises(KayaVaultError):
        decrypt_package(package, "the incorrect export passphrase")
    outer = json.loads(package)
    ciphertext = bytearray(base64.urlsafe_b64decode(outer["ciphertext"])); ciphertext[-1] ^= 1
    outer["ciphertext"] = base64.urlsafe_b64encode(ciphertext).decode()
    with pytest.raises(KayaVaultError):
        decrypt_package(json.dumps(outer).encode(), "a sufficiently long export passphrase")


def test_future_and_unknown_crypto_formats_fail_safely():
    package = json.loads(encrypt_package(fixture_payload(), "a sufficiently long export passphrase"))
    package["version"] = 99
    with pytest.raises(KayaVaultError, match="Unsupported"):
        decrypt_package(json.dumps(package).encode(), "a sufficiently long export passphrase")


def test_offline_cli_validates_and_extracts_without_kaya_configuration(tmp_path):
    payload = fixture_payload()
    payload["items"][0]["attachments"] = [{"metadata": {"name": "recovery.txt"}, "content": base64.b64encode(b"offline recovery").decode(), "sha256": "b481f9c2b2a8e86babc1fff4f2a9310c1742bfa8be7c491656d8f6ed9f750510"}]
    package = tmp_path / "test.kayavault"; package.write_bytes(encrypt_package(payload, "a sufficiently long export passphrase"))
    passphrase = tmp_path / "passphrase"; passphrase.write_text("a sufficiently long export passphrase", encoding="utf-8")
    extract = tmp_path / "recovered"
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / "scripts" / "kayavault_recovery.py"), str(package), "--passphrase-file", str(passphrase), "--extract", str(extract)], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (extract / "item-0001" / "recovery.txt").read_bytes() == b"offline recovery"
