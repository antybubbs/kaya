#!/usr/bin/env python3
"""Validate, inspect or extract a Kaya portable Secret Vault backup."""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.kayavault import KayaVaultError, decrypt_package


def safe_name(value: str, fallback: str) -> str:
    name = Path(value or fallback).name.replace("\x00", "")
    return name if name not in {"", ".", ".."} else fallback


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline recovery utility for .kayavault exports")
    parser.add_argument("package", type=Path)
    parser.add_argument("--passphrase-file", type=Path, help="Read the export passphrase from a protected file")
    parser.add_argument("--extract", type=Path, help="Extract decrypted records and attachments into this new directory")
    parser.add_argument("--list", action="store_true", help="List record titles after validation")
    args = parser.parse_args()
    passphrase = args.passphrase_file.read_text(encoding="utf-8").rstrip("\r\n") if args.passphrase_file else getpass.getpass("Export passphrase: ")
    try:
        payload = decrypt_package(args.package.read_bytes(), passphrase)
    except (OSError, KayaVaultError) as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        return 2
    items = payload.get("items", [])
    print(f"Valid .kayavault v{payload.get('version')} package: {len(items)} items, {len(payload.get('collections', []))} collections")
    if args.list:
        for item in items:
            print(f"- [{item.get('type', 'unknown')}] {item.get('payload', {}).get('title', 'Untitled')}")
    if args.extract:
        if args.extract.exists():
            print("Extraction directory already exists; refusing to overwrite it.", file=sys.stderr)
            return 3
        args.extract.mkdir(parents=True, mode=0o700)
        records = []
        for index, item in enumerate(items, 1):
            record = {key: value for key, value in item.items() if key != "attachments"}
            record_dir = args.extract / f"item-{index:04d}"
            record_dir.mkdir(mode=0o700)
            (record_dir / "record.json").write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
            for attachment_index, attachment in enumerate(item.get("attachments", []), 1):
                content = base64.b64decode(attachment.get("content", ""), validate=True)
                expected = attachment.get("sha256", "")
                if not expected or not hashlib.sha256(content).hexdigest() == expected:
                    raise KayaVaultError("Extracted attachment hash does not match the authenticated manifest")
                filename = safe_name(attachment.get("metadata", {}).get("name", ""), f"attachment-{attachment_index}")
                (record_dir / filename).write_bytes(content)
            records.append(record)
        (args.extract / "manifest.json").write_text(json.dumps({"format": payload.get("format"), "version": payload.get("version"), "created_at": payload.get("created_at"), "records": records, "collections": payload.get("collections", [])}, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Extracted to {args.extract}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
