"""Load the deterministic Stage 2B fixture into a verified disposable database."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.models import DNSRecognisedDevice
from scripts.kaya_test_migrations import _verify_connected_target, verify_disposable_url
from tests.fixtures.stage2b_acceptance import seed_stage2b_acceptance


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("KAYA_TEST_POSTGRES_URL"))
    parser.add_argument("--fixture-file", required=True)
    args = parser.parse_args()
    marker = os.environ.get("KAYA_STAGE2B_TEST_MARKER")
    if marker != "I_UNDERSTAND_DISPOSABLE_STAGE2B":
        raise SystemExit("Refusing to seed without KAYA_STAGE2B_TEST_MARKER=I_UNDERSTAND_DISPOSABLE_STAGE2B")
    if not args.url:
        raise SystemExit("--url or KAYA_TEST_POSTGRES_URL is required")
    verify_disposable_url(args.url)
    engine = create_engine(args.url, future=True)
    try:
        _verify_connected_target(engine, args.url)
        with sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)() as db:
            result = seed_stage2b_acceptance(db)
        safe_result = {key: value for key, value in result.items() if key != "password"}
        safe_result["dns_client_ids"] = [
            row.id for row in db.query(DNSRecognisedDevice).order_by(DNSRecognisedDevice.id).all()
        ]
        safe_result["network_only_email"] = "stage2b-network@example.invalid"
        safe_result["asset_only_email"] = "stage2b-asset@example.invalid"
        safe_result["dns_only_email"] = "stage2b-dns@example.invalid"
        fixture_path = Path(args.fixture_file).resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
        try:
            fixture_path.relative_to(temp_root)
        except ValueError as exc:
            raise SystemExit("--fixture-file must be inside the system temporary directory") from exc
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        fixture_path.write_text(json.dumps(safe_result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(safe_result, sort_keys=True))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
