"""Run the explicit Phase 6 existing-install upgrade workflow."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from app.core.config import resolve_database_password
from app.db.phase6_cutover import clean_failed_target, prepare_failed_retry, run_upgrade


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target-url", default=os.environ.get("KAYA_POSTGRES_DATABASE_URL", ""))
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--clean-failed-target", action="store_true")
    parser.add_argument("--migration-id")
    parser.add_argument("--source-fingerprint")
    args = parser.parse_args()
    target_url = resolve_database_password(
        args.target_url, os.environ.get("DATABASE_PASSWORD_FILE", "")
    )
    if not target_url.startswith("postgresql"):
        parser.error("--target-url or KAYA_POSTGRES_DATABASE_URL must be a PostgreSQL URL")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    recovery_backup = None
    if args.clean_failed_target:
        if not args.migration_id or not args.source_fingerprint:
            parser.error("--clean-failed-target requires --migration-id and --source-fingerprint")
        clean_failed_target(
            target_url,
            args.migration_id,
            args.source_fingerprint,
            args.data_dir.resolve(),
        )
        recovery_backup = prepare_failed_retry(args.data_dir.resolve(), args.source_fingerprint)
    run_upgrade(
        args.source.resolve(),
        target_url,
        args.backup_dir.resolve(),
        args.data_dir.resolve(),
        recovery_backup=recovery_backup,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
