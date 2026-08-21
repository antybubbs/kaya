"""Read-only PostgreSQL patch-upgrade preflight and post-upgrade verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.core.config import get_settings
from app.db.migrations import CURRENT_REVISION
from app.db.postgres_upgrade import (
    DEFAULT_BACKUP_MAX_AGE_HOURS,
    PostgresUpgradePreflightError,
    collect_upgrade_preflight,
)
from app.db.session import engine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--target-image", required=True)
    preflight.add_argument(
        "--backup-max-age-hours", type=float, default=DEFAULT_BACKUP_MAX_AGE_HOURS
    )
    preflight.add_argument("--allow-stale-backup", action="store_true")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--target-image", required=True)
    args = parser.parse_args(argv)
    settings = get_settings()
    try:
        if args.command == "preflight":
            result = collect_upgrade_preflight(
                engine,
                Path(settings.postgres_backup_dir),
                args.target_image,
                max_backup_age_hours=args.backup_max_age_hours,
                allow_stale_backup=args.allow_stale_backup,
            )
        else:
            result = collect_upgrade_preflight(
                engine,
                Path(settings.postgres_backup_dir),
                args.target_image,
                max_backup_age_hours=DEFAULT_BACKUP_MAX_AGE_HOURS,
                allow_stale_backup=True,
            )
            result["verification"] = "post_upgrade_database_and_schema_verified"
            result["expected_alembic_head"] = CURRENT_REVISION
    except PostgresUpgradePreflightError as exc:
        print(json.dumps({"result": "FAIL", "reason": str(exc)}))
        return 2
    print(json.dumps({"result": "PASS", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
