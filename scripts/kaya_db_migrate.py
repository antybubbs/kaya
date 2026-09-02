"""Offline Kaya database conversion commands."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    convert = subparsers.add_parser("sqlite-to-postgres")
    convert.add_argument("--source", type=Path, required=True)
    convert.add_argument("--target-url", required=True)
    convert.add_argument("--backup-directory", type=Path, required=True)
    convert.add_argument("--batch-size", type=int, default=2_000)
    convert.add_argument("--dry-run", action="store_true")
    convert.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # Establish SQLITE_TMPDIR before importing the converter and SQLite modules.
    from app.db.sqlite_temp import configure_sqlite_temp_directory

    configure_sqlite_temp_directory(arguments.source)
    from app.db.sqlite_to_postgres import SQLiteToPostgresError, migrate, preflight

    try:
        if arguments.dry_run:
            result = preflight(arguments.source, arguments.target_url)
        else:
            result = migrate(
                arguments.source,
                arguments.target_url,
                arguments.backup_directory,
                batch_size=arguments.batch_size,
            )
    except (OSError, ValueError, SQLiteToPostgresError) as exc:
        logging.getLogger(__name__).error("migration_result result=FAILED reason=%s", str(exc)[:500])
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True, default=str)
    if arguments.report:
        arguments.report.write_text(rendered + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("migration_id", "source_revision", "target_revision", "source_size_bytes", "target_size_bytes", "rows_total", "duration_seconds", "rows_per_second", "result") if key in result}, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
