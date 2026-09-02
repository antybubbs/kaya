"""Run a disposable, deterministic SQLite sentinel writer for Phase 6 tests."""

from __future__ import annotations

import argparse
import os
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

from app.db.phase6_test_hooks import record


def main() -> int:
    if os.environ.get("KAYA_TEST_MODE", "false").lower() != "true":
        raise SystemExit("phase6_legacy_writer requires KAYA_TEST_MODE=true")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--max-writes", type=int, default=0)
    args = parser.parse_args()
    connection = sqlite3.connect(args.database, timeout=5)
    counter = 0
    try:
        while not args.stop_file.exists() and (not args.max_writes or counter < args.max_writes):
            counter += 1
            now = datetime.now(UTC).isoformat()
            connection.execute(
                "INSERT INTO remote_manager_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                ("phase6-test-writer", f"sentinel-{counter}-{now}"),
            )
            connection.commit()
            record(
                "sqlite.writer.commit",
                counter=counter,
                timestamp=now,
                pid=os.getpid(),
            )
            time.sleep(max(0.01, args.interval))
    finally:
        connection.close()
    record("sqlite.writer.stopped", counter=counter, pid=os.getpid())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
