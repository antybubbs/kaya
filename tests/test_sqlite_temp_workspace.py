"""Docker-only regression coverage for SQLite's constrained /tmp workspace."""

from __future__ import annotations

import os
import shutil
import sqlite3
from pathlib import Path

import pytest

from app.db import migrations


@pytest.mark.skipif(
    not os.environ.get("KAYA_SQLITE_TEMP_INTEGRATION"),
    reason="run explicitly in the constrained-/tmp Docker integration environment",
)
def test_large_index_uses_kaya_sqlite_temp_workspace() -> None:
    persistent_root = os.environ.get("KAYA_SQLITE_TEMP_INTEGRATION_ROOT")
    if not persistent_root:
        pytest.fail("KAYA_SQLITE_TEMP_INTEGRATION_ROOT must be a persistent mount")

    root = Path(persistent_root)
    root.mkdir(parents=True, exist_ok=True)
    database_path = root / "kaya.sqlite3"
    sqlite_temp_directory = root / "sqlite-tmp"
    for path in (
        database_path,
        database_path.with_name(database_path.name + "-wal"),
        database_path.with_name(database_path.name + "-shm"),
    ):
        path.unlink(missing_ok=True)
    shutil.rmtree(sqlite_temp_directory, ignore_errors=True)
    try:
        sqlite_temp_directory = migrations._prepare_sqlite_temp_directory(database_path)
        assert os.environ["SQLITE_TMPDIR"] == str(sqlite_temp_directory)
        assert database_path.parent.stat().st_dev == sqlite_temp_directory.stat().st_dev
        assert shutil.disk_usage("/tmp").total <= 128 * 1024 * 1024

        connection = sqlite3.connect(database_path)
        try:
            connection.execute("PRAGMA temp_store=FILE")
            connection.execute("PRAGMA cache_size=1000")
            connection.execute(
                "CREATE TABLE dns_client_traffic_events "
                "(dns_client_id INTEGER NOT NULL, observed_at TEXT NOT NULL)"
            )
            connection.executemany(
                "INSERT INTO dns_client_traffic_events VALUES (?, ?)",
                ((row % 31, f"{row:08d}-" + ("x" * 248)) for row in range(800_000)),
            )
            connection.commit()

            max_managed_bytes = 0
            max_managed_entries = 0
            max_tmp_bytes = 0
            managed_fd_seen = False
            tmp_fd_seen = False
            baseline_tmp_fds = {
                os.readlink(descriptor)
                for descriptor in Path("/proc/self/fd").iterdir()
                if descriptor.exists() and os.readlink(descriptor).startswith("/tmp/")
            }

            def observe_workspaces() -> int:
                nonlocal max_managed_bytes, max_managed_entries, max_tmp_bytes
                nonlocal managed_fd_seen, tmp_fd_seen
                managed_files = [
                    item for item in sqlite_temp_directory.iterdir() if item.is_file()
                ]
                max_managed_entries = max(max_managed_entries, len(managed_files))
                max_managed_bytes = max(
                    max_managed_bytes,
                    sum(item.stat().st_size for item in managed_files),
                )
                max_tmp_bytes = max(
                    max_tmp_bytes,
                    sum(
                        item.stat().st_size
                        for item in Path("/tmp").iterdir()
                        if item.is_file()
                    ),
                )
                for descriptor in Path("/proc/self/fd").iterdir():
                    try:
                        target = os.readlink(descriptor)
                    except OSError:
                        continue
                    managed_fd_seen |= str(sqlite_temp_directory) in target
                    tmp_fd_seen |= (
                        target.startswith("/tmp/") and target not in baseline_tmp_fds
                    )
                return 0

            connection.set_progress_handler(observe_workspaces, 10_000)
            connection.execute(
                "CREATE INDEX ix_dns_client_traffic_client_observed "
                "ON dns_client_traffic_events (dns_client_id, observed_at)"
            )
            connection.commit()
            connection.set_progress_handler(None, 0)
        finally:
            connection.close()

        assert max_managed_entries > 0 or managed_fd_seen
        assert max_tmp_bytes == 0
        assert not tmp_fd_seen
        with sqlite3.connect(database_path) as verification:
            assert verification.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='ix_dns_client_traffic_client_observed'"
            ).fetchone()
    finally:
        database_path.unlink(missing_ok=True)
        database_path.with_name(database_path.name + "-wal").unlink(missing_ok=True)
        database_path.with_name(database_path.name + "-shm").unlink(missing_ok=True)
        shutil.rmtree(sqlite_temp_directory, ignore_errors=True)
