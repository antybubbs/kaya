"""Disposable Linux harness for post-preflight SQLite temp ENOSPC."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path


def fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def fd_targets() -> set[str]:
    targets: set[str] = set()
    for descriptor in Path(f"/proc/{os.getpid()}/fd").iterdir():
        try:
            targets.add(os.readlink(descriptor))
        except OSError:
            continue
    return targets


def make_source(path: Path, rows: int) -> None:
    import sqlite3

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE dns_client_traffic_events "
            "(dns_client_id INTEGER NOT NULL, observed_at TEXT NOT NULL)"
        )
        for start in range(0, rows, 10_000):
            connection.executemany(
                "INSERT INTO dns_client_traffic_events VALUES (?, ?)",
                ((row % 31, f"{row:012d}") for row in range(start, min(start + 10_000, rows))),
            )
        connection.commit()
    finally:
        connection.close()


def create_index(path: Path) -> None:
    import sqlite3

    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute(
            "CREATE INDEX ix_dns_client_traffic_client_observed "
            "ON dns_client_traffic_events (dns_client_id, observed_at)"
        )
        connection.commit()
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--managed-temp", type=Path, required=True)
    parser.add_argument("--rows", type=int, default=1_200_000)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    managed_temp = arguments.managed_temp.resolve()
    root.mkdir(parents=True, exist_ok=True)
    managed_temp.mkdir(parents=True, exist_ok=True)
    source = root / "source.sqlite3"
    operation = root / "operation.sqlite3"
    for path in (source, operation):
        path.unlink(missing_ok=True)

    os.environ["SQLITE_TMPDIR"] = str(managed_temp)
    sqlite_loaded_before_import = "sqlite3" in sys.modules
    import sqlite3

    make_source(source, arguments.rows)
    shutil.copy2(source, operation)
    source_fingerprint = fingerprint(source)
    required_bytes = max(1 * 1024 * 1024, operation.stat().st_size // 2)
    initial_free = shutil.disk_usage(managed_temp).free
    preflight_passed = initial_free >= required_bytes
    if not preflight_passed:
        raise RuntimeError(f"preflight unexpectedly failed: free={initial_free} required={required_bytes}")

    baseline_tmp = {target for target in fd_targets() if target.startswith("/tmp/")}
    managed_activity = threading.Event()
    stop_observer = threading.Event()
    observed_managed: set[str] = set()
    observed_tmp: set[str] = set()

    def observe() -> None:
        while not stop_observer.is_set():
            targets = fd_targets()
            observed_managed.update(target for target in targets if str(managed_temp) in target)
            observed_tmp.update(
                target for target in targets if target.startswith("/tmp/") and target not in baseline_tmp
            )
            if any(str(managed_temp) in target for target in targets):
                managed_activity.set()
            time.sleep(0.001)

    observer = threading.Thread(target=observe, daemon=True)
    observer.start()
    filler = managed_temp / ".kaya-runtime-exhaustion-filler"
    filler_started = threading.Event()

    def fill_after_activity() -> None:
        if not managed_activity.wait(timeout=30):
            return
        free = shutil.disk_usage(managed_temp).free
        target = max(0, free - 512 * 1024)
        filler_started.set()
        try:
            with filler.open("wb") as handle:
                remaining = target
                block = b"K" * (1024 * 1024)
                while remaining:
                    chunk = block[: min(len(block), remaining)]
                    handle.write(chunk)
                    remaining -= len(chunk)
        except OSError:
            # The filler itself may win the race to the final free blocks.
            pass

    filler_thread = threading.Thread(target=fill_after_activity, daemon=True)
    filler_thread.start()
    failure: str | None = None
    try:
        create_index(operation)
    except (OSError, sqlite3.DatabaseError) as exc:
        failure = str(exc)
    finally:
        stop_observer.set()
        observer.join(timeout=5)
        filler_thread.join(timeout=5)
    managed_free_after_failure = shutil.disk_usage(managed_temp).free
    filler.unlink(missing_ok=True)

    failed_fingerprint = fingerprint(source)
    with sqlite3.connect(operation) as connection:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()

    retry = root / "retry.sqlite3"
    retry.unlink(missing_ok=True)
    shutil.copy2(source, retry)
    create_index(retry)
    with sqlite3.connect(retry) as connection:
        retry_index = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' "
            "AND name='ix_dns_client_traffic_client_observed'"
        ).fetchone()

    print(json.dumps({
        "sqlite_tmpdir": os.environ["SQLITE_TMPDIR"],
        "sqlite_loaded_before_import": sqlite_loaded_before_import,
        "source_device": source.stat().st_dev,
        "managed_temp_device": managed_temp.stat().st_dev,
        "tmp_device": Path("/tmp").stat().st_dev,
        "initial_managed_free_bytes": initial_free,
        "preflight_required_bytes": required_bytes,
        "preflight": "PASS",
        "managed_activity_observed": bool(observed_managed),
        "managed_fd_targets": sorted(observed_managed),
        "filler_started_after_activity": filler_started.is_set(),
        "managed_free_bytes_after_failure": managed_free_after_failure,
        "failure": failure,
        "tmp_fd_targets": sorted(observed_tmp),
        "source_fingerprint_unchanged": source_fingerprint == failed_fingerprint,
        "quick_check": quick_check,
        "foreign_key_errors": len(foreign_keys),
        "retry_succeeded": bool(retry_index),
    }, sort_keys=True))
    if not failure or not filler_started.is_set() or not observed_managed:
        return 2
    if "full" not in failure.lower() and "space" not in failure.lower():
        return 3
    if observed_tmp or source_fingerprint != failed_fingerprint or quick_check != "ok" or foreign_keys:
        return 4
    return 0 if retry_index else 5


if __name__ == "__main__":
    raise SystemExit(main())
