"""Opt-in, test-only controls for deterministic Phase 6 lifecycle tests.

This module deliberately has no HTTP or remote control surface.  A failpoint
is usable only when ``KAYA_TEST_MODE=true`` is explicitly set in the disposable
test process.  Production configuration rejects any attempt to configure one.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path


class Phase6TestFailpointError(RuntimeError):
    """Controlled failure raised by an explicitly enabled test failpoint."""


FAILPOINT_ACTIONS = {
    "before_source_capture": "pause",
    "after_source_capture": "pause",
    "after_postgres_prepare": "pause",
    "fail_during_copy": "raise",
    "fail_during_validation": "raise",
    "pause_cutover_pending": "pause",
    "pause_after_postgres_active": "pause",
    "fail_state": "raise",
}

_triggered: set[str] = set()


def _test_mode() -> bool:
    return os.environ.get("KAYA_TEST_MODE", "false").lower() == "true"


def validate_configuration() -> None:
    """Reject failpoints unless the process is explicitly a test process."""
    configured = os.environ.get("KAYA_TEST_FAILPOINT", "").strip()
    if not configured:
        return
    if configured not in FAILPOINT_ACTIONS:
        raise RuntimeError(f"Unknown Phase 6 test failpoint: {configured}")
    if not _test_mode():
        raise RuntimeError("Phase 6 test failpoints require KAYA_TEST_MODE=true.")


def _control_path(name: str, suffix: str) -> Path:
    directory = Path(os.environ.get("KAYA_TEST_FAILPOINT_DIR", "/tmp"))
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"kaya-phase6-{name}.{suffix}"


def record(event: str, **values: object) -> None:
    """Append redacted lifecycle evidence to an explicitly configured test file."""
    if not _test_mode():
        return
    destination = os.environ.get("KAYA_TEST_OBSERVABILITY_FILE", "").strip()
    if not destination:
        return
    payload = {
        "event": event,
        "pid": os.getpid(),
        "timestamp": datetime.now(UTC).isoformat(),
        **values,
    }
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, sort_keys=True, default=str) + "\n")


def worker_started(name: str, database_engine: str) -> None:
    """Record worker startup only for an explicitly enabled test process."""
    record(
        "phase6.worker.started",
        worker=name,
        database_engine=database_engine,
    )


def worker_write(subsystem: str, database_engine: str) -> None:
    """Record a worker transaction write without recording row contents."""
    if subsystem in {
        "dns_collector",
        "compute_monitor",
        "ha",
        "notification_outbox",
        "notification_delivery",
        "notification_retention",
        "retention",
    }:
        record(
            "phase6.worker.write",
            worker=subsystem,
            database_engine=database_engine,
        )


def database_identity(context: str, database_role: str) -> None:
    """Record a redacted database role for an explicitly instrumented test."""
    if _test_mode():
        record(
            "phase12.db.identity",
            context=" ".join(str(context).split())[:80],
            database_role=" ".join(str(database_role).split())[:80],
        )


def hit(name: str) -> None:
    """Trigger one predefined test checkpoint at most once per process."""
    validate_configuration()
    if not _test_mode() or os.environ.get("KAYA_TEST_FAILPOINT", "").strip() != name:
        return
    if name in _triggered:
        return
    _triggered.add(name)
    action = FAILPOINT_ACTIONS[name]
    record("phase6.failpoint.hit", failpoint=name, action=action)
    if action == "raise":
        raise Phase6TestFailpointError(f"Controlled Phase 6 test failure at {name}.")
    release = _control_path(name, "release")
    hit_marker = _control_path(name, "hit")
    hit_marker.touch(exist_ok=True)
    while not release.exists():
        time.sleep(0.05)
    release.unlink(missing_ok=True)
    hit_marker.unlink(missing_ok=True)
