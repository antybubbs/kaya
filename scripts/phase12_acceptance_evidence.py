#!/usr/bin/env python3
"""Create the redacted, fixed-shape Phase 12 acceptance report."""

from __future__ import annotations

import json
import os
from pathlib import Path

SCENARIOS = [
    "Fresh install has bootstrap/app role split", "Fresh runtime kaya is non-superuser",
    "Fresh DB/schema owned correctly", "Fresh application HTTP uses kaya",
    "Fresh worker writes use kaya", "Legacy PostgreSQL fixture created",
    "Legacy kaya starts as superuser", "Legacy DB/schema ownership baseline",
    "Legacy representative data exists", "Legacy topology detected",
    "Safety backup required/created", "Safety backup verified",
    "Bootstrap secret persisted", "kaya_bootstrap created", "kaya demoted",
    "kaya LOGIN preserved", "kaya password preserved", "DB owner remains kaya",
    "Schema owner remains kaya", "Table access preserved", "Sequence/identity access preserved",
    "Alembic migration capability preserved", "Kaya starts after role migration",
    "Authenticated HTTP smoke", "Representative application write", "Worker PostgreSQL write",
    "Runtime HTTP role is kaya", "Runtime worker role is kaya", "Runtime does not use bootstrap role",
    "Restart idempotency", "Image replacement idempotency", "Partial migration recovery",
    "Migration interruption recovery", "Ambiguous topology fails closed", "Unrelated PostgreSQL role preserved",
    "Unrelated PostgreSQL DB preserved", "No verified backup prevents mutation",
    "Role-topology diagnostics", "Secret/log leakage review", "Backup after migration",
    "Backup verification", "Restore to disposable PostgreSQL", "Restored data valid",
    "Restored deployment recreates correct role topology", "Restored Kaya authenticated read/write",
    "Bootstrap secret persists through restart", "Application secret persists through restart",
    "Bootstrap/app secrets are separated", "PostgreSQL patch upgrade after role migration",
    "Role topology survives patch upgrade", "Phase 6 SQLite migration regression",
    "Retained SQLite unchanged", "Phase 8 backup regression", "Phase 9 no-fallback regression",
    "Phase 10 compatibility regression", "Phase 11 upgrade-readiness regression",
    "PostgreSQL integration suite", "Migration/role focused tests", "Non-Docker regression suite",
    "Security tests", "Compose validation", "Workflow validation", "Cleanup/isolation",
]


def main() -> int:
    statuses = dict.fromkeys(SCENARIOS, "BLOCKED")
    for raw in os.environ.get("PHASE12_PASS_ROWS", "").split("|"):
        if raw:
            if raw not in statuses:
                raise SystemExit(f"unknown Phase 12 scenario: {raw}")
            statuses[raw] = "PASS"
    for key, status in (("PHASE12_FAIL_ROWS", "FAIL"), ("PHASE12_BLOCKED_ROWS", "BLOCKED")):
        for raw in os.environ.get(key, "").split("|"):
            if raw:
                if raw not in statuses:
                    raise SystemExit(f"unknown Phase 12 scenario: {raw}")
                statuses[raw] = status
    output = {
        "phase": "12",
        "workflow": "Phase 12 PostgreSQL Role Topology Migration Validation",
        "rows": [{"scenario": name, "status": statuses[name]} for name in SCENARIOS],
        "summary": {status: list(statuses.values()).count(status) for status in ("PASS", "FAIL", "BLOCKED")},
    }
    Path(os.environ.get("PHASE12_ACCEPTANCE_OUTPUT", "phase12_acceptance.json")).write_text(
        json.dumps(output, indent=2) + "\n", encoding="utf-8"
    )
    return 1 if any(value != "PASS" for value in statuses.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
