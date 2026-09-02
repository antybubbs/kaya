#!/usr/bin/env python3
"""Maintain the canonical, redacted Phase 12 acceptance evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

SCENARIOS = {
    1: "Fresh install has bootstrap/app role split", 2: "Fresh runtime kaya is non-superuser", 3: "Fresh DB/schema owned correctly",
    4: "Fresh application HTTP uses kaya", 5: "Fresh worker writes use kaya", 6: "Legacy PostgreSQL fixture created",
    7: "Legacy kaya starts as superuser", 8: "Legacy DB/schema ownership baseline", 9: "Legacy representative data exists",
    10: "Legacy topology detected", 11: "Safety backup required/created", 12: "Safety backup verified",
    13: "Bootstrap secret persisted", 14: "kaya_bootstrap created", 15: "kaya demoted", 16: "kaya LOGIN preserved",
    17: "kaya password preserved", 18: "DB owner remains kaya", 19: "Schema owner remains kaya", 20: "Table access preserved",
    21: "Sequence/identity access preserved", 22: "Alembic migration capability preserved", 23: "Kaya starts after role migration",
    24: "Authenticated HTTP smoke", 25: "Representative application write", 26: "Worker PostgreSQL write",
    27: "Runtime HTTP role is kaya", 28: "Runtime worker role is kaya", 29: "Runtime does not use bootstrap role",
    30: "Restart idempotency", 31: "Image replacement idempotency", 32: "Partial migration recovery",
    33: "Migration interruption recovery", 34: "Ambiguous topology fails closed", 35: "Unrelated PostgreSQL role preserved",
    36: "Unrelated PostgreSQL DB preserved", 37: "No verified backup prevents mutation", 38: "Role-topology diagnostics",
    39: "Secret/log leakage review", 40: "Backup after migration", 41: "Backup verification", 42: "Restore to disposable PostgreSQL",
    43: "Restored data valid", 44: "Restored deployment recreates correct role topology", 45: "Restored Kaya authenticated read/write",
    46: "Bootstrap secret persists through restart", 47: "Application secret persists through restart", 48: "Bootstrap/app secrets are separated",
    49: "PostgreSQL patch upgrade after role migration", 50: "Role topology survives patch upgrade", 51: "Phase 6 SQLite migration regression",
    52: "Retained SQLite unchanged", 53: "Phase 8 backup regression", 54: "Phase 9 no-fallback regression",
    55: "Phase 10 compatibility regression", 56: "Phase 11 upgrade-readiness regression", 57: "PostgreSQL integration suite",
    58: "Migration/role focused tests", 59: "Non-Docker regression suite", 60: "Security tests", 61: "Compose validation",
    62: "Workflow validation", 63: "Cleanup/isolation",
}

assert sorted(SCENARIOS) == list(range(1, 64))
assert len(SCENARIOS) == len(set(SCENARIOS)) == 63


def fresh() -> dict[int, dict[str, object]]:
    return {number: {"id": number, "name": name, "status": "BLOCKED", "evidence": {}} for number, name in SCENARIOS.items()}


def load(path: Path) -> dict[int, dict[str, object]]:
    if not path.exists():
        return fresh()
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("rows", [])
    result = fresh()
    for row in rows:
        number = int(row["id"])
        if number not in result or row.get("name") != SCENARIOS[number]:
            raise ValueError("invalid Phase 12 scenario registry")
        result[number] = {"id": number, "name": SCENARIOS[number], "status": row.get("status", "BLOCKED"), "evidence": row.get("evidence", {})}
    return result


def write(path: Path, rows: dict[int, dict[str, object]]) -> None:
    statuses = [row["status"] for row in rows.values()]
    output = {
        "phase": "12",
        "workflow": "Phase 12 PostgreSQL Role Topology Migration Validation",
        "rows": [rows[number] for number in range(1, 64)],
        "summary": {status: statuses.count(status) for status in ("PASS", "FAIL", "BLOCKED")},
    }
    path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=os.environ.get("PHASE12_ACCEPTANCE_OUTPUT", "phase12_acceptance.json"))
    parser.add_argument("--scenario", type=int)
    parser.add_argument("--status", choices=("PASS", "FAIL", "BLOCKED"))
    parser.add_argument("--evidence", default="{}")
    args = parser.parse_args()
    path = Path(args.output)
    rows = load(path)
    if args.scenario is not None:
        if args.scenario not in rows or args.status is None:
            parser.error("scenario and status must be supplied together")
        rows[args.scenario]["status"] = args.status
        rows[args.scenario]["evidence"] = json.loads(args.evidence)
    write(path, rows)
    counts = {status: sum(item["status"] == status for item in rows.values()) for status in ("PASS", "FAIL", "BLOCKED")}
    return 0 if counts == {"PASS": 63, "FAIL": 0, "BLOCKED": 0} else 1


if __name__ == "__main__":
    raise SystemExit(main())
