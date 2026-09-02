"""Write the complete redacted Phase 9 lifecycle acceptance matrix."""

from __future__ import annotations

import json
import os
from pathlib import Path

SCENARIOS = [
    "Fresh install uses PostgreSQL", "Fresh install has no authoritative SQLite",
    "Fresh production startup fails closed without PostgreSQL", "Existing PostgreSQL startup",
    "Existing PostgreSQL representative writes", "Existing PostgreSQL restart",
    "Existing PostgreSQL image replacement", "Active PostgreSQL with stale SQLite present",
    "No SQLite migration rerun", "Legacy SQLite detected", "Legacy SQLite verified backup",
    "Legacy SQLite migration", "PostgreSQL cutover", "Migrated authenticated HTTP smoke",
    "Migrated representative writes", "Retained SQLite fingerprint unchanged",
    "Migrated restart", "Migrated image replacement", "PostgreSQL outage after cutover",
    "No SQLite fallback", "PostgreSQL recovery", "Missing retained SQLite post-cutover",
    "Corrupted retained SQLite post-cutover", "Migration failure preserves source",
    "Failed target remains non-authoritative", "Migration retry and recovery",
    "Unsupported SQLite schema rejected", "Ambiguous/path-safe SQLite handling",
    "Authority state persistence", "SQLite migration backup preserved",
    "PostgreSQL operational backups preserved", "Backup-retention separation",
    "Worker writes PostgreSQL only", "Retained SQLite not mutated by workers",
    "PostgreSQL diagnostics", "PostgreSQL backup", "SQLite migration tooling",
    "SQLite unit/test fixtures", "PostgreSQL integration suite", "Non-Docker regression suite",
    "Security and path tests", "Secret/log leakage review", "Compose validation",
    "Migration-chain validation", "Cleanup and isolation",
]


def _numbers(value: str) -> set[int]:
    return {int(item) for item in value.split(",") if item.strip()}


def main() -> None:
    passed = _numbers(os.environ.get("PHASE9_PASS_ROWS", ""))
    failed = _numbers(os.environ.get("PHASE9_FAIL_ROWS", ""))
    blocked = _numbers(os.environ.get("PHASE9_BLOCKED_ROWS", ""))
    summaries = json.loads(os.environ.get("PHASE9_EVIDENCE_SUMMARY", "{}"))
    durations = json.loads(os.environ.get("PHASE9_DURATION_JSON", "{}"))
    rows = []
    for number, name in enumerate(SCENARIOS, 1):
        if number in failed:
            result = "FAIL"
        elif number in blocked:
            result = "BLOCKED"
        elif number in passed:
            result = "PASS"
        else:
            result = "FAIL"
        rows.append({
            "scenario_number": number,
            "scenario_name": name,
            "result": result,
            "evidence_summary": summaries.get(str(number), "no evidence recorded"),
            "duration_ms": durations.get(str(number)),
        })
    output = Path(os.environ.get("PHASE9_RESULT_FILE", "phase9_acceptance.json"))
    output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    if any(row["result"] == "FAIL" for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
