"""Write the complete redacted Phase 10 database-platform acceptance matrix."""

from __future__ import annotations

import json
import os
from pathlib import Path

SCENARIOS = [
    "Fresh PostgreSQL 16 install", "Existing PostgreSQL 16 startup", "Representative writes", "Current schema matches expected Alembic head", "Exactly one Alembic head", "Fresh PostgreSQL base to head", "Supported older PostgreSQL schema to current head", "Existing current head does not remigrate", "Database schema newer than application fails closed", "Missing migration revision fails closed", "Multiple Alembic heads detected in test fixture", "Automatic Alembic downgrade not performed", "Old-image rollback behavior validated", "Current-image restart after migration", "PostgreSQL server version detected", "Supported PostgreSQL major accepted", "Unsupported older PostgreSQL major handling", "Unsupported newer PostgreSQL major handling", "Compatibility diagnostics", "About/System database metadata", "Phase 8 PostgreSQL backup still works", "Backup compatibility metadata", "Backup verification", "Restore compatibility preflight", "Restore drill", "Phase 9 legacy SQLite detection still works", "Phase 9 SQLite migration still works", "Phase 9 retained SQLite remains non-authoritative", "PostgreSQL outage still has no SQLite fallback", "Phase 6 failed-target retry flow", "Phase 6 migration_id preserved on failure", "Phase 6 preflight failure records FAILED safely", "Deprecated config precedence", "Fresh installer PostgreSQL-only", "Production entrypoint rejects SQLite authority", "Worker startup/write still PostgreSQL", "Database diagnostics", "PostgreSQL integration suite", "Migration-specific test suite", "Non-Docker regression suite", "Security/secret review", "Compose validation", "Workflow validation", "Historical migration graph integrity", "Cleanup/isolation",
]


def numbers(value: str) -> set[int]:
    return {int(item) for item in value.split(",") if item.strip()}


def main() -> int:
    passed = numbers(os.environ.get("PHASE10_PASS_ROWS", ""))
    failed = numbers(os.environ.get("PHASE10_FAIL_ROWS", ""))
    blocked = numbers(os.environ.get("PHASE10_BLOCKED_ROWS", ""))
    summaries = json.loads(os.environ.get("PHASE10_EVIDENCE_SUMMARY", "{}"))
    output = Path(os.environ.get("PHASE10_RESULT_FILE", "phase10_acceptance.json"))
    rows = []
    for number, name in enumerate(SCENARIOS, 1):
        result = "FAIL" if number in failed else "BLOCKED" if number in blocked else "PASS" if number in passed else "FAIL"
        rows.append({"scenario_number": number, "scenario_name": name, "result": result, "evidence_summary": summaries.get(str(number), "scenario was not exercised")})
    output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return 1 if any(row["result"] != "PASS" for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
