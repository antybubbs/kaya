"""Write the complete, redacted Phase 11 acceptance matrix."""

from __future__ import annotations

import json
import os
from pathlib import Path

SCENARIOS = [
    "Current supported PostgreSQL pin identified",
    "PostgreSQL 16 platform contract",
    "Patch-upgrade preflight",
    "Preflight requires verified backup",
    "Preflight rejects unsupported target major",
    "Older PostgreSQL 16.x starts",
    "Kaya runs on older supported 16.x fixture",
    "Representative pre-upgrade data",
    "Pre-upgrade backup",
    "Pre-upgrade backup verification",
    "Credential fingerprint captured",
    "Clean PostgreSQL shutdown",
    "PostgreSQL image replacement within 16.x",
    "Same data volume reused",
    "New PostgreSQL 16.x starts",
    "PostgreSQL server version changed as expected",
    "Kaya reconnects",
    "SQLAlchemy pool recovers",
    "Existing data preserved",
    "Representative post-upgrade write",
    "Sequence/identity correctness",
    "Worker recovery",
    "Worker PostgreSQL write",
    "Retained SQLite unchanged",
    "PostgreSQL diagnostics after upgrade",
    "Backup after upgrade",
    "Backup verification after upgrade",
    "Older-16 backup restored into current 16",
    "Restored Alembic revision",
    "Restored representative data",
    "Kaya reads restored DB",
    "Kaya writes restored DB",
    "PostgreSQL role remains non-superuser",
    "DB ownership/privileges preserved",
    "Installed extension inventory",
    "Encoding/collation/locale inventory",
    "PostgreSQL 15 rejected/handled per policy",
    "PostgreSQL 17 rejected/handled per policy",
    "No automatic major upgrade",
    "No automatic PostgreSQL downgrade",
    "Upgrade failure before image replacement safe",
    "Upgrade failure after image replacement recoverable",
    "Pre-upgrade backup remains available after failure",
    "Version-drift diagnostics",
    "About/System upgrade metadata",
    "Patch-upgrade documentation",
    "Major-upgrade future plan documented",
    "Phase 8 backup/restore regression",
    "Phase 9 no-SQLite-fallback regression",
    "Phase 10 schema compatibility regression",
    "PostgreSQL integration suite",
    "Migration-specific tests",
    "Non-Docker regression suite",
    "Security/secret review",
    "Compose validation",
    "Workflow validation",
    "Cleanup/isolation",
]


def main() -> None:
    output = Path(os.environ.get("PHASE11_ACCEPTANCE_OUTPUT", "phase11_acceptance.json"))
    passed = {int(value) for value in os.environ.get("PHASE11_PASS_ROWS", "").split(",") if value}
    failed = {int(value) for value in os.environ.get("PHASE11_FAIL_ROWS", "").split(",") if value}
    blocked = {int(value) for value in os.environ.get("PHASE11_BLOCKED_ROWS", "").split(",") if value}
    summaries = json.loads(os.environ.get("PHASE11_EVIDENCE_SUMMARY", "{}"))
    rows = []
    for number, name in enumerate(SCENARIOS, 1):
        result = "FAIL" if number in failed else "BLOCKED" if number in blocked else "PASS" if number in passed else "BLOCKED"
        rows.append(
            {
                "scenario_number": number,
                "scenario_name": name,
                "result": result,
                "evidence_summary": summaries.get(str(number), "not exercised by this validation run"),
            }
        )
    output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    if len(rows) != 57 or any(row["result"] not in {"PASS", "FAIL", "BLOCKED"} for row in rows):
        raise SystemExit("invalid Phase 11 acceptance matrix")


if __name__ == "__main__":
    main()
