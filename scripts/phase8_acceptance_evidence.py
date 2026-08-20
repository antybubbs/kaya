"""Write a redacted, explicit Phase 8 acceptance matrix artifact."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

SCENARIOS = [
    "Production PostgreSQL Compose startup", "Kaya operational with PostgreSQL", "Authenticated HTTP smoke", "Representative application writes", "Manual PostgreSQL backup", "Backup SHA-256 metadata", "Backup archive verification", "Backup permissions", "Backup during live writes", "Scheduled backup", "Backup retention", "Unrelated backup-directory file preserved", "Missing backup destination", "Unwritable backup destination", "Constrained/full backup destination", "Interrupted backup", "Partial backup rejected", "Corrupted archive rejected", "Disposable restore", "Restored Alembic revision", "Restored representative data", "Kaya read against restored DB", "Restore-drill cleanup", "PostgreSQL restart", "Kaya restart", "Whole Compose down/up", "Image replacement", "Credential persistence", "PostgreSQL outage", "Bounded DB-backed failure", "No SQLite fallback", "PostgreSQL recovery", "SQLAlchemy pool recovery", "Worker startup order", "Worker recovery", "Worker writes PostgreSQL", "Retained SQLite unchanged", "Database-size diagnostics", "Largest-table/index diagnostics", "PostgreSQL connection diagnostics", "SQLAlchemy pool diagnostics", "Deadlock/lock diagnostics", "Backup diagnostics", "Version/revision diagnostics", "Retention workload behaviour", "PostgreSQL role/security", "Secret/log leakage review", "Non-Docker regression tests", "PostgreSQL integration tests", "GitHub Actions runtime execution", "Cleanup/isolation",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    blocked = {int(value) for value in os.environ.get("PHASE8_BLOCKED_ROWS", "").split(",") if value}
    passed = {int(value) for value in os.environ.get("PHASE8_PASS_ROWS", "").split(",") if value}
    failed = {int(value) for value in os.environ.get("PHASE8_FAIL_ROWS", "").split(",") if value}
    evidence = os.environ.get("PHASE8_EVIDENCE_SUMMARY", "validated by Phase 8D workflow")
    try:
        metrics = json.loads(os.environ.get("PHASE8_METRICS_JSON", "{}"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid PHASE8_METRICS_JSON: {exc}") from exc
    rows = []
    for number, name in enumerate(SCENARIOS, 1):
        result = "FAIL" if number in failed else "BLOCKED" if number in blocked else "PASS" if number in passed else "BLOCKED"
        summary = evidence if result == "PASS" else "scenario failed in the Phase 8D runtime harness" if result == "FAIL" else "not exercised by this validation run; see Phase 8D report"
        rows.append(
            {
                "scenario_number": number,
                "scenario_name": name,
                "result": result,
                "evidence_summary": summary,
                "duration_or_metric_if_relevant": metrics.get(str(number)),
            }
        )
    if args.output.suffix.lower() == ".json":
        args.output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    else:
        lines = ["scenario_number\tscenario_name\tresult\tevidence_summary"]
        lines.extend(
            f"{row['scenario_number']}\t{row['scenario_name']}\t{row['result']}\t{row['evidence_summary']}"
            for row in rows
        )
        args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
