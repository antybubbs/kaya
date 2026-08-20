"""Write a redacted, explicit Phase 8 acceptance matrix artifact."""

from __future__ import annotations

import argparse
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
    lines = ["scenario_number\tscenario_name\tresult\tevidence_summary"]
    for number, name in enumerate(SCENARIOS, 1):
        result = "BLOCKED" if number in blocked else "PASS" if number in passed else "BLOCKED"
        summary = "validated by Phase 8C workflow" if result == "PASS" else "not exercised by this validation run; see Phase 8C report"
        lines.append(f"{number}\t{name}\t{result}\t{summary}")
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
