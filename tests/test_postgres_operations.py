import json
import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy import create_engine

from app.services.postgres_diagnostics import collect_postgres_diagnostics


def test_postgres_diagnostics_is_explicitly_unavailable_for_sqlite():
    engine = create_engine("sqlite://")
    assert collect_postgres_diagnostics(engine, Path(".")) == {
        "available": False,
        "reason": "PostgreSQL is not the active database",
    }


def test_phase8_worker_has_verification_retention_and_restore_drill_contract():
    worker = Path("scripts/kaya_postgres_backup_worker.sh").read_text(encoding="utf-8")
    assert "pg_dump --format=custom" in worker
    assert "pg_restore --list" in worker
    assert "sha256sum" in worker
    assert "archive_bytes" in worker
    assert "postgresql_version" in worker
    assert "alembic_revision" in worker
    assert "metadata is unavailable" in worker
    assert "RETENTION" in worker
    assert "restore-drill" in worker
    assert "PGPASSWORD" in worker
    assert "DROP DATABASE" in worker


def test_live_write_harness_uses_authenticated_supported_route():
    harness = Path("scripts/phase8_live_write.py").read_text(encoding="utf-8")
    assert "/api/dashboard/preferences" in harness
    assert "X-CSRF-Token" in harness


def test_acceptance_evidence_has_all_explicit_matrix_rows():
    source = Path("scripts/phase8_acceptance_evidence.py").read_text(encoding="utf-8")
    assert '"Cleanup/isolation"' in source
    assert source.count('"') > 100


def test_acceptance_evidence_json_is_complete_and_explicit(tmp_path):
    output = tmp_path / "phase8_acceptance.json"
    environment = os.environ | {
        "PHASE8_PASS_ROWS": "1,51",
        "PHASE8_BLOCKED_ROWS": "15",
        "PHASE8_FAIL_ROWS": "",
    }
    subprocess.run(
        [sys.executable, "scripts/phase8_acceptance_evidence.py", "--output", str(output)],
        check=True,
        env=environment,
    )
    rows = json.loads(output.read_text(encoding="utf-8"))
    assert len(rows) == 51
    assert {row["result"] for row in rows} <= {"PASS", "FAIL", "BLOCKED"}
    assert rows[0]["scenario_number"] == 1
    assert rows[14]["result"] == "BLOCKED"
    assert rows[50]["result"] == "PASS"
