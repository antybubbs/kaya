from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_phase13_registry_is_exactly_fifty_fail_closed_rows(tmp_path):
    evidence = tmp_path / "acceptance.json"
    result = __import__("subprocess").run(
        ["python", "scripts/phase13_acceptance_evidence.py", "--output", str(evidence)],
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 1
    document = json.loads(evidence.read_text(encoding="utf-8"))
    assert [row["id"] for row in document["rows"]] == list(range(1, 51))
    assert document["summary"] == {"PASS": 0, "FAIL": 0, "BLOCKED": 50}


def test_phase13_workflow_has_manual_and_change_triggers():
    workflow = (ROOT / ".github/workflows/phase13-runtime.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "push:" in workflow and "pull_request:" in workflow
    assert "phase13_acceptance.json" in workflow
    assert "Phase 13 PostgreSQL Production Rollout Readiness" in workflow


def test_phase13_runner_uses_primary_compose_and_authoritative_regressions():
    script = (ROOT / "scripts/phase13_runtime_validation.sh").read_text(encoding="utf-8")
    assert "docker-compose.yml" in script
    assert "phase7d_runtime_validation.sh" in script
    assert "phase12_runtime_validation.sh" in script
    assert "postgres:16.14" in script
    assert "summary']=={'PASS':50,'FAIL':0,'BLOCKED':0}" in script
