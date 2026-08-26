from pathlib import Path


WORKFLOWS = Path(".github/workflows")


def test_permanent_workflow_set_has_no_phase_workflow_files():
    assert sorted(path.name for path in WORKFLOWS.glob("*.yml")) == [
        "ci.yml",
        "database-deep-validation.yml",
        "database.yml",
        "docker.yml",
        "security.yml",
    ]


def test_database_workflows_keep_daily_and_manual_boundaries():
    database = (WORKFLOWS / "database.yml").read_text(encoding="utf-8")
    deep = (WORKFLOWS / "database-deep-validation.yml").read_text(encoding="utf-8")

    assert "push:" in database and "pull_request:" in database
    assert "workflow_dispatch:" in database
    assert "workflow_dispatch:" in deep
    assert "push:" not in deep and "pull_request:" not in deep
    assert "scripts/phase9_runtime_validation.sh" in database
    assert "scripts/phase12_runtime_validation.sh" in deep
    assert "actions/upload-artifact@v4" in deep
    assert "if: failure()" in deep


def test_ci_and_docker_workflow_names_are_permanent():
    assert "name: CI" in (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert "name: Docker" in (WORKFLOWS / "docker.yml").read_text(encoding="utf-8")
