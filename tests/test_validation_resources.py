import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.kaya_validation_resources import phase12a_project_name, validate_config


def test_phase12_config_accepts_only_run_scoped_mutable_resources():
    config = {
        "services": {
            "kaya": {
                "container_name": "kaya_phase12a_run_1_kaya",
                "volumes": [{"type": "volume", "source": "postgres_secret"}],
            }
        },
        "volumes": {"postgres_secret": {"name": "kaya_phase12a_run_1_secret"}},
        "networks": {"default": {}},
    }

    result = validate_config(config, "kaya_phase12a_run_1")

    assert result["volumes"] == ["kaya_phase12a_run_1_secret"]
    assert result["containers"] == ["kaya_phase12a_run_1_kaya"]
    assert result["networks"] == ["kaya_phase12a_run_1_default"]


@pytest.mark.parametrize(
    "config",
    [
        {"volumes": {"secret": {"name": "kaya_phase6_postgres_secret"}}},
        {"volumes": {"secret": {"external": True, "name": "kaya_phase12a_old_secret"}}},
        {"services": {"kaya": {"container_name": "kaya"}}},
    ],
)
def test_phase12_config_rejects_protected_or_ambiguous_resources(config):
    with pytest.raises(RuntimeError):
        validate_config(config, "kaya_phase12a_run_1")


def test_phase12_project_name_must_be_run_scoped():
    with pytest.raises(RuntimeError):
        validate_config({}, "kaya_phase12")


@pytest.mark.parametrize(
    ("run_id", "attempt", "expected"),
    [("32492499388", "1", "kaya_phase12a_32492499388_1"), ("local", "1", "kaya_phase12a_local_1")],
)
def test_phase12a_project_name_uses_exact_github_identifiers(run_id, attempt, expected):
    assert phase12a_project_name(run_id, attempt) == expected


@pytest.mark.parametrize("value", ["../../volume", "name/data", "foo bar", "foo:bar"])
def test_phase12a_project_name_rejects_unsafe_identifiers(value):
    with pytest.raises(ValueError):
        phase12a_project_name(value, "1")


def test_phase12_config_rejects_undefined_named_volume():
    with pytest.raises(RuntimeError, match="undefined named volume"):
        validate_config(
            {"services": {"kaya": {"volumes": [{"type": "volume", "source": "missing"}]}}, "volumes": {}},
            "kaya_phase12a_run_1",
        )


def test_phase12a_exact_github_compose_render_has_no_slash_volume_source():
    if shutil.which("docker") is None:
        pytest.skip("Docker is not installed")
    project = phase12a_project_name("32492499388", "1")
    env = os.environ.copy()
    env.update(
        {
            "KAYA_IMAGE": "kaya-phase12-app-local",
            "PHASE12A_PROJECT": project,
            "PHASE12A_ROOT": str(Path.cwd() / "phase12a-32492499388_1"),
        }
    )
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.phase12a-ci.yml",
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    rendered = json.loads(result.stdout)
    assert {definition["name"] for definition in rendered["volumes"].values()} == {
        f"{project}_postgres_data",
        f"{project}_postgres_secret",
    }
    for service in rendered["services"].values():
        for mount in service.get("volumes", []):
            if mount.get("type") == "volume":
                assert mount["source"] in {"postgres_data", "postgres_secret"}
                assert "/" not in mount["source"]
            else:
                assert "/data" not in mount["source"] or mount["type"] == "bind"
    assert f"{project}/data" not in result.stdout


def test_phase12_cleanup_has_no_broad_destructive_commands_or_protected_names():
    files = [
        Path("scripts/phase12_runtime_validation.sh"),
        Path("scripts/phase12a_cleanup_validation.sh"),
        Path(".github/workflows/phase12-runtime.yml"),
        Path("docker-compose.phase12a-ci.yml"),
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in files)

    assert "down -v" not in text
    assert "docker system prune" not in text
    assert "docker volume prune" not in text
    assert "kaya_phase6_postgres_secret" not in text
    assert "kaya_postgres_data" not in text


def test_phase7_to_11_validation_has_no_unguarded_volume_teardown():
    paths = list(Path("scripts").glob("phase[7-9]*_runtime_validation.sh"))
    paths += [Path("scripts/phase10_runtime_validation.sh"), Path("scripts/phase11_runtime_validation.sh")]
    paths += list(Path(".github/workflows").glob("phase[7-9]*-runtime.yml"))
    paths += [Path(".github/workflows/phase10-runtime.yml"), Path(".github/workflows/phase11-runtime.yml")]
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)

    assert "down -v" not in text
    assert "docker volume prune" not in text
    assert "docker system prune" not in text
    assert "cleanup-compose --project" in text


def test_phase8_one_shot_backup_workers_do_not_restart_dependencies():
    workflow = Path(".github/workflows/phase8-runtime.yml").read_text(encoding="utf-8")
    script = Path("scripts/phase8d_runtime_validation.sh").read_text(encoding="utf-8")

    assert "run --rm --no-deps --entrypoint bash postgres-backup" in workflow
    assert "compose run --rm --no-deps" in script
    assert "compose run --rm --entrypoint bash postgres-backup" not in script


def test_phase9_retry_fixture_cleanup_is_exact_and_run_scoped():
    script = Path("scripts/phase9_runtime_validation.sh").read_text(encoding="utf-8")

    assert "cleanup_owned_retry_fixture" in script
    assert 'fixture="$ROOT/retry-data"' in script
    assert '"$fixture:/phase9-cleanup:rw"' in script
    assert "test ! -L /phase9-cleanup" in script
    assert "find /phase9-cleanup -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +" in script
    assert "chmod -R 777" not in script


def test_phase11_cleanup_resolves_the_candidate_application_image():
    workflow = Path(".github/workflows/phase11-runtime.yml").read_text(encoding="utf-8")

    assert "KAYA_IMAGE: kaya:phase11-${{ github.sha }}" in workflow
    assert 'KAYA_IMAGE="$PHASE11_APP_IMAGE"' in workflow
