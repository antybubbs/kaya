from pathlib import Path

import pytest

from scripts.kaya_validation_resources import validate_config


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
