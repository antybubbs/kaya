from pathlib import Path

from scripts.kaya_phase6_recovery_policy import is_explicit_recovery_command


BASE = [
    "python",
    "-m",
    "scripts.kaya_phase6_upgrade",
    "--source",
    "/app/data/kaya.db",
    "--backup-dir",
    "/app/data/backups",
    "--data-dir",
    "/app/data",
    "--clean-failed-target",
    "--migration-id",
    "59022f58-320e-45f1-8703-c148bc9a83e5",
    "--source-fingerprint",
    "2b3edf1e83cf27b45d1e83f50e4c7458b4b5e9f2ca4d0798e02ef8b6a5f3f354",
]


def test_exact_recovery_command_is_recognised():
    assert is_explicit_recovery_command(BASE)


def test_normal_entrypoint_command_is_not_recovery():
    assert not is_explicit_recovery_command(["sh", "-c", "exec uvicorn app.main:app"])


def test_malformed_fingerprint_is_not_recovery():
    command = BASE.copy()
    command[-1] = "g" * 64
    assert not is_explicit_recovery_command(command)


def test_syntactically_valid_wrong_identifier_reaches_database_guards():
    command = BASE.copy()
    command[-3] = "different-migration-id"
    command[-1] = "0" * 64
    assert is_explicit_recovery_command(command)


def test_missing_recovery_arguments_are_not_recovery():
    assert not is_explicit_recovery_command(BASE[:-2])
    assert not is_explicit_recovery_command([*BASE[:-4], "--migration-id", BASE[-3]])


def test_unknown_or_duplicate_options_are_not_recovery():
    assert not is_explicit_recovery_command([*BASE, "--unexpected"])
    assert not is_explicit_recovery_command([*BASE, "--clean-failed-target"])


def test_entrypoint_bootstraps_runtime_secrets_before_failed_state_check():
    entrypoint = Path("docker-entrypoint.sh").read_text(encoding="utf-8")
    assert entrypoint.index('set -a') < entrypoint.index('UPGRADE_STATE_FILE=')
    assert "scripts.kaya_phase6_recovery_policy" in entrypoint
    assert '"$UPGRADE_STATE" != "FAILED"' in entrypoint
    assert '"$PHASE6_RECOVERY_MODE" != "true"' in entrypoint
