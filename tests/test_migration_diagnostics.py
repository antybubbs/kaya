import logging
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from app.core.config import Settings
from app.db import migrations
from app.db.backup import MigrationBackup


class ForcedStageFailure(RuntimeError):
    pass


CORE_STAGES = (
    migrations.STAGE_OPENING_DATABASE,
    migrations.STAGE_INTEGRITY_CHECKS,
    migrations.STAGE_CREATING_BACKUP,
    migrations.STAGE_COMPATIBILITY,
    migrations.STAGE_ALEMBIC_MIGRATION,
    migrations.STAGE_SCHEMA_VALIDATION,
    migrations.STAGE_STAMPING_REVISION,
    migrations.STAGE_BACKUP_RETENTION,
    migrations.STAGE_STARTUP_COMPLETE,
)


def _settings(path: Path, backup_dir: Path) -> Settings:
    return Settings(
        app_env="test",
        encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
        database_url=f"sqlite:///{path.as_posix()}",
        migration_backup_dir=str(backup_dir),
    )


@pytest.mark.parametrize("failed_stage", CORE_STAGES)
def test_every_fatal_migration_stage_emits_full_traceback_for_container_logs(
    tmp_path, monkeypatch, caplog, failed_stage
):
    import app.core.config as config_module
    import app.db.session as session_module
    from app.db import cli

    path = tmp_path / "kaya.db"
    if failed_stage != migrations.STAGE_ALEMBIC_MIGRATION:
        path.touch()
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    backup = MigrationBackup(tmp_path / "backup.sqlite3", tmp_path / "backup.json")

    class Script:
        @staticmethod
        def get_heads():
            return [migrations.BASELINE_REVISION]

        @staticmethod
        def get_revision(_revision):
            return object()

    revision_calls = 0

    def revision(_path):
        nonlocal revision_calls
        revision_calls += 1
        return None if revision_calls == 1 else migrations.BASELINE_REVISION

    monkeypatch.setattr(
        migrations.ScriptDirectory, "from_config", lambda _config: Script()
    )
    monkeypatch.setattr(migrations, "_revision", revision)
    monkeypatch.setattr(migrations, "_has_application_tables", lambda _engine: True)
    monkeypatch.setattr(migrations, "validate_legacy_database", lambda _path: None)
    monkeypatch.setattr(
        migrations, "_backup_if_enabled", lambda *_args, **_kwargs: backup
    )
    monkeypatch.setattr(migrations, "migrate_pre_alembic_database", lambda _path: None)
    monkeypatch.setattr(
        migrations,
        "_apply_missing_baseline_objects",
        lambda _path, _sqlite_temp_directory: None,
    )
    monkeypatch.setattr(migrations, "validate_schema", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        migrations, "validate_startup_database", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(migrations, "prune_migration_backups", lambda *_args: None)
    monkeypatch.setattr(migrations.command, "upgrade", lambda *_args: None)
    monkeypatch.setattr(migrations.command, "stamp", lambda *_args: None)

    original_enter = migrations.MigrationProgress.enter

    def fail_at_stage(progress, stage):
        original_enter(progress, stage)
        if stage == failed_stage:
            raise ForcedStageFailure(f"forced failure inside {stage}")

    monkeypatch.setattr(migrations.MigrationProgress, "enter", fail_at_stage)
    caplog.set_level(logging.INFO)

    monkeypatch.setattr(
        config_module, "get_settings", lambda: _settings(path, tmp_path / "backups")
    )
    monkeypatch.setattr(session_module, "engine", engine)

    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 1
    assert f"Database migration aborted at stage: {failed_stage}" in caplog.text
    assert "Fatal database migration failure" in caplog.text
    assert "Traceback (most recent call last)" in caplog.text
    assert f"forced failure inside {failed_stage}" in caplog.text
    fatal_records = [
        record
        for record in caplog.records
        if record.getMessage() == "Fatal database migration failure"
    ]
    assert len(fatal_records) == 1
    assert fatal_records[0].exc_info is not None


def test_multiple_migration_heads_fail_before_database_access_with_actionable_diagnostic(
    tmp_path, monkeypatch, caplog
):
    from app.db.migrations import DatabaseMigrationError, prepare_database

    path = tmp_path / "kaya.db"
    path.touch()
    settings = _settings(path, tmp_path / "backups")
    engine = create_engine(f"sqlite:///{path.as_posix()}")

    class Script:
        @staticmethod
        def get_heads():
            return ["branch-a", "branch-b"]

    monkeypatch.setattr(migrations.ScriptDirectory, "from_config", lambda _config: Script())
    caplog.set_level(logging.INFO)

    with pytest.raises(DatabaseMigrationError, match="branch-a, branch-b"):
        prepare_database(engine, settings)

    assert "Database has not been modified" in caplog.text
    assert "Developer action required: merge the migration heads" in caplog.text


def test_seed_initialisation_failure_delegates_traceback_to_server(monkeypatch, caplog):
    from app import main

    class Inspector:
        @staticmethod
        def has_table(_name):
            return True

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(main, "inspect", lambda _engine: Inspector())
    monkeypatch.setattr(main, "prepare_database", lambda *_args: None)
    monkeypatch.setattr(main, "SessionLocal", Session)
    monkeypatch.setattr(
        main,
        "initialise_application_defaults",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ForcedStageFailure("forced failure inside Running seed initialisation")
        ),
    )
    caplog.set_level(logging.INFO)

    with pytest.raises(ForcedStageFailure):
        main.bootstrap()

    assert (
        "Application startup aborted at stage: Running seed initialisation"
        in caplog.text
    )
    assert "Fatal database migration failure" not in caplog.text
    assert "Traceback (most recent call last)" not in caplog.text


def test_cli_top_level_logs_one_full_traceback_before_clean_exit(monkeypatch, caplog):
    from app.db import cli

    monkeypatch.setattr(
        migrations,
        "prepare_database",
        lambda *_args: (_ for _ in ()).throw(
            ForcedStageFailure("forced CLI migration failure")
        ),
    )
    caplog.set_level(logging.INFO)

    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 1
    assert "Fatal database migration failure" in caplog.text
    assert "Traceback (most recent call last)" in caplog.text
    assert "forced CLI migration failure" in caplog.text
    fatal_records = [
        record
        for record in caplog.records
        if record.getMessage() == "Fatal database migration failure"
    ]
    assert len(fatal_records) == 1
