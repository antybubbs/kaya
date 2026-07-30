import json
import shutil
import sqlite3
import textwrap
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import Session

import app.db.backup as backup_module
import app.db.migrations as migrations_module
from app.core.config import Settings
from app.db.backup import DatabaseBackupError, create_sqlite_backup
from app.db.migrations import (
    BASELINE_REVISION,
    DatabaseMigrationError,
    prepare_database,
)
from app.db.validation import (
    DatabaseValidationError,
    validate_schema,
    validate_sqlite_integrity,
)
from app.models.models import IPAddress, NetworkMonitor


def settings_for(path: Path, backup_dir: Path) -> Settings:
    return Settings(
        app_env="test",
        encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
        database_url=f"sqlite:///{path.as_posix()}",
        migration_backup_dir=str(backup_dir),
    )


def engine_for(path: Path):
    return create_engine(f"sqlite:///{path.as_posix()}")


def test_fresh_install_and_repeated_start_are_idempotent(tmp_path):
    path = tmp_path / "kaya.db"
    settings = settings_for(path, tmp_path / "backups")
    engine = engine_for(path)

    first = prepare_database(engine, settings)
    first_stat = path.stat()
    second = prepare_database(engine, settings)

    with sqlite3.connect(path) as connection:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    assert first.current_revision == BASELINE_REVISION
    assert second.current_revision == BASELINE_REVISION
    assert first.backup is None and second.backup is None
    assert list((tmp_path / "backups").glob("*.sqlite3")) == []
    assert path.stat().st_size == first_stat.st_size
    assert revision == BASELINE_REVISION
    assert integrity == "ok"
    assert foreign_keys == []


def test_clean_restart_uses_lightweight_startup_validation(tmp_path, monkeypatch):
    path = tmp_path / "kaya.db"
    settings = settings_for(path, tmp_path / "backups")
    prepare_database(engine_for(path), settings)

    monkeypatch.setattr(
        migrations_module,
        "validate_schema",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("clean startup must not run full schema introspection")
        ),
    )

    result = prepare_database(engine_for(path), settings)

    assert result.current_revision == BASELINE_REVISION
    assert result.backup is None


def test_future_revision_upgrades_once_with_backup(tmp_path, monkeypatch):
    path = tmp_path / "kaya.db"
    backup_dir = tmp_path / "backups"
    settings = settings_for(path, backup_dir)
    prepare_database(engine_for(path), settings)

    project = tmp_path / "future-project"
    shutil.copytree("migrations", project / "migrations")
    shutil.copy("alembic.ini", project / "alembic.ini")
    revision = "20260730_02_test"
    (project / "migrations" / "versions" / f"{revision}.py").write_text(
        textwrap.dedent(f'''\
            """Disposable future migration workflow probe."""

            from alembic import op
            import sqlalchemy as sa

            revision = "{revision}"
            down_revision = "{BASELINE_REVISION}"
            branch_labels = None
            depends_on = None


            def upgrade():
                op.create_table(
                    "migration_workflow_probe",
                    sa.Column("id", sa.Integer(), primary_key=True),
                )


            def downgrade():
                op.drop_table("migration_workflow_probe")
            '''),
        encoding="utf-8",
    )
    monkeypatch.setattr(migrations_module, "PROJECT_ROOT", project)

    upgraded = prepare_database(engine_for(path), settings)
    repeated = prepare_database(engine_for(path), settings)

    with sqlite3.connect(path) as connection:
        applied_revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
        probe_count = connection.execute(
            "SELECT count(*) FROM migration_workflow_probe"
        ).fetchone()[0]
    assert upgraded.previous_revision == BASELINE_REVISION
    assert upgraded.current_revision == revision
    assert upgraded.backup is not None
    assert repeated.current_revision == revision
    assert repeated.backup is None
    assert applied_revision == revision
    assert probe_count == 0
    assert len(list(backup_dir.glob("*.sqlite3"))) == 1


@pytest.mark.parametrize(
    "historical_release", ["v0.18.x", "v0.20.x", "v0.22.x", "v0.24.x", "v0.25.x"]
)
def test_reconstructed_historical_upgrade_creates_backup_and_preserves_user(
    tmp_path, historical_release
):
    path = tmp_path / "kaya.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR(255) NOT NULL UNIQUE, "
            "password_hash VARCHAR(255) NOT NULL, first_name VARCHAR(120), last_name VARCHAR(120), "
            "role VARCHAR(30), is_active BOOLEAN, totp_secret TEXT, "
            "totp_enabled BOOLEAN DEFAULT 0 NOT NULL, created_at DATETIME)"
        )
        connection.execute(
            "INSERT INTO users (id, email, password_hash, role, is_active, totp_enabled, created_at) "
            "VALUES (1, ?, 'fake-hash', 'admin', 1, 0, CURRENT_TIMESTAMP)",
            (f"{historical_release}@example.invalid",),
        )
    settings = settings_for(path, tmp_path / "backups")

    result = prepare_database(engine_for(path), settings)
    backup_count = len(list((tmp_path / "backups").glob("*.sqlite3")))
    repeated = prepare_database(engine_for(path), settings)

    assert result.compatibility_applied is True
    assert repeated.compatibility_applied is False
    assert len(list((tmp_path / "backups").glob("*.sqlite3"))) == backup_count == 1
    assert result.backup and result.backup.database_path.is_file()
    metadata = json.loads(result.backup.metadata_path.read_text(encoding="utf-8"))
    assert metadata["source_revision"] == "pre-alembic"
    with sqlite3.connect(path) as connection:
        user = connection.execute(
            "SELECT email, password_hash FROM users WHERE id=1"
        ).fetchone()
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
    assert user == (f"{historical_release}@example.invalid", "fake-hash")
    assert revision == BASELINE_REVISION
    with sqlite3.connect(result.backup.database_path) as restored:
        restored_user = restored.execute(
            "SELECT email, password_hash FROM users WHERE id=1"
        ).fetchone()
        has_revision = restored.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alembic_version'"
        ).fetchone()
    assert restored_user == user
    assert has_revision is None


def test_current_pre_alembic_schema_is_validated_then_stamped(tmp_path):
    path = tmp_path / "kaya.db"
    settings = settings_for(path, tmp_path / "backups")
    prepare_database(engine_for(path), settings)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE alembic_version")

    result = prepare_database(engine_for(path), settings)

    assert result.previous_revision is None
    assert result.current_revision == BASELINE_REVISION
    assert result.compatibility_applied is True
    assert result.backup is not None


def test_historical_integer_latency_is_backed_up_validated_stamped_and_preserved(
    tmp_path,
):
    path = tmp_path / "kaya.db"
    backup_dir = tmp_path / "backups"
    settings = settings_for(path, backup_dir)
    engine = engine_for(path)
    prepare_database(engine, settings)
    with Session(engine) as session:
        address = IPAddress(address="192.0.2.44", name="Synthetic monitor")
        session.add(address)
        session.flush()
        session.add(NetworkMonitor(ip_address_id=address.id, last_latency_ms=12.75))
        session.commit()
    engine.dispose()

    with sqlite3.connect(path) as connection:
        schema_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='network_monitors'"
        ).fetchone()[0]
        assert "last_latency_ms FLOAT" in schema_sql
        schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_master SET sql=replace(sql, 'last_latency_ms FLOAT', "
            "'last_latency_ms INTEGER') WHERE type='table' AND name='network_monitors'"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.execute("DROP TABLE alembic_version")

    result = prepare_database(engine_for(path), settings)
    repeated = prepare_database(engine_for(path), settings)

    assert result.previous_revision is None
    assert result.current_revision == BASELINE_REVISION
    assert result.compatibility_applied is True
    assert result.backup is not None
    assert repeated.compatibility_applied is False
    assert len(list(backup_dir.glob("*.sqlite3"))) == 1
    with sqlite3.connect(path) as connection:
        declared = {
            row[1]: row[2]
            for row in connection.execute("PRAGMA table_info(network_monitors)")
        }
        latency = connection.execute(
            "SELECT last_latency_ms, typeof(last_latency_ms) FROM network_monitors"
        ).fetchone()
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()[0]
    assert declared["last_latency_ms"] == "INTEGER"
    assert latency == (12.75, "real")
    assert revision == BASELINE_REVISION


def test_unchanged_failed_transition_reuses_verified_backup(tmp_path, monkeypatch):
    path = tmp_path / "kaya.db"
    backup_dir = tmp_path / "backups"
    settings = settings_for(path, backup_dir)
    engine = engine_for(path)
    prepare_database(engine, settings)
    engine.dispose()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE alembic_version")

    def fail_compatibility(_path):
        raise RuntimeError("synthetic unchanged compatibility failure")

    monkeypatch.setattr(
        migrations_module, "migrate_pre_alembic_database", fail_compatibility
    )
    with pytest.raises(DatabaseMigrationError):
        prepare_database(engine_for(path), settings)
    first_backups = list(backup_dir.glob("*.sqlite3"))
    with pytest.raises(DatabaseMigrationError):
        prepare_database(engine_for(path), settings)

    assert len(first_backups) == 1
    assert list(backup_dir.glob("*.sqlite3")) == first_backups


def test_corrupt_database_fails_without_starting_migration(tmp_path):
    path = tmp_path / "kaya.db"
    path.write_bytes(b"clearly-not-sqlite")
    with pytest.raises(DatabaseMigrationError):
        prepare_database(engine_for(path), settings_for(path, tmp_path / "backups"))
    assert list((tmp_path / "backups").glob("*.sqlite3")) == []


def test_unknown_revision_fails_before_backup(tmp_path):
    path = tmp_path / "kaya.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"
        )
        connection.execute("INSERT INTO alembic_version VALUES ('unknown_revision')")
    with pytest.raises(DatabaseMigrationError):
        prepare_database(engine_for(path), settings_for(path, tmp_path / "backups"))
    assert list((tmp_path / "backups").glob("*.sqlite3")) == []


def test_missing_required_table_aborts_startup(tmp_path):
    path = tmp_path / "kaya.db"
    settings = settings_for(path, tmp_path / "backups")
    prepare_database(engine_for(path), settings)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE licences")
    with pytest.raises(DatabaseMigrationError):
        prepare_database(engine_for(path), settings)


def test_baseline_downgrade_is_disabled(tmp_path):
    path = tmp_path / "kaya.db"
    settings = settings_for(path, tmp_path / "backups")
    prepare_database(engine_for(path), settings)
    from alembic import command

    from app.db.migrations import _alembic_config

    with pytest.raises(RuntimeError, match="intentionally disabled"):
        command.downgrade(_alembic_config(settings.database_url), "base")


def test_backup_failure_is_fail_closed(tmp_path, monkeypatch):
    source = tmp_path / "source.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE safe (id INTEGER PRIMARY KEY)")
    backup_dir = tmp_path / "backups"
    monkeypatch.setattr(
        backup_module.os,
        "chmod",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("synthetic failure")),
    )
    with pytest.raises(DatabaseBackupError):
        create_sqlite_backup(
            source, backup_dir, source_revision="old", target_revision="new"
        )


def test_integrity_validation_rejects_missing_file(tmp_path):
    with pytest.raises(DatabaseValidationError):
        validate_sqlite_integrity(tmp_path / "missing.db")


def test_schema_validation_rejects_missing_column(tmp_path):
    path = tmp_path / "schema.db"
    metadata = MetaData()
    Table(
        "sample",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("name", String(20)),
    )
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"
        )
        connection.execute("INSERT INTO alembic_version VALUES ('synthetic')")
    with pytest.raises(DatabaseValidationError, match="missing columns: name"):
        validate_schema(path, metadata)


def test_schema_validation_rejects_unexpected_column_type(tmp_path):
    path = tmp_path / "schema.db"
    metadata = MetaData()
    Table(
        "sample",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("name", String(20)),
    )
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, name INTEGER)")
        connection.execute(
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"
        )
        connection.execute("INSERT INTO alembic_version VALUES ('synthetic')")
    with pytest.raises(
        DatabaseValidationError, match="has type INTEGER; expected VARCHAR"
    ):
        validate_schema(path, metadata)


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, "0 B"), (1024, "1.0 KiB"), (1024**2, "1.0 MiB"), (1024**3, "1.0 GiB")],
)
def test_human_bytes_uses_binary_units(value, expected):
    from app.services.about import human_bytes

    assert human_bytes(value) == expected
