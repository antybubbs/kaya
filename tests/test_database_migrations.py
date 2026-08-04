import json
import logging
import shutil
import sqlite3
import textwrap
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import Session

import app.db.backup as backup_module
import app.db.migrations as migrations_module
import app.db.validation as validation_module
from app.core.config import Settings
from app.db.backup import DatabaseBackupError, create_sqlite_backup
from app.db.migrations import (
    BASELINE_REVISION,
    CURRENT_REVISION,
    DatabaseMigrationError,
    prepare_database,
)
from app.db.validation import (
    DatabaseValidationError,
    validate_schema,
    validate_sqlite_integrity,
)
from app.models.models import IPAddress, NetworkMonitor, User


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
        remote_columns = {row[1] for row in connection.execute("PRAGMA table_info(remote_access)")}
    assert first.current_revision == CURRENT_REVISION
    assert second.current_revision == CURRENT_REVISION
    assert first.backup is None and second.backup is None
    assert list((tmp_path / "backups").glob("*.sqlite3")) == []
    assert path.stat().st_size == first_stat.st_size
    assert revision == CURRENT_REVISION
    assert integrity == "ok"
    assert foreign_keys == []
    assert "rdp_cert_fingerprints" in remote_columns


def test_oidc_hardening_migration_revokes_legacy_bearer_invitations(tmp_path):
    from alembic import command
    from app.db.migrations import _alembic_config
    from app.models.models import OIDCProvider

    path = tmp_path / "kaya.db"
    settings = settings_for(path, tmp_path / "backups")
    engine = engine_for(path)
    prepare_database(engine, settings)
    with Session(engine) as db:
        admin = User(email="admin@example.invalid", password_hash="fake-hash", role="admin", is_active=True)
        target = User(email="recipient@example.invalid", password_hash="fake-hash", role="viewer", is_active=True)
        provider = OIDCProvider(name="Fake IdP", issuer="https://id.example.invalid", client_id="fake", is_enabled=True)
        db.add_all([admin, target, provider])
        db.commit()
        ids = (admin.id, target.id, provider.id)

    config = _alembic_config(settings.database_url)
    command.downgrade(config, "20260803_02")
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO oidc_link_invitations "
            "(token_hash, user_id, provider_id, created_by_user_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, datetime('now', '+30 minutes'))",
            ("a" * 64, ids[1], ids[2], ids[0]),
        )
        connection.commit()

    command.upgrade(config, "head")
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT recipient_binding_hash, provider_binding_hash, revoked_at, used_at FROM oidc_link_invitations"
        ).fetchone()
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
    assert row[0] == "legacy-revoked"
    assert row[1] == "legacy-revoked"
    assert row[2] is not None
    assert row[3] is None
    assert revision == CURRENT_REVISION


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

    assert result.current_revision == CURRENT_REVISION
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
            down_revision = "{CURRENT_REVISION}"
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
    assert upgraded.previous_revision == CURRENT_REVISION
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
    assert revision == CURRENT_REVISION
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
    assert result.current_revision == CURRENT_REVISION
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
    assert result.current_revision == CURRENT_REVISION
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
    assert revision == CURRENT_REVISION


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


def test_pre_alembic_transition_backs_up_before_schema_changes(tmp_path, monkeypatch):
    path = tmp_path / "kaya.db"
    backup_dir = tmp_path / "backups"
    settings = settings_for(path, backup_dir)
    engine = engine_for(path)
    prepare_database(engine, settings)
    with Session(engine) as session:
        session.add(
            User(
                email="backup-order@example.invalid",
                password_hash="fake-hash",
                role="admin",
                is_active=True,
            )
        )
        session.commit()
    engine.dispose()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE alembic_version")
    events = []
    original_backup = migrations_module._backup_if_enabled
    original_compatibility = migrations_module.migrate_pre_alembic_database

    def tracked_backup(*args, **kwargs):
        result = original_backup(*args, **kwargs)
        events.append("backup")
        assert result and result.database_path.is_file()
        return result

    def tracked_compatibility(database_path):
        events.append("compatibility")
        return original_compatibility(database_path)

    monkeypatch.setattr(migrations_module, "_backup_if_enabled", tracked_backup)
    monkeypatch.setattr(
        migrations_module, "migrate_pre_alembic_database", tracked_compatibility
    )

    result = prepare_database(engine_for(path), settings)

    assert events[:2] == ["backup", "compatibility"]
    assert result.backup is not None
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM users").fetchone() == (1,)


def test_slow_quick_check_cannot_block_pre_alembic_transition(tmp_path, monkeypatch):
    path = tmp_path / "kaya.db"
    settings = settings_for(path, tmp_path / "backups")
    engine = engine_for(path)
    prepare_database(engine, settings)
    engine.dispose()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE alembic_version")
    monkeypatch.setattr(
        validation_module,
        "validate_sqlite_integrity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("routine startup must not call strict quick_check")
        ),
    )

    result = prepare_database(engine_for(path), settings)
    repeated = prepare_database(engine_for(path), settings)

    assert result.compatibility_applied is True
    assert repeated.compatibility_applied is False
    assert len(list((tmp_path / "backups").glob("*.sqlite3"))) == 1


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


def test_backup_logs_bounded_progress_and_verification(tmp_path, caplog):
    source = tmp_path / "source.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE safe (id INTEGER PRIMARY KEY, payload BLOB)")
        connection.execute("INSERT INTO safe (payload) VALUES (zeroblob(1048576))")
    caplog.set_level(logging.INFO)

    backup = create_sqlite_backup(
        source,
        tmp_path / "backups",
        source_revision="pre-alembic",
        target_revision=BASELINE_REVISION,
    )

    assert backup.database_path.is_file()
    assert "Kaya database: creating pre-migration backup" in caplog.text
    assert "Kaya database: backup progress 25%" in caplog.text
    assert "Kaya database: backup verified" in caplog.text


def test_database_backup_includes_encrypted_web_push_configuration(tmp_path):
    source = tmp_path / "kaya.db"
    settings = settings_for(source, tmp_path / "migration-backups")
    prepare_database(engine_for(source), settings)
    fake_ciphertext = "gAAAAABsynthetic-fernet-ciphertext-not-a-real-secret"
    with sqlite3.connect(source) as connection:
        connection.execute(
            """
            INSERT INTO web_push_configurations (
                id, encrypted_private_key, public_key, public_key_fingerprint,
                subject, installation_label, enabled, generated_at, updated_at
            ) VALUES (1, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                fake_ciphertext,
                "synthetic-public-key",
                "SHA256:SYNTHETIC",
                "mailto:backup@example.invalid",
                "Backup test",
            ),
        )

    backup = create_sqlite_backup(
        source,
        tmp_path / "backups",
        source_revision=CURRENT_REVISION,
        target_revision="synthetic-next-revision",
    )

    with sqlite3.connect(backup.database_path) as restored:
        row = restored.execute(
            "SELECT encrypted_private_key, public_key_fingerprint "
            "FROM web_push_configurations WHERE id = 1"
        ).fetchone()
    assert row == (fake_ciphertext, "SHA256:SYNTHETIC")


def test_pre_alembic_backup_is_mandatory_when_optional_backups_are_disabled(
    tmp_path,
):
    path = tmp_path / "kaya.db"
    backup_dir = tmp_path / "backups"
    settings = settings_for(path, backup_dir)
    prepare_database(engine_for(path), settings)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE alembic_version")
    settings.migration_backups_enabled = False

    result = prepare_database(engine_for(path), settings)

    assert result.backup is not None
    assert len(list(backup_dir.glob("*.sqlite3"))) == 1


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
