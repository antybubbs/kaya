from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command

import app.db.phase6_cutover as phase6_cutover
from app.db.phase6_cutover import (
    UpgradeState,
    _write_state,
    authoritative_database_url,
    clean_failed_target,
    detect_installation,
    legacy_sqlite_eligibility,
    prepare_failed_retry,
    _upgrade_supported_legacy_sqlite,
    run_upgrade,
    state_path,
)
from app.db.migrations import _alembic_config
from app.db.sqlite_to_postgres import SQLiteToPostgresError


def test_detects_existing_sqlite_install_from_config_and_file(tmp_path: Path):
    source = tmp_path / "kaya.db"
    source.touch()

    detected = detect_installation(f"sqlite:///{source}", tmp_path)

    assert detected.state == UpgradeState.SQLITE_ACTIVE
    assert detected.source_path == source.resolve()


def test_detects_existing_postgres_without_sqlite_guess(tmp_path: Path):
    detected = detect_installation("postgresql+psycopg://kaya@db/kaya", tmp_path)

    assert detected.state == UpgradeState.EXISTING_POSTGRES_INSTALL
    assert detected.source_path is None


def test_missing_sqlite_source_is_not_treated_as_fresh_install(tmp_path: Path):
    detected = detect_installation(f"sqlite:///{tmp_path / 'missing.db'}", tmp_path)

    assert detected.state == UpgradeState.UNSUPPORTED_OR_AMBIGUOUS
    assert "fresh-install" in detected.reason


def test_postgres_authority_refuses_sqlite_fallback(tmp_path: Path):
    _write_state(tmp_path / "kaya-database-upgrade.json", UpgradeState.POSTGRES_ACTIVE, database_engine="postgresql")

    with pytest.raises(RuntimeError, match="conflicts with configuration"):
        authoritative_database_url(f"sqlite:///{tmp_path / 'kaya.db'}", tmp_path)


def test_intermediate_cutover_state_fails_closed(tmp_path: Path):
    _write_state(
        tmp_path / "kaya-database-upgrade.json",
        UpgradeState.CUTOVER_PENDING,
        database_engine="sqlite",
    )

    with pytest.raises(RuntimeError, match="requires operator recovery"):
        authoritative_database_url(f"sqlite:///{tmp_path / 'kaya.db'}", tmp_path)


def test_state_write_is_valid_and_durable_shape(tmp_path: Path):
    path = tmp_path / "kaya-database-upgrade.json"
    _write_state(path, UpgradeState.FAILED, database_engine="sqlite", error="RuntimeError")

    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["state"] == "FAILED"
    assert value["database_engine"] == "sqlite"
    assert not list(tmp_path.glob(".*kaya-database-upgrade.json.*"))


def test_cutover_pending_is_a_durable_non_authoritative_state(tmp_path: Path):
    path = tmp_path / "kaya-database-upgrade.json"
    _write_state(path, UpgradeState.CUTOVER_PENDING, database_engine="postgresql")

    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["state"] == "CUTOVER_PENDING"
    assert value["database_engine"] == "postgresql"


def test_arbitrary_sqlite_file_is_not_migration_eligible(tmp_path: Path):
    source = tmp_path / "kaya.db"
    source.write_bytes(b"not sqlite")

    eligible, reason = legacy_sqlite_eligibility(source, tmp_path)

    assert not eligible
    assert "valid Kaya database" in reason


def test_sqlite_source_outside_data_directory_is_rejected(tmp_path: Path):
    source = tmp_path.parent / "outside.sqlite3"
    source.touch()

    eligible, reason = legacy_sqlite_eligibility(source, tmp_path)

    assert not eligible
    assert "outside" in reason


def test_historical_sqlite_revision_is_eligible_and_upgraded_with_backup(tmp_path: Path):
    source = tmp_path / "kaya.db"
    command.upgrade(_alembic_config(f"sqlite:///{source.as_posix()}"), "20260813_01")
    with sqlite3.connect(source) as connection:
        connection.execute(
            "INSERT INTO users (email, password_hash, role, is_active, totp_enabled, "
            "authentication_type, is_break_glass, role_source, created_at, updated_at) "
            "VALUES ('historical@example.invalid', 'fake-hash', 'admin', 1, 0, "
            "'local', 0, 'local', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
        connection.commit()

    eligible, reason = legacy_sqlite_eligibility(source, tmp_path)
    assert eligible
    assert "20260813_01" in reason
    working_source = _upgrade_supported_legacy_sqlite(
        source, tmp_path / "backups", tmp_path, "20260813_01"
    )

    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "20260813_01"
        assert connection.execute("SELECT email FROM users").fetchone()[0] == "historical@example.invalid"
    with sqlite3.connect(working_source) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "20260818_02"
    backups = list((tmp_path / "backups").glob("*.sqlite3"))
    assert len(backups) == 1
    metadata = json.loads(backups[0].with_suffix(".json").read_text(encoding="utf-8"))
    assert metadata["source_revision"] == "20260813_01"


def test_preflight_failure_records_failed_state(tmp_path: Path, monkeypatch):
    source = tmp_path / "kaya.db"
    source.touch()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(
        phase6_cutover,
        "detect_installation",
        lambda *_args: SimpleNamespace(state=UpgradeState.SQLITE_ACTIVE),
    )
    monkeypatch.setattr(
        phase6_cutover,
        "preflight",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("synthetic preflight failure")),
    )

    with pytest.raises(RuntimeError, match="synthetic preflight failure"):
        run_upgrade(source, "postgresql+psycopg://kaya@db/kaya", tmp_path / "backups", data_dir)

    state = json.loads(state_path(data_dir).read_text(encoding="utf-8"))
    assert state["state"] == UpgradeState.FAILED.value
    assert state["error"] == "RuntimeError"
    assert state["recovery_artifacts_retained"] is True


def test_migration_id_survives_failed_retry_state(tmp_path: Path, monkeypatch):
    source = tmp_path / "kaya.db"
    source.touch()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    migration_id = "phase10-synthetic-migration"
    monkeypatch.setattr(
        phase6_cutover,
        "detect_installation",
        lambda *_args: SimpleNamespace(state=UpgradeState.SQLITE_ACTIVE),
    )
    monkeypatch.setattr(
        phase6_cutover,
        "preflight",
        lambda *_args: {"source_fingerprint": "a" * 64, "target_revision": "20260818_02"},
    )
    failure = SQLiteToPostgresError("synthetic migration failure")
    failure.migration_id = migration_id
    monkeypatch.setattr(phase6_cutover, "migrate", lambda *_args, **_kwargs: (_ for _ in ()).throw(failure))

    with pytest.raises(SQLiteToPostgresError, match="synthetic migration failure"):
        run_upgrade(source, "postgresql+psycopg://kaya@db/kaya", tmp_path / "backups", data_dir)

    state = json.loads(state_path(data_dir).read_text(encoding="utf-8"))
    assert state["state"] == UpgradeState.FAILED.value
    assert state["migration_id"] == migration_id


def test_failed_retry_requires_failed_source_marker(tmp_path: Path):
    _write_state(state_path(tmp_path), UpgradeState.POSTGRES_ACTIVE, source_fingerprint="a" * 64)

    with pytest.raises(RuntimeError, match="source marker is not FAILED"):
        prepare_failed_retry(tmp_path, "a" * 64)


def test_failed_retry_requires_matching_source_fingerprint(tmp_path: Path):
    _write_state(state_path(tmp_path), UpgradeState.FAILED, source_fingerprint="a" * 64)

    with pytest.raises(RuntimeError, match="source fingerprint does not match"):
        prepare_failed_retry(tmp_path, "b" * 64)


@pytest.mark.parametrize(
    ("state", "migration_id", "source_fingerprint"),
    [
        ("COMPLETED", "migration-1", "a" * 64),
        ("FAILED", "different-migration", "a" * 64),
        ("FAILED", "migration-1", "b" * 64),
    ],
)
def test_failed_target_cleanup_requires_matching_marker(
    monkeypatch, state: str, migration_id: str, source_fingerprint: str
):
    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _statement, _parameters=None):
            return SimpleNamespace(mappings=lambda: self, one_or_none=lambda: {
                "state": state,
                "migration_id": "migration-1",
                "source_fingerprint": "a" * 64,
            })

    class FakeTarget:
        def connect(self):
            return FakeConnection()

        def begin(self):
            return FakeConnection()

        def dispose(self):
            return None

    monkeypatch.setattr(phase6_cutover, "create_engine", lambda *_args, **_kwargs: FakeTarget())
    monkeypatch.setattr(phase6_cutover, "inspect", lambda _target: SimpleNamespace(get_table_names=lambda: ["kaya_migration_state"]))

    with pytest.raises(RuntimeError, match="matching failed migration target"):
        clean_failed_target("postgresql+psycopg://kaya@db/kaya", migration_id, source_fingerprint)
