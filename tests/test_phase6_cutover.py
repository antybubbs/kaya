from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.db.phase6_cutover as phase6_cutover
from app.db.phase6_cutover import (
    UpgradeState,
    _write_state,
    authoritative_database_url,
    detect_installation,
    legacy_sqlite_eligibility,
    run_upgrade,
    state_path,
)
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
