"""Focused safety tests for the standalone SQLite-to-PostgreSQL converter."""

from __future__ import annotations

import sqlite3
from collections import namedtuple
from pathlib import Path

import pytest
from app.db.sqlite_to_postgres import (
    SQLiteToPostgresError,
    _convert_value,
    _classify_sqlite_storage_error,
    _local_preflight_filesystems,
    _validate_source,
    _source_fingerprint,
)
from app.db.backup import create_sqlite_backup
from app.models.models import Base
from scripts.generate_sqlite_migration_fixture import generate


def test_boolean_conversion_accepts_only_sqlite_boolean_values():
    column = Base.metadata.tables["users"].c.is_active
    assert _convert_value(0, column) is False
    assert _convert_value(1, column) is True
    assert _convert_value(None, column) is None
    with pytest.raises(SQLiteToPostgresError):
        _convert_value(2, column)


def test_source_validation_requires_current_head_and_does_not_write(tmp_path: Path):
    source = tmp_path / "source.sqlite3"
    generate(source, traffic_rows=2, metric_rows=2, audit_rows=2)
    before = source.read_bytes()
    revision, fingerprint, tables = _validate_source(source, "20260818_02")
    assert revision == "20260818_02"
    assert len(fingerprint) == 64
    assert tables == set(Base.metadata.tables)
    assert source.read_bytes() == before
    with sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_verified_backup_does_not_change_source_fingerprint(tmp_path: Path):
    source = tmp_path / "source.sqlite3"
    generate(source, traffic_rows=2, metric_rows=2, audit_rows=2)
    before = _source_fingerprint(source)

    create_sqlite_backup(
        source,
        tmp_path / "backups",
        source_revision="20260818_02",
        target_revision="20260818_02",
    )

    assert _source_fingerprint(source) == before


def test_source_validation_rejects_old_revision_without_mutation(tmp_path: Path):
    source = tmp_path / "source.sqlite3"
    generate(source, traffic_rows=1, metric_rows=1, audit_rows=1)
    before = source.read_bytes()
    with sqlite3.connect(source) as connection:
        connection.execute("UPDATE alembic_version SET version_num = '20260818_01'")
        connection.commit()
    changed = source.read_bytes()
    with pytest.raises(SQLiteToPostgresError, match="upgrade it explicitly"):
        _validate_source(source, "20260818_02")
    assert source.read_bytes() == changed
    assert before != changed


def test_filesystem_preflight_accounts_for_shared_source_backup_and_temp_filesystem(tmp_path: Path):
    source = tmp_path / "source.sqlite3"
    source.write_bytes(b"synthetic source")
    backup = tmp_path / "backups"
    temp = tmp_path / "sqlite-tmp"
    temp.mkdir()
    filesystems, estimated = _local_preflight_filesystems(source, backup, temp)
    assert estimated == source.stat().st_size * 3
    assert {record["device"] for record in filesystems.values()} == {source.stat().st_dev}
    assert all(record["capacity_status"] == "sufficient" for record in filesystems.values())
    assert all(record["shared_required_bytes"] == source.stat().st_size * 3 for record in filesystems.values())


def test_storage_error_classifies_exhausted_managed_temp(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.sqlite3"
    temp = tmp_path / "sqlite-tmp"
    temp.mkdir()

    disk_usage = namedtuple("disk_usage", "total used free")

    def usage(path):
        return disk_usage(100, 50 if Path(path) == source.parent else 100, 50 if Path(path) == source.parent else 0)

    monkeypatch.setattr("app.db.sqlite_to_postgres.shutil.disk_usage", usage)
    assert _classify_sqlite_storage_error(
        sqlite3.OperationalError("database or disk is full"), source, temp
    ) == "SQLite managed temporary workspace exhausted."
