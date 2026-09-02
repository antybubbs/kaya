"""Focused safety tests for the standalone SQLite-to-PostgreSQL converter."""

from __future__ import annotations

import sqlite3
from collections import namedtuple
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from app.db.sqlite_to_postgres import (
    SQLiteToPostgresError,
    _canonical,
    _convert_value,
    _copy_table,
    _classify_sqlite_storage_error,
    _dependency_edges,
    _dependency_plan,
    _first_hash_divergence,
    _local_preflight_filesystems,
    _stream_source_hash,
    _stream_target_hash,
    _validate_source,
    _source_fingerprint,
)
from app.db.migrations import CURRENT_REVISION
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


def test_datetime_conversion_respects_naive_model_semantics():
    column = Base.metadata.tables["network_monitor_checks"].c.checked_at
    assert _convert_value("2026-08-26T12:00:00Z", column).tzinfo is None
    assert _convert_value("2026-08-26T12:00:00+00:00", column).tzinfo is None
    assert _convert_value("2026-08-26T12:00:00.123456", column).microsecond == 123456


def test_network_monitor_checks_copy_and_validation_canonicalize_historical_float_storage(tmp_path: Path):
    source = sqlite3.connect(":memory:")
    source.execute(
        "CREATE TABLE network_monitor_checks ("
        "id INTEGER PRIMARY KEY, monitor_id INTEGER NOT NULL, status VARCHAR(30) NOT NULL, "
        "health_state VARCHAR(30), latency_ms INTEGER, packet_loss_percent INTEGER, "
        "response_time_ms INTEGER, error VARCHAR(500), checked_at DATETIME NOT NULL)"
    )
    source.execute(
        "INSERT INTO network_monitor_checks "
        "VALUES (1, 1, 'up', NULL, 12, NULL, 8, NULL, '2026-08-26 12:00:00')"
    )
    source.commit()
    target = create_engine(f"sqlite:///{(tmp_path / 'target.sqlite3').as_posix()}")
    Base.metadata.create_all(target)

    _copy_table(source, target, "network_monitor_checks", batch_size=10)
    source_result = _stream_source_hash(
        source, "network_monitor_checks", [column.name for column in Base.metadata.tables["network_monitor_checks"].columns]
    )
    target_result = _stream_target_hash(
        target, "network_monitor_checks", [column.name for column in Base.metadata.tables["network_monitor_checks"].columns]
    )
    assert source_result[1] == target_result[1]
    assert _canonical(_convert_value(12, Base.metadata.tables["network_monitor_checks"].c.latency_ms)) == _canonical(12.0)

    with target.begin() as connection:
        connection.execute(text("UPDATE network_monitor_checks SET latency_ms = 13.0 WHERE id = 1"))
    diagnostic = _first_hash_divergence(
        source, target, "network_monitor_checks", [column.name for column in Base.metadata.tables["network_monitor_checks"].columns]
    )
    assert diagnostic is not None
    assert diagnostic["column"] == "latency_ms"
    assert diagnostic["source_type"] == "float"
    assert diagnostic["target_type"] == "float"
    assert diagnostic["source_digest"] != diagnostic["target_digest"]
    assert "source_value" not in diagnostic
    assert "target_value" not in diagnostic
    source.close()
    target.dispose()


def test_source_validation_requires_current_head_and_does_not_write(tmp_path: Path):
    source = tmp_path / "source.sqlite3"
    generate(source, traffic_rows=2, metric_rows=2, audit_rows=2)
    before = source.read_bytes()
    revision, fingerprint, tables = _validate_source(source, CURRENT_REVISION)
    assert revision == CURRENT_REVISION
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
        source_revision=CURRENT_REVISION,
        target_revision=CURRENT_REVISION,
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
        _validate_source(source, CURRENT_REVISION)
    assert source.read_bytes() == changed
    assert before != changed


def test_source_validation_rejects_sqlite_orphans_without_mutation(tmp_path: Path):
    source = tmp_path / "orphan.sqlite3"
    generate(source, traffic_rows=1, metric_rows=1, audit_rows=1)
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO dns_client_events (id, dns_client_id, event_type, event_summary, source, created_at) "
            "VALUES (999, 999999, 'synthetic-orphan', 'synthetic orphan', 'fixture', CURRENT_TIMESTAMP)"
        )
        connection.commit()
    before = _source_fingerprint(source)
    with pytest.raises(SQLiteToPostgresError, match="foreign_key_check"):
        _validate_source(source, CURRENT_REVISION)
    assert _source_fingerprint(source) == before


def test_dependency_plan_orders_full_reflected_graph_and_handles_cycles():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    tables, edges = _dependency_edges(engine)
    plan = _dependency_plan(engine)
    positions = {table: index for index, table in enumerate(plan.order)}
    deferred = set(plan.deferred)

    assert len(plan.order) == len(tables)
    assert plan.order == _dependency_plan(engine).order
    assert plan.deferred == _dependency_plan(engine).deferred
    assert plan.cycles
    assert any({"dns_providers", "ha_clusters", "ha_nodes"} <= set(cycle) for cycle in plan.cycles)
    assert any(cycle == ("runbook_pages",) for cycle in plan.cycles)
    assert any(edge.label == "dns_providers.ha_cluster_id->ha_clusters.id" for edge in deferred)
    assert any(edge.label == "runbook_pages.parent_id->runbook_pages.id" for edge in deferred)
    for edge in edges:
        if edge in deferred or edge.child_table == edge.parent_table:
            continue
        assert positions[edge.parent_table] < positions[edge.child_table], edge.label


def test_functional_fixture_contains_dns_and_ha_parent_child_relationships(tmp_path: Path):
    source = tmp_path / "functional.sqlite3"
    from scripts.generate_sqlite_migration_fixture import generate_functional

    generate_functional(source)
    with create_engine(f"sqlite:///{source.as_posix()}").connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM dns_providers")).scalar_one() >= 1
        assert connection.execute(text("SELECT count(*) FROM dns_recognised_devices WHERE provider_id = 1")).scalar_one() >= 1
        assert connection.execute(text("SELECT count(*) FROM dns_client_events WHERE dns_client_id = 1 AND provider_id = 1")).scalar_one() >= 1
        assert connection.execute(text("SELECT count(*) FROM dns_client_observations WHERE dns_client_id = 1 AND provider_id = 1")).scalar_one() >= 1
        assert connection.execute(text("SELECT count(*) FROM dns_client_traffic_events WHERE dns_client_id = 1 AND provider_id = 1")).scalar_one() >= 1
        assert connection.execute(text("SELECT count(*) FROM ha_clusters")).scalar_one() >= 1
        assert connection.execute(text("SELECT count(*) FROM ha_nodes WHERE cluster_id = 1")).scalar_one() >= 2
        assert connection.execute(text("SELECT count(*) FROM ha_lease_replication_states WHERE source_node_id = 1 AND target_node_id = 2")).scalar_one() >= 1


def test_filesystem_preflight_accounts_for_shared_source_backup_and_temp_filesystem(tmp_path: Path):
    source = tmp_path / "source.sqlite3"
    source.write_bytes(b"synthetic source")
    backup = tmp_path / "backups"
    temp = tmp_path / "sqlite-tmp"
    temp.mkdir()
    filesystems, estimated = _local_preflight_filesystems(source, backup, temp)
    assert estimated > source.stat().st_size * 3
    assert {record["device"] for record in filesystems.values()} == {source.stat().st_dev}
    assert all(record["capacity_status"] == "sufficient" for record in filesystems.values())
    assert all(
        record["shared_required_bytes"] == estimated
        for record in filesystems.values()
    )


def test_historical_preflight_includes_conversion_copy(tmp_path: Path):
    source = tmp_path / "source.sqlite3"
    source.write_bytes(b"synthetic source")
    backup = tmp_path / "backups"
    temp = tmp_path / "sqlite-tmp"
    temp.mkdir()

    _, current_estimated = _local_preflight_filesystems(source, backup, temp)
    historical, historical_estimated = _local_preflight_filesystems(
        source,
        backup,
        temp,
        historical_upgrade=True,
        historical_workspace=tmp_path,
    )

    assert historical_estimated == current_estimated + source.stat().st_size
    assert "historical_conversion_copy" in historical


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
