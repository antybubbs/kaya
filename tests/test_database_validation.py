import logging
import sqlite3

import pytest
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, MetaData, Table

from app.db import validation


def _validate_single_column_schema(path, table_name, column_name, model_type):
    metadata = MetaData()
    Table(
        table_name,
        metadata,
        Column("id", Integer, primary_key=True),
        Column(column_name, model_type, nullable=True),
    )
    validation.validate_schema(path, metadata, require_revision=False)


def _database(path):
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))"
        )


def test_valid_database_uses_timed_quick_and_foreign_key_checks(tmp_path, caplog):
    path = tmp_path / "valid.db"
    _database(path)
    caplog.set_level(logging.DEBUG)

    validation.validate_sqlite_integrity(path)

    assert "Opening read-only validation connection started" in caplog.text
    assert "Running PRAGMA quick_check completed" in caplog.text
    assert "Running PRAGMA foreign_key_check completed" in caplog.text
    assert "Closing validation connection completed" in caplog.text
    assert "PRAGMA integrity_check" not in caplog.text


def test_locked_database_fails_after_finite_busy_timeout(tmp_path, monkeypatch):
    path = tmp_path / "locked.db"
    _database(path)
    monkeypatch.setattr(validation, "SQLITE_BUSY_TIMEOUT_MS", 50)
    locker = sqlite3.connect(path)
    try:
        locker.execute("BEGIN EXCLUSIVE")
        with pytest.raises(validation.DatabaseLockedError, match="database locked"):
            validation.validate_sqlite_integrity(path)
    finally:
        locker.rollback()
        locker.close()


def test_slow_validation_is_interrupted_at_operation_deadline(tmp_path, monkeypatch):
    path = tmp_path / "slow.db"
    _database(path)
    monkeypatch.setattr(validation, "VALIDATION_OPERATION_TIMEOUT_SECONDS", 0.0)
    monkeypatch.setattr(validation, "_PROGRESS_HANDLER_INSTRUCTIONS", 1)

    with pytest.raises(
        validation.DatabaseValidationTimeoutError, match="validation timed out"
    ):
        validation.validate_sqlite_integrity(path)


def test_corrupt_database_is_reported_distinctly(tmp_path):
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"synthetic-not-a-sqlite-database")

    with pytest.raises(validation.DatabaseCorruptError, match="database corrupt"):
        validation.validate_sqlite_integrity(path)


def test_wal_mode_database_is_validated_without_removing_sidecars(tmp_path):
    path = tmp_path / "wal.db"
    writer = sqlite3.connect(path)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY)")
        writer.execute("INSERT INTO sample VALUES (1)")
        writer.commit()
        wal_path = path.with_name(path.name + "-wal")
        shm_path = path.with_name(path.name + "-shm")
        assert wal_path.exists() and shm_path.exists()

        validation.validate_sqlite_integrity(path)

        assert wal_path.exists() and shm_path.exists()
    finally:
        writer.close()


def test_validation_connection_is_closed_after_failure(tmp_path, monkeypatch):
    path = tmp_path / "invalid-foreign-key.db"
    _database(path)
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO child VALUES (1, 999)")

    connections = []
    original_connect = sqlite3.connect

    class TrackingConnection(sqlite3.Connection):
        was_closed = False

        def close(self):
            self.was_closed = True
            super().close()

    def tracked_connect(*args, **kwargs):
        kwargs["factory"] = TrackingConnection
        connection = original_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(validation.sqlite3, "connect", tracked_connect)

    with pytest.raises(validation.DatabaseCorruptError, match="invalid references"):
        validation.validate_sqlite_integrity(path)

    assert connections and all(connection.was_closed for connection in connections)


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        ("INTEGER", "INTEGER"),
        ("VARCHAR(120)", "TEXT"),
        ("", "BLOB"),
        ("DOUBLE PRECISION", "REAL"),
        ("DECIMAL(10, 2)", "NUMERIC"),
    ],
)
def test_sqlite_type_affinity_follows_documented_rules(declared, expected):
    assert validation.sqlite_type_affinity(declared) == expected


@pytest.mark.parametrize("declared", ["REAL", "DOUBLE"])
def test_float_model_accepts_real_affinity_aliases(tmp_path, declared):
    path = tmp_path / "real-affinity.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            f"CREATE TABLE sample (id INTEGER PRIMARY KEY, value {declared})"
        )
        connection.execute("INSERT INTO sample VALUES (1, 1.25)")

    _validate_single_column_schema(path, "sample", "value", Float)


def test_historical_integer_float_column_accepts_integer_decimal_and_null(
    tmp_path, caplog
):
    path = tmp_path / "historical-latency.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE network_monitors (id INTEGER PRIMARY KEY, last_latency_ms INTEGER)"
        )
        connection.executemany(
            "INSERT INTO network_monitors VALUES (?, ?)",
            [(1, 12), (2, 0.625), (3, None)],
        )
    caplog.set_level(logging.INFO)

    _validate_single_column_schema(path, "network_monitors", "last_latency_ms", Float)

    assert (
        "Accepted historical SQLite type compatibility: "
        "network_monitors.last_latency_ms INTEGER -> FLOAT"
    ) in caplog.text


def test_historical_integer_float_column_rejects_invalid_text(tmp_path, caplog):
    path = tmp_path / "invalid-latency.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE network_monitors (id INTEGER PRIMARY KEY, last_latency_ms INTEGER)"
        )
        connection.execute("INSERT INTO network_monitors VALUES (1, 'not-a-number')")
    caplog.set_level(logging.ERROR)

    with pytest.raises(
        validation.DatabaseValidationError, match="INTEGER; expected FLOAT"
    ):
        _validate_single_column_schema(
            path, "network_monitors", "last_latency_ms", Float
        )

    assert (
        "Unsupported SQLite type mismatch: "
        "network_monitors.last_latency_ms actual=INTEGER expected=FLOAT"
    ) in caplog.text


def test_boolean_model_accepts_integer_zero_and_one_storage(tmp_path):
    path = tmp_path / "boolean-integer.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE sample (id INTEGER PRIMARY KEY, enabled INTEGER)"
        )
        connection.executemany(
            "INSERT INTO sample VALUES (?, ?)", [(1, 0), (2, 1), (3, None)]
        )

    _validate_single_column_schema(path, "sample", "enabled", Boolean)


def test_datetime_model_accepts_kaya_datetime_declaration_and_text_storage(tmp_path):
    path = tmp_path / "datetime.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE sample (id INTEGER PRIMARY KEY, observed_at DATETIME)"
        )
        connection.execute(
            "INSERT INTO sample VALUES (1, '2026-07-30 12:34:56.000000')"
        )

    _validate_single_column_schema(path, "sample", "observed_at", DateTime)


def test_genuine_incompatible_text_to_integer_mismatch_fails(tmp_path):
    path = tmp_path / "unsafe-text.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE sample (id INTEGER PRIMARY KEY, count_value TEXT)"
        )
        connection.execute("INSERT INTO sample VALUES (1, '12')")

    with pytest.raises(
        validation.DatabaseValidationError, match="TEXT; expected INTEGER"
    ):
        _validate_single_column_schema(path, "sample", "count_value", Integer)
