import json
import os
from collections import namedtuple
from pathlib import Path
import subprocess
import sys

from sqlalchemy import create_engine

from app.services.postgres_diagnostics import collect_postgres_diagnostics


def test_postgres_diagnostics_is_explicitly_unavailable_for_sqlite():
    engine = create_engine("sqlite://")
    assert collect_postgres_diagnostics(engine, Path(".")) == {
        "available": False,
        "reason": "PostgreSQL is not the active database",
    }


# --- Fakes for the PostgreSQL-only diagnostics branch -----------------------
#
# No PostgreSQL server is available in this test environment, and
# collect_postgres_diagnostics gates its entire query set behind
# `engine.dialect.name == "postgresql"`. These fakes stand in for a real
# psycopg connection so the blocking-diagnostics addition (pg_stat_activity +
# pg_blocking_pids) can be exercised without one.

_DatabaseRow = namedtuple("_DatabaseRow", "database bytes version version_num")
_ActivitySummaryRow = namedtuple(
    "_ActivitySummaryRow",
    "active_queries idle_in_transaction waiting_sessions longest_idle_in_transaction_seconds longest_active_query_seconds",
)
_BlockedRow = namedtuple("_BlockedRow", "blocked_pid blocking_pid wait_event_type wait_event state blocked_seconds")


class _FakePool:
    def size(self):
        return 5

    def checkedout(self):
        return 1

    def checkedin(self):
        return 4

    def overflow(self):
        return 0

    def status(self):
        return "Pool size: 5  Connections in pool: 4"


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def one(self):
        return self._rows[0]

    def scalar_one(self):
        return self._rows[0][0]

    def scalar_one_or_none(self):
        return self._rows[0][0] if self._rows else None

    def all(self):
        return self._rows


class _FakeConnection:
    """Routes each `text(...)` clause to a canned result by SQL content.

    `blocking_summary` and `blocked_rows` are swappable per test so both the
    success path and the "blocking diagnostics unavailable" degrade path can
    be exercised against the same fixed responses for every other query.
    """

    def __init__(self, *, blocking_summary=None, blocked_rows=None, blocking_raises=False):
        self.blocking_summary = blocking_summary
        self.blocked_rows = blocked_rows or []
        self.blocking_raises = blocking_raises

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def execute(self, clause):
        sql = str(clause)
        if "pg_blocking_pids" in sql:
            if self.blocking_raises:
                raise RuntimeError("synthetic: role cannot see other sessions")
            return _FakeResult(self.blocked_rows)
        if "FILTER (WHERE state = 'active')" in sql:
            if self.blocking_raises:
                raise RuntimeError("synthetic: role cannot see other sessions")
            return _FakeResult([self.blocking_summary])
        if "pg_database_size" in sql:
            return _FakeResult([_DatabaseRow("kaya", 123456, "PostgreSQL 16.2 on x86_64-pc-linux-gnu", "160002")])
        if "pg_stat_database" in sql:
            return _FakeResult([(2,)])
        if "pg_statio_user_tables" in sql:
            return _FakeResult([("ha_nodes", 4096)])
        if "pg_stat_user_indexes" in sql:
            return _FakeResult([("ix_ha_nodes_cluster_id", "ha_nodes", 2048)])
        if "alembic_version" in sql:
            return _FakeResult([("abc123",)])
        if "pg_stat_activity" in sql:
            return _FakeResult([(3,)])
        raise AssertionError(f"unexpected query in fake connection: {sql}")


class _FakeDialect:
    name = "postgresql"


class _FakeEngine:
    def __init__(self, connection: _FakeConnection):
        self._connection = connection
        self.dialect = _FakeDialect()
        self.pool = _FakePool()

    def connect(self):
        return self._connection


def test_postgres_diagnostics_includes_blocking_session_summary():
    summary = _ActivitySummaryRow(
        active_queries=3,
        idle_in_transaction=1,
        waiting_sessions=1,
        longest_idle_in_transaction_seconds=6.5,
        longest_active_query_seconds=0.2,
    )
    blocked = [_BlockedRow(blocked_pid=101, blocking_pid=202, wait_event_type="Lock", wait_event="transactionid", state="active", blocked_seconds=6.5)]
    connection = _FakeConnection(blocking_summary=summary, blocked_rows=blocked)
    engine = _FakeEngine(connection)

    result = collect_postgres_diagnostics(engine, Path("/nonexistent"))

    assert result["available"] is True
    assert result["blocking"] == {
        "available": True,
        "active_queries": 3,
        "idle_in_transaction": 1,
        "waiting_sessions": 1,
        "longest_idle_in_transaction_seconds": 6.5,
        "longest_active_query_seconds": 0.2,
        "blocked_sessions": [
            {
                "blocked_pid": 101,
                "blocking_pid": 202,
                "wait_event_type": "Lock",
                "wait_event": "transactionid",
                "state": "active",
                "blocked_seconds": 6.5,
            }
        ],
    }
    # The rest of the (pre-existing) diagnostics payload must be unaffected.
    assert result["database"] == "kaya"
    assert result["pool"]["checked_out"] == 1


def test_postgres_diagnostics_blocking_section_degrades_without_breaking_the_rest():
    connection = _FakeConnection(blocking_raises=True)
    engine = _FakeEngine(connection)

    result = collect_postgres_diagnostics(engine, Path("/nonexistent"))

    assert result["available"] is True
    assert result["blocking"] == {"available": False, "reason": "blocking-session diagnostics unavailable"}
    # A failure in the new blocking section must not take down data
    # administrators already rely on (size, version, pool, backups).
    assert result["database"] == "kaya"
    assert result["database_bytes"] == 123456
    assert result["pool"]["size"] == 5
    assert result["largest_tables"] == [{"name": "ha_nodes", "bytes": 4096}]


def test_postgres_diagnostics_blocking_summary_never_includes_sql_text_or_connection_identity():
    summary = _ActivitySummaryRow(
        active_queries=0,
        idle_in_transaction=0,
        waiting_sessions=0,
        longest_idle_in_transaction_seconds=None,
        longest_active_query_seconds=None,
    )
    blocked = [_BlockedRow(blocked_pid=1, blocking_pid=2, wait_event_type="Lock", wait_event="tuple", state="active", blocked_seconds=None)]
    connection = _FakeConnection(blocking_summary=summary, blocked_rows=blocked)
    engine = _FakeEngine(connection)

    result = collect_postgres_diagnostics(engine, Path("/nonexistent"))

    allowed_keys = {"blocked_pid", "blocking_pid", "wait_event_type", "wait_event", "state", "blocked_seconds"}
    for row in result["blocking"]["blocked_sessions"]:
        assert set(row.keys()) == allowed_keys
        for value in row.values():
            assert not isinstance(value, str) or "SELECT" not in value.upper()


def test_phase8_worker_has_verification_retention_and_restore_drill_contract():
    worker = Path("scripts/kaya_postgres_backup_worker.sh").read_text(encoding="utf-8")
    assert "pg_dump --format=custom" in worker
    assert "pg_restore --list" in worker
    assert "sha256sum" in worker
    assert "archive_bytes" in worker
    assert "postgresql_version" in worker
    assert "alembic_revision" in worker
    assert "metadata is unavailable" in worker
    assert "RETENTION" in worker
    assert "restore-drill" in worker
    assert "PGPASSWORD" in worker
    assert "DROP DATABASE" in worker


def test_live_write_harness_uses_authenticated_supported_route():
    harness = Path("scripts/phase8_live_write.py").read_text(encoding="utf-8")
    assert "/api/dashboard/preferences" in harness
    assert "X-CSRF-Token" in harness


def test_acceptance_evidence_has_all_explicit_matrix_rows():
    source = Path("scripts/phase8_acceptance_evidence.py").read_text(encoding="utf-8")
    assert '"Cleanup/isolation"' in source
    assert source.count('"') > 100


def test_acceptance_evidence_json_is_complete_and_explicit(tmp_path):
    output = tmp_path / "phase8_acceptance.json"
    environment = os.environ | {
        "PHASE8_PASS_ROWS": "1,51",
        "PHASE8_BLOCKED_ROWS": "15",
        "PHASE8_FAIL_ROWS": "",
    }
    subprocess.run(
        [sys.executable, "scripts/phase8_acceptance_evidence.py", "--output", str(output)],
        check=True,
        env=environment,
    )
    rows = json.loads(output.read_text(encoding="utf-8"))
    assert len(rows) == 51
    assert {row["result"] for row in rows} <= {"PASS", "FAIL", "BLOCKED"}
    assert rows[0]["scenario_number"] == 1
    assert rows[14]["result"] == "BLOCKED"
    assert rows[50]["result"] == "PASS"
