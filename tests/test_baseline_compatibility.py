"""Regression tests for the pre-Alembic baseline compatibility bridge.

app/db/compatibility.py bridges a pre-Alembic SQLite database up to the
20260730_01 baseline schema before Alembic takes over. Because every NOT NULL
column in Kaya's models declares only an ORM-side ``default=`` (never a SQLite
``server_default``), the baseline's raw CREATE TABLE/ALTER DDL frequently has
no literal DEFAULT for a NOT NULL column. Naively replaying that DDL against
an existing populated table crashes SQLite with "Cannot add a NOT NULL column
with default value NULL" (see users.totp_enabled below for a real, currently
unpatched example in scripts/migrate_sqlite.py). These tests exercise the
decision tree in app/db/compatibility.py that replaces that naive replay.
"""

import sqlite3

import pytest
from alembic import command
from sqlalchemy import Column, Integer, MetaData, Table

from app.db import compatibility as compatibility_module
from app.db.compatibility import (
    BaselineCompatibilityError,
    create_missing_baseline_objects,
)
from app.db.migrations import BASELINE_REVISION, _alembic_config
from app.models.models import Base


def _build_baseline(tmp_path):
    baseline_path = tmp_path / "baseline.sqlite3"
    config = _alembic_config(f"sqlite:///{baseline_path.as_posix()}")
    command.upgrade(config, BASELINE_REVISION)
    return baseline_path


def _legacy_users_table(path, *, extra_columns="", extra_inserts=()):
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE users (id INTEGER NOT NULL PRIMARY KEY, "
            "email VARCHAR(255) NOT NULL, password_hash VARCHAR(255), "
            "role VARCHAR(30) NOT NULL DEFAULT 'viewer', "
            "is_active BOOLEAN NOT NULL DEFAULT 1, "
            "authentication_type VARCHAR(30) NOT NULL DEFAULT 'local', "
            "is_break_glass BOOLEAN NOT NULL DEFAULT 0, "
            "role_source VARCHAR(30) NOT NULL DEFAULT 'local', "
            "created_at DATETIME, updated_at DATETIME"
            f"{extra_columns})"
        )
        connection.execute(
            "INSERT INTO users (id, email, password_hash, created_at, updated_at) "
            "VALUES (1, 'admin@example.invalid', 'hash', '2020-01-01 00:00:00', "
            "'2020-01-02 00:00:00')"
        )
        for statement, params in extra_inserts:
            connection.execute(statement, params)
        connection.commit()


# ---------------------------------------------------------------------------
# 1. Nullable column missing from a populated legacy table.
# ---------------------------------------------------------------------------


def test_missing_nullable_column_is_added_without_a_default(tmp_path):
    baseline_path = _build_baseline(tmp_path)
    db_path = tmp_path / "legacy.sqlite3"
    _legacy_users_table(db_path)

    create_missing_baseline_objects(db_path, baseline_path, Base.metadata)

    with sqlite3.connect(db_path) as connection:
        columns = {
            row[1]: row for row in connection.execute("PRAGMA table_info(users)")
        }
        email = connection.execute("SELECT email FROM users WHERE id=1").fetchone()[0]
    assert columns["first_name"][3] == 0  # not_null flag
    assert email == "admin@example.invalid"


# ---------------------------------------------------------------------------
# 2. NOT NULL column with a valid (ORM scalar) default: users.totp_enabled.
#    This is the exact column/table from the reported crash trace.
# ---------------------------------------------------------------------------


def test_missing_not_null_column_with_scalar_default_is_backfilled_in_one_step(
    tmp_path,
):
    baseline_path = _build_baseline(tmp_path)
    db_path = tmp_path / "legacy.sqlite3"
    _legacy_users_table(
        db_path,
        extra_inserts=[
            (
                "INSERT INTO users (id, email, password_hash, created_at, updated_at) "
                "VALUES (2, 'second@example.invalid', 'hash2', '2020-03-03 00:00:00', "
                "'2020-03-04 00:00:00')",
                (),
            )
        ],
    )

    create_missing_baseline_objects(db_path, baseline_path, Base.metadata)

    with sqlite3.connect(db_path) as connection:
        column = next(
            row
            for row in connection.execute("PRAGMA table_info(users)")
            if row[1] == "totp_enabled"
        )
        values = connection.execute(
            "SELECT id, totp_enabled FROM users ORDER BY id"
        ).fetchall()
    assert column[3] == 1  # not_null
    assert column[4] == "0"  # literal default matches the ORM's default=False
    assert values == [(1, 0), (2, 0)]


# ---------------------------------------------------------------------------
# 3. NOT NULL column that requires explicit legacy-data backfill: users.updated_at.
# ---------------------------------------------------------------------------


def test_missing_not_null_column_requiring_backfill_is_rebuilt_with_constraint(
    tmp_path,
):
    baseline_path = _build_baseline(tmp_path)
    db_path = tmp_path / "legacy.sqlite3"
    # Omit updated_at entirely so it must be added, backfilled, and promoted
    # to NOT NULL via table rebuild - not just left nullable like the legacy
    # scripts/migrate_sqlite.py script does.
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE users (id INTEGER NOT NULL PRIMARY KEY, "
            "email VARCHAR(255) NOT NULL UNIQUE, password_hash VARCHAR(255), "
            "role VARCHAR(30) NOT NULL DEFAULT 'viewer', "
            "is_active BOOLEAN NOT NULL DEFAULT 1, "
            "authentication_type VARCHAR(30) NOT NULL DEFAULT 'local', "
            "is_break_glass BOOLEAN NOT NULL DEFAULT 0, "
            "role_source VARCHAR(30) NOT NULL DEFAULT 'local', "
            "totp_enabled BOOLEAN NOT NULL DEFAULT 0, "
            "created_at DATETIME)"
        )
        connection.execute("CREATE UNIQUE INDEX ix_users_email ON users (email)")
        connection.execute(
            "INSERT INTO users (id, email, password_hash, created_at) "
            "VALUES (1, 'admin@example.invalid', 'hash', '2020-01-01 00:00:00')"
        )
        connection.commit()

    create_missing_baseline_objects(db_path, baseline_path, Base.metadata)

    with sqlite3.connect(db_path) as connection:
        column = next(
            row
            for row in connection.execute("PRAGMA table_info(users)")
            if row[1] == "updated_at"
        )
        row = connection.execute(
            "SELECT email, updated_at FROM users WHERE id=1"
        ).fetchone()
        # The rebuilt table must keep its unique index/constraint.
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO users (id, email, created_at, updated_at) "
                "VALUES (2, 'admin@example.invalid', '2020-01-01', '2020-01-01')"
            )
    assert column[3] == 1  # not_null enforced after rebuild
    assert row[0] == "admin@example.invalid"
    assert row[1] == "2020-01-01 00:00:00"  # backfilled from created_at, not "now"


# ---------------------------------------------------------------------------
# 4. Empty legacy table receiving a non-null column.
# ---------------------------------------------------------------------------


def test_empty_legacy_table_is_recreated_from_baseline(tmp_path):
    baseline_path = _build_baseline(tmp_path)
    db_path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(db_path) as connection:
        # A pre-Alembic 'vlans' table missing the NOT NULL 'name' column
        # entirely, with zero rows - nothing to lose or infer.
        connection.execute(
            "CREATE TABLE vlans (id INTEGER NOT NULL PRIMARY KEY, description TEXT)"
        )
        connection.commit()

    create_missing_baseline_objects(db_path, baseline_path, Base.metadata)

    with sqlite3.connect(db_path) as connection:
        columns = {
            row[1]: row for row in connection.execute("PRAGMA table_info(vlans)")
        }
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(vlans)")}
        count = connection.execute("SELECT count(*) FROM vlans").fetchone()[0]
    assert columns["name"][3] == 1  # not_null
    assert "subnet_cidr" in columns
    assert any("name" in index for index in indexes)
    assert count == 0


# ---------------------------------------------------------------------------
# 5. A column that cannot be safely inferred halts migration with a clear error.
# ---------------------------------------------------------------------------


def test_uninferrable_not_null_column_raises_actionable_error(tmp_path, monkeypatch):
    baseline_path = _build_baseline(tmp_path)
    db_path = tmp_path / "legacy.sqlite3"
    _legacy_users_table(db_path)

    # Simulate a NOT NULL baseline column whose model has no default at all
    # (removed from both the registry and the ORM) - the case this bridge
    # must refuse rather than guess a value for.
    monkeypatch.setattr(
        compatibility_module, "_TIMESTAMP_BACKFILL_COLUMNS", frozenset()
    )
    monkeypatch.setattr(compatibility_module, "_LEGACY_BACKFILL_RULES", {})

    empty_metadata = MetaData()
    Table(
        "users",
        empty_metadata,
        Column("id", Integer, primary_key=True),
    )

    with pytest.raises(BaselineCompatibilityError, match="totp_enabled|updated_at"):
        create_missing_baseline_objects(db_path, baseline_path, empty_metadata)


# ---------------------------------------------------------------------------
# 6/7. Atomicity: a failed attempt must not partially modify the database,
#      and a retry after fixing the cause must succeed cleanly (idempotent).
# ---------------------------------------------------------------------------


def test_failed_compatibility_attempt_leaves_database_completely_unmodified(
    tmp_path, monkeypatch
):
    baseline_path = _build_baseline(tmp_path)
    db_path = tmp_path / "legacy.sqlite3"
    _legacy_users_table(db_path)

    with sqlite3.connect(db_path) as connection:
        before_tables = sorted(
            row[0] for row in connection.execute("SELECT name FROM sqlite_master")
        )
        before_users_columns = [
            row[1] for row in connection.execute("PRAGMA table_info(users)")
        ]

    # Force failure on a column ("users.totp_enabled") that is genuinely
    # resolvable via its ORM scalar default, simulating a transient cause
    # (e.g. a bug in an earlier version of this module) rather than a truly
    # uninferrable column. By the time this fires, every brand-new baseline
    # table has already had its CREATE TABLE executed against the connection,
    # so this also proves those are rolled back, not just users' columns.
    real_plan = compatibility_module._plan_column

    def failing_plan(model_metadata, table_name, column_name, not_null, default):
        if table_name == "users" and column_name == "totp_enabled":
            raise BaselineCompatibilityError("synthetic forced failure")
        return real_plan(model_metadata, table_name, column_name, not_null, default)

    monkeypatch.setattr(compatibility_module, "_plan_column", failing_plan)

    with pytest.raises(BaselineCompatibilityError):
        create_missing_baseline_objects(db_path, baseline_path, Base.metadata)

    with sqlite3.connect(db_path) as connection:
        after_tables = sorted(
            row[0] for row in connection.execute("SELECT name FROM sqlite_master")
        )
        after_users_columns = [
            row[1] for row in connection.execute("PRAGMA table_info(users)")
        ]
    # Every brand-new baseline table created before we reached "users", and
    # every column added to "users" before "totp_enabled", must have been
    # rolled back with it - not left committed from SQLite's per-statement
    # DDL auto-commit under Python's legacy transaction mode.
    assert after_tables == before_tables
    assert after_users_columns == before_users_columns

    # Retrying after the transient cause is gone must succeed and must not
    # error on "duplicate column" from a half-applied previous attempt.
    monkeypatch.undo()
    create_missing_baseline_objects(db_path, baseline_path, Base.metadata)
    with sqlite3.connect(db_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
    assert "totp_enabled" in columns


# ---------------------------------------------------------------------------
# 8. Alembic revision is stamped only after compatibility succeeds.
# ---------------------------------------------------------------------------


def test_alembic_revision_not_stamped_when_compatibility_fails(tmp_path, monkeypatch):
    from sqlalchemy import create_engine

    from app.core.config import Settings
    from app.db.migrations import DatabaseMigrationError, prepare_database
    import app.db.migrations as migrations_module

    path = tmp_path / "kaya.db"
    _legacy_users_table(path)
    settings = Settings(
        app_env="test",
        encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
        database_url=f"sqlite:///{path.as_posix()}",
        migration_backup_dir=str(tmp_path / "backups"),
    )

    def fail_create_missing(_database_path, _baseline_path, _model_metadata):
        raise BaselineCompatibilityError("synthetic compatibility failure")

    monkeypatch.setattr(
        migrations_module, "create_missing_baseline_objects", fail_create_missing
    )

    with pytest.raises(DatabaseMigrationError):
        prepare_database(create_engine(f"sqlite:///{path.as_posix()}"), settings)

    with sqlite3.connect(path) as connection:
        has_revision_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alembic_version'"
        ).fetchone()
    assert has_revision_table is None


# ---------------------------------------------------------------------------
# 9. Indexes and constraints remain correct after a table rebuild, and
#    unrelated data is untouched except for the explicitly backfilled field.
# ---------------------------------------------------------------------------


def test_rebuild_preserves_foreign_keys_and_only_changes_backfilled_column(
    tmp_path,
):
    baseline_path = _build_baseline(tmp_path)
    db_path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE users (id INTEGER NOT NULL PRIMARY KEY, "
            "email VARCHAR(255) NOT NULL UNIQUE, password_hash VARCHAR(255), "
            "role VARCHAR(30) NOT NULL DEFAULT 'viewer', "
            "is_active BOOLEAN NOT NULL DEFAULT 1, "
            "authentication_type VARCHAR(30) NOT NULL DEFAULT 'local', "
            "is_break_glass BOOLEAN NOT NULL DEFAULT 0, "
            "role_source VARCHAR(30) NOT NULL DEFAULT 'local', "
            "totp_enabled BOOLEAN NOT NULL DEFAULT 0, "
            "created_at DATETIME)"
        )
        connection.execute("CREATE UNIQUE INDEX ix_users_email ON users (email)")
        connection.execute(
            "INSERT INTO users (id, email, password_hash, role, created_at) "
            "VALUES (1, 'keep@example.invalid', 'hash-unchanged', 'admin', "
            "'2021-05-05 00:00:00')"
        )
        connection.execute(
            "CREATE TABLE app_sessions (id INTEGER NOT NULL PRIMARY KEY, "
            "session_id VARCHAR(120) NOT NULL, user_id INTEGER NOT NULL, "
            "created_at DATETIME NOT NULL, last_seen_at DATETIME NOT NULL, "
            "FOREIGN KEY(user_id) REFERENCES users(id))"
        )
        connection.execute(
            "INSERT INTO app_sessions (id, session_id, user_id, created_at, last_seen_at) "
            "VALUES (1, 'sess-1', 1, '2021-05-05 00:00:00', '2021-05-05 00:00:00')"
        )
        connection.commit()

    create_missing_baseline_objects(db_path, baseline_path, Base.metadata)

    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_key_check").fetchall()
        row = connection.execute(
            "SELECT email, password_hash, role, created_at FROM users WHERE id=1"
        ).fetchone()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO users (id, email, created_at, updated_at) "
                "VALUES (99, 'keep@example.invalid', '2021-01-01', '2021-01-01')"
            )
        fk_violations = connection.execute(
            "PRAGMA foreign_key_check(app_sessions)"
        ).fetchall()
    assert row == (
        "keep@example.invalid",
        "hash-unchanged",
        "admin",
        "2021-05-05 00:00:00",
    )
    assert fk_violations == []
