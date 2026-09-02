from __future__ import annotations

import json
import sqlite3
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command

import app.db.backup as backup_module
import app.db.phase6_cutover as phase6_cutover
from app.db.backup import (
    canonical_snapshot_fingerprint,
    create_sqlite_backup,
    isolated_snapshot_required_bytes,
    isolated_sqlite_snapshot,
)
from app.db.phase6_cutover import (
    UpgradeState,
    _write_state,
    authoritative_database_url,
    clean_failed_target,
    detect_installation,
    legacy_sqlite_eligibility,
    prepare_failed_retry,
    prepare_failed_pretarget_retry,
    _upgrade_supported_legacy_sqlite,
    run_upgrade,
    state_path,
)
from app.db.migrations import CURRENT_REVISION, _alembic_config
from app.db.sqlite_to_postgres import SQLiteToPostgresError


def test_recovery_fingerprint_makes_no_nested_copy_or_backup_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "verified.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO records VALUES (1, 'fixture')")
        connection.commit()

    real_connect = backup_module.sqlite3.connect

    class GuardedConnection:
        def __init__(self, connection):
            self._connection = connection

        def __getattr__(self, name):
            return getattr(self._connection, name)

        def backup(self, *_args, **_kwargs):
            raise AssertionError("logical fingerprint must not call SQLite backup")

        def close(self):
            return self._connection.close()

    monkeypatch.setattr(
        backup_module.sqlite3,
        "connect",
        lambda *args, **kwargs: GuardedConnection(real_connect(*args, **kwargs)),
    )
    monkeypatch.setattr(
        backup_module.tempfile,
        "TemporaryDirectory",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("logical fingerprint must not create a temporary database")
        ),
    )

    fingerprint = backup_module.canonical_snapshot_fingerprint(source)
    assert len(fingerprint) == 64


def test_recovery_snapshot_space_models_only_concurrent_snapshot(tmp_path: Path):
    source_size = 2_400_000_000
    wal_size = 20_000_000
    available = 4_430_000_000

    required = isolated_snapshot_required_bytes(source_size, wal_size)

    assert required == source_size + wal_size + source_size // 20
    assert available >= required
    assert available < (source_size * 2) + wal_size + source_size // 20

    source = tmp_path / "source.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE records(value TEXT)")
        connection.execute("INSERT INTO records VALUES ('fixture')")
        connection.commit()
    events: list[str] = []
    snapshot_path: Path | None = None
    with isolated_sqlite_snapshot(source, tmp_path) as isolated:
        snapshot_path = isolated
        events.append("snapshot_active")
    events.append("snapshot_destroyed")
    assert snapshot_path is not None and not snapshot_path.exists()
    events.append("working_copy")
    assert events == ["snapshot_active", "snapshot_destroyed", "working_copy"]


def test_canonical_snapshot_ignores_wal_checkpoint_representation(tmp_path: Path):
    source = tmp_path / "kaya.db"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO records(value) VALUES ('stable')")
        connection.commit()
    physical_before = phase6_cutover._source_fingerprint(source)
    snapshot_before = canonical_snapshot_fingerprint(source, tmp_path)
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    physical_after = phase6_cutover._source_fingerprint(source)
    snapshot_after = canonical_snapshot_fingerprint(source, tmp_path)

    assert physical_before != physical_after
    assert snapshot_before == snapshot_after
    assert len({canonical_snapshot_fingerprint(source, tmp_path) for _ in range(3)}) == 1

    with sqlite3.connect(source) as connection:
        connection.execute("INSERT INTO records(value) VALUES ('inserted')")
        connection.commit()
    inserted = canonical_snapshot_fingerprint(source, tmp_path)
    assert inserted != snapshot_after

    with sqlite3.connect(source) as connection:
        connection.execute("UPDATE records SET value = 'updated' WHERE id = 1")
        connection.commit()
    updated = canonical_snapshot_fingerprint(source, tmp_path)
    assert updated != inserted

    with sqlite3.connect(source) as connection:
        connection.execute("DELETE FROM records WHERE id = 1")
        connection.commit()
    deleted = canonical_snapshot_fingerprint(source, tmp_path)
    assert deleted != updated


def test_isolated_snapshot_copies_committed_wal_without_shm_and_preserves_source(
    tmp_path: Path,
):
    source = tmp_path / "kaya.db"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO records(value) VALUES ('A')")
        connection.commit()
        connection.execute("INSERT INTO records(value) VALUES ('B')")
        connection.commit()
        wal = source.with_name(source.name + "-wal")
        assert wal.is_file()
        source_bytes = source.read_bytes()
        wal_bytes = wal.read_bytes()
        source_stat = source.stat()
        wal_stat = wal.stat()

    # Retain SQLite's real sidecar as stale input; replacing it with arbitrary
    # bytes can invalidate a shared-memory mapping and SIGBUS during teardown.
    shm = source.with_name(source.name + "-shm")
    assert shm.is_file()

    with isolated_sqlite_snapshot(source, tmp_path) as isolated:
        assert not isolated.with_name(isolated.name + "-shm").exists()
        with sqlite3.connect(isolated) as snapshot_connection:
            assert snapshot_connection.execute(
                "SELECT value FROM records ORDER BY id"
            ).fetchall() == [("A",), ("B",)]

    assert source.read_bytes() == source_bytes
    assert wal.read_bytes() == wal_bytes
    assert source.stat().st_size == source_stat.st_size
    assert wal.stat().st_size == wal_stat.st_size
    assert source.stat().st_mtime_ns == source_stat.st_mtime_ns
    assert wal.stat().st_mtime_ns == wal_stat.st_mtime_ns


def test_failed_source_identity_rejects_logical_change_but_tolerates_wal_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "kaya.db"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE alembic_version (version_num TEXT)")
        connection.execute("INSERT INTO alembic_version VALUES ('20260813_01')")
        connection.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO records(value) VALUES ('stable')")
        connection.commit()
    backup = create_sqlite_backup(
        source,
        tmp_path / "backups",
        source_revision="20260813_01",
        target_revision="20260818_02",
    )
    metadata = json.loads(backup.metadata_path.read_text(encoding="utf-8"))
    metadata["source_fingerprint"] = "94bd1ee74473482b0d1e133c71a514db9387e8f50ce10a44e0081c0696703e63"
    backup.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    legacy_physical_fingerprint = "2b3efd12bd96a10dc61270417518ff3c01bcbd0b9a455b25b6a7c2dcb040f354"
    _write_state(
        state_path(tmp_path),
        UpgradeState.FAILED,
        migration_id="migration-1",
        source_path=str(source),
        source_fingerprint=legacy_physical_fingerprint,
        target_revision="20260818_02",
    )
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    original_read_revision = phase6_cutover._read_sqlite_revision

    def refuse_live_revision(path: Path) -> str:
        if path == source.resolve():
            raise sqlite3.OperationalError("disk I/O error")
        return original_read_revision(path)

    monkeypatch.setattr(phase6_cutover, "_read_sqlite_revision", refuse_live_revision)
    _, _, _, snapshot, verified_backup = phase6_cutover._validate_failed_source_identity(
        tmp_path, "migration-1", legacy_physical_fingerprint
    )
    assert snapshot == backup.snapshot_fingerprint
    assert verified_backup == backup.database_path

    with sqlite3.connect(source) as connection:
        connection.execute("INSERT INTO records(value) VALUES ('changed')")
        connection.commit()
    with pytest.raises(RuntimeError, match="logical SQLite source changed"):
        phase6_cutover._validate_failed_source_identity(
            tmp_path, "migration-1", legacy_physical_fingerprint
        )


def test_stable_marker_accepts_logical_backup_when_physical_fingerprint_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "kaya.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num TEXT)")
        connection.execute("INSERT INTO alembic_version VALUES ('20260813_01')")
        connection.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO records VALUES (1, 'stable')")
        connection.commit()
    backup = create_sqlite_backup(
        source,
        tmp_path / "backups",
        source_revision="20260813_01",
        target_revision="20260818_02",
    )
    metadata = json.loads(backup.metadata_path.read_text(encoding="utf-8"))
    logical_identity = backup.snapshot_fingerprint
    metadata["source_fingerprint"] = "2b3efd12bd96a10dc61270417518ff3c01bcbd0b9a455b25b6a7c2dcb040f354"
    backup.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    persisted = {
        "state": UpgradeState.FAILED.value,
        "source_fingerprint": "94bd1ee74473482b0d1e133c71a514db9387e8f50ce10a44e0081c0696703e63",
        "original_source_snapshot_fingerprint": logical_identity,
        "target_revision": "20260818_02",
    }
    result = phase6_cutover._verified_backup_snapshot(
        tmp_path, persisted, source, "20260813_01"
    )
    assert result[2] == backup.database_path


def test_stable_marker_rejects_logically_different_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "kaya.db"
    source.touch()
    backup = create_sqlite_backup(
        source,
        tmp_path / "backups",
        source_revision="20260813_01",
        target_revision="20260818_02",
    )
    metadata = json.loads(backup.metadata_path.read_text(encoding="utf-8"))
    metadata["source_fingerprint"] = "94bd1ee74473482b0d1e133c71a514db9387e8f50ce10a44e0081c0696703e63"
    backup.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    persisted = {
        "state": UpgradeState.FAILED.value,
        "source_fingerprint": "94bd1ee74473482b0d1e133c71a514db9387e8f50ce10a44e0081c0696703e63",
        "original_source_snapshot_fingerprint": "f" * 64,
        "target_revision": "20260818_02",
    }
    with pytest.raises(RuntimeError, match="no verified pre-migration backup"):
        phase6_cutover._verified_backup_snapshot(tmp_path, persisted, source, "20260813_01")


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
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == CURRENT_REVISION
    backups = list((tmp_path / "backups").glob("*.sqlite3"))
    assert len(backups) == 1
    metadata = json.loads(backups[0].with_suffix(".json").read_text(encoding="utf-8"))
    assert metadata["source_revision"] == "20260813_01"


def test_legacy_ab_correlation_reuses_verified_backup_when_physical_a_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    verified_backup = tmp_path / "backups" / "pre-migration-original.sqlite3"
    verified_backup.parent.mkdir()
    verified_backup.write_bytes(b"verified-original-backup")
    retained_backup = verified_backup.parent / "pre-migration-conversion.sqlite3"
    retained_backup.write_bytes(b"retained-conversion-backup")
    target_revision = "20260818_02"
    conversion_fingerprint = "cca3b071a0bd02274aecbcab899310516efe0032f7cffab0297566a92f43ddda"

    monkeypatch.setattr(
        phase6_cutover,
        "_heads",
        lambda: (target_revision, SimpleNamespace()),
    )
    monkeypatch.setattr(phase6_cutover, "validate_sqlite_readable", lambda _path: None)
    monkeypatch.setattr(phase6_cutover, "_file_sha256", lambda path: "b" * 64 if path == retained_backup else "a" * 64)
    (retained_backup.with_suffix(".json")).write_text(
        json.dumps(
            {
                "source_revision": target_revision,
                "target_revision": target_revision,
                "source_fingerprint": conversion_fingerprint,
                "backup_filename": retained_backup.name,
                "backup_sha256": "b" * 64,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(phase6_cutover, "_logical_sqlite_fingerprint", lambda path: "logical-b")
    monkeypatch.setattr(
        phase6_cutover,
        "_source_fingerprint",
        lambda _path: (_ for _ in ()).throw(AssertionError("rebuilt B' physical identity must not be read")),
    )
    monkeypatch.setattr(
        phase6_cutover,
        "prepare_database",
        lambda *_args, **_kwargs: SimpleNamespace(current_revision=target_revision),
    )
    monkeypatch.setattr(
        phase6_cutover,
        "get_settings",
        lambda: SimpleNamespace(
            model_copy=lambda update: SimpleNamespace(database_url=update["database_url"])
        ),
    )

    assert phase6_cutover._legacy_historical_target_matches(
        tmp_path,
        tmp_path / "kaya.db",
        "20260813_01",
        {
            "source_fingerprint": conversion_fingerprint,
            "source_revision": target_revision,
            "target_revision": target_revision,
        },
        verified_backup,
    )


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


def test_keyboard_interrupt_during_precheck_leaves_resumable_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "kaya.db"
    source.touch()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(phase6_cutover, "validate_test_configuration", lambda: None)
    monkeypatch.setattr(
        phase6_cutover,
        "detect_installation",
        lambda *_args: SimpleNamespace(state=UpgradeState.SQLITE_ACTIVE),
    )

    def interrupt(*_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(phase6_cutover, "preflight", interrupt)

    with pytest.raises(KeyboardInterrupt):
        run_upgrade(source, "postgresql+psycopg://kaya@db/kaya", tmp_path / "backups", data_dir)

    state = json.loads(state_path(data_dir).read_text(encoding="utf-8"))
    assert state["state"] == UpgradeState.PRECHECK.value


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
    monkeypatch.setattr(
        phase6_cutover,
        "create_sqlite_backup",
        lambda *_args, **_kwargs: SimpleNamespace(snapshot_fingerprint="s" * 64),
    )
    failure = SQLiteToPostgresError("synthetic migration failure")
    failure.migration_id = migration_id
    monkeypatch.setattr(phase6_cutover, "migrate", lambda *_args, **_kwargs: (_ for _ in ()).throw(failure))

    with pytest.raises(SQLiteToPostgresError, match="synthetic migration failure"):
        run_upgrade(source, "postgresql+psycopg://kaya@db/kaya", tmp_path / "backups", data_dir)

    state = json.loads(state_path(data_dir).read_text(encoding="utf-8"))
    assert state["state"] == UpgradeState.FAILED.value
    assert state["migration_id"] == migration_id


def test_historical_upgrade_persists_original_and_conversion_identities(tmp_path: Path, monkeypatch):
    source = tmp_path / "kaya.db"
    source.write_bytes(b"original-source")
    working = tmp_path / ".kaya-historical-upgrade.sqlite3"
    working.write_bytes(b"conversion-source")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    preflights = iter(
        [
            {"source_fingerprint": "a" * 64, "source_revision": "20260813_01", "target_revision": "20260818_02"},
            {"source_fingerprint": "b" * 64, "source_revision": "20260818_02", "target_revision": "20260818_02"},
        ]
    )
    monkeypatch.setattr(phase6_cutover, "validate_test_configuration", lambda: None)
    monkeypatch.setattr(
        phase6_cutover,
        "detect_installation",
        lambda *_args: SimpleNamespace(state=UpgradeState.SQLITE_ACTIVE),
    )
    monkeypatch.setattr(phase6_cutover, "preflight", lambda *_args: next(preflights))
    monkeypatch.setattr(phase6_cutover, "_upgrade_supported_legacy_sqlite", lambda *_args: working)
    monkeypatch.setattr(
        phase6_cutover,
        "create_sqlite_backup",
        lambda *_args, **_kwargs: SimpleNamespace(snapshot_fingerprint="s" * 64),
    )

    def fake_migrate(*_args, state_callback=None, original_source_fingerprint=None, **_kwargs):
        if state_callback:
            state_callback("MIGRATING")
        return {
            "migration_id": "migration-1",
            "target_revision": "20260818_02",
            "conversion_source_fingerprint": "b" * 64,
            "result": "COMPLETED",
        }

    monkeypatch.setattr(phase6_cutover, "migrate", fake_migrate)
    run_upgrade(source, "postgresql+psycopg://kaya@db/kaya", tmp_path / "backups", data_dir)

    state = json.loads(state_path(data_dir).read_text(encoding="utf-8"))
    assert state["original_source_fingerprint"] == "a" * 64
    assert state["conversion_source_fingerprint"] == "b" * 64
    assert state["original_source_snapshot_fingerprint"] == "s" * 64
    assert state["source_fingerprint"] == "a" * 64
    assert state["migration_id"] == "migration-1"


def test_failed_retry_requires_failed_source_marker(tmp_path: Path):
    _write_state(state_path(tmp_path), UpgradeState.POSTGRES_ACTIVE, source_fingerprint="a" * 64)

    with pytest.raises(RuntimeError, match="source marker is not FAILED"):
        prepare_failed_retry(tmp_path, "a" * 64)


def _prepare_pretarget_failed_fixture(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "kaya.db"
    head, _ = phase6_cutover._heads()
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num TEXT)")
        connection.execute("INSERT INTO alembic_version VALUES (?)", (head,))
        connection.commit()
    source_fingerprint = phase6_cutover._source_fingerprint(source)
    backup = create_sqlite_backup(
        source,
        tmp_path / "backups",
        source_revision=head,
        target_revision=head,
    )
    _write_state(
        state_path(tmp_path),
        UpgradeState.FAILED,
        database_engine="sqlite",
        source_path=str(source),
        source_fingerprint=source_fingerprint,
        original_source_fingerprint=source_fingerprint,
        original_source_snapshot_fingerprint=backup.snapshot_fingerprint,
        conversion_source_fingerprint=source_fingerprint,
        source_revision=head,
        target_revision=head,
        migration_id=None,
        error="SQLiteToPostgresError",
        recovery_artifacts_retained=True,
    )
    return source, source_fingerprint


def test_pre_target_failed_retry_verifies_target_absence_and_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source, source_fingerprint = _prepare_pretarget_failed_fixture(tmp_path)
    monkeypatch.setattr(phase6_cutover, "isolated_sqlite_snapshot", lambda *_args, **_kwargs: nullcontext(source))

    class EmptyTarget:
        def dispose(self):
            return None

    monkeypatch.setattr(phase6_cutover, "create_engine", lambda *_args, **_kwargs: EmptyTarget())
    monkeypatch.setattr(
        phase6_cutover,
        "inspect",
        lambda _target: SimpleNamespace(get_table_names=lambda: []),
    )

    verified_backup = prepare_failed_pretarget_retry(
        tmp_path, "postgresql+psycopg://kaya@db/kaya"
    )

    assert verified_backup.is_file()
    state = json.loads(state_path(tmp_path).read_text(encoding="utf-8"))
    assert state["state"] == UpgradeState.PRECHECK.value
    assert state["migration_id"] is None
    assert state["source_path"] == str(source.resolve())

    monkeypatch.setattr(phase6_cutover, "validate_test_configuration", lambda: None)
    monkeypatch.setattr(
        phase6_cutover,
        "detect_installation",
        lambda *_args: SimpleNamespace(state=UpgradeState.SQLITE_ACTIVE),
    )
    monkeypatch.setattr(
        phase6_cutover,
        "preflight",
        lambda *_args: {
            "source_fingerprint": source_fingerprint,
            "source_revision": phase6_cutover._heads()[0],
            "target_revision": phase6_cutover._heads()[0],
        },
    )
    monkeypatch.setattr(
        phase6_cutover,
        "migrate",
        lambda *_args, **_kwargs: {
            "migration_id": "new-migration",
            "target_revision": phase6_cutover._heads()[0],
            "conversion_source_fingerprint": source_fingerprint,
            "result": "COMPLETED",
        },
    )
    run_upgrade(
        source,
        "postgresql+psycopg://kaya@db/kaya",
        tmp_path / "backups",
        tmp_path,
        recovery_backup=verified_backup,
    )
    assert json.loads(state_path(tmp_path).read_text(encoding="utf-8"))["state"] == UpgradeState.POSTGRES_ACTIVE.value


def test_pre_target_failed_retry_rejects_existing_postgres_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _prepare_pretarget_failed_fixture(tmp_path)
    source = tmp_path / "kaya.db"
    monkeypatch.setattr(phase6_cutover, "isolated_sqlite_snapshot", lambda *_args, **_kwargs: nullcontext(source))

    class ExistingTarget:
        def dispose(self):
            return None

    monkeypatch.setattr(phase6_cutover, "create_engine", lambda *_args, **_kwargs: ExistingTarget())
    monkeypatch.setattr(
        phase6_cutover,
        "inspect",
        lambda _target: SimpleNamespace(get_table_names=lambda: ["kaya_migration_state"]),
    )

    with pytest.raises(RuntimeError, match="target migration evidence exists"):
        prepare_failed_pretarget_retry(
            tmp_path, "postgresql+psycopg://kaya@db/kaya"
        )


def test_pre_target_failed_retry_rejects_snapshot_identity_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source, _ = _prepare_pretarget_failed_fixture(tmp_path)
    state = json.loads(state_path(tmp_path).read_text(encoding="utf-8"))
    state["original_source_snapshot_fingerprint"] = "b" * 64
    state_path(tmp_path).write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(
        phase6_cutover,
        "isolated_sqlite_snapshot",
        lambda *_args, **_kwargs: nullcontext(source),
    )

    with pytest.raises(RuntimeError, match="no verified pre-migration backup"):
        prepare_failed_pretarget_retry(
            tmp_path, "postgresql+psycopg://kaya@db/kaya"
        )


def test_disposable_historical_copy_cleanup_preserves_recovery_artifacts(tmp_path: Path):
    working = tmp_path / ".kaya-historical-upgrade-test.sqlite3"
    working.write_bytes(b"temporary")
    working.with_name(working.name + "-wal").write_bytes(b"wal")
    working.with_name(working.name + "-shm").write_bytes(b"shm")
    retained = tmp_path / "pre-migration-retained.sqlite3"
    retained.write_bytes(b"backup")

    phase6_cutover._remove_disposable_historical_copy(working, tmp_path)

    assert not working.exists()
    assert not working.with_name(working.name + "-wal").exists()
    assert not working.with_name(working.name + "-shm").exists()
    assert retained.exists()


def test_failed_retry_requires_matching_source_fingerprint(tmp_path: Path):
    _write_state(
        state_path(tmp_path),
        UpgradeState.FAILED,
        migration_id="migration-1",
        source_fingerprint="a" * 64,
    )

    with pytest.raises(RuntimeError, match="source fingerprint does not match"):
        prepare_failed_retry(tmp_path, "b" * 64)


def test_failed_retry_recomputes_original_source_identity(tmp_path: Path):
    source = tmp_path / "kaya.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num TEXT)")
        connection.execute("INSERT INTO alembic_version VALUES ('20260818_02')")
        connection.commit()
    fingerprint = phase6_cutover._source_fingerprint(source)
    backup = create_sqlite_backup(
        source,
        tmp_path / "backups",
        source_revision="20260818_02",
        target_revision="20260818_02",
    )
    _write_state(
        state_path(tmp_path),
        UpgradeState.FAILED,
        migration_id="migration-1",
        source_path=str(source),
        source_fingerprint=fingerprint,
        target_revision="20260818_02",
    )

    prepare_failed_retry(tmp_path, fingerprint)

    state = json.loads(state_path(tmp_path).read_text(encoding="utf-8"))
    assert state["state"] == UpgradeState.PRECHECK.value
    assert state["original_source_fingerprint"] == fingerprint
    assert state["original_source_snapshot_fingerprint"] == backup.snapshot_fingerprint

    source.unlink()
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num TEXT)")
        connection.execute("INSERT INTO alembic_version VALUES ('20260818_02')")
        connection.execute("CREATE TABLE changed_after_failure (value TEXT)")
        connection.commit()
    _write_state(
        state_path(tmp_path),
        UpgradeState.FAILED,
        migration_id="migration-1",
        source_path=str(source),
        source_fingerprint=fingerprint,
        source_revision="20260818_02",
        target_revision="20260818_02",
    )
    with pytest.raises(RuntimeError, match="source changed after failure"):
        prepare_failed_retry(tmp_path, fingerprint)


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
            return SimpleNamespace(
                mappings=lambda: SimpleNamespace(
                    one_or_none=lambda: {
                        "state": state,
                        "migration_id": "migration-1",
                        "source_fingerprint": "a" * 64,
                    }
                )
            )

    class FakeTarget:
        def connect(self):
            return FakeConnection()

        def begin(self):
            return FakeConnection()

        def dispose(self):
            return None

    monkeypatch.setattr(phase6_cutover, "create_engine", lambda *_args, **_kwargs: FakeTarget())
    monkeypatch.setattr(
        phase6_cutover,
        "inspect",
        lambda _target: SimpleNamespace(
            get_table_names=lambda: ["kaya_migration_state"],
            get_columns=lambda _table: [
                {"name": "state"},
                {"name": "migration_id"},
                {"name": "source_fingerprint"},
            ],
        ),
    )

    with pytest.raises(RuntimeError, match="matching failed migration target"):
        clean_failed_target("postgresql+psycopg://kaya@db/kaya", migration_id, source_fingerprint)
