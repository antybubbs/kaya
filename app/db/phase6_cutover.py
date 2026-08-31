"""Durable, fail-closed orchestration for the SQLite-to-PostgreSQL upgrade."""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from alembic.util.exc import CommandError
from sqlalchemy import create_engine, inspect, text

from app.core.config import redact_database_url, sqlite_database_path
from app.db.backup import (
    MigrationBackup,
    _file_sha256,
    _logical_sqlite_fingerprint,
    create_sqlite_backup,
    isolated_sqlite_snapshot,
)
from app.db.validation import validate_sqlite_readable
from app.db.phase6_test_hooks import hit as test_failpoint, validate_configuration as validate_test_configuration
from app.db.migrations import prepare_database
from app.db.sqlite_to_postgres import _heads, _source_fingerprint, migrate, preflight
from app.core.config import get_settings, postgres_engine_options

logger = logging.getLogger(__name__)


class UpgradeState(StrEnum):
    NEW_POSTGRES_INSTALL = "NEW_POSTGRES_INSTALL"
    EXISTING_POSTGRES_INSTALL = "EXISTING_POSTGRES_INSTALL"
    SQLITE_ACTIVE = "SQLITE_ACTIVE"
    PRECHECK = "PRECHECK"
    MAINTENANCE = "MAINTENANCE"
    BACKED_UP = "BACKED_UP"
    POSTGRES_PREPARED = "POSTGRES_PREPARED"
    MIGRATING = "MIGRATING"
    VALIDATING = "VALIDATING"
    POSTGRES_READY = "POSTGRES_READY"
    CUTOVER_PENDING = "CUTOVER_PENDING"
    POSTGRES_ACTIVE = "POSTGRES_ACTIVE"
    FAILED = "FAILED"
    UNSUPPORTED_OR_AMBIGUOUS = "UNSUPPORTED_OR_AMBIGUOUS"


STATE_FILENAME = "kaya-database-upgrade.json"
REPORT_FILENAME = "kaya-database-upgrade-report.json"


@dataclass(frozen=True)
class Installation:
    state: UpgradeState
    database_engine: str
    source_path: Path | None
    state_path: Path
    reason: str = ""


def legacy_sqlite_eligibility(source_path: Path, data_dir: Path) -> tuple[bool, str]:
    """Validate a controlled legacy source before automatic migration starts."""
    source = source_path.resolve()
    data_root = data_dir.resolve()
    try:
        source.relative_to(data_root)
    except ValueError:
        return False, "legacy SQLite source is outside the configured data directory"
    if not source.is_file():
        return False, "legacy SQLite source does not exist"
    try:
        with sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True) as connection:
            connection.execute("PRAGMA query_only=ON")
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                return False, "legacy SQLite source failed integrity validation"
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            revision = connection.execute(
                "SELECT version_num FROM alembic_version"
            ).fetchall()
    except (OSError, sqlite3.DatabaseError) as exc:
        return False, f"legacy SQLite source is not a valid Kaya database ({type(exc).__name__})"
    if len(revision) != 1 or not revision[0][0]:
        return False, "legacy SQLite source has no single Alembic revision"
    if "users" not in tables:
        return False, "legacy SQLite source is missing the required users table"
    expected_head, script = _heads()
    source_revision = revision[0][0]
    try:
        script.get_revision(source_revision)
    except (KeyError, TypeError, CommandError):
        return False, f"legacy SQLite revision {source_revision} is unknown"

    pending = [expected_head]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        if current == source_revision:
            if source_revision == expected_head:
                return True, "eligible legacy Kaya SQLite source at current head"
            return True, (
                f"eligible legacy Kaya SQLite source; revision {source_revision} "
                f"will be upgraded to {expected_head} before PostgreSQL conversion"
            )
        revision_node = script.get_revision(current)
        down_revision = revision_node.down_revision
        if isinstance(down_revision, tuple):
            pending.extend(down_revision)
        elif down_revision:
            pending.append(down_revision)
    return False, f"legacy SQLite revision {source_revision} is not an ancestor of {expected_head}"


def _upgrade_supported_legacy_sqlite(
    source_path: Path, backup_dir: Path, data_dir: Path, source_revision: str
) -> Path:
    """Upgrade a verified working copy of a known historical SQLite revision."""
    expected_head, _ = _heads()
    if source_revision == expected_head:
        return source_path
    # The CLI accepts an explicitly supplied source and may keep state and
    # retry artifacts in a separate directory.  The entrypoint still applies
    # the stricter configured-data-root check before invoking this path.
    eligible, reason = legacy_sqlite_eligibility(source_path, source_path.parent)
    if not eligible:
        raise RuntimeError(reason)
    logger.info(
        "Legacy SQLite schema upgrade starting source_revision=%s target_revision=%s",
        source_revision,
        expected_head,
    )
    source_backup = create_sqlite_backup(
        source_path,
        backup_dir,
        source_revision=source_revision,
        target_revision=expected_head,
    )
    file_descriptor, working_name = tempfile.mkstemp(
        prefix=".kaya-historical-upgrade-",
        suffix=".sqlite3",
        dir=data_dir,
    )
    os.close(file_descriptor)
    working_path = Path(working_name)
    started = time.monotonic()
    try:
        shutil.copyfile(source_backup.database_path, working_path)
        os.chmod(working_path, 0o600)
        logger.info(
            "Legacy SQLite schema upgrade working_copy_size=%s bytes=%s",
            _human_size(working_path.stat().st_size),
            working_path.stat().st_size,
        )
        settings = get_settings().model_copy(
            update={
                "database_url": f"sqlite:///{working_path.resolve().as_posix()}",
                "data_dir": str(data_dir.resolve()),
                "migration_backup_dir": str(backup_dir.resolve()),
                # The immutable source backup above is the mandatory pre-DDL backup;
                # the working copy must not create a second source artifact.
                "migration_backups_enabled": False,
            }
        )
        source_engine = create_engine(settings.database_url)
        stop_heartbeat = threading.Event()

        def heartbeat() -> None:
            while not stop_heartbeat.wait(30.0):
                logger.info(
                    "Historical SQLite schema upgrade still running elapsed=%.0fs",
                    time.monotonic() - started,
                )

        heartbeat_thread = threading.Thread(
            target=heartbeat, name="kaya-legacy-upgrade-heartbeat", daemon=True
        )
        heartbeat_thread.start()
        try:
            result = prepare_database(source_engine, settings)
        finally:
            stop_heartbeat.set()
            heartbeat_thread.join(timeout=1.0)
            source_engine.dispose()
        if result.previous_revision != source_revision:
            raise RuntimeError(
                "historical SQLite working copy had an unexpected Alembic revision"
            )
        if result.current_revision != expected_head:
            raise RuntimeError(
                f"historical SQLite upgrade stopped at {result.current_revision}; expected {expected_head}"
            )
    except BaseException:
        _remove_disposable_historical_copy(working_path, data_dir)
        raise
    logger.info(
        "Historical SQLite schema upgrade completed elapsed=%.1fs source_revision=%s target_revision=%s backup=%s validation=passed",
        time.monotonic() - started,
        source_revision,
        expected_head,
        source_backup.database_path.name,
    )
    return working_path


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _remove_disposable_historical_copy(path: Path | None, data_dir: Path) -> None:
    if path is None:
        return
    try:
        resolved = path.resolve()
        resolved.relative_to(data_dir.resolve())
    except (OSError, ValueError):
        return
    if not resolved.name.startswith(".kaya-historical-upgrade-"):
        return
    for candidate in (
        resolved,
        resolved.with_name(resolved.name + "-wal"),
        resolved.with_name(resolved.name + "-shm"),
    ):
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            logger.warning("Could not remove disposable historical conversion artifact")
            return
    logger.info("Disposable historical SQLite conversion copy removed")


def state_path(data_dir: Path) -> Path:
    return data_dir / STATE_FILENAME


def report_path(data_dir: Path) -> Path:
    return data_dir / REPORT_FILENAME


def _read_state(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Kaya database upgrade state is unreadable.") from exc
    if not isinstance(value, dict) or value.get("state") not in {item.value for item in UpgradeState}:
        raise RuntimeError("Kaya database upgrade state is invalid.")
    return value


def _original_source_fingerprint(persisted: dict[str, Any]) -> str | None:
    """Read the explicit identity, falling back to the legacy field."""
    return persisted.get("original_source_fingerprint") or persisted.get("source_fingerprint")


def _persisted_source_path(persisted: dict[str, Any], data_dir: Path) -> Path:
    source_value = persisted.get("source_path")
    if not isinstance(source_value, str) or not source_value:
        raise RuntimeError("Refusing recovery: FAILED marker has no source path.")
    source = Path(source_value).resolve()
    try:
        source.relative_to(data_dir.resolve())
    except ValueError as exc:
        raise RuntimeError("Refusing recovery: FAILED source path is outside the data directory.") from exc
    return source


def _read_sqlite_revision(source: Path) -> str:
    try:
        with sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True) as connection:
            row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    except (OSError, sqlite3.DatabaseError) as exc:
        raise RuntimeError("Refusing recovery: FAILED source revision could not be verified.") from exc
    if not row or not row[0]:
        raise RuntimeError("Refusing recovery: FAILED source has no single Alembic revision.")
    return str(row[0])


def _verified_backup_snapshot(
    data_dir: Path,
    persisted: dict[str, Any],
    source: Path,
    source_revision: str | None,
) -> tuple[str, str, Path]:
    backup_dir = data_dir / "backups"
    original_fingerprint = _original_source_fingerprint(persisted)
    target_revision = persisted.get("target_revision")
    stable_marker = bool(persisted.get("original_source_snapshot_fingerprint"))
    expected_head, script = _heads()

    def is_supported_lineage(candidate_revision: Any) -> bool:
        if not isinstance(candidate_revision, str) or not candidate_revision:
            return False
        if not isinstance(target_revision, str) or not target_revision:
            return False
        try:
            script.get_revision(candidate_revision)
            script.get_revision(target_revision)
        except (KeyError, TypeError, CommandError):
            return False
        pending = [target_revision]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            if current == candidate_revision:
                return True
            revision = script.get_revision(current)
            down_revision = revision.down_revision
            if isinstance(down_revision, tuple):
                pending.extend(item for item in down_revision if item)
            elif down_revision:
                pending.append(down_revision)
        return candidate_revision == expected_head == target_revision

    for metadata_path in backup_dir.glob("*.json"):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        backup_name = metadata.get("backup_filename")
        backup_path = Path(backup_name) if isinstance(backup_name, str) else None
        candidate_revision = metadata.get("source_revision")
        physical_match = metadata.get("source_fingerprint") == original_fingerprint
        if (
            metadata.get("source_filename") != source.name
            or (source_revision and metadata.get("source_revision") != source_revision)
            or metadata.get("target_revision") != target_revision
            or not is_supported_lineage(candidate_revision)
            or backup_path is None
            or backup_path.is_absolute()
            or backup_path.name != backup_name
        ):
            continue
        if not stable_marker:
            logger.info(
                "database.recovery backup_candidate=legacy_original physical_fingerprint_match=%s",
                str(physical_match).lower(),
            )
        candidate = backup_dir / backup_path
        if not candidate.is_file():
            logger.warning("database.recovery backup_candidate=rejected reason=missing")
            continue
        try:
            if metadata.get("backup_sha256") != _file_sha256(candidate):
                logger.warning("database.recovery backup_candidate=rejected reason=sha_mismatch")
                continue
            validate_sqlite_readable(candidate)
            snapshot = _logical_sqlite_fingerprint(candidate)
        except (OSError, RuntimeError, ValueError, sqlite3.DatabaseError) as exc:
            message = str(exc).lower()
            if "disk is full" in message or "no space left" in message or "insufficient space" in message:
                logger.error("database.recovery backup_candidate=rejected reason=disk_full")
                raise RuntimeError(
                    "Recovery snapshot cannot be created: insufficient disk space."
                ) from exc
            reason = "sqlite_invalid" if isinstance(exc, RuntimeError) else "snapshot_failed"
            logger.warning("database.recovery backup_candidate=rejected reason=%s", reason)
            continue
        if stable_marker:
            if snapshot != persisted.get("original_source_snapshot_fingerprint"):
                logger.warning("database.recovery backup_candidate=rejected reason=marker_logical_identity_mismatch")
                continue
            logger.info(
                "database.recovery backup_candidate=stable_original physical_fingerprint_match=%s",
                str(physical_match).lower(),
            )
            logger.info("database.recovery backup_logical_identity=matched marker_logical_identity=matched")
        elif metadata.get("snapshot_fingerprint") not in {None, snapshot}:
            logger.warning("database.recovery backup_candidate=rejected reason=snapshot_identity_mismatch")
            continue
        logger.info("database.recovery backup_sha=validated backup_revision=validated")
        logger.info("database.recovery backup_lineage=validated")
        return snapshot, str(metadata["source_revision"]), candidate
    raise RuntimeError("Refusing recovery: no verified pre-migration backup proves the source lineage.")


def _validate_failed_source_identity(
    data_dir: Path, migration_id: str, original_source_fingerprint: str
) -> tuple[dict[str, Any], Path, str, str, Path]:
    persisted = _read_state(state_path(data_dir))
    if not persisted or persisted.get("state") != UpgradeState.FAILED.value:
        raise RuntimeError("Refusing recovery: source marker is not FAILED.")
    if persisted.get("migration_id") != migration_id:
        raise RuntimeError("Refusing recovery: source migration ID does not match.")
    if _original_source_fingerprint(persisted) != original_source_fingerprint:
        raise RuntimeError("Refusing recovery: source fingerprint does not match FAILED marker.")
    source = _persisted_source_path(persisted, data_dir)
    backup_snapshot, backup_revision, verified_backup = _verified_backup_snapshot(
        data_dir, persisted, source, str(persisted.get("source_revision") or "")
    )
    with isolated_sqlite_snapshot(source, data_dir) as isolated_source:
        source_revision = _read_sqlite_revision(isolated_source)
        logger.info("database.recovery source_revision=validated revision=%s", source_revision)
        if source_revision != backup_revision:
            raise RuntimeError("Refusing recovery: FAILED source revision does not match verified backup lineage.")
        if _logical_sqlite_fingerprint(isolated_source) != backup_snapshot:
            raise RuntimeError("Refusing recovery: logical SQLite source changed after failure.")
    if _source_fingerprint(source) != original_source_fingerprint:
        logger.info("database.recovery legacy_physical_fingerprint=mismatch_tolerated")
    persisted_snapshot = persisted.get("original_source_snapshot_fingerprint")
    if persisted_snapshot and persisted_snapshot != backup_snapshot:
        raise RuntimeError("Refusing recovery: persisted source snapshot identity is invalid.")
    logger.info("database.recovery identity_mode=stable_snapshot backup_lineage=validated logical_source_identity=matched")
    return persisted, source, source_revision, backup_snapshot, verified_backup


def _legacy_historical_target_matches(
    data_dir: Path,
    source: Path,
    source_revision: str,
    row: Any,
    verified_backup: Path,
) -> bool:
    """Prove the old A/B marker came from the validated original backup."""
    target_revision = row["target_revision"]
    conversion_fingerprint = row["source_fingerprint"]
    expected_head, _ = _heads()

    def reject(reason: str) -> bool:
        logger.warning("database.recovery conversion_backup=rejected reason=%s", reason)
        return False

    if (
        not isinstance(conversion_fingerprint, str)
        or len(conversion_fingerprint) != 64
        or any(character not in "0123456789abcdef" for character in conversion_fingerprint)
        or source_revision == row["source_revision"]
        or row["source_revision"] != expected_head
        or target_revision != expected_head
    ):
        return reject("target_identity_mismatch")
    backup_dir = data_dir / "backups"
    retained_conversion: Path | None = None
    retained_logical_fingerprint: str | None = None
    for metadata_path in sorted(backup_dir.glob("*.json"), reverse=True):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (
            metadata.get("source_revision") != row["source_revision"]
            or metadata.get("target_revision") != target_revision
            or metadata.get("source_fingerprint") != conversion_fingerprint
        ):
            continue
        backup_name = metadata.get("backup_filename")
        if (
            not isinstance(backup_name, str)
            or not backup_name
            or Path(backup_name).is_absolute()
            or Path(backup_name).name != backup_name
        ):
            return reject("conversion_backup_filename_invalid")
        candidate = (backup_dir / backup_name).resolve()
        try:
            candidate.relative_to(backup_dir.resolve())
        except ValueError:
            return reject("conversion_backup_path_invalid")
        if not candidate.is_file():
            logger.warning("database.recovery conversion_backup=rejected reason=conversion_backup_missing")
            continue
        try:
            if metadata.get("backup_sha256") != _file_sha256(candidate):
                logger.warning("database.recovery conversion_backup=rejected reason=conversion_backup_sha_mismatch")
                continue
            validate_sqlite_readable(candidate)
            retained_logical_fingerprint = _logical_sqlite_fingerprint(candidate)
        except (OSError, RuntimeError, ValueError, sqlite3.DatabaseError):
            logger.warning("database.recovery conversion_backup=rejected reason=conversion_backup_sqlite_invalid")
            continue
        retained_conversion = candidate
        logger.info(
            "database.recovery conversion_backup=validated source_revision=%s target_revision=%s",
            row["source_revision"],
            target_revision,
        )
        break
    if retained_conversion is None or retained_logical_fingerprint is None:
        return reject("conversion_backup_missing")
    if not verified_backup.is_file():
        return reject("original_backup_missing")
    try:
        validate_sqlite_readable(verified_backup)
        with tempfile.TemporaryDirectory(prefix=".kaya-recovery-", dir=data_dir) as temporary_dir:
            working_path = Path(temporary_dir) / "conversion.sqlite3"
            shutil.copyfile(verified_backup, working_path)
            settings = get_settings().model_copy(
                update={
                    "database_url": f"sqlite:///{working_path.resolve().as_posix()}",
                    "data_dir": str(data_dir.resolve()),
                    "migration_backup_dir": str(backup_dir.resolve()),
                    "migration_backups_enabled": False,
                }
            )
            source_engine = create_engine(settings.database_url)
            try:
                result = prepare_database(source_engine, settings)
            finally:
                source_engine.dispose()
            if result.current_revision != target_revision:
                logger.warning("database.recovery rebuilt_conversion=rejected reason=conversion_revision_mismatch")
                return False
            rebuilt_logical_fingerprint = _logical_sqlite_fingerprint(working_path)
    except (OSError, RuntimeError, sqlite3.DatabaseError):
        logger.warning("database.recovery rebuilt_conversion=rejected reason=conversion_upgrade_failed")
        return False
    if retained_conversion is None or conversion_fingerprint != row["source_fingerprint"]:
        return reject("conversion_target_identity_mismatch")
    logger.info("database.recovery conversion_target_identity=matched")
    if rebuilt_logical_fingerprint != retained_logical_fingerprint:
        return reject("conversion_logical_identity_mismatch")
    logger.info(
        "database.recovery rebuilt_conversion_revision=validated conversion_logical_identity=matched "
        "source_revision=%s target_revision=%s",
        source_revision,
        target_revision,
    )
    return True


def _write_state(path: Path, state: UpgradeState, **values: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    try:
        previous = json.loads(path.read_text(encoding="utf-8")).get("state")
    except (FileNotFoundError, OSError, json.JSONDecodeError, AttributeError):
        pass
    payload = {"state": state.value, "updated_at": datetime.now(UTC).isoformat(), **values}
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, default=str)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            Path(temporary).unlink()
        except FileNotFoundError:
            pass
    if previous != state.value:
        logger.info(
            "database.cutover.state previous=%s current=%s",
            previous or "NONE",
            state.value,
        )


def detect_installation(database_url: str, data_dir: Path) -> Installation:
    """Classify the installation without guessing from a database filename alone."""
    marker = state_path(data_dir)
    persisted = _read_state(marker)
    source = sqlite_database_path(database_url)
    engine_name = "sqlite" if source else "postgresql" if database_url.startswith("postgresql") else "unknown"
    if persisted:
        state = UpgradeState(persisted["state"])
        if state == UpgradeState.POSTGRES_ACTIVE and engine_name != "postgresql":
            return Installation(UpgradeState.UNSUPPORTED_OR_AMBIGUOUS, engine_name, source, marker, "authoritative PostgreSQL state conflicts with configuration")
        return Installation(state, engine_name, source, marker)
    if engine_name == "sqlite" and source and source.exists():
        return Installation(UpgradeState.SQLITE_ACTIVE, engine_name, source, marker)
    if engine_name == "postgresql":
        return Installation(UpgradeState.EXISTING_POSTGRES_INSTALL, engine_name, None, marker)
    if engine_name == "sqlite" and source is not None:
        return Installation(UpgradeState.UNSUPPORTED_OR_AMBIGUOUS, engine_name, source, marker, "SQLite is not a valid fresh-install database; configure PostgreSQL")
    return Installation(UpgradeState.UNSUPPORTED_OR_AMBIGUOUS, engine_name, source, marker, "database configuration is not supported")


def authoritative_database_url(configured_url: str, data_dir: Path) -> str:
    """Return the configured URL, refusing silent SQLite fallback after cutover."""
    installation = detect_installation(configured_url, data_dir)
    if installation.state == UpgradeState.UNSUPPORTED_OR_AMBIGUOUS and installation.reason:
        raise RuntimeError(installation.reason)
    if installation.state == UpgradeState.POSTGRES_ACTIVE and not configured_url.startswith("postgresql"):
        raise RuntimeError("PostgreSQL is authoritative but the configured database is not PostgreSQL.")
    if installation.state in {
        UpgradeState.FAILED,
        UpgradeState.PRECHECK,
        UpgradeState.MAINTENANCE,
        UpgradeState.BACKED_UP,
        UpgradeState.POSTGRES_PREPARED,
        UpgradeState.MIGRATING,
        UpgradeState.VALIDATING,
        UpgradeState.POSTGRES_READY,
        UpgradeState.CUTOVER_PENDING,
        UpgradeState.UNSUPPORTED_OR_AMBIGUOUS,
    }:
        raise RuntimeError("Kaya database upgrade state requires operator recovery before startup.")
    return configured_url


def run_upgrade(
    source_path: Path,
    target_url: str,
    backup_dir: Path,
    data_dir: Path,
    *,
    recovery_backup: Path | None = None,
) -> dict[str, Any]:
    """Run the existing migrator and commit PostgreSQL authority only after validation."""
    marker = state_path(data_dir)
    validate_test_configuration()
    state_source_path = source_path
    persisted_recovery = _read_state(marker) if recovery_backup is not None else None
    if recovery_backup is not None:
        source_path = recovery_backup.resolve()
        if not source_path.is_file():
            raise RuntimeError("Verified recovery backup is not available for retry.")
        state_source_path = Path(str((persisted_recovery or {}).get("source_path") or state_source_path))
    installation = detect_installation(f"sqlite:///{source_path}", data_dir)
    if installation.state not in {UpgradeState.SQLITE_ACTIVE, UpgradeState.PRECHECK}:
        raise RuntimeError(f"SQLite upgrade is not eligible from state {installation.state}.")
    _write_state(marker, UpgradeState.PRECHECK, database_engine="sqlite", source_path=str(state_source_path))
    dry_run: dict[str, Any] = {}
    original_source_fingerprint: str | None = None
    conversion_source_fingerprint: str | None = None
    original_source_snapshot_fingerprint: str | None = None
    conversion_source = source_path
    try:
        dry_run = preflight(source_path, target_url, True)
        original_source_fingerprint = (persisted_recovery or {}).get("original_source_fingerprint") or dry_run["source_fingerprint"]
        conversion_source_fingerprint = original_source_fingerprint
        source_revision = dry_run.get("source_revision")
        verified_backup = (
            MigrationBackup(
                source_path,
                source_path.with_suffix(".json"),
                "reused",
                (persisted_recovery or {}).get("original_source_snapshot_fingerprint"),
            )
            if recovery_backup is not None
            else create_sqlite_backup(
                source_path,
                backup_dir,
                source_revision=source_revision,
                target_revision=dry_run["target_revision"],
            )
        )
        original_source_snapshot_fingerprint = verified_backup.snapshot_fingerprint or _logical_sqlite_fingerprint(source_path)
        if not original_source_snapshot_fingerprint:
            raise RuntimeError("Verified SQLite backup has no stable snapshot identity.")
        _write_state(marker, UpgradeState.MAINTENANCE, database_engine="sqlite", source_path=str(state_source_path), source_revision=source_revision, source_fingerprint=original_source_fingerprint, original_source_fingerprint=original_source_fingerprint, original_source_snapshot_fingerprint=original_source_snapshot_fingerprint, conversion_source_fingerprint=conversion_source_fingerprint, target_revision=dry_run["target_revision"], progress="writes and background workers are stopped before conversion")
        if source_revision and source_revision != dry_run.get("target_revision"):
            conversion_source = _upgrade_supported_legacy_sqlite(
                source_path,
                backup_dir,
                data_dir,
                source_revision,
            )
            # Re-capture the source after Alembic has completed.  The converter
            # remains current-head-only and therefore cannot consume the old file.
            dry_run = preflight(conversion_source, target_url)
            conversion_source_fingerprint = dry_run["source_fingerprint"]
        def transition(name: str) -> None:
            state = UpgradeState(name)
            _write_state(
                marker,
                state,
                database_engine="sqlite" if state in {UpgradeState.BACKED_UP, UpgradeState.POSTGRES_PREPARED, UpgradeState.MIGRATING, UpgradeState.VALIDATING} else "postgresql",
                source_fingerprint=original_source_fingerprint,
                original_source_fingerprint=original_source_fingerprint,
                original_source_snapshot_fingerprint=original_source_snapshot_fingerprint,
                conversion_source_fingerprint=conversion_source_fingerprint,
                target_revision=dry_run["target_revision"],
            )

        test_failpoint("fail_state")
        report = migrate(
            conversion_source,
            target_url,
            backup_dir,
            state_callback=transition,
            original_source_fingerprint=original_source_fingerprint,
            original_source_snapshot_fingerprint=original_source_snapshot_fingerprint,
        )
        if report.get("result") != "COMPLETED":
            raise RuntimeError("SQLite migration did not complete.")
        _write_state(marker, UpgradeState.POSTGRES_READY, database_engine="postgresql", target_url=redact_database_url(target_url), source_fingerprint=original_source_fingerprint, original_source_fingerprint=original_source_fingerprint, original_source_snapshot_fingerprint=original_source_snapshot_fingerprint, conversion_source_fingerprint=report["conversion_source_fingerprint"], target_revision=report["target_revision"], migration_id=report["migration_id"])
        safe_report = {key: value for key, value in report.items() if key not in {"source_backup"} or isinstance(value, dict)}
        _write_state(report_path(data_dir), UpgradeState.POSTGRES_READY, **safe_report)
        _write_state(marker, UpgradeState.CUTOVER_PENDING, database_engine="sqlite", target_url=redact_database_url(target_url), source_path=str(state_source_path), source_fingerprint=original_source_fingerprint, original_source_fingerprint=original_source_fingerprint, original_source_snapshot_fingerprint=original_source_snapshot_fingerprint, conversion_source_fingerprint=report["conversion_source_fingerprint"], target_revision=report["target_revision"], migration_id=report["migration_id"])
        test_failpoint("pause_cutover_pending")
        _write_state(marker, UpgradeState.POSTGRES_ACTIVE, database_engine="postgresql", target_url=redact_database_url(target_url), source_path=str(state_source_path), source_fingerprint=original_source_fingerprint, original_source_fingerprint=original_source_fingerprint, original_source_snapshot_fingerprint=original_source_snapshot_fingerprint, conversion_source_fingerprint=report["conversion_source_fingerprint"], target_revision=report["target_revision"], migration_id=report["migration_id"], recovery_artifacts_retained=True)
        test_failpoint("pause_after_postgres_active")
        logger.info("database migration and cutover completed source=%s target=%s", source_path.name, redact_database_url(target_url))
        return report
    except Exception as exc:
        _write_state(
            marker,
            UpgradeState.FAILED,
            database_engine="sqlite",
            source_path=str(state_source_path),
            source_fingerprint=original_source_fingerprint or dry_run.get("source_fingerprint"),
            original_source_fingerprint=original_source_fingerprint or dry_run.get("source_fingerprint"),
            original_source_snapshot_fingerprint=original_source_snapshot_fingerprint,
            conversion_source_fingerprint=conversion_source_fingerprint or dry_run.get("source_fingerprint"),
            target_revision=dry_run.get("target_revision"),
            migration_id=getattr(exc, "migration_id", None),
            error=type(exc).__name__,
            recovery_artifacts_retained=True,
        )
        logger.error("database migration failed; SQLite remains authoritative and preserved")
        raise
    finally:
        if conversion_source.resolve() != source_path.resolve():
            _remove_disposable_historical_copy(conversion_source, data_dir)


def clean_failed_target(
    target_url: str,
    migration_id: str,
    source_fingerprint: str,
    data_dir: Path | None = None,
) -> None:
    """Reset only a target proven to be this upgrade's failed, non-active target."""
    source_path: Path | None = None
    source_revision: str | None = None
    source_snapshot: str | None = None
    verified_backup: Path | None = None
    if data_dir is not None:
        _, source_path, source_revision, source_snapshot, verified_backup = _validate_failed_source_identity(
            data_dir, migration_id, source_fingerprint
        )
    target = create_engine(target_url, **postgres_engine_options(get_settings()))
    try:
        inspector = inspect(target)
        if "kaya_migration_state" not in inspector.get_table_names():
            raise RuntimeError("Refusing cleanup: target has no Kaya migration marker.")
        columns = {column["name"] for column in inspector.get_columns("kaya_migration_state")}
        optional_columns = {
            "original_source_fingerprint",
            "conversion_source_fingerprint",
            "original_source_snapshot_fingerprint",
            "source_revision",
            "target_revision",
        }
        selected_columns = [
            "state",
            "migration_id",
            "source_fingerprint",
            *(column for column in optional_columns if column in columns),
        ]
        with target.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT " + ", ".join(selected_columns) + " "
                    "FROM kaya_migration_state ORDER BY started_at DESC LIMIT 1"
                )
            ).mappings().one_or_none()
        if not row or row["state"] != "FAILED" or row["migration_id"] != migration_id:
            raise RuntimeError("Refusing cleanup: target is not the matching failed migration target.")
        if "original_source_fingerprint" in columns:
            if row["original_source_fingerprint"] != source_fingerprint:
                raise RuntimeError("Refusing cleanup: target original source fingerprint does not match.")
            if (
                source_snapshot is None
                or row.get("original_source_snapshot_fingerprint") != source_snapshot
            ):
                raise RuntimeError("Refusing cleanup: target logical source snapshot identity does not match.")
            if (
                not isinstance(row.get("conversion_source_fingerprint"), str)
                or len(row["conversion_source_fingerprint"]) != 64
            ):
                raise RuntimeError("Refusing cleanup: target conversion source identity is invalid.")
            if row["conversion_source_fingerprint"] != source_fingerprint and (
                data_dir is None
                or source_path is None
                or source_revision is None
                or verified_backup is None
                or not _legacy_historical_target_matches(
                    data_dir,
                    source_path,
                    source_revision,
                    {
                        "source_fingerprint": row["conversion_source_fingerprint"],
                        "source_revision": row.get("source_revision"),
                        "target_revision": row.get("target_revision"),
                    },
                    verified_backup,
                )
            ):
                raise RuntimeError("Refusing cleanup: target conversion source identity does not match.")
        elif row["source_fingerprint"] != source_fingerprint:
            if (
                data_dir is None
                or source_path is None
                or source_revision is None
                or verified_backup is None
                or not _legacy_historical_target_matches(
                    data_dir, source_path, source_revision, row, verified_backup
                )
            ):
                raise RuntimeError("Refusing cleanup: target is not the matching failed migration target.")
        with target.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        logger.info("failed PostgreSQL migration target cleaned migration_id=%s", migration_id)
    finally:
        target.dispose()


def prepare_failed_retry(data_dir: Path, source_fingerprint: str) -> Path:
    """Permit retry only after a matching failed source marker is verified."""
    marker = state_path(data_dir)
    persisted, source, _, source_snapshot, verified_backup = _validate_failed_source_identity(
        data_dir, str((_read_state(marker) or {}).get("migration_id") or ""), source_fingerprint
    )
    values: dict[str, Any] = {
        "database_engine": "sqlite",
        "source_path": str(source),
        "source_fingerprint": source_fingerprint,
        "original_source_fingerprint": source_fingerprint,
        "original_source_snapshot_fingerprint": source_snapshot,
        "recovery_artifacts_retained": True,
    }
    if persisted.get("conversion_source_fingerprint"):
        values["conversion_source_fingerprint"] = persisted["conversion_source_fingerprint"]
    _write_state(marker, UpgradeState.PRECHECK, **values)
    return verified_backup


def _assert_pre_target_postgres_absent(target_url: str) -> None:
    target = create_engine(target_url, **postgres_engine_options(get_settings()))
    try:
        tables = set(inspect(target).get_table_names())
    except Exception as exc:
        raise RuntimeError(
            "Refusing pre-target retry: PostgreSQL target state could not be verified."
        ) from exc
    finally:
        target.dispose()
    if tables:
        raise RuntimeError(
            "Refusing pre-target retry: PostgreSQL target migration evidence exists."
        )
    logger.info("database.recovery pre_target_postgres=absent")


def prepare_failed_pretarget_retry(data_dir: Path, target_url: str) -> Path:
    """Verify a FAILED migration stopped before target creation and return its backup."""
    persisted = _read_state(state_path(data_dir))
    if not persisted or persisted.get("state") != UpgradeState.FAILED.value:
        raise RuntimeError("Refusing pre-target retry: source marker is not FAILED.")
    if "migration_id" in persisted and persisted["migration_id"] is not None:
        raise RuntimeError("Refusing pre-target retry: migration target may have started.")
    if persisted.get("database_engine") != "sqlite":
        raise RuntimeError("Refusing pre-target retry: PostgreSQL is authoritative.")
    source_fingerprint = persisted.get("source_fingerprint")
    original_fingerprint = persisted.get("original_source_fingerprint")
    if not isinstance(source_fingerprint, str) or len(source_fingerprint) != 64:
        raise RuntimeError("Refusing pre-target retry: FAILED source identity is missing.")
    if original_fingerprint is not None and original_fingerprint != source_fingerprint:
        raise RuntimeError("Refusing pre-target retry: original source identity is inconsistent.")
    source = _persisted_source_path(persisted, data_dir)
    if _source_fingerprint(source) != source_fingerprint:
        raise RuntimeError("Refusing pre-target retry: source fingerprint does not match FAILED marker.")
    backup_snapshot, backup_revision, verified_backup = _verified_backup_snapshot(
        data_dir, persisted, source, str(persisted.get("source_revision") or "")
    )
    with isolated_sqlite_snapshot(source, data_dir) as isolated_source:
        source_revision = _read_sqlite_revision(isolated_source)
        if source_revision != backup_revision:
            raise RuntimeError("Refusing pre-target retry: source revision does not match backup lineage.")
        if _logical_sqlite_fingerprint(isolated_source) != backup_snapshot:
            raise RuntimeError("Refusing pre-target retry: source snapshot identity changed.")
    persisted_snapshot = persisted.get("original_source_snapshot_fingerprint")
    if not isinstance(persisted_snapshot, str) or persisted_snapshot != backup_snapshot:
        raise RuntimeError("Refusing pre-target retry: persisted snapshot identity is invalid.")
    conversion_fingerprint = persisted.get("conversion_source_fingerprint")
    if conversion_fingerprint not in {None, source_fingerprint}:
        raise RuntimeError("Refusing pre-target retry: conversion source identity is inconsistent.")
    _assert_pre_target_postgres_absent(target_url)
    _write_state(
        state_path(data_dir),
        UpgradeState.PRECHECK,
        database_engine="sqlite",
        source_path=str(source),
        source_fingerprint=source_fingerprint,
        original_source_fingerprint=source_fingerprint,
        original_source_snapshot_fingerprint=backup_snapshot,
        conversion_source_fingerprint=conversion_fingerprint or source_fingerprint,
        target_revision=persisted.get("target_revision"),
        migration_id=None,
        recovery_artifacts_retained=True,
    )
    logger.info("database.recovery pre_target_retry=verified backup=retained")
    return verified_backup
