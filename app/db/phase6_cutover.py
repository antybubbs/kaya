"""Durable, fail-closed orchestration for the SQLite-to-PostgreSQL upgrade."""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from alembic.util.exc import CommandError
from sqlalchemy import create_engine, inspect, text

from app.core.config import redact_database_url, sqlite_database_path
from app.db.backup import create_sqlite_backup
from app.db.phase6_test_hooks import hit as test_failpoint, validate_configuration as validate_test_configuration
from app.db.migrations import prepare_database
from app.db.sqlite_to_postgres import _heads, migrate, preflight
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
        "legacy_sqlite schema_upgrade state=starting source_revision=%s target_revision=%s",
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
    shutil.copyfile(source_backup.database_path, working_path)
    os.chmod(working_path, 0o600)
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
    try:
        result = prepare_database(source_engine, settings)
    finally:
        source_engine.dispose()
    if result.previous_revision != source_revision:
        raise RuntimeError(
            "historical SQLite working copy had an unexpected Alembic revision"
        )
    if result.current_revision != expected_head:
        raise RuntimeError(
            f"historical SQLite upgrade stopped at {result.current_revision}; expected {expected_head}"
        )
    logger.info(
        "legacy_sqlite schema_upgrade state=complete source_revision=%s target_revision=%s backup=%s validation=passed",
        source_revision,
        expected_head,
        source_backup.database_path.name,
    )
    return working_path


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


def run_upgrade(source_path: Path, target_url: str, backup_dir: Path, data_dir: Path) -> dict[str, Any]:
    """Run the existing migrator and commit PostgreSQL authority only after validation."""
    marker = state_path(data_dir)
    validate_test_configuration()
    installation = detect_installation(f"sqlite:///{source_path}", data_dir)
    if installation.state not in {UpgradeState.SQLITE_ACTIVE, UpgradeState.PRECHECK}:
        raise RuntimeError(f"SQLite upgrade is not eligible from state {installation.state}.")
    _write_state(marker, UpgradeState.PRECHECK, database_engine="sqlite", source_path=str(source_path))
    dry_run: dict[str, Any] = {}
    try:
        dry_run = preflight(source_path, target_url, True)
        _write_state(marker, UpgradeState.MAINTENANCE, database_engine="sqlite", source_fingerprint=dry_run["source_fingerprint"], target_revision=dry_run["target_revision"], progress="writes and background workers are stopped before conversion")
        source_revision = dry_run.get("source_revision")
        conversion_source = source_path
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
        def transition(name: str) -> None:
            state = UpgradeState(name)
            _write_state(
                marker,
                state,
                database_engine="sqlite" if state in {UpgradeState.BACKED_UP, UpgradeState.POSTGRES_PREPARED, UpgradeState.MIGRATING, UpgradeState.VALIDATING} else "postgresql",
                source_fingerprint=dry_run["source_fingerprint"],
                target_revision=dry_run["target_revision"],
            )

        test_failpoint("fail_state")
        report = migrate(conversion_source, target_url, backup_dir, state_callback=transition)
        if report.get("result") != "COMPLETED":
            raise RuntimeError("SQLite migration did not complete.")
        source_fingerprint = dry_run["source_fingerprint"]
        _write_state(marker, UpgradeState.POSTGRES_READY, database_engine="postgresql", target_url=redact_database_url(target_url), source_fingerprint=source_fingerprint, target_revision=report["target_revision"], migration_id=report["migration_id"])
        safe_report = {key: value for key, value in report.items() if key not in {"source_backup"} or isinstance(value, dict)}
        _write_state(report_path(data_dir), UpgradeState.POSTGRES_READY, **safe_report)
        _write_state(marker, UpgradeState.CUTOVER_PENDING, database_engine="sqlite", target_url=redact_database_url(target_url), source_path=str(source_path), source_fingerprint=source_fingerprint, target_revision=report["target_revision"], migration_id=report["migration_id"])
        test_failpoint("pause_cutover_pending")
        _write_state(marker, UpgradeState.POSTGRES_ACTIVE, database_engine="postgresql", target_url=redact_database_url(target_url), source_path=str(source_path), source_fingerprint=source_fingerprint, target_revision=report["target_revision"], migration_id=report["migration_id"], recovery_artifacts_retained=True)
        test_failpoint("pause_after_postgres_active")
        logger.info("database migration and cutover completed source=%s target=%s", source_path.name, redact_database_url(target_url))
        return report
    except Exception as exc:
        _write_state(
            marker,
            UpgradeState.FAILED,
            database_engine="sqlite",
            source_path=str(source_path),
            source_fingerprint=dry_run.get("source_fingerprint"),
            target_revision=dry_run.get("target_revision"),
            migration_id=getattr(exc, "migration_id", None),
            error=type(exc).__name__,
            recovery_artifacts_retained=True,
        )
        logger.error("database migration failed; SQLite remains authoritative and preserved")
        raise


def clean_failed_target(target_url: str, migration_id: str, source_fingerprint: str) -> None:
    """Reset only a target proven to be this upgrade's failed, non-active target."""
    target = create_engine(target_url, **postgres_engine_options(get_settings()))
    try:
        inspector = inspect(target)
        if "kaya_migration_state" not in inspector.get_table_names():
            raise RuntimeError("Refusing cleanup: target has no Kaya migration marker.")
        with target.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT state, migration_id, source_fingerprint "
                    "FROM kaya_migration_state ORDER BY started_at DESC LIMIT 1"
                )
            ).mappings().one_or_none()
        if not row or row["state"] != "FAILED" or row["migration_id"] != migration_id or row["source_fingerprint"] != source_fingerprint:
            raise RuntimeError("Refusing cleanup: target is not the matching failed migration target.")
        with target.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        logger.info("failed PostgreSQL migration target cleaned migration_id=%s", migration_id)
    finally:
        target.dispose()


def prepare_failed_retry(data_dir: Path, source_fingerprint: str) -> None:
    """Permit retry only after a matching failed source marker is verified."""
    marker = state_path(data_dir)
    persisted = _read_state(marker)
    if not persisted or persisted.get("state") != UpgradeState.FAILED.value:
        raise RuntimeError("Refusing retry: source marker is not FAILED.")
    if persisted.get("source_fingerprint") != source_fingerprint:
        raise RuntimeError("Refusing retry: source fingerprint does not match FAILED marker.")
    _write_state(
        marker,
        UpgradeState.PRECHECK,
        database_engine="sqlite",
        source_path=persisted.get("source_path"),
        source_fingerprint=source_fingerprint,
        recovery_artifacts_retained=True,
    )
