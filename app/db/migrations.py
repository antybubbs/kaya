from __future__ import annotations

import logging
import sqlite3
import tempfile
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Engine

from app.core.config import Settings, sqlite_database_path
from app.db.backup import MigrationBackup, create_sqlite_backup, prune_migration_backups
from app.db.compatibility import (
    BaselineCompatibilityError,
    create_missing_baseline_objects,
    migrate_pre_alembic_database,
)
from app.db.validation import (
    DatabaseValidationError,
    SQLITE_BUSY_TIMEOUT_MS,
    classify_sqlite_error,
    validate_legacy_database,
    validate_schema,
    validate_startup_database,
)
from app.models.models import Base

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
BASELINE_REVISION = "20260730_01"
CURRENT_REVISION = "20260813_01"
STAGE_OPENING_DATABASE = "Opening database"
STAGE_INTEGRITY_CHECKS = "Checking database readability"
STAGE_CREATING_BACKUP = "Creating backup"
STAGE_COMPATIBILITY = "Running compatibility migration"
STAGE_ALEMBIC_MIGRATION = "Running Alembic migration"
STAGE_SCHEMA_VALIDATION = "Running schema validation"
STAGE_STAMPING_REVISION = "Stamping Alembic revision"
STAGE_BACKUP_RETENTION = "Applying backup retention"
STAGE_STARTUP_COMPLETE = "Startup complete"


class DatabaseMigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class MigrationResult:
    previous_revision: str | None
    current_revision: str
    backup: MigrationBackup | None
    compatibility_applied: bool


@dataclass
class MigrationProgress:
    stage: str = STAGE_OPENING_DATABASE
    stage_started: float = field(default_factory=perf_counter)
    entered: bool = False

    def enter(self, stage: str) -> None:
        now = perf_counter()
        if self.entered:
            logger.info(
                "Kaya database: stage complete: %s (elapsed %.3fs)",
                self.stage,
                now - self.stage_started,
            )
        self.stage = stage
        self.stage_started = now
        self.entered = True
        logger.info("Kaya database: %s", stage)

    def finish(self) -> None:
        logger.info(
            "Kaya database: stage complete: %s (elapsed %.3fs)",
            self.stage,
            perf_counter() - self.stage_started,
        )


def _alembic_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _revision(path: Path) -> str | None:
    try:
        return _read_revision(path)
    except sqlite3.Error as exc:
        raise classify_sqlite_error(
            exc, operation="reading the Alembic revision"
        ) from exc


def _read_revision(path: Path) -> str | None:
    with closing(
        sqlite3.connect(path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1_000)
    ) as connection:
        connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}").close()
        with closing(
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alembic_version'"
            )
        ) as cursor:
            exists = cursor.fetchone()
        if not exists:
            return None
        with closing(
            connection.execute("SELECT version_num FROM alembic_version")
        ) as cursor:
            rows = cursor.fetchall()
    if len(rows) > 1:
        raise DatabaseMigrationError(
            "The database contains multiple Alembic revisions."
        )
    return rows[0][0] if rows else None


def _has_application_tables(engine: Engine) -> bool:
    return bool(set(inspect(engine).get_table_names()) - {"alembic_version"})


def _backup_if_enabled(
    settings: Settings,
    path: Path,
    source_revision: str | None,
    target_revision: str,
    *,
    required: bool = False,
) -> MigrationBackup | None:
    if not settings.migration_backups_enabled and not required:
        logger.warning(
            "Automatic SQLite migration backup disabled by explicit configuration"
        )
        return None
    if not settings.migration_backups_enabled:
        logger.warning(
            "Pre-Alembic transition requires a verified backup; ignoring the disabled-backup setting for this transition"
        )
    return create_sqlite_backup(
        path,
        Path(settings.migration_backup_dir),
        source_revision=source_revision or "pre-alembic",
        target_revision=target_revision,
    )


def _apply_missing_baseline_objects(database_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="kaya-baseline-") as directory:
        baseline_path = Path(directory) / "baseline.sqlite3"
        baseline_config = Config(str(PROJECT_ROOT / "alembic.ini"))
        baseline_config.set_main_option(
            "script_location", str(PROJECT_ROOT / "migrations")
        )
        baseline_config.set_main_option(
            "sqlalchemy.url", f"sqlite:///{baseline_path.as_posix()}"
        )
        command.upgrade(baseline_config, BASELINE_REVISION)
        create_missing_baseline_objects(database_path, baseline_path, Base.metadata)


def prepare_database(engine: Engine, settings: Settings) -> MigrationResult:
    """Bring a database safely to Alembic head before application services start."""
    started = perf_counter()
    progress = MigrationProgress()
    backup = None
    compatibility_applied = False
    migration_required = False
    schema_fully_validated = False
    try:
        progress.enter(STAGE_OPENING_DATABASE)
        database_path = sqlite_database_path(settings.database_url)
        if database_path is None:
            raise DatabaseMigrationError(
                "Only file-backed SQLite migration is currently supported."
            )
        config = _alembic_config(settings.database_url)
        script = ScriptDirectory.from_config(config)
        heads = script.get_heads()
        if len(heads) != 1:
            head_list = ", ".join(sorted(heads)) or "none"
            logger.error(
                "Multiple Alembic migration heads detected: %s. Database has not "
                "been modified. Developer action required: merge the migration heads.",
                head_list,
            )
            raise DatabaseMigrationError(
                f"Multiple Alembic migration heads detected: {head_list}. "
                "Database has not been modified; developer action required: merge the migration heads."
            )
        target_revision = heads[0]
        detected_revision = _revision(database_path) if database_path.exists() else None
        logger.debug(
            "Database migration starting: type=sqlite current=%s target=%s",
            detected_revision,
            target_revision,
        )
        if not database_path.exists() or not _has_application_tables(engine):
            logger.info("Kaya database: fresh database detected")
            database_path.parent.mkdir(parents=True, exist_ok=True)
            migration_required = True
            progress.enter(STAGE_ALEMBIC_MIGRATION)
            command.upgrade(config, "head")
            previous_revision = None
        else:
            previous_revision = detected_revision
            if previous_revision is None:
                logger.info("Kaya database: existing pre-Alembic database detected")
                migration_required = True
                progress.enter(STAGE_INTEGRITY_CHECKS)
                validate_legacy_database(database_path)
                progress.enter(STAGE_CREATING_BACKUP)
                backup = _backup_if_enabled(
                    settings,
                    database_path,
                    None,
                    BASELINE_REVISION,
                    required=True,
                )
                if backup:
                    logger.info(
                        "Kaya database: backup ready filename=%s",
                        backup.database_path.name,
                    )
                progress.enter(STAGE_COMPATIBILITY)
                logger.info("Kaya database: running compatibility upgrade")
                migrate_pre_alembic_database(database_path)
                _apply_missing_baseline_objects(database_path)
                compatibility_applied = True
                logger.info("Kaya database: compatibility upgrade complete")
                progress.enter(STAGE_SCHEMA_VALIDATION)
                try:
                    validate_schema(
                        database_path, Base.metadata, require_revision=False
                    )
                except DatabaseValidationError:
                    # A historical database now has the complete baseline schema,
                    # but legitimately lacks objects introduced after that baseline.
                    progress.enter(STAGE_STAMPING_REVISION)
                    command.stamp(config, BASELINE_REVISION)
                    logger.info("Kaya database: baseline stamped")
                    progress.enter(STAGE_ALEMBIC_MIGRATION)
                    command.upgrade(config, "head")
                else:
                    # The revision table alone was lost from an otherwise current
                    # database. Stamping head avoids replaying already-present DDL.
                    progress.enter(STAGE_STAMPING_REVISION)
                    command.stamp(config, target_revision)
                    logger.info("Kaya database: current schema stamped")
                    schema_fully_validated = True
            elif previous_revision != target_revision:
                # ScriptDirectory rejects an unknown revision before any write.
                script.get_revision(previous_revision)
                migration_required = True
                logger.info(
                    "Kaya database: Alembic upgrade required current=%s target=%s",
                    previous_revision,
                    target_revision,
                )
                progress.enter(STAGE_CREATING_BACKUP)
                backup = _backup_if_enabled(
                    settings, database_path, previous_revision, target_revision
                )
                if backup:
                    logger.info(
                        "Kaya database: backup ready filename=%s",
                        backup.database_path.name,
                    )
                progress.enter(STAGE_ALEMBIC_MIGRATION)
                command.upgrade(config, "head")
        current_revision = _revision(database_path)
        if current_revision != target_revision:
            raise DatabaseMigrationError(
                f"Database revision {current_revision!r} does not match target {target_revision!r}."
            )
        progress.enter(STAGE_SCHEMA_VALIDATION)
        if migration_required and not schema_fully_validated:
            validate_schema(database_path, Base.metadata)
        else:
            validate_startup_database(
                database_path, required_tables=Base.metadata.tables
            )
        if backup:
            progress.enter(STAGE_BACKUP_RETENTION)
            prune_migration_backups(
                Path(settings.migration_backup_dir),
                settings.migration_backup_retention_count,
            )
        progress.enter(STAGE_STARTUP_COMPLETE)
        progress.finish()
    except Exception as exc:
        location = (
            backup.database_path.name if backup else "no verified backup was created"
        )
        if progress.stage == STAGE_COMPATIBILITY and isinstance(
            exc, BaselineCompatibilityError
        ):
            # create_missing_baseline_objects runs its DDL inside one explicit
            # SQLite transaction and rolls back on any failure, so the source
            # database itself is unchanged by this attempt.
            logger.error(
                "Database migration aborted at stage: %s. The source database was "
                "not modified (compatibility DDL is transactional and was rolled "
                "back). Recovery: %s. Backup: %s.",
                progress.stage,
                exc,
                location,
            )
        else:
            logger.error(
                "Database migration aborted at stage: %s. Recovery: restore %s and inspect migration logs.",
                progress.stage,
                location,
            )
        if isinstance(exc, DatabaseMigrationError):
            raise
        raise DatabaseMigrationError(
            "Database preparation failed; application startup has been aborted."
        ) from exc
    logger.debug("Database preparation completed in %.3fs", perf_counter() - started)
    if migration_required:
        logger.info(
            "Kaya database ready: revision=%s migrated=true backup=%s",
            current_revision,
            backup.database_path.name if backup else "none",
        )
    else:
        logger.info(
            "Kaya database ready: revision=%s migration_required=false",
            current_revision,
        )
    return MigrationResult(
        previous_revision, current_revision, backup, compatibility_applied
    )
