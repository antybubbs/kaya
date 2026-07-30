from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.db.validation import (
    SQLITE_BUSY_TIMEOUT_MS,
    DatabaseValidationError,
    validate_sqlite_integrity,
)

logger = logging.getLogger(__name__)
BACKUP_OPERATION_TIMEOUT_SECONDS = 600.0
_HASH_CHUNK_BYTES = 1024 * 1024


class DatabaseBackupError(RuntimeError):
    pass


@dataclass(frozen=True)
class MigrationBackup:
    database_path: Path
    metadata_path: Path


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _source_fingerprint(source: Path) -> str:
    """Fingerprint the main database and WAL without recording database content."""
    digest = hashlib.sha256()
    for label, candidate in (
        (b"database\0", source),
        (b"wal\0", source.with_name(source.name + "-wal")),
    ):
        digest.update(label)
        if not candidate.is_file():
            digest.update(b"missing\0")
            continue
        digest.update(str(candidate.stat().st_size).encode("ascii") + b"\0")
        with candidate.open("rb") as handle:
            while chunk := handle.read(_HASH_CHUNK_BYTES):
                digest.update(chunk)
    return digest.hexdigest()


def _reusable_backup(
    backup_directory: Path,
    source: Path,
    *,
    source_revision: str,
    target_revision: str,
    source_fingerprint: str,
) -> MigrationBackup | None:
    for metadata_path in sorted(
        backup_directory.glob("pre-migration-*.json"), reverse=True
    ):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            backup_filename = metadata.get("backup_filename")
            if (
                not isinstance(backup_filename, str)
                or Path(backup_filename).name != backup_filename
            ):
                continue
            if not (
                metadata.get("source_filename") == source.name
                and metadata.get("source_revision") == source_revision
                and metadata.get("target_revision") == target_revision
                and metadata.get("source_fingerprint") == source_fingerprint
            ):
                continue
            backup_path = backup_directory / backup_filename
            if not backup_path.is_file() or metadata.get(
                "backup_sha256"
            ) != _file_sha256(backup_path):
                logger.warning(
                    "Ignoring reusable migration backup candidate with failed digest verification"
                )
                continue
            validate_sqlite_integrity(backup_path)
        except (OSError, ValueError, DatabaseValidationError):
            logger.warning(
                "Ignoring unreadable or invalid reusable migration backup candidate"
            )
            continue
        logger.debug(
            "Reusing verified migration backup for unchanged database: %s",
            backup_path.name,
        )
        return MigrationBackup(backup_path, metadata_path)
    return None


def create_sqlite_backup(
    source: Path,
    backup_directory: Path,
    *,
    source_revision: str,
    target_revision: str,
) -> MigrationBackup:
    """Create and verify an immutable pre-migration backup using SQLite's API."""
    source = source.resolve()
    backup_directory = backup_directory.resolve()
    if not source.is_file():
        raise DatabaseBackupError(
            "The SQLite database does not exist or is not a regular file."
        )
    try:
        backup_directory.mkdir(parents=True, exist_ok=True)
        os.chmod(backup_directory, 0o700)
    except OSError as exc:
        raise DatabaseBackupError(
            "Could not prepare the private migration backup directory."
        ) from exc
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    safe_target = target_revision.replace("/", "-")[:64]
    backup_path = backup_directory / f"pre-migration-{safe_target}-{timestamp}.sqlite3"
    metadata_path = backup_path.with_suffix(".json")
    if backup_path.exists() or metadata_path.exists():
        raise DatabaseBackupError("Refusing to overwrite an existing migration backup.")

    source_fingerprint = _source_fingerprint(source)
    reusable = _reusable_backup(
        backup_directory,
        source,
        source_revision=source_revision,
        target_revision=target_revision,
        source_fingerprint=source_fingerprint,
    )
    if reusable is not None:
        return reusable

    logger.debug("SQLite pre-migration backup starting")
    try:
        backup_started = time.monotonic()
        next_progress = backup_started + 5.0

        def backup_progress(status: int, remaining: int, total: int) -> None:
            nonlocal next_progress
            elapsed = time.monotonic() - backup_started
            if elapsed >= BACKUP_OPERATION_TIMEOUT_SECONDS:
                raise DatabaseBackupError(
                    "SQLite backup timed out after "
                    f"{BACKUP_OPERATION_TIMEOUT_SECONDS:.0f}s."
                )
            if time.monotonic() >= next_progress:
                logger.debug(
                    "SQLite pre-migration backup still running: pages=%s/%s elapsed=%.3fs status=%s",
                    total - remaining,
                    total,
                    elapsed,
                    status,
                )
                next_progress = time.monotonic() + 5.0

        with closing(
            sqlite3.connect(source, timeout=SQLITE_BUSY_TIMEOUT_MS / 1_000)
        ) as source_connection:
            source_connection.execute(
                f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}"
            ).close()
            with closing(
                sqlite3.connect(backup_path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1_000)
            ) as backup_connection:
                backup_connection.execute(
                    f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}"
                ).close()
                source_connection.backup(
                    backup_connection,
                    pages=1_000,
                    progress=backup_progress,
                    sleep=0.1,
                )
        os.chmod(backup_path, 0o600)
        validate_sqlite_integrity(backup_path)
        backup_sha256 = _file_sha256(backup_path)
        metadata_path.write_text(
            json.dumps(
                {
                    "created_at": datetime.now(UTC).isoformat(),
                    "source_filename": source.name,
                    "source_revision": source_revision,
                    "target_revision": target_revision,
                    "backup_filename": backup_path.name,
                    "source_fingerprint": source_fingerprint,
                    "backup_sha256": backup_sha256,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(metadata_path, 0o600)
    except Exception as exc:
        for partial in (backup_path, metadata_path):
            try:
                partial.unlink(missing_ok=True)
            except OSError:
                pass
        if isinstance(exc, DatabaseBackupError):
            raise
        raise DatabaseBackupError(
            "Could not create and verify the SQLite migration backup."
        ) from exc
    logger.debug("SQLite pre-migration backup completed: %s", backup_path.name)
    return MigrationBackup(backup_path, metadata_path)


def prune_migration_backups(backup_directory: Path, retention_count: int) -> None:
    """Keep recent backup pairs, while never deleting the sole known-good backup."""
    if retention_count < 1 or not backup_directory.exists():
        return
    backups = sorted(backup_directory.glob("pre-migration-*.sqlite3"), reverse=True)
    for backup in backups[max(retention_count, 1) :]:
        backup.unlink(missing_ok=True)
        backup.with_suffix(".json").unlink(missing_ok=True)
