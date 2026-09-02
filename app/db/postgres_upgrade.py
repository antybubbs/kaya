"""Read-only PostgreSQL patch-upgrade preflight and verification helpers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from app.db.migrations import CURRENT_REVISION
from app.db.platform_compatibility import (
    SUPPORTED_POSTGRES_IMAGE,
    SUPPORTED_POSTGRES_MAJOR,
    postgres_server_version,
)

POSTGRES_IMAGE_PATTERN = re.compile(r"^postgres:(\d+)\.(\d+)$")
DEFAULT_BACKUP_MAX_AGE_HOURS = 168


class PostgresUpgradePreflightError(RuntimeError):
    """The deployment is not safe to begin a PostgreSQL patch upgrade."""


def parse_postgres_image(image: str) -> tuple[int, int]:
    """Validate a precise PostgreSQL image tag and return major/minor."""
    match = POSTGRES_IMAGE_PATTERN.fullmatch(image.strip())
    if not match:
        raise PostgresUpgradePreflightError(
            "PostgreSQL image must use an explicit postgres:<major>.<minor> tag."
        )
    major, minor = (int(value) for value in match.groups())
    if major < 1 or minor < 0:
        raise PostgresUpgradePreflightError("PostgreSQL image version is invalid.")
    return major, minor


def _iso_age_hours(value: str) -> float:
    created = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return max(0.0, (datetime.now(UTC) - created).total_seconds() / 3600)


def latest_verified_backup(
    backup_directory: Path, *, max_age_hours: float
) -> dict[str, Any] | None:
    """Return the newest locally verified backup metadata within the age limit."""
    candidates: list[dict[str, Any]] = []
    for metadata_path in backup_directory.glob("kaya-*.dump.json"):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            archive = metadata_path.with_suffix("")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if metadata.get("verification_state") != "verified":
                continue
            if metadata.get("sha256") != digest:
                continue
            if int(metadata.get("archive_bytes", -1)) != archive.stat().st_size:
                continue
            age_hours = _iso_age_hours(str(metadata["created_at"]))
            if age_hours > max_age_hours:
                continue
            metadata["archive"] = archive.name
            metadata["age_hours"] = round(age_hours, 3)
            candidates.append(metadata)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
    return max(candidates, key=lambda item: item["created_at"]) if candidates else None


def collect_upgrade_preflight(
    engine: Engine,
    backup_directory: Path,
    target_image: str,
    *,
    max_backup_age_hours: float = DEFAULT_BACKUP_MAX_AGE_HOURS,
    allow_stale_backup: bool = False,
) -> dict[str, Any]:
    """Collect safe upgrade facts without changing the database."""
    if max_backup_age_hours <= 0:
        raise PostgresUpgradePreflightError("backup age limit must be positive")
    target_major, target_minor = parse_postgres_image(target_image)
    if target_major != SUPPORTED_POSTGRES_MAJOR:
        raise PostgresUpgradePreflightError(
            f"Target PostgreSQL major {target_major} is unsupported; Kaya supports PostgreSQL {SUPPORTED_POSTGRES_MAJOR}."
        )
    if engine.dialect.name != "postgresql":
        raise PostgresUpgradePreflightError("PostgreSQL is required for this preflight.")
    try:
        version = postgres_server_version(engine)
        with engine.connect() as connection:
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version LIMIT 1")
            ).scalar_one_or_none()
            connection.execute(text("SELECT 1")).scalar_one()
            table_exists = "users" in inspect(connection).get_table_names()
    except Exception as exc:
        raise PostgresUpgradePreflightError("PostgreSQL reachability check failed.") from exc
    if version.major != SUPPORTED_POSTGRES_MAJOR:
        raise PostgresUpgradePreflightError(
            f"Current PostgreSQL major {version.major} is unsupported; expected {SUPPORTED_POSTGRES_MAJOR}."
        )
    if revision != CURRENT_REVISION:
        raise PostgresUpgradePreflightError(
            f"Alembic revision is {revision or 'unknown'}; expected {CURRENT_REVISION}."
        )
    backup = latest_verified_backup(
        backup_directory, max_age_hours=max_backup_age_hours
    )
    if backup is None and not allow_stale_backup:
        raise PostgresUpgradePreflightError(
            "No recent verified PostgreSQL backup is available. Create and verify one before upgrading."
        )
    return {
        "current_postgres_version": version.server_version,
        "current_postgres_major": version.major,
        "target_postgres_image": target_image,
        "target_postgres_major": target_major,
        "target_postgres_minor": target_minor,
        "current_alembic_revision": revision,
        "expected_alembic_head": CURRENT_REVISION,
        "database_reachable": True,
        "representative_schema_available": table_exists,
        "database_compatibility": "compatible",
        "recommended_postgres_image": SUPPORTED_POSTGRES_IMAGE,
        "latest_verified_backup": backup,
        "backup_required": True,
        "backup_max_age_hours": max_backup_age_hours,
        "backup_override_used": bool(allow_stale_backup and backup is None),
    }
