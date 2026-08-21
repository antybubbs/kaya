"""Fail-closed compatibility checks for Kaya's supported database platform."""

from __future__ import annotations

import re
from dataclasses import dataclass

from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


SUPPORTED_POSTGRES_MAJOR = 16
SUPPORTED_POSTGRES_IMAGE = "postgres:16.14"


class DatabasePlatformCompatibilityError(RuntimeError):
    """The database is not safe for this Kaya image."""


@dataclass(frozen=True)
class PlatformVersion:
    server_version: str
    server_version_num: int
    major: int


def postgres_server_version(engine: Engine) -> PlatformVersion:
    """Read and parse the server-reported PostgreSQL version."""
    with engine.connect() as connection:
        version = str(connection.execute(text("SHOW server_version")).scalar_one())
        number = int(connection.execute(text("SHOW server_version_num")).scalar_one())
    major = number // 10000 if number >= 100000 else number // 10000
    if major < 1:
        match = re.match(r"(\d+)", version)
        major = int(match.group(1)) if match else 0
    return PlatformVersion(version, number, major)


def migration_graph(script: ScriptDirectory) -> dict:
    """Return non-sensitive, machine-readable migration graph facts."""
    revisions = list(script.walk_revisions())
    ids = [revision.revision for revision in revisions]
    duplicate_ids = sorted({revision for revision in ids if ids.count(revision) > 1})
    known = set(ids)
    missing_down = sorted(
        {
            down_revision
            for revision in revisions
            for down_revision in (
                revision.down_revision
                if isinstance(revision.down_revision, tuple)
                else (revision.down_revision,)
            )
            if down_revision and down_revision not in known
        }
    )
    heads = sorted(script.get_heads())
    return {
        "current_heads": heads,
        "head_count": len(heads),
        "current_head": heads[0] if len(heads) == 1 else None,
        "revision_count": len(ids),
        "missing_down_revisions": missing_down,
        "duplicate_revision_ids": duplicate_ids,
    }


def validate_postgres_platform(
    engine: Engine, script: ScriptDirectory
) -> PlatformVersion:
    """Validate PostgreSQL major and packaged migration graph before DDL."""
    if engine.dialect.name != "postgresql":
        raise DatabasePlatformCompatibilityError(
            "Kaya production requires PostgreSQL; the configured database engine is unsupported."
        )
    version = postgres_server_version(engine)
    if version.major != SUPPORTED_POSTGRES_MAJOR:
        raise DatabasePlatformCompatibilityError(
            "Unsupported PostgreSQL major version. Kaya supports PostgreSQL 16; "
            "use a compatible PostgreSQL server or a supported Kaya release."
        )
    graph = migration_graph(script)
    if graph["head_count"] != 1 or graph["missing_down_revisions"] or graph["duplicate_revision_ids"]:
        raise DatabasePlatformCompatibilityError(
            "The packaged Alembic migration graph is invalid; exactly one complete head is required."
        )
    revisions = []
    with engine.connect() as connection:
        if "alembic_version" in inspect(connection).get_table_names():
            revisions = list(
                connection.execute(text("SELECT version_num FROM alembic_version"))
                .scalars()
                .all()
            )
    if len(revisions) > 1:
        raise DatabasePlatformCompatibilityError(
            "Database contains multiple Alembic revisions; startup is stopped safely."
        )
    if revisions:
        current = revisions[0]
        try:
            traversed = {
                revision.revision
                for revision in script.iterate_revisions(graph["current_head"], current)
            }
        except Exception as exc:
            raise DatabasePlatformCompatibilityError(
                "Database schema revision is not present in this Kaya image's migration chain. "
                "Use a compatible/newer Kaya image or restore a compatible backup."
            ) from exc
        if current not in traversed:
            if current == graph["current_head"]:
                return version
            raise DatabasePlatformCompatibilityError(
                "Database schema is newer than this Kaya image supports. "
                "Use a compatible/newer Kaya image or restore a compatible backup."
            )
    return version
