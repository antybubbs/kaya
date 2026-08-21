import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.db.postgres_upgrade import (
    PostgresUpgradePreflightError,
    collect_upgrade_preflight,
    latest_verified_backup,
    parse_postgres_image,
)
from app.db.platform_compatibility import PlatformVersion


def test_parse_postgres_image_requires_precise_tag():
    assert parse_postgres_image("postgres:16.14") == (16, 14)
    with pytest.raises(PostgresUpgradePreflightError):
        parse_postgres_image("postgres:16")
    with pytest.raises(PostgresUpgradePreflightError):
        parse_postgres_image("postgres:16.14@sha256:synthetic")


def test_latest_verified_backup_checks_archive_digest_and_state(tmp_path: Path):
    archive = tmp_path / "kaya-20260821T010000Z.dump"
    archive.write_bytes(b"synthetic custom archive")
    metadata = {
        "archive_bytes": archive.stat().st_size,
        "created_at": "2026-08-21T01:00:00Z",
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "verification_state": "verified",
    }
    archive.with_name(archive.name + ".json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )
    assert latest_verified_backup(tmp_path, max_age_hours=10000)["archive"] == archive.name
    metadata["verification_state"] = "pending"
    archive.with_name(archive.name + ".json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )
    assert latest_verified_backup(tmp_path, max_age_hours=10000) is None


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value


class _Connection:
    def execute(self, statement):
        sql = str(statement)
        if "version_num" in sql:
            return _Result("20260818_02")
        return _Result(1)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _Engine:
    dialect = SimpleNamespace(name="postgresql")

    def connect(self):
        return _Connection()


def test_preflight_requires_recent_verified_backup(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        "app.db.postgres_upgrade.postgres_server_version",
        lambda _engine: PlatformVersion("16.14", 160014, 16),
    )
    monkeypatch.setattr(
        "app.db.postgres_upgrade.inspect",
        lambda _connection: SimpleNamespace(get_table_names=lambda: ["users"]),
    )
    with pytest.raises(PostgresUpgradePreflightError, match="verified PostgreSQL backup"):
        collect_upgrade_preflight(_Engine(), tmp_path, "postgres:16.14")
