"""The Data Integrity migration is additive and grants the repair capability to administrators only."""
import sqlite3

from alembic import command
from sqlalchemy.orm import Session

from app.db.migrations import _alembic_config
from app.models.models import HardwareAsset, User
from tests.test_database_migrations import engine_for, settings_for


def _grants(path):
    with sqlite3.connect(path) as connection:
        return sorted(connection.execute(
            "SELECT users.email, permissions.allowed FROM user_module_permissions permissions "
            "JOIN users ON users.id = permissions.user_id WHERE permissions.module_key = 'data_integrity.repair'"
        ).fetchall())


def test_upgrade_grants_repair_capability_to_existing_administrators_and_downgrade_removes_it(tmp_path):
    path = tmp_path / "kaya.db"
    config = _alembic_config(settings_for(path, tmp_path / "backups").database_url)
    command.upgrade(config, "20261018_01")
    with Session(engine_for(path)) as db:
        db.add_all([
            User(email=f"{role}@example.invalid", password_hash="fake-hash", role=role, is_active=True)
            for role in ("admin", "editor", "viewer")
        ])
        db.add(HardwareAsset(name="Synthetic asset", status="In use"))
        db.commit()

    command.upgrade(config, "head")
    assert _grants(path) == [("admin@example.invalid", 1)]
    with sqlite3.connect(path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'data_integrity_%'")}
        assert tables == {"data_integrity_runs", "data_integrity_findings", "data_integrity_finding_events"}
        assert connection.execute("SELECT COUNT(*) FROM data_integrity_findings").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM hardware_assets").fetchone() == (1,)

    command.upgrade(config, "head")  # idempotent at head
    assert _grants(path) == [("admin@example.invalid", 1)]

    command.downgrade(config, "20261018_01")
    assert _grants(path) == []
    with sqlite3.connect(path) as connection:
        assert not connection.execute("SELECT name FROM sqlite_master WHERE name LIKE 'data_integrity_%'").fetchall()
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone() == (3,)
