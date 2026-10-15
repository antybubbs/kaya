from datetime import datetime

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text

from app.db.migrations import _alembic_config


def _upgrade(path):
    url = f"sqlite:///{path.as_posix()}"
    command.upgrade(_alembic_config(url), "20261017_01")
    return url


def test_assignment_monitoring_schema_is_additive_and_round_trips(tmp_path):
    path = tmp_path / "stage2a-test.db"
    url = _upgrade(path)
    engine = create_engine(url)
    try:
        inspector = inspect(engine)
        monitoring_columns = {row["name"] for row in inspector.get_columns("traffic_device_monitoring")}
        period_columns = {row["name"] for row in inspector.get_columns("traffic_device_monitoring_periods")}
        aggregate_columns = {row["name"] for row in inspector.get_columns("traffic_device_aggregates")}
        assert {"asset_id", "assignment_id"} <= monitoring_columns
        assert {"asset_id", "assignment_id", "endpoint_address", "address_family", "exporter_identity"} <= period_columns
        assert {"asset_id", "assignment_id", "endpoint_address", "address_family", "exporter_identity"} <= aggregate_columns
        with engine.begin() as db:
            assert db.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "20261017_01"
        command.downgrade(_alembic_config(url), "20261016_01")
        command.upgrade(_alembic_config(url), "20261017_01")
    finally:
        engine.dispose()


def test_assignment_monitoring_downgrade_refuses_incompatible_rows(tmp_path):
    path = tmp_path / "stage2a-guard-test.db"
    url = _upgrade(path)
    engine = create_engine(url)
    now = datetime.utcnow().isoformat(sep=" ")
    try:
        with engine.begin() as db:
            db.execute(text("INSERT INTO hardware_assets (id, name, status, created_at, updated_at) VALUES (910001, 'Stage 2A synthetic asset', 'In use', :now, :now)"), {"now": now})
            db.execute(text("INSERT INTO asset_network_assignments (id, asset_id, address, address_family, started_at, provenance, status, created_at, updated_at) VALUES (910001, 910001, '192.0.2.90', 4, :now, 'stage2a_test', 'confirmed', :now, :now)"), {"now": now})
            db.execute(text("INSERT INTO traffic_device_monitoring (id, asset_id, assignment_id, is_enabled, status, updated_at) VALUES (910001, 910001, 910001, 1, 'active', :now)"), {"now": now})
        with pytest.raises(RuntimeError, match="assignment-backed"):
            command.downgrade(_alembic_config(url), "20261016_01")
    finally:
        engine.dispose()
