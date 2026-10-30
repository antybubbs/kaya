import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.models import (
    AssetNetworkAssignment,
    HardwareAsset,
    TrafficDeviceMonitoring,
    TrafficDeviceMonitoringPeriod,
    TrafficMonitoringConfiguration,
    TrafficSource,
    User,
)
from app.services.device_traffic import set_asset_monitoring


@pytest.fixture
def postgres_factory():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=4, max_overflow=0)
    yield sessionmaker(bind=engine)
    engine.dispose()


def test_postgres_concurrent_asset_monitoring_activation_is_serialized(postgres_factory):
    factory = postgres_factory
    now = datetime(2026, 1, 1, 12)
    tag = uuid.uuid4().hex[:10]
    with factory.begin() as db:
        user = User(email=f"stage2b-monitoring-race-{tag}@example.invalid", role="admin")
        asset = HardwareAsset(name=f"Stage 2B monitoring race {tag}", status="In use")
        source = TrafficSource(name=f"Stage 2B monitoring source {tag}", provider_key="netflow_v9", source_category="flow", is_enabled=True, is_deleted=False)
        db.add_all([user, asset, source])
        if db.get(TrafficMonitoringConfiguration, 1) is None:
            db.add(TrafficMonitoringConfiguration(id=1, is_enabled=True))
        db.flush()
        assignment = AssetNetworkAssignment(
            asset_id=asset.id, address="192.0.2.244", address_family=4,
            source_id=source.id, exporter_identity="stage2b-exporter",
            started_at=now - timedelta(minutes=1), provenance="stage2b-race", status="confirmed",
        )
        db.add(assignment)
        db.flush()
        user_id, asset_id, source_id = user.id, asset.id, source.id

    def enable():
        with factory() as db:
            actor = db.get(User, user_id)
            try:
                result = set_asset_monitoring(db, actor, db.get(HardwareAsset, asset_id), True, now=now)
                db.commit()
                return result["changed"]
            except Exception:
                db.rollback()
                raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: enable(), (1, 2)))

    try:
        with factory() as db:
            assert sorted(results) == [False, True]
            assert db.query(TrafficDeviceMonitoring).filter_by(asset_id=asset_id, is_enabled=True).count() == 1
            assert db.query(TrafficDeviceMonitoringPeriod).filter_by(asset_id=asset_id, ended_at=None).count() == 1
            assert db.execute(text("SELECT count(*) FROM audit_logs WHERE entity = 'traffic_device_monitoring' AND detail = 'Changed asset network traffic monitoring' AND entity_id = :id"), {"id": str(db.query(TrafficDeviceMonitoring).filter_by(asset_id=asset_id).one().id)}).scalar_one() == 1
    finally:
        with factory.begin() as db:
            monitoring_ids = [row.id for row in db.query(TrafficDeviceMonitoring.id).filter_by(asset_id=asset_id)]
            db.execute(text("DELETE FROM audit_logs WHERE entity = 'traffic_device_monitoring' AND entity_id IN (SELECT CAST(id AS TEXT) FROM traffic_device_monitoring WHERE asset_id = :asset_id)"), {"asset_id": asset_id})
            db.query(TrafficDeviceMonitoringPeriod).filter(TrafficDeviceMonitoringPeriod.monitoring_id.in_(monitoring_ids or [-1])).delete(synchronize_session=False)
            db.query(TrafficDeviceMonitoring).filter_by(asset_id=asset_id).delete(synchronize_session=False)
            db.query(AssetNetworkAssignment).filter_by(asset_id=asset_id).delete(synchronize_session=False)
            db.query(HardwareAsset).filter_by(id=asset_id).delete(synchronize_session=False)
            db.query(TrafficSource).filter_by(id=source_id).delete(synchronize_session=False)
            db.query(User).filter_by(id=user_id).delete(synchronize_session=False)
