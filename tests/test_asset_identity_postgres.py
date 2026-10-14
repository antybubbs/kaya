import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.models import AssetNetworkAssignment, HardwareAsset, TrafficSource, User
from app.services.asset_identity import assign_network_identity


@pytest.fixture
def postgres_factory():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=4, max_overflow=0)
    yield sessionmaker(bind=engine)
    engine.dispose()


def test_postgres_concurrent_assignment_confirmation_allows_only_one_owner(postgres_factory):
    factory = postgres_factory
    with factory.begin() as db:
        admin = User(email="identity-race-admin@example.invalid", role="admin")
        first = HardwareAsset(name="Identity race one", status="In use")
        second = HardwareAsset(name="Identity race two", status="In use")
        source = TrafficSource(id=91, name="Identity race source", provider_key="netflow_v9", source_category="flow_export", is_enabled=True, is_deleted=False)
        db.add_all([admin, first, second, source])
        db.flush()
        admin_id, first_id, second_id = admin.id, first.id, second.id

    def confirm(asset_id: int):
        with factory() as db:
            actor = db.get(User, admin_id)
            try:
                row = assign_network_identity(
                    db,
                    actor,
                    asset_id=asset_id,
                    address="198.51.100.240",
                    started_at=datetime(2026, 1, 1),
                    provenance="postgres-race-test",
                    source_id=91,
                    exporter_identity="race-exporter",
                )
                return ("ok", row.id)
            except ValueError:
                db.rollback()
                return ("conflict", None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(confirm, [first_id, second_id]))

    assert sorted(result[0] for result in results) == ["conflict", "ok"]
    with factory() as db:
        rows = db.query(AssetNetworkAssignment).filter_by(address="198.51.100.240", source_id=91, exporter_identity="race-exporter").all()
        assert len(rows) == 1
        audit_count = db.execute(
            text("SELECT count(*) FROM audit_logs WHERE entity = 'asset_network_assignment' AND detail = 'Confirmed asset network assignment'")
        ).scalar_one()
        assert audit_count == 1

