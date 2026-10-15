from datetime import datetime, timedelta
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import AssetNetworkAssignment, DHCPLeaseHistory, DNSProviderConfig, HardwareAsset
from app.services.asset_identity import reconcile_dhcp_assignment


def test_confirmed_dhcp_identity_reassignment_closes_old_assignment_without_backfill():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    now = datetime(2026, 1, 1, 12)
    with factory() as db:
        provider = DNSProviderConfig(name="Reconciliation fixture", base_url="https://example.invalid", provider_type="pihole")
        asset = HardwareAsset(name="Reconciled DHCP asset")
        db.add_all([provider, asset])
        db.flush()
        old_lease = DHCPLeaseHistory(provider_id=provider.id, ip_address="192.0.2.10", mac_address="aa:bb:cc:dd:ee:ff", lease_started_at=now - timedelta(hours=1), first_seen_at=now - timedelta(hours=1), last_seen_at=now - timedelta(minutes=5), is_active=False, ended_at=now - timedelta(minutes=5))
        new_lease = DHCPLeaseHistory(provider_id=provider.id, ip_address="192.0.2.11", mac_address="aa:bb:cc:dd:ee:ff", lease_started_at=now, first_seen_at=now, last_seen_at=now, is_active=True)
        db.add_all([old_lease, new_lease])
        db.flush()
        old_assignment = AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.10", address_family=4, dhcp_lease_id=old_lease.id, started_at=now - timedelta(hours=1), provenance="adoption", status="confirmed")
        db.add(old_assignment)
        db.commit()

        assert reconcile_dhcp_assignment(db, new_lease, observed_at=now) == "reassigned"
        db.commit()
        assignments = db.query(AssetNetworkAssignment).filter_by(asset_id=asset.id).order_by(AssetNetworkAssignment.started_at).all()
        assert len(assignments) == 2
        assert assignments[0].ended_at == now
        assert assignments[1].address == "192.0.2.11"
        assert assignments[1].started_at == now
        assert assignments[1].dhcp_lease_id == new_lease.id
        assert assignments[1].provenance == "dhcp_reconciliation"


@pytest.fixture
def postgres_factory():
    url = os.environ.get("KAYA_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("KAYA_TEST_POSTGRES_URL is not configured")
    engine = create_engine(url, pool_size=4, max_overflow=0)
    yield sessionmaker(bind=engine)
    engine.dispose()


def test_postgres_concurrent_dhcp_reassignment_is_idempotent(postgres_factory):
    factory = postgres_factory
    now = datetime(2026, 1, 1, 12)
    with factory.begin() as db:
        provider = DNSProviderConfig(name="PostgreSQL reconciliation fixture", base_url="https://example.invalid", provider_type="pihole")
        asset = HardwareAsset(name="PostgreSQL reconciliation asset")
        db.add_all([provider, asset])
        db.flush()
        old_lease = DHCPLeaseHistory(provider_id=provider.id, ip_address="192.0.2.20", mac_address="aa:bb:cc:dd:ee:20", lease_started_at=now - timedelta(hours=1), first_seen_at=now - timedelta(hours=1), last_seen_at=now - timedelta(minutes=5), is_active=False, ended_at=now - timedelta(minutes=5))
        new_lease = DHCPLeaseHistory(provider_id=provider.id, ip_address="192.0.2.21", mac_address="aa:bb:cc:dd:ee:20", lease_started_at=now, first_seen_at=now, last_seen_at=now, is_active=True)
        db.add_all([old_lease, new_lease])
        db.flush()
        db.add(AssetNetworkAssignment(asset_id=asset.id, address="192.0.2.20", address_family=4, dhcp_lease_id=old_lease.id, started_at=now - timedelta(hours=1), provenance="adoption", status="confirmed"))
        db.flush()
        lease_id, asset_id = new_lease.id, asset.id

    def reconcile_once():
        with factory() as db:
            lease = db.get(DHCPLeaseHistory, lease_id)
            result = reconcile_dhcp_assignment(db, lease, observed_at=now)
            db.commit()
            return result

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: reconcile_once(), (1, 2)))

    with factory() as db:
        rows = db.query(AssetNetworkAssignment).filter_by(asset_id=asset_id).order_by(AssetNetworkAssignment.started_at).all()
        assert sorted(results) == ["reassigned", "review_required"]
        assert len(rows) == 2
        assert sum(row.ended_at is None for row in rows) == 1
