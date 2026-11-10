import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.models import AuditLog, AssetIdentityEvidence, AssetNetworkAssignment, HardwareAsset, IPAddress, TrafficSource, User
from app.services.asset_identity import assign_network_identity, confirm_identity_evidence, revoke_identity_evidence, set_administrator_hostname


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


def test_postgres_administrator_hostname_lifecycle_is_transactional_and_preserves_history(postgres_factory, monkeypatch):
    token = "pg-hostname-" + os.urandom(4).hex()
    with postgres_factory.begin() as db:
        admin = User(email=f"{token}-admin@example.invalid", role="admin", is_active=True)
        asset = HardwareAsset(name=f"{token} asset", status="In use")
        other = HardwareAsset(name=f"{token} other", status="In use")
        db.add_all([admin, asset, other])
        db.flush()
        record = IPAddress(address=f"198.51.100.{20 + (asset.id % 100)}", name="old.example.invalid", mac_address="02:00:00:00:00:21", assignment_type="Static")
        db.add(record)
        db.flush()
        assignment = AssetNetworkAssignment(asset_id=asset.id, address=record.address, address_family=4, ip_address_id=record.id, started_at=datetime(2026, 1, 1), provenance="synthetic-static", status="confirmed")
        db.add(assignment)
        db.flush()
        admin_id, asset_id, other_id, record_id = admin.id, asset.id, other.id, record.id
        assignment_id, record_address = assignment.id, record.address

    try:
        with postgres_factory() as db:
            actor = db.get(User, admin_id)
            confirm_identity_evidence(db, actor, asset_id=asset_id, evidence_type="mac", value="02:00:00:00:00:21", source="manual")
            old = confirm_identity_evidence(db, actor, asset_id=asset_id, evidence_type="hostname", value="old.example.invalid", source="dhcp")
            revoke_identity_evidence(db, actor, old.id)
            result = set_administrator_hostname(db, actor, asset_id=asset_id, hostname="managed.example.invalid", managed_ip_address_id=record_id, update_managed_hostname=True)
            assert result["hostname"] == "managed.example.invalid"
            assert db.get(IPAddress, record_id).name == "managed.example.invalid"
            assert db.get(AssetIdentityEvidence, old.id).status == "revoked"
            manual = db.query(AssetIdentityEvidence).filter_by(asset_id=asset_id, source="administrator", status="confirmed").one()
            assert manual.normalised_value == "managed.example.invalid"
            assert db.query(AssetNetworkAssignment).filter_by(id=assignment_id).one().address == record_address

            with pytest.raises(ValueError, match="not associated"):
                set_administrator_hostname(db, actor, asset_id=other_id, hostname="other.example.invalid", managed_ip_address_id=record_id, update_managed_hostname=True)

            set_administrator_hostname(db, actor, asset_id=asset_id, hostname="")
            assert db.get(AssetIdentityEvidence, manual.id).status == "revoked"
            assert db.query(AssetIdentityEvidence).filter_by(asset_id=asset_id, source="administrator", status="confirmed").count() == 0

        with postgres_factory() as db:
            actor = db.get(User, admin_id)
            monkeypatch.setattr("app.services.asset_identity.write_audit", lambda *args, **kwargs: None)
            with pytest.raises(RuntimeError, match="could not be audited"):
                set_administrator_hostname(db, actor, asset_id=asset_id, hostname="rolled-back.example.invalid")
            assert db.query(AssetIdentityEvidence).filter_by(asset_id=asset_id, normalised_value="rolled-back.example.invalid").count() == 0
            assert db.query(AssetNetworkAssignment).filter_by(id=assignment_id).one().address == record_address
    finally:
        with postgres_factory.begin() as db:
            db.query(AuditLog).filter(AuditLog.user_id == admin_id).delete(synchronize_session=False)
            db.query(AssetIdentityEvidence).filter(AssetIdentityEvidence.asset_id.in_([asset_id, other_id])).delete(synchronize_session=False)
            db.query(AssetNetworkAssignment).filter(AssetNetworkAssignment.asset_id.in_([asset_id, other_id])).delete(synchronize_session=False)
            db.query(IPAddress).filter(IPAddress.id == record_id).delete(synchronize_session=False)
            db.query(HardwareAsset).filter(HardwareAsset.id.in_([asset_id, other_id])).delete(synchronize_session=False)
            db.query(User).filter(User.id == admin_id).delete(synchronize_session=False)

