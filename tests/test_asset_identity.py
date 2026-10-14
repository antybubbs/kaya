from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import AssetIdentityEvidence, AssetNetworkAssignment, HardwareAsset, User
from app.services.asset_identity import (
    _assignment_lock_key,
    asset_identity_summary,
    assign_network_identity,
    close_network_assignment,
    confirm_identity_evidence,
    revoke_identity_evidence,
)


def database():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def setup():
    db = database()
    admin = User(id=1, email="admin@example.invalid", role="admin")
    asset = HardwareAsset(id=1, name="Test device", status="In use")
    other = HardwareAsset(id=2, name="Other device", status="In use")
    db.add_all([admin, asset, other])
    db.commit()
    return db, admin, asset, other


def test_identity_confirmation_and_revocation_preserve_history():
    db, admin, *_ = setup()
    row = confirm_identity_evidence(db, admin, asset_id=1, evidence_type="mac", value="00-11-22-33-44-55", source="synthetic")
    assert row.normalised_value == "00:11:22:33:44:55"
    revoke_identity_evidence(db, admin, row.id)
    assert db.get(AssetIdentityEvidence, row.id).status == "revoked"
    assert len(asset_identity_summary(db, 1)["identities"]) == 1


def test_same_hostname_and_mac_evidence_can_be_scoped_without_merging_assets():
    db, admin, *_ = setup()
    first = confirm_identity_evidence(db, admin, asset_id=1, evidence_type="hostname", value="shared", source="dns", source_scope="provider-a")
    second = confirm_identity_evidence(db, admin, asset_id=2, evidence_type="hostname", value="shared", source="dns", source_scope="provider-b")
    assert first.id != second.id
    mac = confirm_identity_evidence(db, admin, asset_id=2, evidence_type="mac", value="001122334455", source="dhcp", source_scope="range-a")
    assert mac.asset_id == 2
    with pytest.raises(ValueError, match="already confirmed"):
        confirm_identity_evidence(db, admin, asset_id=1, evidence_type="mac", value="001122334455", source="dhcp", source_scope="range-a")


def test_assignments_are_time_bounded_and_conflicts_are_rejected():
    db, admin, *_ = setup()
    start = datetime(2026, 1, 1)
    row = assign_network_identity(db, admin, asset_id=1, address="192.0.2.10", started_at=start, ended_at=start + timedelta(days=1), provenance="dhcp")
    with pytest.raises(ValueError, match="conflicting"):
        assign_network_identity(db, admin, asset_id=2, address="192.0.2.10", started_at=start + timedelta(hours=1), provenance="dhcp")
    close_network_assignment(db, admin, row.id, start + timedelta(hours=12))
    assert db.get(AssetNetworkAssignment, row.id).ended_at == start + timedelta(hours=12)


def test_ipv4_and_ipv6_assignments_and_multiple_active_addresses():
    db, admin, *_ = setup()
    first = assign_network_identity(db, admin, asset_id=1, address="192.0.2.11", started_at=datetime(2026, 1, 1), provenance="static")
    second = assign_network_identity(db, admin, asset_id=1, address="2001:db8::11", started_at=datetime(2026, 1, 1), provenance="static")
    assert first.address_family == 4 and second.address_family == 6
    assert len(asset_identity_summary(db, 1)["assignments"]) == 2


def test_exporter_scope_prevents_cross_exporter_conflicts():
    db, admin, *_ = setup()
    start = datetime(2026, 1, 1)
    assign_network_identity(db, admin, asset_id=1, address="192.0.2.12", started_at=start, provenance="flow", source_id=7, exporter_identity="exporter-a")
    second = assign_network_identity(db, admin, asset_id=2, address="192.0.2.12", started_at=start, provenance="flow", source_id=7, exporter_identity="exporter-b")
    assert second.exporter_identity == "exporter-b"


def test_identity_mutations_require_admin():
    db, _, *_ = setup()
    viewer = User(id=3, email="viewer@example.invalid", role="viewer")
    with pytest.raises(PermissionError):
        confirm_identity_evidence(db, viewer, asset_id=1, evidence_type="mac", value="001122334455", source="test")


def test_assignment_lock_key_distinguishes_null_and_scoped_contexts():
    base = _assignment_lock_key("192.0.2.20", 4, None, None, None)
    vlan = _assignment_lock_key("192.0.2.20", 4, 10, None, None)
    exporter = _assignment_lock_key("192.0.2.20", 4, 10, 7, "exporter-a")
    assert len({base, vlan, exporter}) == 3
