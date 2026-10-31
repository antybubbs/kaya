from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import AuditLog, AssetIdentityEvidence, AssetNetworkAssignment, HardwareAsset, IPAddress, RemoteManagerSetting, User, VLAN
from app.services.asset_identity import (
    _assignment_lock_key,
    asset_identity_summary,
    assign_network_identity,
    close_network_assignment,
    confirm_existing_identity_evidence,
    confirm_existing_network_assignment,
    confirm_identity_evidence,
    revoke_identity_evidence,
    set_administrator_hostname,
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


def test_existing_identity_suggestion_can_be_confirmed_without_replacing_history():
    db, admin, *_ = setup()
    row = AssetIdentityEvidence(
        asset_id=1, evidence_type="mac", normalised_value="00:11:22:33:44:55",
        source="dhcp", status="pending",
    )
    db.add(row)
    db.commit()
    confirmed = confirm_existing_identity_evidence(db, admin, row.id)
    assert confirmed.id == row.id
    assert confirmed.status == "confirmed"
    assert db.query(AssetIdentityEvidence).count() == 1


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


def test_network_assignment_audit_is_mandatory_at_essential_capture_level():
    db, admin, *_ = setup()
    db.add(RemoteManagerSetting(key="audit_capture_level", value="essential"))
    db.commit()

    row = assign_network_identity(
        db, admin, asset_id=1, address="192.0.2.30", started_at=datetime(2026, 1, 1), provenance="flow",
    )

    assert db.get(AssetNetworkAssignment, row.id) is not None
    assert db.query(AuditLog).filter_by(entity="asset_network_assignment", entity_id=str(row.id)).count() == 1


def test_network_assignment_rolls_back_when_audit_persistence_fails(monkeypatch):
    db, admin, *_ = setup()
    monkeypatch.setattr("app.services.asset_identity.write_audit", lambda *args, **kwargs: None)

    with pytest.raises(RuntimeError, match="could not be audited"):
        assign_network_identity(
            db, admin, asset_id=1, address="192.0.2.31", started_at=datetime(2026, 1, 1), provenance="flow",
        )

    assert db.query(AssetNetworkAssignment).filter_by(address="192.0.2.31").count() == 0


def test_pending_network_assignment_can_be_approved_with_current_vlan_context():
    db, admin, *_ = setup()
    vlan = VLAN(id=9, name="Synthetic VLAN", subnet_cidr="192.0.2.0/24")
    db.add(vlan)
    db.flush()
    row = AssetNetworkAssignment(
        asset_id=1, address="192.0.2.10", address_family=4, vlan_id=9,
        started_at=datetime(2026, 1, 1), provenance="dhcp", status="pending",
    )
    db.add(row)
    db.commit()
    confirmed = confirm_existing_network_assignment(db, admin, row.id)
    assert confirmed.status == "confirmed"
    assert confirmed.network_cidr == "192.0.2.0/24"


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


def test_administrator_hostname_replaces_revoked_evidence_and_can_be_cleared():
    db, admin, *_ = setup()
    old = confirm_identity_evidence(db, admin, asset_id=1, evidence_type="hostname", value="old.example.invalid", source="dhcp")
    revoke_identity_evidence(db, admin, old.id)
    result = set_administrator_hostname(db, admin, asset_id=1, hostname="managed.example.invalid")
    assert result["hostname"] == "managed.example.invalid"
    assert db.get(AssetIdentityEvidence, old.id).status == "revoked"
    manual = db.query(AssetIdentityEvidence).filter_by(asset_id=1, source="administrator", status="confirmed").one()
    assert manual.normalised_value == "managed.example.invalid"
    set_administrator_hostname(db, admin, asset_id=1, hostname="replacement.example.invalid")
    assert db.get(AssetIdentityEvidence, manual.id).status == "revoked"
    set_administrator_hostname(db, admin, asset_id=1, hostname="")
    assert db.query(AssetIdentityEvidence).filter_by(source="administrator", status="confirmed").count() == 0
    assert db.get(AssetIdentityEvidence, manual.id).status == "revoked"


def test_administrator_hostname_validates_and_updates_only_related_static_record():
    db, admin, asset, *_ = setup()
    confirm_identity_evidence(db, admin, asset_id=asset.id, evidence_type="mac", value="02:00:00:00:00:01", source="manual")
    record = IPAddress(id=10, address="192.0.2.10", name="old.example.invalid", mac_address="02:00:00:00:00:01", assignment_type="Static")
    db.add(record)
    assignment = AssetNetworkAssignment(asset_id=asset.id, address=record.address, address_family=4, ip_address_id=record.id, started_at=datetime(2026, 1, 1), provenance="static", status="confirmed")
    db.add(assignment)
    db.commit()
    with pytest.raises(ValueError, match="valid hostname"):
        set_administrator_hostname(db, admin, asset_id=asset.id, hostname="bad name")
    set_administrator_hostname(db, admin, asset_id=asset.id, hostname="new.example.invalid", managed_ip_address_id=record.id, update_managed_hostname=True)
    assert db.get(IPAddress, record.id).name == "new.example.invalid"
    assert db.query(AssetNetworkAssignment).filter_by(id=assignment.id).one().address == "192.0.2.10"


def test_assignment_lock_key_distinguishes_null_and_scoped_contexts():
    base = _assignment_lock_key("192.0.2.20", 4, None, None, None)
    vlan = _assignment_lock_key("192.0.2.20", 4, 10, None, None)
    exporter = _assignment_lock_key("192.0.2.20", 4, 10, 7, "exporter-a")
    assert len({base, vlan, exporter}) == 3
