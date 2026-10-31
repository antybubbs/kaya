from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DHCPRange,
    DNSRecognisedDevice,
    HardwareAsset,
    HardwareAssetTagSequence,
    IPAddress,
    RemoteManagerSetting,
    TrafficDiscoveryObservation,
    TrafficSource,
    User,
    VLAN,
)
from app.services.asset_discovery import adopt_discovered_device, compose_discovered_devices, get_discovered_device


def database():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_composition_groups_dhcp_with_its_dns_client_but_keeps_traffic_context_separate():
    db = database()
    now = datetime(2026, 1, 2)
    db.add_all([
        DNSRecognisedDevice(
            id=1, provider_id=1, logical_provider_key="synthetic", identity_type="mac",
            identity_value="00:11:22:33:44:55", hostname="laptop.example", current_ip="192.0.2.10",
            mac_address="00:11:22:33:44:55", normalised_mac="00:11:22:33:44:55",
            first_seen_at=now, last_seen_at=now,
        ),
        DHCPLeaseHistory(
            id=1, provider_id=1, dns_client_id=1, ip_address="192.0.2.10",
            mac_address="00:11:22:33:44:55", hostname="laptop.example",
            lease_started_at=now, first_seen_at=now, last_seen_at=now,
        ),
        TrafficSource(id=1, name="Synthetic exporter", provider_key="cisco_nsel", source_category="flow", is_enabled=True),
        TrafficDiscoveryObservation(
            id=1, source_id=1, exporter_identity="edge-a", endpoint_ip="192.0.2.10",
            address_family=4, endpoint_role="original_source", bucket_start=now,
            first_seen_at=now, last_seen_at=now, observation_count=2,
        ),
    ])
    db.commit()

    result = compose_discovered_devices(db)

    assert result["total"] == 2
    dns_row = next(row for row in result["rows"] if row["kind"] == "dns")
    assert dns_row["sources"] == ["DHCP", "DNS Manager"]
    traffic_row = next(row for row in result["rows"] if row["kind"] == "traffic")
    assert traffic_row["traffic"][0]["exporter_identity"] == "edge-a"


def test_dns_candidate_falls_back_to_provider_mac_when_normalised_mac_is_missing():
    db = database()
    db.add(DNSRecognisedDevice(
        id=7, provider_id=1, logical_provider_key="synthetic", identity_type="mac",
        identity_value="00:11:22:33:44:77", hostname="fallback.example",
        current_ip="192.0.2.77", mac_address="00:11:22:33:44:77",
        first_seen_at=datetime(2026, 1, 1), last_seen_at=datetime(2026, 1, 2),
    ))
    db.commit()

    candidate = get_discovered_device(db, "dns:7")

    assert candidate["mac_addresses"] == ["00:11:22:33:44:77"]


def test_different_mac_is_not_blocked_by_historical_ip_assignment():
    db = database()
    old_at = datetime(2026, 1, 1)
    new_at = datetime(2026, 1, 2)
    old_asset = HardwareAsset(id=6, name="alyssa-iphone.hal.local", status="In use")
    old_mac = "be:44:47:87:e0:32"
    new_mac = "b0:45:30:9a:93:1b"
    client = DNSRecognisedDevice(
        id=1, provider_id=1, logical_provider_key="hal-dns", identity_type="mac",
        identity_value=new_mac, hostname="sky-decoder", current_ip="192.0.2.178",
        mac_address=new_mac, normalised_mac=new_mac, hardware_asset_id=old_asset.id,
        first_seen_at=new_at, last_seen_at=new_at,
    )
    db.add_all([
        old_asset,
        client,
        AssetIdentityEvidence(
            asset_id=old_asset.id, evidence_type="mac", normalised_value=old_mac,
            source="discovery", source_scope="dhcp", status="confirmed",
            first_observed_at=old_at, last_observed_at=old_at,
        ),
        IPAddress(id=1, address="192.0.2.178"),
        AssetNetworkAssignment(
            asset_id=old_asset.id, address="192.0.2.178", address_family=4,
            ip_address_id=1, started_at=old_at, ended_at=new_at,
            provenance="dhcp_reconciliation", status="confirmed",
        ),
    ])
    db.commit()

    candidate = get_discovered_device(db, "dns:1")

    assert candidate["asset_id"] is None
    assert candidate["identity_conflict"] is True
    assert candidate["historical_assignments"][0]["asset_id"] == old_asset.id


def test_alyssa_sky_reassignment_can_be_adopted_without_merging_identity():
    db = database()
    old_at = datetime(2026, 1, 1)
    reassigned_at = datetime(2026, 1, 2)
    old_asset = HardwareAsset(id=6, asset_tag="HAL-0006", name="alyssa-iphone.hal.local", status="In use")
    old_mac = "be:44:47:87:e0:32"
    old_private_mac = "f4:c7:aa:1b:19:1c"
    sky_mac = "b0:45:30:9a:93:1b"
    vlan = VLAN(id=1, name="VLAN 1", subnet_cidr="192.0.2.0/24")
    dhcp_range = DHCPRange(id=1, name="Main Home DHCP Range VLAN 1", vlan_id=1, start_address="192.0.2.150", end_address="192.0.2.210", is_enabled=True)
    ip = IPAddress(id=1, address="192.0.2.178", vlan_id=1, name="DHCP address")
    sky_client = DNSRecognisedDevice(
        id=1, provider_id=1, logical_provider_key="hal-dns", identity_type="mac",
        identity_value=sky_mac, hostname="sky-decoder", current_ip=ip.address,
        mac_address=sky_mac, normalised_mac=sky_mac, hardware_asset_id=old_asset.id,
        first_seen_at=reassigned_at, last_seen_at=reassigned_at,
    )
    db.add_all([
        old_asset, vlan, dhcp_range, ip, sky_client,
        AssetIdentityEvidence(asset_id=old_asset.id, evidence_type="mac", normalised_value=old_mac, source="discovery", source_scope="dhcp", status="confirmed", first_observed_at=old_at, last_observed_at=old_at),
        AssetIdentityEvidence(asset_id=old_asset.id, evidence_type="mac", normalised_value=old_private_mac, source="discovery", source_scope="dhcp", status="confirmed", first_observed_at=old_at, last_observed_at=old_at),
        DHCPLeaseHistory(id=1, provider_id=1, dns_client_id=1, dhcp_range_id=1, ip_address=ip.address, mac_address=sky_mac, hostname="sky-decoder", provider_lease_id="73", lease_started_at=reassigned_at, first_seen_at=reassigned_at, last_seen_at=reassigned_at, is_active=True),
        AssetNetworkAssignment(asset_id=old_asset.id, address=ip.address, address_family=4, vlan_id=1, ip_address_id=1, started_at=old_at, ended_at=reassigned_at, provenance="dhcp_reconciliation", status="confirmed"),
    ])
    admin = User(id=1, email="synthetic-admin@example.invalid", password_hash="x", role="admin", is_active=True)
    db.add(admin)
    db.commit()

    candidate = get_discovered_device(db, "dns:1")
    adopted = adopt_discovered_device(db, admin, candidate, new_name="Sky Decoder")

    assert adopted.id != old_asset.id
    db.refresh(sky_client)
    assert sky_client.hardware_asset_id == adopted.id
    assert {row.normalised_value for row in db.query(AssetIdentityEvidence).filter_by(asset_id=old_asset.id, evidence_type="mac", status="confirmed")} == {old_mac, old_private_mac}
    old_assignment = db.query(AssetNetworkAssignment).filter_by(asset_id=old_asset.id).one()
    assert old_assignment.ended_at == reassigned_at
    new_assignment = db.query(AssetNetworkAssignment).filter_by(asset_id=adopted.id).one()
    assert new_assignment.address == ip.address
    assert new_assignment.dhcp_lease_id is None  # Adoption preserves the source lease separately.


def test_reused_dhcp_identifier_is_retained_for_review_without_blocking_new_mac_adoption():
    db = database()
    old_at = datetime(2026, 1, 1)
    reassigned_at = datetime(2026, 1, 2)
    old_asset = HardwareAsset(id=6, asset_tag="HAL-0006", name="alyssa-iphone.hal.local", status="In use")
    sky_mac = "b0:45:30:9a:93:1b"
    ip = IPAddress(id=1, address="192.0.2.178")
    client = DNSRecognisedDevice(
        id=1, provider_id=1, logical_provider_key="hal-dns", identity_type="mac",
        identity_value=sky_mac, hostname="sky-decoder", current_ip=ip.address,
        mac_address=sky_mac, normalised_mac=sky_mac, provider_client_id="73",
        first_seen_at=reassigned_at, last_seen_at=reassigned_at,
    )
    db.add_all([
        old_asset,
        ip,
        client,
        AssetIdentityEvidence(asset_id=old_asset.id, evidence_type="mac", normalised_value="be:44:47:87:e0:32", source="discovery", source_scope="dhcp", status="confirmed", first_observed_at=old_at, last_observed_at=old_at),
        AssetIdentityEvidence(asset_id=old_asset.id, evidence_type="dhcp_client_id", normalised_value="73", source="dhcp", source_scope=None, status="confirmed", first_observed_at=old_at, last_observed_at=old_at),
        AssetNetworkAssignment(asset_id=old_asset.id, address=ip.address, address_family=4, ip_address_id=ip.id, started_at=old_at, ended_at=reassigned_at, provenance="dhcp_reconciliation", status="confirmed"),
    ])
    admin = User(id=1, email="synthetic-admin@example.invalid", password_hash="x", role="admin", is_active=True)
    db.add(admin)
    db.commit()

    candidate = get_discovered_device(db, "dns:1")
    adopted = adopt_discovered_device(db, admin, candidate, new_name="Sky Decoder")

    assert adopted.id != old_asset.id
    assert db.get(DNSRecognisedDevice, client.id).hardware_asset_id == adopted.id
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=old_asset.id, evidence_type="mac", status="confirmed").count() == 1
    # The provider's client record number is never adopted as a DHCP client ID;
    # the old asset's historical "73" evidence is left for Data Integrity review.
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=adopted.id, evidence_type="dhcp_client_id").count() == 0
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=adopted.id, evidence_type="mac", normalised_value=sky_mac, status="confirmed").count() == 1
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=old_asset.id, evidence_type="dhcp_client_id", normalised_value="73").one().status == "confirmed"
    assert db.query(AssetNetworkAssignment).filter_by(asset_id=old_asset.id).one().ended_at == reassigned_at


def test_explicit_dhcp_candidate_namespace_resolves_grouped_active_lease():
    db = database()
    now = datetime(2026, 1, 2)
    db.add(DHCPLeaseHistory(
        id=3009, provider_id=1, ip_address="192.0.2.19", mac_address="00:11:22:33:44:55",
        hostname="phone.example", provider_lease_id="client-3009", lease_started_at=now,
        first_seen_at=now, last_seen_at=now, is_active=True,
    ))
    db.commit()

    candidate = get_discovered_device(db, "dhcp:3009")

    assert candidate["kind"] == "dhcp"
    assert candidate["ip_addresses"] == ["192.0.2.19"]
    assert candidate["mac_addresses"] == ["00:11:22:33:44:55"]
    assert candidate["dhcp_client_ids"] == ["client-3009"]
    assert get_discovered_device(db, "dhcp:not-an-id") is None


def test_explicit_dhcp_candidate_marks_expired_lease_stale():
    db = database()
    now = datetime(2026, 1, 2)
    db.add(DHCPLeaseHistory(
        id=3010, provider_id=1, ip_address="192.0.2.20", lease_started_at=now - timedelta(days=2),
        first_seen_at=now - timedelta(days=2), last_seen_at=now - timedelta(days=1),
        expires_at=now - timedelta(days=1), is_active=False,
    ))
    db.commit()

    candidate = get_discovered_device(db, "dhcp:3010")

    assert candidate["review_state"] == "stale"
    assert candidate["stale_reason"] == "DHCP lease expired."


def test_new_mac_with_expired_dhcp_lease_can_be_adopted_without_current_ip_assignment():
    db = database()
    now = datetime(2026, 1, 2)
    admin = User(email="expired-adopter@example.invalid", role="admin", is_active=True)
    ip = IPAddress(id=1, address="192.0.2.20")
    lease = DHCPLeaseHistory(
        id=3011, provider_id=1, ip_address=ip.address, mac_address="02:00:00:00:20:11",
        hostname="expired-device", lease_started_at=now - timedelta(days=2),
        first_seen_at=now - timedelta(days=2), last_seen_at=now - timedelta(days=1),
        expires_at=now - timedelta(days=1), is_active=False,
    )
    db.add_all([admin, ip, lease])
    db.commit()

    adopted = adopt_discovered_device(db, admin, get_discovered_device(db, f"dhcp:{lease.id}"), new_name="Expired device")

    assert adopted.name == "Expired device"
    assert db.query(AssetIdentityEvidence).filter_by(asset_id=adopted.id, evidence_type="mac").count() == 1
    assert db.query(AssetNetworkAssignment).filter_by(asset_id=adopted.id).count() == 0


def test_new_mac_can_reuse_historical_ip_without_closing_history():
    db = database()
    now = datetime(2026, 1, 2)
    admin = User(email="reused-ip-adopter@example.invalid", role="admin", is_active=True)
    old_asset = HardwareAsset(id=6, name="Previous owner", status="In use")
    ip = IPAddress(id=1, address="192.0.2.21")
    db.add_all([
        admin, old_asset, ip,
        AssetNetworkAssignment(asset_id=old_asset.id, address=ip.address, address_family=4, ip_address_id=ip.id, started_at=now - timedelta(days=3), ended_at=now - timedelta(days=1), provenance="dhcp_reconciliation", status="confirmed"),
        DHCPLeaseHistory(id=3012, provider_id=1, ip_address=ip.address, mac_address="02:00:00:00:21:12", hostname="new-device", lease_started_at=now, first_seen_at=now, last_seen_at=now, is_active=True),
    ])
    db.commit()

    adopted = adopt_discovered_device(db, admin, get_discovered_device(db, "dhcp:3012"), new_name="New device")

    assert adopted.id != old_asset.id
    assert db.query(AssetNetworkAssignment).filter_by(asset_id=old_asset.id).one().ended_at is not None
    assert db.query(AssetNetworkAssignment).filter_by(asset_id=adopted.id).count() == 1


def test_confirmed_mac_cannot_be_adopted_as_a_second_asset_even_when_lease_is_stale():
    db = database()
    now = datetime(2026, 1, 2)
    admin = User(email="duplicate-mac-adopter@example.invalid", role="admin", is_active=True)
    old_asset = HardwareAsset(id=6, name="Existing MAC owner", status="In use")
    mac = "02:00:00:00:22:13"
    lease = DHCPLeaseHistory(id=3013, provider_id=1, ip_address="192.0.2.22", mac_address=mac, hostname="duplicate-device", lease_started_at=now - timedelta(days=2), first_seen_at=now - timedelta(days=2), last_seen_at=now - timedelta(days=1), is_active=False)
    db.add_all([admin, old_asset, lease, AssetIdentityEvidence(asset_id=old_asset.id, evidence_type="mac", normalised_value=mac, source="discovery", source_scope="dhcp", status="confirmed", first_observed_at=now - timedelta(days=2), last_observed_at=now - timedelta(days=1))])
    db.commit()

    with pytest.raises(ValueError, match="already confirmed"):
        adopt_discovered_device(db, admin, get_discovered_device(db, f"dhcp:{lease.id}"), new_name="Wrong duplicate")


def test_admin_adoption_creates_one_asset_and_reviewed_evidence_atomically():
    db = database()
    admin = User(id=1, email="admin@example.invalid", role="admin", is_active=True)
    vlan = VLAN(id=1, name="Synthetic LAN", subnet_cidr="192.0.2.0/24")
    ip = IPAddress(id=1, vlan_id=1, address="192.0.2.10", name="Laptop")
    client = DNSRecognisedDevice(
        id=1, provider_id=1, logical_provider_key="synthetic", identity_type="mac",
        identity_value="00:11:22:33:44:55", hostname="laptop.example", current_ip=ip.address,
        mac_address="00:11:22:33:44:55", normalised_mac="00:11:22:33:44:55",
        first_seen_at=datetime(2026, 1, 1), last_seen_at=datetime(2026, 1, 2),
    )
    db.add_all([
        admin, vlan, ip, client,
        RemoteManagerSetting(key="asset_tags_auto_generate", value="1"),
        RemoteManagerSetting(key="asset_tags_prefix", value="HAL"),
        RemoteManagerSetting(key="asset_tags_separator", value="-"),
        RemoteManagerSetting(key="asset_tags_padding", value="4"),
        RemoteManagerSetting(key="asset_tags_start_number", value="1"),
        HardwareAssetTagSequence(id=1, next_number=1),
    ])
    db.commit()
    candidate = next(row for row in compose_discovered_devices(db)["rows"] if row["kind"] == "dns")

    asset = adopt_discovered_device(db, admin, candidate, new_name="Adopted laptop")

    assert asset.name == "Adopted laptop"
    db.refresh(client)
    assert client.hardware_asset_id == asset.id
    assert db.query(HardwareAsset).count() == 1
    assert asset.asset_tag == "HAL-0001"


def test_network_traffic_adoption_creates_source_scoped_assignment_without_managed_ip():
    db = database()
    now = datetime(2026, 1, 2)
    admin = User(id=1, email="traffic-admin@example.invalid", role="admin", is_active=True)
    source = TrafficSource(id=1, name="Synthetic exporter", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False)
    observation = TrafficDiscoveryObservation(
        id=1, source_id=1, exporter_identity="192.0.2.1", endpoint_ip="192.0.2.20",
        address_family=4, endpoint_role="original_source", bucket_start=now,
        first_seen_at=now, last_seen_at=now, observation_count=3, classification="internal", confidence="high",
    )
    db.add_all([admin, source, observation])
    db.commit()
    candidate = compose_discovered_devices(db)["rows"][0]

    asset = adopt_discovered_device(db, admin, candidate, new_name="Traffic-only device")

    assignment = db.query(AssetNetworkAssignment).one()
    assert asset.name == "Traffic-only device"
    assert assignment.asset_id == asset.id
    assert assignment.ip_address_id is None
    assert assignment.source_id == source.id
    assert assignment.exporter_identity == "192.0.2.1"


def test_adoption_audit_is_required_even_when_capture_level_is_essential():
    db = database()
    admin = User(id=1, email="admin@example.invalid", role="admin", is_active=True)
    client = DNSRecognisedDevice(
        id=1, provider_id=1, logical_provider_key="synthetic", identity_type="mac",
        identity_value="00:11:22:33:44:77", hostname="essential-audit.example",
        current_ip="192.0.2.77", mac_address="00:11:22:33:44:77",
        normalised_mac="00:11:22:33:44:77", first_seen_at=datetime(2026, 1, 1),
        last_seen_at=datetime(2026, 1, 2),
    )
    db.add_all([
        admin,
        client,
        RemoteManagerSetting(key="audit_capture_level", value="essential"),
    ])
    db.commit()
    candidate = next(row for row in compose_discovered_devices(db)["rows"] if row["kind"] == "dns")

    asset = adopt_discovered_device(db, admin, candidate, new_name="Essential audit asset")

    assert asset.id is not None
    assert db.query(HardwareAsset).count() == 1


def test_adoption_audit_failure_is_returned_as_controlled_service_error(monkeypatch):
    from fastapi import HTTPException

    import app.routers.hardware_assets as hardware_assets

    db = database()
    admin = User(id=1, email="admin@example.invalid", role="admin", is_active=True)
    db.add(admin)
    db.commit()
    candidate = {"id": "dns:560", "kind": "dns", "review_state": "review"}
    request = SimpleNamespace()

    monkeypatch.setattr(hardware_assets, "validate_csrf_token", lambda *_args: None)
    monkeypatch.setattr(hardware_assets, "get_discovered_device", lambda *_args: candidate)
    monkeypatch.setattr(hardware_assets, "list_values", lambda *_args: {"category": []})
    monkeypatch.setattr(
        hardware_assets,
        "adopt_discovered_device",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("internal audit detail")),
    )

    with pytest.raises(HTTPException) as exc_info:
        hardware_assets.adopt_discovered_device_route(
            request,
            candidate_id="dns:560",
            asset_id=None,
            new_name="Synthetic",
            category="",
            csrf_token="synthetic-csrf",
            db=db,
            user=admin,
        )

    assert exc_info.value.status_code == 503
    assert "audit record was not saved" in exc_info.value.detail
    assert "internal audit detail" not in exc_info.value.detail


def test_adoption_conflict_returns_review_page_with_submitted_values(monkeypatch):
    import app.routers.hardware_assets as hardware_assets

    db = database()
    admin = User(id=1, email="admin@example.invalid", role="admin", is_active=True)
    existing = HardwareAsset(id=7, name="Existing synthetic asset", status="In use")
    db.add_all([admin, existing])
    db.commit()
    candidate = {
        "id": "dns:561", "kind": "dns", "name": "Sky Decoder", "review_state": "review",
        "asset_id": None, "ip_addresses": ["192.0.2.178"], "mac_addresses": ["b0:45:30:9a:93:1b"],
        "dhcp_client_ids": ["73"], "sources": ["DHCP", "DNS Manager"], "identity_conflict": True,
    }
    rendered = {}

    monkeypatch.setattr(hardware_assets, "validate_csrf_token", lambda *_args: None)
    monkeypatch.setattr(hardware_assets, "get_discovered_device", lambda *_args: candidate)
    monkeypatch.setattr(hardware_assets, "list_values", lambda *_args: {"category": ["Media"]})
    monkeypatch.setattr(hardware_assets, "csrf_context", lambda *_args: {"csrf_token": "synthetic-csrf"})
    monkeypatch.setattr(
        hardware_assets.templates,
        "TemplateResponse",
        lambda *args, **kwargs: rendered.update({"context": args[2], "status_code": kwargs["status_code"]}) or rendered,
    )
    monkeypatch.setattr(
        hardware_assets,
        "adopt_discovered_device",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("The selected evidence is already confirmed for another asset in this source scope.")),
    )

    response = hardware_assets.adopt_discovered_device_route(
        SimpleNamespace(),
        candidate_id="dns:561",
        asset_id=existing.id,
        new_name="Sky Decoder replacement",
        category="Media",
        csrf_token="synthetic-csrf",
        db=db,
        user=admin,
    )

    assert response is rendered
    assert rendered["status_code"] == 409
    assert rendered["context"]["error"] == "The selected evidence is already confirmed for another asset in this source scope."
    assert rendered["context"]["selected_asset_id"] == existing.id
    assert rendered["context"]["new_name"] == "Sky Decoder replacement"
    assert rendered["context"]["category"] == "Media"


def test_adoption_requires_administrator():
    db = database()
    viewer = User(id=1, email="viewer@example.invalid", role="viewer", is_active=True)
    with pytest.raises(PermissionError):
        adopt_discovered_device(db, viewer, {"id": "dns:1", "review_state": "review", "kind": "dns", "name": "Synthetic", "ip_addresses": [], "mac_addresses": [], "dhcp_client_ids": []})


def test_ip_only_and_traffic_observations_remain_review_only():
    db = database()
    admin = User(id=1, email="admin@example.invalid", role="admin", is_active=True)
    db.add(admin)
    db.commit()
    for kind in ("dns", "traffic"):
        with pytest.raises(ValueError, match="stable|review-only"):
            adopt_discovered_device(
                db,
                admin,
                {"id": f"{kind}:1", "review_state": "review", "kind": kind, "name": "Synthetic",
                 "ip_addresses": ["192.0.2.10"], "mac_addresses": [], "dhcp_client_ids": []},
            )


def test_admin_adoption_can_attach_to_existing_asset_without_creating_another():
    db = database()
    admin = User(id=1, email="admin@example.invalid", role="admin", is_active=True)
    existing = HardwareAsset(id=1, name="Existing synthetic asset", status="In use")
    client = DNSRecognisedDevice(
        id=1, provider_id=1, logical_provider_key="synthetic", identity_type="mac",
        identity_value="00:11:22:33:44:66", hostname="existing.example",
        current_ip="192.0.2.44", mac_address="00:11:22:33:44:66",
        normalised_mac="00:11:22:33:44:66", first_seen_at=datetime(2026, 1, 1),
        last_seen_at=datetime(2026, 1, 2),
    )
    db.add_all([admin, existing, client])
    db.commit()
    candidate = next(row for row in compose_discovered_devices(db)["rows"] if row["kind"] == "dns")

    adopted = adopt_discovered_device(db, admin, candidate, asset_id=existing.id)

    assert adopted.id == existing.id
    assert db.query(HardwareAsset).count() == 1
    db.refresh(client)
    assert client.hardware_asset_id == existing.id
