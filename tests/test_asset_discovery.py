from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    AssetNetworkAssignment,
    DHCPLeaseHistory,
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
