from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    DHCPLeaseHistory,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    TrafficDiscoveryObservation,
    TrafficSource,
    User,
    VLAN,
)
from app.services.asset_discovery import adopt_discovered_device, compose_discovered_devices


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
    db.add_all([admin, vlan, ip, client])
    db.commit()
    candidate = next(row for row in compose_discovered_devices(db)["rows"] if row["kind"] == "dns")

    asset = adopt_discovered_device(db, admin, candidate, new_name="Adopted laptop")

    assert asset.name == "Adopted laptop"
    db.refresh(client)
    assert client.hardware_asset_id == asset.id
    assert db.query(HardwareAsset).count() == 1
    assert db.query(HardwareAsset).one().name == "Adopted laptop"


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
