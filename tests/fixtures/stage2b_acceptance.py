"""Deterministic synthetic fixture for Stage 2B browser acceptance.

The fixture is intentionally explicit: it seeds no providers, credentials, or
external-service state and fails if the required cardinalities are not met.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.core.security import hash_password
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    TrafficAggregate,
    TrafficDeviceAggregate,
    TrafficDeviceMonitoring,
    TrafficDeviceMonitoringPeriod,
    TrafficDiscoveryNetworkMapping,
    TrafficDiscoveryObservation,
    TrafficInterface,
    TrafficMonitoringConfiguration,
    TrafficSource,
    User,
    UserModulePermission,
    VLAN,
)


FIXTURE_PASSWORD = "Stage2B-fixture-password-012345"
FIXTURE_NOW = datetime(2026, 1, 15, 12, 0, 0)


def seed_stage2b_acceptance(db) -> dict[str, int | str]:
    """Seed and verify the complete disposable Stage 2B acceptance dataset."""
    admin = User(id=9001, email="stage2b-admin@example.invalid", password_hash=hash_password(FIXTURE_PASSWORD), first_name="Stage", last_name="Administrator", role="admin")
    viewer = User(id=9002, email="stage2b-viewer@example.invalid", password_hash=hash_password(FIXTURE_PASSWORD), first_name="Stage", last_name="Viewer", role="viewer")
    network_only = User(id=9003, email="stage2b-network@example.invalid", password_hash=hash_password(FIXTURE_PASSWORD), role="viewer")
    asset_only = User(id=9004, email="stage2b-asset@example.invalid", password_hash=hash_password(FIXTURE_PASSWORD), role="viewer")
    dns_only = User(id=9005, email="stage2b-dns@example.invalid", password_hash=hash_password(FIXTURE_PASSWORD), role="viewer")
    db.add_all([admin, viewer, network_only, asset_only, dns_only])
    db.flush()
    db.add_all(UserModulePermission(user_id=admin.id, module_key=key, allowed=True) for key in {"asset_manager", "network_monitor", "dns_manager", "vlan_ip_manager"})
    for user, allowed in (
        (viewer, {"asset_manager", "network_monitor", "dns_manager", "vlan_ip_manager"}),
        (network_only, {"network_monitor"}),
        (asset_only, {"asset_manager"}),
        (dns_only, {"dns_manager"}),
    ):
        db.add_all(UserModulePermission(user_id=user.id, module_key=key, allowed=True) for key in allowed)

    db.add(TrafficMonitoringConfiguration(id=1, is_enabled=True))
    source_a = TrafficSource(id=9101, name="Stage2B Cisco exporter", provider_key="cisco_nsel", source_category="flow_export", is_enabled=True, is_deleted=False, configuration_state="configured", health_state="healthy", exporter_allowlist_json='["192.0.2.1"]', collector_port=2055)
    source_b = TrafficSource(id=9102, name="Stage2B NetFlow exporter", provider_key="netflow_v9", source_category="flow_export", is_enabled=True, is_deleted=False, configuration_state="configured", health_state="healthy", exporter_allowlist_json='["192.0.2.2"]', collector_port=2056)
    db.add_all([source_a, source_b])
    db.flush()
    iface_a = TrafficInterface(source_id=source_a.id, interface_key="wan-a", display_name="WAN A", is_wan=True)
    iface_b = TrafficInterface(source_id=source_b.id, interface_key="wan-b", display_name="WAN B", is_wan=True)
    db.add_all([iface_a, iface_b])
    vlan_a = VLAN(id=9201, name="Stage2B LAN A", subnet_cidr="192.0.2.0/25")
    vlan_b = VLAN(id=9202, name="Stage2B LAN B", subnet_cidr="192.0.2.128/25")
    db.add_all([vlan_a, vlan_b])
    db.flush()
    db.add_all([
        TrafficDiscoveryNetworkMapping(source_id=source_a.id, exporter_identity="192.0.2.1", vlan_id=vlan_a.id, created_by_user_id=admin.id, updated_by_user_id=admin.id),
        TrafficDiscoveryNetworkMapping(source_id=source_b.id, exporter_identity="192.0.2.2", vlan_id=vlan_b.id, created_by_user_id=admin.id, updated_by_user_id=admin.id),
    ])
    managed_ips = [
        IPAddress(id=9250 + index, vlan_id=vlan_a.id if index % 2 else vlan_b.id, address=(f"192.0.2.{index + 10}" if index % 2 else f"192.0.2.{index + 129}"), name=f"Stage2B managed IP {index}")
        for index in range(1, 4)
    ]
    db.add_all(managed_ips)
    provider = DNSProviderConfig(id=9301, name="Stage2B synthetic Pi-hole", provider_type="pihole", base_url="http://dns.invalid", is_enabled=True)
    db.add(provider)
    db.flush()

    assets = []
    assignments = []
    for index in range(1, 13):
        asset = HardwareAsset(id=9400 + index, asset_tag=f"STAGE2B-{index:03d}", name=f"Stage2B Asset {index:03d}", status="In use")
        assets.append(asset)
        source_id = source_a.id if index % 2 else source_b.id
        exporter = "192.0.2.1" if index % 2 else "192.0.2.2"
        vlan_id = vlan_a.id if index % 2 else vlan_b.id
        address = f"192.0.2.{index + 10 if index % 2 else index + 129}"
        assignments.append(AssetNetworkAssignment(asset_id=asset.id, address=address, address_family=4, vlan_id=vlan_id, network_cidr="192.0.2.0/25" if index % 2 else "192.0.2.128/25", ip_address_id=(managed_ips[index - 1].id if index <= 3 else None), source_id=source_id, exporter_identity=exporter, started_at=FIXTURE_NOW - timedelta(days=2), provenance="stage2b acceptance fixture", status="confirmed", confirmed_by=admin.id, confirmed_at=FIXTURE_NOW - timedelta(days=2)))
    static_asset = HardwareAsset(id=9450, asset_tag="STAGE2B-STATIC", name="Stage2B Static Asset", status="In use")
    assets.append(static_asset)
    assignments.append(AssetNetworkAssignment(asset_id=static_asset.id, address="192.0.2.50", address_family=4, vlan_id=vlan_a.id, network_cidr=vlan_a.subnet_cidr, started_at=FIXTURE_NOW - timedelta(days=1), provenance="stage2b static source-less fixture", status="confirmed", confirmed_by=admin.id, confirmed_at=FIXTURE_NOW - timedelta(days=1)))
    db.add_all(assets + assignments)
    db.flush()
    db.add(AssetIdentityEvidence(asset_id=assets[0].id, evidence_type="mac", normalised_value="02:00:00:00:00:01", source="dns", status="confirmed", confirmed_by=admin.id, confirmed_at=FIXTURE_NOW))

    monitor = TrafficDeviceMonitoring(asset_id=assets[0].id, assignment_id=assignments[0].id, is_enabled=True, status="active", enabled_at=FIXTURE_NOW - timedelta(days=1))
    inactive = TrafficDeviceMonitoring(asset_id=assets[1].id, assignment_id=assignments[1].id, is_enabled=False, status="disabled")
    db.add_all([monitor, inactive])
    db.flush()
    active_period = TrafficDeviceMonitoringPeriod(monitoring_id=monitor.id, asset_id=assets[0].id, assignment_id=assignments[0].id, endpoint_address=assignments[0].address, address_family=4, exporter_identity="192.0.2.1", started_at=FIXTURE_NOW - timedelta(days=1))
    historical_period = TrafficDeviceMonitoringPeriod(monitoring_id=monitor.id, asset_id=assets[0].id, assignment_id=assignments[0].id, endpoint_address=assignments[0].address, address_family=4, exporter_identity="192.0.2.1", started_at=FIXTURE_NOW - timedelta(days=4), ended_at=FIXTURE_NOW - timedelta(days=2))
    db.add_all([active_period, historical_period])
    db.flush()
    db.add_all([
        TrafficDeviceAggregate(period_id=active_period.id, asset_id=assets[0].id, assignment_id=assignments[0].id, endpoint_address=assignments[0].address, address_family=4, exporter_identity="192.0.2.1", source_id=source_a.id, interface_id=iface_a.id, bucket_start=FIXTURE_NOW - timedelta(hours=1), bucket_seconds=300, direction="download", bytes_total=1000, packets_total=10, sample_count=1, attribution_confidence="high"),
        TrafficDeviceAggregate(period_id=active_period.id, asset_id=assets[0].id, assignment_id=assignments[0].id, endpoint_address=assignments[0].address, address_family=4, exporter_identity="192.0.2.1", source_id=source_a.id, interface_id=iface_a.id, bucket_start=FIXTURE_NOW - timedelta(hours=1), bucket_seconds=300, direction="upload", bytes_total=300, packets_total=3, sample_count=1, attribution_confidence="high"),
    ])
    db.add_all([
        TrafficAggregate(source_id=source_a.id, interface_id=iface_a.id, bucket_start=FIXTURE_NOW - timedelta(hours=1), bucket_seconds=300, direction="download", traffic_class="interface_total", bytes_total=1000, sample_count=1),
        TrafficAggregate(source_id=source_a.id, interface_id=iface_a.id, bucket_start=FIXTURE_NOW - timedelta(hours=1), bucket_seconds=300, direction="upload", traffic_class="interface_total", bytes_total=300, sample_count=1),
    ])

    for index in range(60):
        address = f"192.0.2.{10 + index}"
        source = source_a if index % 2 == 0 else source_b
        exporter = "192.0.2.1" if index % 2 == 0 else "192.0.2.2"
        db.add(TrafficDiscoveryObservation(source_id=source.id, exporter_identity=exporter, endpoint_ip=address, address_family=4, endpoint_role="original_source", bucket_start=FIXTURE_NOW - timedelta(minutes=index), first_seen_at=FIXTURE_NOW - timedelta(minutes=index), last_seen_at=FIXTURE_NOW, observation_count=index + 1, classification="internal", confidence="confirmed" if index < 12 else "unknown"))
    for index, asset in enumerate(assets[:3]):
        address = assignments[index].address
        client = DNSRecognisedDevice(provider_id=provider.id, logical_provider_key="stage2b-pihole", identity_key=f"stage2b-client-{index}", identity_type="mac", identity_value=f"02:00:00:00:10:{index:02x}", hostname=f"stage2b-host-{index}.invalid", current_ip=address, mac_address=f"02:00:00:00:10:{index:02x}", provider_type="pihole", friendly_name=f"Stage2B DNS {index}", is_known=True, hardware_asset_id=asset.id, linked_ip_record_id=managed_ips[index].id, last_seen_at=FIXTURE_NOW)
        db.add(client)
    db.add(DNSRecognisedDevice(provider_id=provider.id, logical_provider_key="stage2b-pihole", identity_key="stage2b-unlinked", identity_type="mac", identity_value="02:00:00:00:20:01", hostname="unlinked.stage2b.invalid", current_ip="192.0.2.90", mac_address="02:00:00:00:20:01", provider_type="pihole", friendly_name="Stage2B Unlinked", is_known=False, last_seen_at=FIXTURE_NOW))
    db.flush()
    for index, client in enumerate(db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.provider_id == provider.id).all()[:3]):
        db.add(DHCPLeaseHistory(provider_id=provider.id, dns_client_id=client.id, ip_address=client.current_ip, mac_address=client.mac_address, hostname=client.hostname, provider_lease_id=f"stage2b-lease-{index}", lease_started_at=FIXTURE_NOW - timedelta(hours=2), first_seen_at=FIXTURE_NOW - timedelta(hours=2), last_seen_at=FIXTURE_NOW, is_active=True, source="stage2b fixture"))
    db.commit()

    counts = {
        "sources": db.query(TrafficSource).filter(TrafficSource.id.in_([source_a.id, source_b.id])).count(),
        "vlans": db.query(VLAN).filter(VLAN.id.in_([vlan_a.id, vlan_b.id])).count(),
        "mappings": db.query(TrafficDiscoveryNetworkMapping).count(),
        "assets": db.query(HardwareAsset).filter(HardwareAsset.id >= 9400, HardwareAsset.id < 9500).count(),
        "observations": db.query(TrafficDiscoveryObservation).count(),
        "dns_clients": db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.provider_id == provider.id).count(),
        "dhcp_leases": db.query(DHCPLeaseHistory).filter(DHCPLeaseHistory.provider_id == provider.id).count(),
        "device_aggregates": db.query(TrafficDeviceAggregate).count(),
    }
    expected = {"sources": 2, "vlans": 2, "mappings": 2, "assets": 13, "observations": 60, "dns_clients": 4, "dhcp_leases": 3, "device_aggregates": 2}
    if counts != expected:
        raise AssertionError(f"Stage2B fixture incomplete: expected {expected}, got {counts}")
    return counts | {"admin_email": admin.email, "viewer_email": viewer.email, "password": FIXTURE_PASSWORD}
