from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HardwareAsset,
    IPAddress,
    TrafficDeviceAggregate,
    TrafficDeviceMonitoring,
    TrafficDeviceMonitoringPeriod,
    TrafficSource,
    User,
    UserModulePermission,
    VLAN,
)
from app.routers.hardware_assets import asset_profile_context
from app.services.asset_profile_reporting import asset_reporting_context


def test_asset_profile_does_not_leak_disabled_module_sections():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    admin = User(id=1, email="admin@example.invalid", role="admin")
    asset = HardwareAsset(id=1, name="Synthetic asset", status="In use")
    provider = DNSProviderConfig(id=1, name="Synthetic DNS", provider_type="test", base_url="https://dns.invalid")
    client = DNSRecognisedDevice(
        id=1, provider_id=1, logical_provider_key="synthetic", identity_type="mac",
        identity_value="00:11:22:33:44:55", normalised_mac="00:11:22:33:44:55",
        current_ip="192.0.2.10", hardware_asset_id=1,
    )
    db.add_all([admin, asset, provider, client, AssetIdentityEvidence(
        asset_id=1, evidence_type="mac", normalised_value="00:11:22:33:44:55",
        source="dhcp", status="confirmed",
    )])
    db.commit()

    profile = asset_profile_context(db, admin, asset)

    assert profile["identity_rows"]
    assert profile["dns_clients"] is None
    assert profile["dhcp_leases"] is None
    assert profile["managed_ips"] is None
    assert profile["discovery_links"] is None


def test_asset_reporting_is_permission_aware_and_bounded():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    admin = User(id=1, email="admin@example.invalid", role="admin")
    asset = HardwareAsset(id=1, name="Synthetic asset", status="In use")
    db.add_all([admin, asset])
    db.commit()

    result = asset_reporting_context(db, admin, asset.id, period="7d")

    assert result["period"] == "7d"
    assert result["window"]["end"] > result["window"]["start"]
    assert result["traffic"] is None
    assert result["dns"] is None
    assert result["uptime"] is None


def test_asset_reporting_excludes_ambiguous_traffic_assignment_buckets(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    now = datetime.utcnow().replace(second=0, microsecond=0)
    admin = User(id=1, email="admin@example.invalid", role="admin")
    asset = HardwareAsset(id=1, name="Synthetic traffic asset", status="In use")
    vlan = VLAN(id=1, name="Synthetic VLAN", subnet_cidr="192.0.2.0/24")
    ip = IPAddress(id=1, vlan_id=1, address="192.0.2.10", name="Synthetic endpoint")
    source = TrafficSource(id=1, name="Synthetic source", provider_key="test", source_category="flow", is_enabled=True)
    monitoring = TrafficDeviceMonitoring(id=1, ip_address_id=1, is_enabled=True)
    period = TrafficDeviceMonitoringPeriod(id=1, monitoring_id=1, ip_address_id=1, started_at=now - timedelta(hours=2))
    assignment = AssetNetworkAssignment(
        id=1, asset_id=1, address=ip.address, address_family=4, vlan_id=1, network_cidr="192.0.2.0/24",
        ip_address_id=1, source_id=1, exporter_identity="synthetic-exporter", started_at=now - timedelta(hours=2), provenance="review", status="confirmed",
    )
    db.add_all([admin, asset, vlan, ip, source, monitoring, period, assignment, UserModulePermission(user_id=1, module_key="network_monitor", allowed=True)])
    db.add_all([
        TrafficDeviceAggregate(id=1, period_id=1, ip_address_id=1, source_id=1, bucket_start=now - timedelta(hours=1), bucket_seconds=300, direction="download", bytes_total=300, packets_total=3),
        TrafficDeviceAggregate(id=2, period_id=1, ip_address_id=1, source_id=1, bucket_start=now - timedelta(hours=1), bucket_seconds=300, direction="upload", bytes_total=100, packets_total=1),
    ])
    db.commit()
    monkeypatch.setattr("app.services.asset_profile_reporting.has_module_access", lambda _db, _user, key: key == "network_monitor")

    result = asset_reporting_context(db, admin, 1, period="24h",)

    assert result["traffic"]["download_bytes"] == 300
    assert result["traffic"]["upload_bytes"] == 100
    assignment2 = AssetNetworkAssignment(
        id=2, asset_id=1, address=ip.address, address_family=4, vlan_id=1, network_cidr="192.0.2.0/24",
        ip_address_id=1, source_id=1, exporter_identity="another-exporter", started_at=now - timedelta(hours=2), provenance="review", status="confirmed",
    )
    db.add(assignment2)
    db.commit()
    ambiguous = asset_reporting_context(db, admin, 1, period="24h")
    assert ambiguous["traffic"]["download_bytes"] == 0
    assert ambiguous["traffic"]["excluded_buckets"] == 2
