from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import AssetIdentityEvidence, DNSProviderConfig, DNSRecognisedDevice, HardwareAsset, User
from app.routers.hardware_assets import asset_profile_context


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
