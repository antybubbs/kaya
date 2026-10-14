from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    DHCPLeaseHistory,
    DNSProviderConfig,
    DNSRecognisedDevice,
    HardwareAsset,
    TrafficDiscoveryNetworkMapping,
    TrafficDiscoveryObservation,
    TrafficSource,
    VLAN,
)
from app.services.asset_identity_resolution import (
    evidence_for_asset,
    resolve_discovery_observation,
    resolve_observed_ip,
)


def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def seed_asset(db, asset_id=1):
    db.add(HardwareAsset(id=asset_id, name=f"Synthetic asset {asset_id}", status="In use"))
    db.commit()


def test_confirmed_assignment_is_time_and_network_context_aware():
    db = db_session()
    seed_asset(db)
    vlan = VLAN(id=1, name="Synthetic LAN", subnet_cidr="192.0.2.0/24")
    db.add(vlan)
    db.flush()
    start = datetime(2026, 1, 1)
    db.add(AssetNetworkAssignment(
        asset_id=1, address="192.0.2.10", address_family=4, vlan_id=1,
        network_cidr="192.0.2.0/24", started_at=start,
        provenance="dhcp", status="confirmed",
    ))
    db.commit()
    result = resolve_observed_ip(db, "192.0.2.10", start + timedelta(hours=1), vlan_id=1)
    assert result.state == "confirmed_match"
    assert result.candidates[0].asset_id == 1

    vlan.subnet_cidr = "192.0.2.0/25"
    db.commit()
    stale = resolve_observed_ip(db, "192.0.2.10", start + timedelta(hours=1), vlan_id=1)
    assert stale.state == "unresolved"
    assert not stale.candidates


def test_dhcp_reuse_does_not_inherit_previous_asset():
    db = db_session()
    seed_asset(db, 1)
    seed_asset(db, 2)
    provider = DNSProviderConfig(id=1, name="Synthetic DNS", provider_type="test", base_url="https://dns.invalid")
    first = DNSRecognisedDevice(id=1, provider_id=1, logical_provider_key="test", identity_type="mac", identity_value="00:11:22:33:44:55", normalised_mac="00:11:22:33:44:55", hardware_asset_id=1, is_known=True)
    second = DNSRecognisedDevice(id=2, provider_id=1, logical_provider_key="test", identity_type="mac", identity_value="00:11:22:33:44:66", normalised_mac="00:11:22:33:44:66", hardware_asset_id=2, is_known=True)
    db.add_all([provider, first, second])
    db.flush()
    before = datetime(2026, 1, 1)
    after = datetime(2026, 1, 2)
    db.add_all([
        DHCPLeaseHistory(id=1, provider_id=1, dns_client_id=1, ip_address="192.0.2.20", mac_address="00:11:22:33:44:55", lease_started_at=before, first_seen_at=before, last_seen_at=before, ended_at=after, is_active=False),
        DHCPLeaseHistory(id=2, provider_id=1, dns_client_id=2, ip_address="192.0.2.20", mac_address="00:11:22:33:44:66", lease_started_at=after, first_seen_at=after, last_seen_at=after, is_active=True),
    ])
    db.commit()
    old = resolve_observed_ip(db, "192.0.2.20", before + timedelta(hours=1))
    new = resolve_observed_ip(db, "192.0.2.20", after + timedelta(hours=1))
    assert {candidate.asset_id for candidate in old.candidates} == {1}
    assert {candidate.asset_id for candidate in new.candidates} == {2}


def test_conflicting_evidence_is_ambiguous_and_ip_only_is_unresolved():
    db = db_session()
    seed_asset(db, 1)
    seed_asset(db, 2)
    observed = datetime(2026, 1, 1)
    db.add_all([
        AssetIdentityEvidence(asset_id=1, evidence_type="hostname", normalised_value="shared", source="dns", status="confirmed", first_observed_at=observed, last_observed_at=observed),
        AssetIdentityEvidence(asset_id=2, evidence_type="hostname", normalised_value="shared", source="dns", status="confirmed", first_observed_at=observed, last_observed_at=observed),
    ])
    db.commit()
    ambiguous = resolve_observed_ip(db, "192.0.2.30", observed, hostname="shared")
    assert ambiguous.state == "ambiguous"
    assert {candidate.asset_id for candidate in ambiguous.candidates} == {1, 2}
    unresolved = resolve_observed_ip(db, "192.0.2.30", observed)
    assert unresolved.state == "unresolved"
    assert not unresolved.candidates


def test_original_discovery_requires_current_mapping_and_translated_endpoint_is_review_only():
    db = db_session()
    seed_asset(db)
    source = TrafficSource(id=1, name="Synthetic flow", provider_key="test", source_category="flow", is_enabled=True, is_deleted=False)
    vlan = VLAN(id=1, name="Synthetic LAN", subnet_cidr="192.0.2.0/24")
    db.add_all([source, vlan])
    db.flush()
    db.add(AssetNetworkAssignment(
        asset_id=1, address="192.0.2.40", address_family=4, vlan_id=1,
        network_cidr="192.0.2.0/24", source_id=1, exporter_identity="198.51.100.10",
        started_at=datetime(2026, 1, 1), provenance="flow", status="confirmed",
    ))
    db.add(TrafficDiscoveryNetworkMapping(id=1, source_id=1, exporter_identity="198.51.100.10", vlan_id=1, is_enabled=True))
    observation = TrafficDiscoveryObservation(
        id=1, source_id=1, exporter_identity="198.51.100.10", endpoint_ip="192.0.2.40",
        address_family=4, endpoint_role="original", bucket_start=datetime(2026, 1, 1),
        first_seen_at=datetime(2026, 1, 1), last_seen_at=datetime(2026, 1, 1), observation_count=1,
        classification="internal", confidence="high",
    )
    db.add(observation)
    db.commit()
    result = resolve_discovery_observation(db, 1)
    assert result.state == "confirmed_match"
    observation.endpoint_role = "translated"
    db.commit()
    assert resolve_discovery_observation(db, 1).state == "unresolved"


def test_disabled_mapping_and_missing_modules_fail_closed_without_mutation():
    db = db_session()
    source = TrafficSource(id=1, name="Synthetic flow", provider_key="test", source_category="flow", is_enabled=True)
    vlan = VLAN(id=1, name="Synthetic LAN", subnet_cidr="192.0.2.0/24")
    db.add_all([source, vlan])
    db.flush()
    db.add(TrafficDiscoveryNetworkMapping(id=1, source_id=1, exporter_identity="198.51.100.10", vlan_id=1, is_enabled=False))
    db.add(TrafficDiscoveryObservation(
        id=1, source_id=1, exporter_identity="198.51.100.10", endpoint_ip="192.0.2.40",
        address_family=4, endpoint_role="original", bucket_start=datetime(2026, 1, 1),
        first_seen_at=datetime(2026, 1, 1), last_seen_at=datetime(2026, 1, 1), observation_count=1,
        classification="internal", confidence="high",
    ))
    db.commit()
    result = resolve_discovery_observation(db, 1)
    assert result.state == "unresolved"
    assert db.query(AssetNetworkAssignment).count() == 0
    assert resolve_observed_ip(db, "2001:db8::1", datetime(2026, 1, 1)).state == "unresolved"


def test_asset_evidence_report_separates_revoked_history():
    db = db_session()
    seed_asset(db)
    db.add_all([
        AssetIdentityEvidence(asset_id=1, evidence_type="mac", normalised_value="00:11:22:33:44:55", source="dhcp", status="confirmed"),
        AssetIdentityEvidence(asset_id=1, evidence_type="hostname", normalised_value="old", source="dns", status="revoked"),
    ])
    db.commit()
    report = evidence_for_asset(db, 1)
    assert len(report["current"]) == 1
    assert len(report["stale"]) == 1


def test_asset_evidence_report_marks_changed_vlan_context_stale():
    db = db_session()
    seed_asset(db)
    vlan = VLAN(id=1, name="Synthetic LAN", subnet_cidr="192.0.2.0/24")
    db.add(vlan)
    db.flush()
    db.add(AssetNetworkAssignment(
        asset_id=1, address="192.0.2.10", address_family=4, vlan_id=1,
        network_cidr="192.0.2.0/24", started_at=datetime.utcnow() - timedelta(minutes=1),
        provenance="static", status="confirmed",
    ))
    db.commit()
    vlan.subnet_cidr = "192.0.2.0/25"
    db.commit()
    report = evidence_for_asset(db, 1)
    assert not report["current"]
    assert report["stale"][0].match_state == "stale"
