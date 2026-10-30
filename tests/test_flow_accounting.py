from datetime import datetime
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import DHCPLeaseHistory
from app.services.flow_accounting import classify_flow, resolve_flow_attribution, retention_cutoffs
from app.services.flow_protocol import NormalizedFlowRecord


def record(**overrides):
    values = {
        "exporter_identity": "192.0.2.10", "source_id": 1, "sequence": 1, "record_index": 0,
        "observed_at": datetime(2026, 1, 1, 12, 0), "flow_start": None, "flow_end": None,
        "source_ip": "192.0.2.20", "destination_ip": "198.51.100.20", "source_port": 443,
        "destination_port": 51515, "protocol": 6, "input_interface": 2, "output_interface": 10,
        "translated_source_ip": None, "translated_destination_ip": None,
        "translated_source_port": None, "translated_destination_port": None,
        "bytes_total": 100, "packets_total": 1, "direction": "unknown", "event_type": None,
        "connection_id": "1", "cumulative_counters": False, "data_quality": "complete",
    }
    values.update(overrides)
    return NormalizedFlowRecord(**values)


def test_classification_requires_configured_topology_and_supports_ipv4_ipv6():
    assert classify_flow(record(), local_networks=["192.0.2.0/24"]).traffic_class == "internet_upload"
    assert classify_flow(record(source_ip="198.51.100.20", destination_ip="192.0.2.30"), local_networks=["192.0.2.0/24"]).traffic_class == "internet_download"
    assert classify_flow(record(destination_ip="192.0.2.30"), local_networks=["192.0.2.0/24"]).traffic_class == "internal_lan"
    assert classify_flow(record(source_ip="2001:db8::10", destination_ip="2001:db8::20"), local_networks=["2001:db8::/64"]).traffic_class == "internal_lan"
    assert classify_flow(record(), local_networks=[]).traffic_class == "unknown"


def test_wan_interface_mapping_takes_precedence_over_address_assumptions():
    interfaces = [SimpleNamespace(interface_index=2, is_enabled=True, is_wan=True)]
    assert classify_flow(record(input_interface=2), interfaces=interfaces, local_networks=[]).traffic_class == "wan_inbound"
    assert classify_flow(record(input_interface=10, output_interface=2), interfaces=interfaces, local_networks=[]).traffic_class == "wan_outbound"


def test_retention_cutoffs_are_bounded_by_bucket_class():
    now = datetime(2026, 1, 10)
    cutoffs = retention_cutoffs(now, short_days=7, hourly_days=30, daily_days=365)
    assert set(cutoffs) == {300, 3600, 86400}
    assert (now - cutoffs[300]).days == 7


def test_attribution_is_time_bounded_and_marks_reused_or_ambiguous_ips_unknown():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    observed = datetime(2026, 1, 10)
    with factory() as db:
        db.add(DHCPLeaseHistory(ip_address="192.0.2.20", lease_started_at=datetime(2026, 1, 1), first_seen_at=datetime(2026, 1, 1), last_seen_at=datetime(2026, 1, 5), expires_at=datetime(2026, 1, 5), is_active=False))
        db.commit()
        result = resolve_flow_attribution(db, record(observed_at=observed))
        assert result.state == "unresolved"
        assert result.unresolved_reason == "no_time_bounded_identity"
        db.add(DHCPLeaseHistory(ip_address="192.0.2.20", lease_started_at=datetime(2026, 1, 6), first_seen_at=datetime(2026, 1, 6), last_seen_at=observed, expires_at=None, is_active=True))
        db.commit()
        result = resolve_flow_attribution(db, record(observed_at=observed))
        assert result.state == "resolved"
        db.add(DHCPLeaseHistory(ip_address="192.0.2.20", lease_started_at=datetime(2026, 1, 7), first_seen_at=datetime(2026, 1, 7), last_seen_at=observed, expires_at=None, is_active=True))
        db.commit()
        assert resolve_flow_attribution(db, record(observed_at=observed)).unresolved_reason == "ambiguous_dhcp_history"
