from datetime import datetime

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    IPAddress,
    TrafficDiscoveryConfiguration,
    TrafficDiscoveryObservation,
    TrafficDiscoveryLink,
    TrafficLocalNetwork,
    TrafficSource,
    VLAN,
)
from app.services.network_discovery_matching import match_endpoint
from app.services.audit import write_audit
from app.routers.network_discovery import DiscoveryDecision, _decision


def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def setup(session):
    session.add_all([
        TrafficDiscoveryConfiguration(id=1, is_enabled=True),
        TrafficSource(id=1, name="Flow", provider_key="netflow_v9", source_category="flow_export", is_enabled=True),
        TrafficLocalNetwork(id=1, name="LAN", network_cidr="10.0.0.0/24", is_enabled=True),
        VLAN(id=1, name="LAN", subnet_cidr="10.0.0.0/24"),
        IPAddress(id=1, vlan_id=1, address="10.0.0.20", name="Managed host"),
        TrafficDiscoveryObservation(
            source_id=1, exporter_identity="192.0.2.1", endpoint_ip="10.0.0.20", address_family=4,
            endpoint_role="original_source", bucket_start=datetime(2026, 1, 1), bucket_seconds=300,
            first_seen_at=datetime(2026, 1, 1), last_seen_at=datetime(2026, 1, 1), observation_count=1,
            classification="internal", confidence="high",
        ),
    ])
    session.commit()


def test_exact_matching_is_read_only_and_does_not_enable_device_monitoring():
    session = db()
    setup(session)

    result = match_endpoint(session, 1, "10.0.0.20", classification="internal")

    assert result.status == "unlinked"
    assert result.confidence == "high"
    assert result.managed_ip_address_id == 1
    assert session.query(IPAddress).one().traffic_monitoring is None


def test_ipv6_and_dhcp_reuse_are_conservative():
    session = db()
    session.add(TrafficLocalNetwork(id=2, name="IPv6", network_cidr="2001:db8:1::/64", is_enabled=True))
    session.commit()

    result = match_endpoint(session, 1, "2001:db8:1::20", classification="internal")
    reused = match_endpoint(session, 1, "10.0.0.21", classification="internal")

    assert result.status == "unlinked"
    assert result.reason == "no_exact_managed_record"
    assert reused.status == "unmatched"
    assert reused.managed_ip_address_id is None


def test_overlapping_network_context_is_ambiguous():
    session = db()
    session.add_all([
        TrafficLocalNetwork(id=2, name="LAN wide", network_cidr="10.0.0.0/8", is_enabled=True),
        TrafficLocalNetwork(id=3, name="Overlap", network_cidr="10.0.0.0/25", is_enabled=True),
    ])
    session.commit()

    result = match_endpoint(session, 1, "10.0.0.20", classification="internal")

    assert result.status == "ambiguous"
    assert result.reason == "overlapping_local_networks"


def test_discovery_link_identity_includes_endpoint_role():
    session = db()
    setup(session)
    session.add_all([
        TrafficDiscoveryLink(
            source_id=1, exporter_identity="192.0.2.1", endpoint_ip="10.0.0.20",
            endpoint_role="original_source", state="linked",
        ),
        TrafficDiscoveryLink(
            source_id=1, exporter_identity="192.0.2.1", endpoint_ip="10.0.0.20",
            endpoint_role="translated_source", state="ignored",
        ),
    ])
    session.commit()
    assert session.query(TrafficDiscoveryLink).count() == 2


def test_audit_can_share_the_decision_transaction():
    session = db()
    setup(session)
    session.add(TrafficDiscoveryLink(
        source_id=1, exporter_identity="192.0.2.1", endpoint_ip="10.0.0.20",
        endpoint_role="original_source", state="linked",
    ))
    audit = write_audit(
        session, None, "discovery_link", "traffic_discovery_endpoint", "1:original_source",
        force=True, commit=False,
    )
    assert audit is not None
    session.rollback()
    assert session.query(TrafficDiscoveryLink).count() == 0
    assert session.query(type(audit)).count() == 0


def test_translated_endpoint_cannot_be_linked_and_identity_is_bounded():
    session = db()
    setup(session)
    with pytest.raises(HTTPException) as translated:
        _decision(
            None, session, None, 1, "192.0.2.1", "translated_source", "10.0.0.20",
            DiscoveryDecision(confirmation=True, managed_ip_address_id=1), action="link",
        )
    assert translated.value.status_code == 409
    with pytest.raises(HTTPException) as oversized:
        _decision(
            None, session, None, 1, "x" * 46, "original_source", "10.0.0.20",
            DiscoveryDecision(confirmation=True, managed_ip_address_id=1), action="link",
        )
    assert oversized.value.status_code == 400
