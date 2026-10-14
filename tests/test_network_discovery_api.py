from datetime import datetime
from types import SimpleNamespace

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
    TrafficDiscoveryNetworkMapping,
    TrafficSource,
    VLAN,
)
from app.services.network_discovery_matching import match_endpoint
from app.services.audit import write_audit
from app.routers.network_discovery import (
    DiscoveryDecision,
    DiscoveryNetworkMappingPayload,
    _decision,
    create_network_mapping,
    delete_network_mapping,
    update_network_mapping,
    list_network_mappings,
    _row_payload,
)


def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def setup(session):
    session.add_all([
        TrafficDiscoveryConfiguration(id=1, is_enabled=True),
        TrafficSource(id=1, name="Flow", provider_key="netflow_v9", source_category="flow_export", is_enabled=True),
        VLAN(id=1, name="LAN", subnet_cidr="10.0.0.0/24"),
        TrafficDiscoveryNetworkMapping(id=1, source_id=1, exporter_identity="192.0.2.1", vlan_id=1, is_enabled=True),
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

    result = match_endpoint(session, 1, "192.0.2.1", "10.0.0.20", classification="internal")

    assert result.status == "unlinked"
    assert result.confidence == "high"
    assert result.managed_ip_address_id == 1
    assert session.query(IPAddress).one().traffic_monitoring is None


def test_ipv6_and_dhcp_reuse_are_conservative():
    session = db()
    setup(session)
    session.add(VLAN(id=2, name="IPv6", subnet_cidr="2001:db8:1::/64"))
    session.add(TrafficDiscoveryNetworkMapping(id=2, source_id=1, exporter_identity="192.0.2.1", vlan_id=2, is_enabled=True))
    session.commit()

    result = match_endpoint(session, 1, "192.0.2.1", "2001:db8:1::20", classification="internal")
    reused = match_endpoint(session, 1, "192.0.2.1", "10.0.0.21", classification="internal")

    assert result.status == "unlinked"
    assert result.reason == "no_exact_managed_record"
    assert reused.status == "unlinked"
    assert reused.reason == "no_exact_managed_record"
    assert reused.managed_ip_address_id is None


def test_overlapping_network_context_is_ambiguous():
    session = db()
    setup(session)
    session.add_all([
        VLAN(id=2, name="LAN wide", subnet_cidr="10.0.0.0/8"),
        VLAN(id=3, name="Overlap", subnet_cidr="10.0.0.0/25"),
        TrafficDiscoveryNetworkMapping(id=2, source_id=1, exporter_identity="192.0.2.1", vlan_id=2, is_enabled=True),
        TrafficDiscoveryNetworkMapping(id=3, source_id=1, exporter_identity="192.0.2.1", vlan_id=3, is_enabled=True),
    ])
    session.commit()

    result = match_endpoint(session, 1, "192.0.2.1", "10.0.0.20", classification="internal")

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


def _observation_row():
    return SimpleNamespace(
        source_id=1,
        exporter_identity="192.0.2.1",
        endpoint_ip="10.0.0.20",
        endpoint_role="original_source",
        first_seen_at=datetime(2026, 1, 1),
        last_seen_at=datetime(2026, 1, 1),
        observation_count=1,
    )


def _stored_link(session):
    link = TrafficDiscoveryLink(
        source_id=1, exporter_identity="192.0.2.1", endpoint_ip="10.0.0.20",
        endpoint_role="original_source", managed_ip_address_id=1, state="linked",
        mapping_vlan_id=1, mapping_network_cidr="10.0.0.0/24",
    )
    session.add(link)
    session.commit()
    return link


def test_historical_link_is_valid_only_for_unchanged_mapping_context():
    session = db()
    setup(session)
    _stored_link(session)

    assert _row_payload(session, _observation_row())["status"] == "linked"
    assert _row_payload(session, _observation_row())["link_validity"] == "valid"

    session.query(TrafficDiscoveryNetworkMapping).one().is_enabled = False
    session.commit()
    disabled = _row_payload(session, _observation_row())
    assert disabled["status"] == "stale"
    assert disabled["link_validity"] == "stale"
    assert disabled["historical_managed_ip_address_id"] == 1


def test_subnet_change_is_stale_even_when_endpoint_is_in_new_network():
    session = db()
    setup(session)
    _stored_link(session)
    session.query(VLAN).one().subnet_cidr = "10.0.0.0/25"
    session.commit()

    result = _row_payload(session, _observation_row())
    assert result["status"] == "stale"
    assert result["status_reason"] == "mapping_network_changed"


def test_missing_target_and_overlapping_context_are_not_valid_links():
    session = db()
    setup(session)
    _stored_link(session)
    session.delete(session.get(IPAddress, 1))
    session.commit()
    missing = _row_payload(session, _observation_row())
    assert missing["status"] == "unresolved"
    assert missing["status_reason"] == "managed_ip_record_missing"

    session = db()
    setup(session)
    _stored_link(session)
    session.add(VLAN(id=2, name="Overlap", subnet_cidr="10.0.0.0/25"))
    session.add(TrafficDiscoveryNetworkMapping(id=2, source_id=1, exporter_identity="192.0.2.1", vlan_id=2, is_enabled=True))
    session.commit()
    ambiguous = _row_payload(session, _observation_row())
    assert ambiguous["status"] == "ambiguous"
    assert ambiguous["status_reason"] == "overlapping_local_networks"


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


def test_exporter_vlan_mapping_crud_is_admin_audited_and_does_not_touch_local_networks(monkeypatch):
    session = db()
    session.add_all([
        TrafficSource(id=2, name="Second flow", provider_key="cisco_nsel", source_category="flow_export", is_enabled=True),
        VLAN(id=2, name="Second LAN", subnet_cidr="10.2.0.0/16"),
    ])
    session.commit()
    monkeypatch.setattr("app.routers.network_discovery.validate_csrf_token", lambda *_args: None)
    monkeypatch.setattr("app.routers.network_discovery.write_audit", lambda *_args, **_kwargs: object())
    monkeypatch.setattr("app.routers.network_discovery.trusted_client_ip", lambda _request: "192.0.2.10")
    request = type("Request", (), {"headers": {"x-csrf-token": "synthetic"}, "client": type("Client", (), {"host": "192.0.2.10"})()})()
    user = type("User", (), {"id": 7})()
    payload = DiscoveryNetworkMappingPayload(source_id=2, exporter_identity="192.0.2.9", vlan_id=2)
    created = create_network_mapping(request, payload, session, user)
    assert created["vlan_id"] == 2
    updated = update_network_mapping(request, created["id"], payload.model_copy(update={"is_enabled": False}), session, user)
    assert updated["is_enabled"] is False
    with pytest.raises(HTTPException) as duplicate:
        create_network_mapping(request, payload, session, user)
    assert duplicate.value.status_code == 409
    delete_network_mapping(request, created["id"], DiscoveryDecision(confirmation=True), session, user)
    assert session.query(TrafficDiscoveryNetworkMapping).count() == 0


def test_mapping_listing_exposes_safe_options_and_current_validity():
    session = db()
    session.add(TrafficSource(id=2, name="Cisco", provider_key="cisco_nsel", source_category="flow_export", is_enabled=True, exporter_allowlist_json='["192.0.2.9"]'))
    session.add(VLAN(id=2, name="Office", subnet_cidr="10.2.0.0/16"))
    session.add(TrafficDiscoveryNetworkMapping(id=2, source_id=2, exporter_identity="192.0.2.9", vlan_id=2, is_enabled=True))
    session.commit()
    result = list_network_mappings(session, object())
    assert result["sources"] == [{"id": 2, "name": "Cisco", "provider_key": "cisco_nsel", "is_enabled": True, "exporters": ["192.0.2.9"]}]
    assert result["vlans"] == [{"id": 2, "name": "Office", "subnet_cidr": "10.2.0.0/16"}]
    assert result["mappings"][-1]["validity"] == "valid"
    assert result["mappings"][-1]["network_cidr"] == "10.2.0.0/16"
