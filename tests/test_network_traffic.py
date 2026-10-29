import json
import asyncio
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import decrypt_secret
from app.db.session import Base
from app.models.models import TrafficAggregate, TrafficCounterObservation, TrafficFlowCollectorGlobalState, TrafficFlowCollectorState, TrafficInterface, TrafficMonitoringConfiguration, TrafficPollingLease, TrafficSource
from app.services.network_traffic import (
    apply_source_secrets,
    source_public_dict,
    validate_destination,
    validate_exporters,
    validate_local_network,
    validate_source_input,
)
from app.routers import network_monitor as network_monitor_router
from app.services.network_traffic_poller import _upsert_aggregate, acquire_polling_lease, poll_source_once
from app.services.network_traffic_snmp import InterfaceSnapshot, calculate_rate


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as session:
        yield session


def source_data(**overrides):
    values = {
        "name": "Synthetic edge firewall",
        "provider_key": "snmpv3",
        "source_category": "interface_polling",
        "is_enabled": True,
        "destination_ip": "192.0.2.10",
        "security_name": "kaya-monitor",
        "snmp_auth_protocol": "SHA-256",
        "snmp_privacy_protocol": "AES128",
        "snmp_authentication": "fake-authentication-secret",
        "snmp_privacy": "fake-privacy-secret",
    }
    values.update(overrides)
    return values


def test_source_configuration_is_validated_and_credentials_are_encrypted(db):
    values = validate_source_input(source_data())
    row = TrafficSource(**values)
    apply_source_secrets(row, source_data(), creating=True)
    db.add(row)
    db.commit()

    assert row.encrypted_snmp_authentication != "fake-authentication-secret"
    assert decrypt_secret(row.encrypted_snmp_authentication) == "fake-authentication-secret"
    public = source_public_dict(row)
    assert "fake-authentication-secret" not in json.dumps(public)
    assert "encrypted_snmp_authentication" not in public
    assert public["has_snmp_authentication"] is True


@pytest.mark.parametrize("provider", ["netflow_v9", "cisco_nsel"])
def test_flow_sources_do_not_require_or_store_snmp_credentials(db, provider):
    values = validate_source_input({
        "name": f"{provider} fixture",
        "provider_key": provider,
        "source_category": "flow_export",
        "collector_port": 2055,
        "exporter_allowlist": ["192.168.1.1"],
    })
    row = TrafficSource(**values)
    apply_source_secrets(row, {"snmp_authentication": "ignored-secret", "snmp_privacy": "ignored-secret"}, creating=True)
    db.add(row)
    db.commit()

    assert row.is_enabled is False
    assert row.destination_ip is None
    assert row.collector_port == 2055
    assert row.exporter_allowlist_json == '["192.168.1.1"]'
    assert row.security_name is None
    assert row.encrypted_snmp_authentication is None
    assert row.encrypted_snmp_privacy is None


def test_snmp_sources_still_require_credentials_when_enabled():
    with pytest.raises(ValueError, match="private destination and security name"):
        validate_source_input(source_data(security_name=None))


@pytest.mark.parametrize("field,value", [("exporter_allowlist", ["not-an-ip"]), ("collector_port", 1023), ("collector_port", 65536)])
def test_flow_source_rejects_invalid_exporter_or_collector_port(field, value):
    values = {
        "name": "Invalid flow fixture",
        "provider_key": "cisco_nsel",
        "source_category": "flow_export",
        "collector_port": 2055,
        "exporter_allowlist": ["192.168.1.1"],
    }
    values[field] = value
    with pytest.raises(ValueError):
        validate_source_input(values)


def test_editing_flow_source_does_not_retain_incompatible_snmp_secrets(db):
    row = TrafficSource(**validate_source_input(source_data()))
    apply_source_secrets(row, source_data(), creating=True)
    db.add(row)
    db.commit()

    values = validate_source_input({
        "name": row.name,
        "provider_key": "cisco_nsel",
        "source_category": "flow_export",
        "collector_port": 2055,
        "exporter_allowlist": ["192.168.1.1"],
    }, existing=row)
    for key, value in values.items():
        setattr(row, key, value)
    apply_source_secrets(row, values)
    db.commit()

    assert row.provider_key == "cisco_nsel"
    assert row.encrypted_snmp_authentication is None
    assert row.encrypted_snmp_privacy is None
    assert row.security_name is None


def test_source_form_has_provider_specific_labels_and_actions():
    template = Path("app/templates/network_traffic.html").read_text(encoding="utf-8")
    script = Path("app/static/js/network_traffic.js").read_text(encoding="utf-8")
    discovery_script = Path("app/static/js/network_traffic_discovery.js").read_text(encoding="utf-8")
    diagnostics_enhancer = Path("app/static/js/network_traffic_diagnostics_enhancer.js").read_text(encoding="utf-8")
    assert 'data-source-enable-label' in template
    assert "Enable flow collection after saving" in script
    assert "Enable polling after saving" in script
    assert "button.hidden = flow" in script
    assert "if (provider === \"snmpv3\")" in script
    assert "template_lifecycle" in diagnostics_enhancer
    assert "template_lifecycle_summary" in diagnostics_enhancer
    assert "Template lifecycle" in diagnostics_enhancer
    assert "Flow discovery" in template
    assert "/api/network-discovery/summary" in discovery_script
    assert "Translated endpoint cannot be linked" in discovery_script
    assert "data-discovery-key" in discovery_script
    assert "X-CSRF-Token" in discovery_script


@pytest.mark.parametrize("value", ["localhost", "127.0.0.1", "8.8.8.8", "not-an-ip"])
def test_snmp_destination_rejects_ssrf_targets(value):
    with pytest.raises(ValueError):
        validate_destination(value)


def test_exporter_and_local_network_validation_is_literal_and_canonical():
    assert validate_exporters(["192.0.2.20", "192.0.2.20", "2001:db8::20"]) == ["192.0.2.20", "2001:db8::20"]
    assert validate_local_network("192.168.10.12/24") == "192.168.10.0/24"
    with pytest.raises(ValueError):
        validate_exporters(["flow-exporter.example.test"])


def test_aggregate_interval_is_split_across_utc_boundaries(db):
    source = TrafficSource(**validate_source_input(source_data()))
    db.add(source)
    db.flush()
    interface = TrafficInterface(source_id=source.id, interface_key="ifIndex:1", display_name="WAN")
    db.add(interface)
    db.flush()
    observed_at = datetime(2026, 1, 1, 0, 5, 0)
    _upsert_aggregate(db, source.id, interface.id, observed_at, 300, "download", 8_000, 600)
    db.commit()
    rows = db.query(TrafficAggregate).filter_by(source_id=source.id, interface_id=interface.id, bucket_seconds=300).order_by(TrafficAggregate.bucket_start).all()
    assert [row.bytes_total for row in rows] == [300_000, 300_000]
    assert all(row.is_approximate for row in rows)


def test_multiple_sources_and_interfaces_have_independent_identity_boundaries(db):
    rows = []
    for index in (1, 2):
        values = validate_source_input(source_data(name=f"Source {index}", destination_ip=f"192.0.2.{index}"))
        row = TrafficSource(**values)
        apply_source_secrets(row, source_data(), creating=True)
        db.add(row)
        db.flush()
        interface = TrafficInterface(source_id=row.id, interface_key="ifIndex:7", display_name=f"WAN {index}", is_wan=True)
        db.add(interface)
        rows.append((row, interface))
    db.commit()
    assert [row.id for row, _ in rows] == [1, 2]
    assert db.query(TrafficInterface).count() == 2
    assert {interface.source_id for _, interface in rows} == {rows[0][0].id, rows[1][0].id}


def test_disabled_by_default_configuration_and_source_retirement_preserve_records(db):
    config = TrafficMonitoringConfiguration(id=1)
    values = validate_source_input(source_data(is_enabled=False))
    source = TrafficSource(**values)
    db.add_all([config, source])
    db.commit()
    source.is_deleted = True
    source.deleted_at = source.updated_at
    source.is_enabled = False
    source.configuration_state = "disabled"
    db.commit()
    assert db.get(TrafficMonitoringConfiguration, 1).is_enabled is False
    assert db.get(TrafficSource, source.id).is_deleted is True
    assert db.get(TrafficSource, source.id).is_enabled is False


def test_traffic_mutations_require_csrf_and_admin_route_dependencies():
    route = next(route for route in network_monitor_router.router.routes if route.path.endswith("/traffic/sources") and "POST" in route.methods)
    dependency_calls = {dependency.call for dependency in route.dependant.dependencies}
    assert network_monitor_router.require_admin in dependency_calls
    request = Request({"type": "http", "method": "POST", "path": "/networking/ip-wan-monitor/traffic/sources", "headers": [], "session": {"csrf_token": "expected"}})
    with pytest.raises(HTTPException) as failure:
        network_monitor_router.create_traffic_source(request, network_monitor_router.TrafficSourcePayload(**source_data()), db=None, user=None)
    assert failure.value.status_code == 400


def test_stage_25_pages_stay_within_network_monitor_module_and_overview_is_minimal(db):
    paths = {route.path for route in network_monitor_router.router.routes}
    assert "/networking/ip-wan-monitor/traffic" in paths
    assert "/networking/ip-wan-monitor/traffic/sources/manage" in paths
    assert "/networking/ip-wan-monitor/traffic/settings" in paths
    assert "/networking/ip-wan-monitor/traffic/diagnostics/view" in paths
    source = TrafficSource(**validate_source_input(source_data()))
    db.add(source)
    db.flush()
    db.add(TrafficInterface(source_id=source.id, interface_key="ifIndex:1", display_name="WAN", is_wan=True))
    db.commit()
    overview = network_monitor_router.traffic_overview(db, None)
    assert overview["module_enabled"] is False
    assert overview["summary"]["wan_interfaces"] == 1
    assert "encrypted_snmp_authentication" not in str(overview)


def test_flow_source_health_is_provider_aware_and_does_not_use_snmp_success(db):
    source = TrafficSource(**validate_source_input({
        "name": "Synthetic NSEL health",
        "provider_key": "cisco_nsel",
        "source_category": "flow_export",
        "is_enabled": True,
        "collector_port": 2055,
        "exporter_allowlist": ["192.0.2.1"],
    }))
    db.add(source)
    db.flush()
    global_state = TrafficFlowCollectorGlobalState(id=1, listener_state="running")
    state = TrafficFlowCollectorState(source_id=source.id, listener_state="running", template_cache_size=2)
    db.add_all([global_state, state])
    db.commit()
    public = network_monitor_router._traffic_source_public(
        source,
        flow_states={source.id: state},
        global_state=global_state,
        now=datetime.utcnow(),
    )
    assert public["health_state"] == "collector_healthy_awaiting_traffic"
    assert public["last_success_at"] is None
    state.last_datagram_at = datetime.utcnow()
    state.last_valid_flow_at = datetime.utcnow()
    assert network_monitor_router._traffic_source_public(
        source, flow_states={source.id: state}, global_state=global_state, now=datetime.utcnow()
    )["health_state"] == "receiving_decoding"


def test_flow_source_recovers_after_historical_errors(db):
    source = TrafficSource(**validate_source_input({
        "name": "Recovered NSEL health",
        "provider_key": "cisco_nsel",
        "source_category": "flow_export",
        "is_enabled": True,
        "collector_port": 2055,
        "exporter_allowlist": ["192.0.2.1"],
    }))
    db.add(source)
    db.flush()
    now = datetime.utcnow()
    state = TrafficFlowCollectorState(
        source_id=source.id,
        listener_state="running",
        last_datagram_at=now,
        last_valid_flow_at=now,
        packets_rejected=1342,
        decode_failures=1342,
        unknown_templates=267836,
        template_lifecycle_json=json.dumps([{
            "status": "lookup_failed",
            "at": (now - timedelta(hours=2)).isoformat() + "Z",
        }]),
    )
    global_state = TrafficFlowCollectorGlobalState(id=1, listener_state="running")
    db.add_all([state, global_state])
    db.flush()
    public = network_monitor_router._traffic_source_public(
        source, flow_states={source.id: state}, global_state=global_state, now=now
    )
    assert public["health_state"] == "receiving_decoding"
    assert public["last_decoded_at"].startswith(now.isoformat())


def test_flow_source_is_degraded_for_recent_processing_error(db):
    source = TrafficSource(**validate_source_input({
        "name": "Currently degraded NSEL health",
        "provider_key": "cisco_nsel",
        "source_category": "flow_export",
        "is_enabled": True,
        "collector_port": 2055,
        "exporter_allowlist": ["192.0.2.1"],
    }))
    db.add(source)
    db.flush()
    now = datetime.utcnow()
    state = TrafficFlowCollectorState(
        source_id=source.id,
        listener_state="running",
        last_datagram_at=now,
        last_valid_flow_at=now,
        packets_rejected=1,
        template_lifecycle_json=json.dumps([{
            "status": "rejected",
            "reason": "malformed_packet",
            "at": (now - timedelta(minutes=2)).isoformat() + "Z",
        }]),
    )
    global_state = TrafficFlowCollectorGlobalState(id=1, listener_state="running")
    db.add_all([state, global_state])
    db.flush()
    public = network_monitor_router._traffic_source_public(
        source, flow_states={source.id: state}, global_state=global_state, now=now
    )
    assert public["health_state"] == "degraded"


def test_counter_rates_use_elapsed_time_and_establish_a_baseline():
    assert calculate_rate(None, 100, 10).baseline is True
    result = calculate_rate(100, 1_100, 10)
    assert result.bits_per_second == 800
    assert calculate_rate(100, 1_100, 20).bits_per_second == 400
    assert calculate_rate(1_100, 900, 10).reset is True


def test_counter_wrap_is_only_accepted_near_the_counter_boundary():
    maximum = (1 << 32) - 1
    result = calculate_rate(maximum - 10, 5, 1, counter_bits=32)
    assert result.wrapped is True
    assert result.bits_per_second == 128
    assert calculate_rate(2_000, 5, 1, counter_bits=32).reset is True


class FakeSNMPProvider:
    def __init__(self, snapshots):
        self.snapshots = snapshots

    async def discover_interfaces(self, source):
        return self.snapshots


class StateChangingProvider(FakeSNMPProvider):
    def __init__(self, snapshots, change):
        super().__init__(snapshots)
        self.change = change

    async def discover_interfaces(self, source):
        self.change(source)
        return self.snapshots


def _poll_source(db, *, enabled=True):
    config = TrafficMonitoringConfiguration(id=1, is_enabled=enabled)
    values = validate_source_input(source_data(is_enabled=True))
    source = TrafficSource(**values)
    apply_source_secrets(source, source_data(), creating=True)
    db.add_all([config, source])
    db.commit()
    return source.id


def test_polling_persists_discovery_baselines_rates_and_aggregates_without_double_counting(db):
    source_id = _poll_source(db)
    first = InterfaceSnapshot(7, "ifIndex:7", "outside", "outside", 1, 1, 1_000_000_000, 1_000, 2_000, 64, 10, 100)
    second = InterfaceSnapshot(7, "ifIndex:7", "outside", "outside", 1, 1, 1_000_000_000, 2_000, 4_000, 64, 10, 110)
    def factory():
        return db
    assert asyncio.run(poll_source_once(factory, source_id, provider=FakeSNMPProvider([first]), now=datetime(2026, 1, 1, 0, 0, 0))) is True
    db.expire_all()
    assert db.query(TrafficCounterObservation).one().inbound_bps is None
    assert asyncio.run(poll_source_once(factory, source_id, provider=FakeSNMPProvider([second]), now=datetime(2026, 1, 1, 0, 0, 10))) is True
    db.expire_all()
    observation = db.query(TrafficCounterObservation).order_by(TrafficCounterObservation.observed_at.desc()).first()
    assert observation.inbound_bps == 800
    assert observation.outbound_bps == 1600
    assert db.query(TrafficAggregate).count() == 6


def test_disabled_feature_prevents_polling_and_lease_is_exclusive(db):
    source_id = _poll_source(db, enabled=False)
    snapshot = InterfaceSnapshot(7, "ifIndex:7", "outside", None, 1, 1, 1_000_000_000, 1, 1, 64, 1, 1)
    assert asyncio.run(poll_source_once(lambda: db, source_id, provider=FakeSNMPProvider([snapshot]))) is False
    first = acquire_polling_lease(db, "owner-a", datetime(2026, 1, 1))
    second = acquire_polling_lease(db, "owner-b", datetime(2026, 1, 1, 0, 0, 1))
    assert first is True
    assert second is False


def test_flow_sources_are_never_authorized_for_snmp_polling_again(db):
    db.add(TrafficMonitoringConfiguration(id=1, is_enabled=True))
    values = validate_source_input({
        "name": "Synthetic NSEL polling guard",
        "provider_key": "cisco_nsel",
        "source_category": "flow_export",
        "is_enabled": True,
        "collector_port": 2055,
        "exporter_allowlist": ["192.0.2.1"],
    })
    source = TrafficSource(**values)
    db.add(source)
    db.commit()
    assert asyncio.run(poll_source_once(lambda: db, source.id, provider=FakeSNMPProvider([]))) is False
    assert source.last_error_category is None
    assert source.consecutive_failures == 0


def test_flow_sources_are_never_authorized_for_snmp_polling(db):
    db.add(TrafficMonitoringConfiguration(id=1, is_enabled=True))
    values = validate_source_input({
        "name": "Synthetic NSEL polling guard",
        "provider_key": "cisco_nsel",
        "source_category": "flow_export",
        "is_enabled": True,
        "collector_port": 2055,
        "exporter_allowlist": ["192.0.2.1"],
    })
    source = TrafficSource(**values)
    db.add(source)
    db.commit()
    assert asyncio.run(poll_source_once(lambda: db, source.id, provider=FakeSNMPProvider([]))) is False
    assert source.last_error_category is None
    assert source.consecutive_failures == 0


@pytest.mark.parametrize("change", ["lease", "source", "module"])
def test_lost_lease_or_disabled_state_rejects_late_poll_persistence(db, change):
    source_id = _poll_source(db, enabled=True)
    snapshot = InterfaceSnapshot(7, "ifIndex:7", "outside", None, 1, 1, 1_000_000_000, 100, 100, 64, 1, 1)
    token = "owner-a"
    assert acquire_polling_lease(db, token, datetime(2026, 1, 1)) is True

    def change_state(row):
        if change == "lease":
            lease = db.get(TrafficPollingLease, 1)
            lease.lease_until = datetime(2025, 12, 31, 23, 59, 59)
        elif change == "source":
            row.is_enabled = False
        else:
            db.get(TrafficMonitoringConfiguration, 1).is_enabled = False
        db.commit()

    result = asyncio.run(poll_source_once(lambda: db, source_id, provider=StateChangingProvider([snapshot], change_state), now=datetime(2026, 1, 1), lease_token=token))
    assert result is False
    assert db.query(TrafficCounterObservation).count() == 0
