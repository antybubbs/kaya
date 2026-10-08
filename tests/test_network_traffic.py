import json
import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import decrypt_secret
from app.db.session import Base
from app.models.models import TrafficAggregate, TrafficCounterObservation, TrafficInterface, TrafficLocalNetwork, TrafficMonitoringConfiguration, TrafficPollingLease, TrafficSource
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
from app.services.network_traffic_snmp import InterfaceSnapshot, SNMPProviderError, calculate_rate


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
    factory = lambda: db
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


@pytest.mark.parametrize("change", ["lease", "source", "module"])
def test_lost_lease_or_disabled_state_rejects_late_poll_persistence(db, change):
    source_id = _poll_source(db, enabled=True)
    source = db.get(TrafficSource, source_id)
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
