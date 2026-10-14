from datetime import datetime, timedelta
import threading
import time
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    TrafficDiscoveryConfiguration,
    TrafficDiscoveryObservation,
    TrafficDiscoverySummary,
    TrafficDiscoveryNetworkMapping,
    TrafficSource,
    VLAN,
)
from app.services.flow_protocol import NormalizedFlowRecord
from app.services.network_discovery import persist_discovery_batch
from app.services.network_discovery import DiscoveryRuntime


def record(**overrides):
    values = dict(
        exporter_identity="192.0.2.1",
        source_id=7,
        sequence=1,
        record_index=0,
        observed_at=datetime(2026, 1, 1, 12, 0),
        flow_start=None,
        flow_end=None,
        source_ip="10.0.0.20",
        destination_ip="198.51.100.20",
        source_port=1234,
        destination_port=443,
        protocol=6,
        input_interface=2,
        output_interface=7,
        translated_source_ip=None,
        translated_destination_ip=None,
        translated_source_port=None,
        translated_destination_port=None,
        bytes_total=100,
        packets_total=1,
        direction="bidirectional",
        event_type=None,
        connection_id=None,
        cumulative_counters=False,
        data_quality="complete",
    )
    values.update(overrides)
    return NormalizedFlowRecord(**values)


def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def source(provider_key="netflow_v9", source_id=1):
    return TrafficSource(
        id=source_id,
        name=f"Source {source_id}",
        provider_key=provider_key,
        source_category="flow_export" if provider_key != "snmpv3" else "interface_polling",
        is_enabled=True,
        is_deleted=False,
    )


def enabled_setup(session, *, provider_key="netflow_v9", max_detail_rows=100000, max_summary_rows=100000):
    session.add_all([
        TrafficDiscoveryConfiguration(id=1, is_enabled=True, max_detail_rows=max_detail_rows, max_summary_rows=max_summary_rows),
        VLAN(id=1, name="LAN", subnet_cidr="10.0.0.0/24"),
        TrafficDiscoveryNetworkMapping(id=1, source_id=1, exporter_identity="192.0.2.1", vlan_id=1, is_enabled=True),
        source(provider_key),
    ])
    session.commit()


NOW = datetime(2026, 1, 1, 12, 0)


def test_disabled_discovery_writes_nothing_and_does_not_need_network_context():
    session = db()
    session.add_all([TrafficDiscoveryConfiguration(id=1, is_enabled=False), source()])
    session.commit()

    assert persist_discovery_batch(session, 1, [record()]) == 0
    assert session.query(TrafficDiscoveryObservation).count() == 0
    assert session.query(TrafficDiscoverySummary).count() == 0


def test_enabled_discovery_is_provider_independent_and_does_not_create_device_usage():
    session = db()
    enabled_setup(session)
    translated = record(translated_source_ip="10.0.0.21")

    assert persist_discovery_batch(session, 1, [translated, translated], now=NOW) == 4
    session.commit()
    details = session.query(TrafficDiscoveryObservation).order_by(TrafficDiscoveryObservation.endpoint_role).all()
    assert len(details) == 2
    assert {row.endpoint_role for row in details} == {"original_source", "translated_source"}
    assert all(row.observation_count == 2 for row in details)
    assert session.query(TrafficDiscoverySummary).count() == 2
    assert "traffic_device_aggregates" in Base.metadata.tables


def test_ipv6_and_overlapping_networks_are_classified_conservatively():
    session = db()
    session.add_all([
        TrafficDiscoveryConfiguration(id=1, is_enabled=True),
        VLAN(id=1, name="LAN A", subnet_cidr="10.0.0.0/8"),
        VLAN(id=2, name="LAN B", subnet_cidr="10.1.0.0/16"),
        VLAN(id=3, name="IPv6", subnet_cidr="2001:db8:1234::/48"),
        TrafficDiscoveryNetworkMapping(id=1, source_id=1, exporter_identity="192.0.2.1", vlan_id=1, is_enabled=True),
        TrafficDiscoveryNetworkMapping(id=2, source_id=1, exporter_identity="192.0.2.1", vlan_id=2, is_enabled=True),
        TrafficDiscoveryNetworkMapping(id=3, source_id=1, exporter_identity="192.0.2.1", vlan_id=3, is_enabled=True),
        source(),
    ])
    session.commit()

    ipv6 = record(source_ip="2001:db8:1234::20", destination_ip="2001:db8:ffff::20")
    assert persist_discovery_batch(session, 1, [record(source_ip="10.1.0.20"), ipv6], now=NOW) == 2
    session.commit()
    rows = session.query(TrafficDiscoveryObservation).all()
    assert {row.endpoint_ip for row in rows} == {"10.1.0.20", "2001:db8:1234::20"}
    overlap = next(row for row in rows if row.endpoint_ip == "10.1.0.20")
    assert overlap.classification == "ambiguous"
    assert overlap.ambiguity_reason == "overlapping_local_networks"


def test_sources_and_exporters_are_isolated_and_snmp_is_excluded():
    session = db()
    session.add_all([
        TrafficDiscoveryConfiguration(id=1, is_enabled=True),
        VLAN(id=1, name="LAN", subnet_cidr="10.0.0.0/24"),
        TrafficDiscoveryNetworkMapping(id=1, source_id=1, exporter_identity="192.0.2.1", vlan_id=1, is_enabled=True),
        TrafficDiscoveryNetworkMapping(id=2, source_id=1, exporter_identity="192.0.2.2", vlan_id=1, is_enabled=True),
        source(source_id=1),
        source(provider_key="snmpv3", source_id=2),
    ])
    session.commit()

    assert persist_discovery_batch(session, 1, [record(exporter_identity="192.0.2.1")], now=NOW) == 1
    assert persist_discovery_batch(session, 1, [record(exporter_identity="192.0.2.2")], now=NOW) == 1
    assert persist_discovery_batch(session, 2, [record()], now=NOW) == 0
    session.commit()
    assert session.query(TrafficDiscoveryObservation).count() == 2
    assert {row.exporter_identity for row in session.query(TrafficDiscoveryObservation)} == {"192.0.2.1", "192.0.2.2"}


def test_retention_and_row_limits_only_trim_discovery_tables():
    session = db()
    enabled_setup(session, max_detail_rows=1, max_summary_rows=1)
    old = datetime(2025, 1, 1, 12, 0)
    session.add(TrafficDiscoveryObservation(
        source_id=1, exporter_identity="192.0.2.1", endpoint_ip="10.0.0.30", address_family=4,
        endpoint_role="original_source", bucket_start=old, bucket_seconds=300,
        first_seen_at=old, last_seen_at=old, observation_count=1,
    ))
    session.commit()

    persist_discovery_batch(session, 1, [record(source_ip="10.0.0.31")], now=datetime(2026, 1, 1, 12, 0))
    session.commit()
    assert session.query(TrafficDiscoveryObservation).count() == 1
    assert session.query(TrafficDiscoveryObservation).first().endpoint_ip == "10.0.0.31"
    assert session.query(TrafficDiscoverySummary).count() == 1


class _RuntimeSession:
    def __init__(self, state):
        self.state = state

    def __enter__(self):
        self.state["database_calls"] += 1
        return self

    def __exit__(self, *_args):
        return False

    def get(self, model, _key):
        if model is TrafficDiscoveryConfiguration:
            return SimpleNamespace(is_enabled=self.state["enabled"])
        return None

    def commit(self):
        self.state["commits"] += 1


def _runtime_factory(state):
    return lambda: _RuntimeSession(state)


def test_runtime_disabled_path_does_not_enqueue_or_persist():
    state = {"enabled": False, "database_calls": 0, "commits": 0}
    persisted = []
    runtime = DiscoveryRuntime(_runtime_factory(state), persist=lambda *_args: persisted.append(True))
    runtime.start()
    try:
        assert not runtime.enabled()
        assert not runtime.enqueue(1, [record()])
        assert runtime.stats()["enqueued"] == 0
        assert runtime.stats()["queued"] == 0
        assert persisted == []
    finally:
        runtime.stop()


def test_runtime_enqueue_is_non_blocking_and_slow_persistence_isolated():
    state = {"enabled": True, "database_calls": 0, "commits": 0}
    started = threading.Event()
    release = threading.Event()

    def slow_persist(*_args):
        started.set()
        release.wait(1)

    runtime = DiscoveryRuntime(_runtime_factory(state), persist=slow_persist, queue_size=2)
    runtime.start()
    try:
        began = time.perf_counter()
        assert runtime.enqueue(7, [record()])
        enqueue_ms = (time.perf_counter() - began) * 1000
        assert enqueue_ms < 50
        assert started.wait(1)
        assert runtime.stats()["persisted"] == 0
    finally:
        release.set()
        runtime.stop()


def test_runtime_full_queue_drops_without_blocking_and_disable_invalidates():
    state = {"enabled": True, "database_calls": 0, "commits": 0}
    started = threading.Event()
    release = threading.Event()

    def blocked_persist(*_args):
        started.set()
        release.wait(1)

    runtime = DiscoveryRuntime(_runtime_factory(state), persist=blocked_persist, queue_size=1)
    runtime.start()
    try:
        assert runtime.enqueue(1, [record()])
        assert started.wait(1)
        assert runtime.enqueue(1, [record()])
        assert not runtime.enqueue(1, [record()])
        assert runtime.stats()["dropped"] == 1
        state["enabled"] = False
        runtime.invalidate_enablement()
        deadline = time.monotonic() + 1
        while runtime.enabled() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not runtime.enabled()
        assert not runtime.enqueue(1, [record()])
    finally:
        release.set()
        runtime.stop()
