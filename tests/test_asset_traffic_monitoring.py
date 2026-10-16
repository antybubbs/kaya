from datetime import datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    AssetNetworkAssignment,
    HardwareAsset,
    TrafficDeviceAggregate,
    TrafficDeviceMonitoring,
    TrafficDeviceMonitoringPeriod,
    TrafficMonitoringConfiguration,
    TrafficSource,
    TrafficDiscoveryNetworkMapping,
    VLAN,
)
from app.services.asset_identity import assign_network_identity, eligible_traffic_contexts
from app.services.device_traffic import asset_monitoring_status, persist_device_traffic, set_asset_monitoring
from app.services.flow_protocol import NormalizedFlowRecord


def _factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _record(at):
    return NormalizedFlowRecord(
        exporter_identity="192.0.2.1", source_id=1, sequence=1, record_index=0,
        observed_at=at, flow_start=None, flow_end=None, source_ip="192.0.2.55",
        destination_ip="198.51.100.20", source_port=1, destination_port=2, protocol=6,
        input_interface=2, output_interface=10, translated_source_ip=None,
        translated_destination_ip=None, translated_source_port=None,
        translated_destination_port=None, bytes_total=100, packets_total=2,
        direction="unknown", event_type=None, connection_id=None,
        cumulative_counters=False, data_quality="complete",
    )


def test_assignment_monitoring_collects_without_managed_ip_and_closes_period():
    factory = _factory()
    with factory() as db:
        now = datetime(2026, 1, 1, 12)
        asset = HardwareAsset(name="Synthetic asset", status="In use")
        source = TrafficSource(id=1, name="Synthetic flow", provider_key="netflow_v9", source_category="flow", is_enabled=True, is_deleted=False)
        db.add_all([asset, source, TrafficMonitoringConfiguration(id=1, is_enabled=True)])
        db.flush()
        assignment = AssetNetworkAssignment(
            asset_id=asset.id, address="192.0.2.55", address_family=4,
            source_id=1, exporter_identity="192.0.2.1", started_at=now - timedelta(minutes=1),
            provenance="test", status="confirmed",
        )
        db.add(assignment)
        db.commit()
        user = SimpleNamespace(id=None, role="admin")

        result = set_asset_monitoring(db, user, asset, True, now=now)
        db.commit()
        assert result["enabled"] is True
        assert db.query(TrafficDeviceMonitoring).one().ip_address_id is None
        assert db.query(TrafficDeviceMonitoringPeriod).one().assignment_id == assignment.id

        assert persist_device_traffic(db, _record(now), 100, 2, 1) == 1
        db.commit()
        assert db.query(TrafficDeviceAggregate).count() == 3
        assert db.query(TrafficDeviceAggregate).filter(TrafficDeviceAggregate.assignment_id == assignment.id).count() == 3

        set_asset_monitoring(db, user, asset, False, now=now + timedelta(hours=1))
        db.commit()
        assert db.query(TrafficDeviceMonitoringPeriod).one().ended_at == now + timedelta(hours=1)
        assert asset_monitoring_status(db, asset.id)["enabled"] is False


def test_enabled_asset_monitoring_requires_current_assignment_context():
    factory = _factory()
    with factory() as db:
        now = datetime(2026, 1, 1, 12)
        asset = HardwareAsset(name="Synthetic stale asset", status="In use")
        vlan = VLAN(name="Synthetic VLAN", subnet_cidr="192.0.2.0/24")
        source = TrafficSource(id=1, name="Synthetic flow", provider_key="netflow_v9", source_category="flow", is_enabled=True, is_deleted=False)
        db.add_all([asset, vlan, source, TrafficMonitoringConfiguration(id=1, is_enabled=True)])
        db.flush()
        assignment = AssetNetworkAssignment(
            asset_id=asset.id, address="192.0.2.55", address_family=4, vlan_id=vlan.id,
            network_cidr="192.0.2.0/24", source_id=1, exporter_identity="192.0.2.1",
            started_at=now - timedelta(hours=1), provenance="test", status="confirmed",
        )
        db.add(assignment)
        db.flush()
        monitor = TrafficDeviceMonitoring(asset_id=asset.id, assignment_id=assignment.id, is_enabled=True, status="active")
        db.add(monitor)
        db.commit()

        vlan.subnet_cidr = "198.51.100.0/24"
        db.commit()
        status = asset_monitoring_status(db, asset.id, now=now)
        assert status["enabled"] is True
        assert status["status"] == "review_required"
        assert "network context changed" in status["reason"]


def test_static_asset_context_selection_is_explicit_and_does_not_enable_monitoring():
    factory = _factory()
    with factory() as db:
        now = datetime(2026, 1, 1, 12)
        user = SimpleNamespace(id=1, role="admin")
        asset = HardwareAsset(name="Synthetic static asset", status="In use")
        vlan = VLAN(name="Synthetic trusted VLAN", subnet_cidr="192.0.2.0/24")
        source = TrafficSource(id=1, name="Synthetic exporter", provider_key="netflow_v9", source_category="flow", is_enabled=True, is_deleted=False)
        db.add_all([asset, vlan, source, TrafficMonitoringConfiguration(id=1, is_enabled=True)])
        db.flush()
        mapping = TrafficDiscoveryNetworkMapping(source_id=source.id, exporter_identity="192.0.2.1", vlan_id=vlan.id, is_enabled=True)
        source_less = AssetNetworkAssignment(
            asset_id=asset.id, address="192.0.2.55", address_family=4, vlan_id=vlan.id,
            network_cidr=vlan.subnet_cidr, started_at=now - timedelta(minutes=1),
            provenance="static acceptance fixture", status="confirmed",
        )
        db.add_all([mapping, source_less])
        db.commit()

        options = eligible_traffic_contexts(db, source_less.address)
        assert len(options) == 1
        assert options[0]["mapping_id"] == mapping.id
        assert asset_monitoring_status(db, asset.id)["enabled"] is False

        assignment = assign_network_identity(
            db, user, asset_id=asset.id, address=source_less.address,
            started_at=now, vlan_id=vlan.id, source_id=source.id,
            exporter_identity=mapping.exporter_identity,
            provenance="administrator traffic context",
        )
        assert assignment.status == "confirmed"
        db.commit()
        assert db.query(TrafficDeviceMonitoring).filter_by(asset_id=asset.id).count() == 0
