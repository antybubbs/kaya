from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import IPAddress, TrafficDeviceAggregate, TrafficDeviceMonitoringPeriod, TrafficMonitoringConfiguration, TrafficSource, VLAN
from app.services.device_traffic import device_monitoring_status, persist_device_traffic, set_device_monitoring
from app.services.flow_collector import process_records
from app.services.flow_protocol import NormalizedFlowRecord


def rec(**overrides):
    values = dict(exporter_identity="192.0.2.1", source_id=1, sequence=1, record_index=0, observed_at=datetime(2026, 1, 1, 12), flow_start=None, flow_end=None, source_ip="192.0.2.20", destination_ip="198.51.100.20", source_port=1, destination_port=2, protocol=6, input_interface=2, output_interface=10, translated_source_ip=None, translated_destination_ip=None, translated_source_port=None, translated_destination_port=None, bytes_total=100, packets_total=2, direction="unknown", event_type=None, connection_id=None, cumulative_counters=False, data_quality="complete")
    values.update(overrides)
    return NormalizedFlowRecord(**values)


def setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_opt_in_periods_are_closed_and_reenabled_without_backfill():
    factory = setup()
    with factory() as db:
        vlan = VLAN(name="Test")
        db.add(vlan)
        db.flush()
        ip = IPAddress(vlan_id=vlan.id, address="192.0.2.20", assignment_type="Static")
        db.add_all([ip, TrafficMonitoringConfiguration(id=1, is_enabled=True), TrafficSource(id=1, name="Fixture", provider_key="netflow_v9", source_category="flow", is_enabled=True, is_deleted=False)])
        db.commit()
        first = datetime(2026, 1, 1, 12)
        assert set_device_monitoring(db, ip, True, now=first)["changed"]
        db.commit()
        assert persist_device_traffic(db, rec(observed_at=first), 100, 2, 1) == 1
        db.commit()
        assert db.query(TrafficDeviceAggregate).count() == 3
        set_device_monitoring(db, ip, False, now=first + timedelta(hours=1))
        db.commit()
        set_device_monitoring(db, ip, True, now=first + timedelta(hours=2))
        db.commit()
        assert db.query(TrafficDeviceMonitoringPeriod).count() == 2
        assert db.query(TrafficDeviceAggregate).count() == 3
        assert device_monitoring_status(db, ip.id)["enabled"] is True


def test_collector_keeps_device_opt_in_separate_from_source_totals():
    factory = setup()
    with factory() as db:
        vlan = VLAN(name="Test")
        db.add(vlan)
        db.flush()
        ip = IPAddress(vlan_id=vlan.id, address="192.0.2.20", assignment_type="Static")
        db.add_all([ip, TrafficMonitoringConfiguration(id=1, is_enabled=False), TrafficSource(id=1, name="Fixture", provider_key="netflow_v9", source_category="flow", is_enabled=True, is_deleted=False)])
        db.commit()
        result = process_records(db, [rec()], source_id=1)
        db.commit()
        assert result["accepted"] == 1
        assert db.query(TrafficDeviceAggregate).count() == 0


def test_nsel_directional_deltas_are_attributed_to_the_matching_device_direction():
    factory = setup()
    with factory() as db:
        vlan = VLAN(name="Test")
        db.add(vlan)
        db.flush()
        ip = IPAddress(vlan_id=vlan.id, address="192.0.2.20", assignment_type="Static")
        db.add_all([ip, TrafficMonitoringConfiguration(id=1, is_enabled=True), TrafficSource(id=1, name="Fixture", provider_key="cisco_nsel", source_category="flow", is_enabled=True, is_deleted=False)])
        db.commit()
        set_device_monitoring(db, ip, True, now=datetime(2026, 1, 1, 12))
        db.commit()
        persist_device_traffic(db, rec(forward_bytes=70, reverse_bytes=30, forward_packets=7, reverse_packets=3), 100, 10, 1)
        db.commit()
        assert db.query(TrafficDeviceAggregate).count() == 6
        aggregate = db.query(TrafficDeviceAggregate).filter_by(direction="upload", bucket_seconds=300).one()
        assert aggregate.direction == "upload"
        assert aggregate.bytes_total == 70
        assert aggregate.packets_total == 7
