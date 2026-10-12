from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    IPAddress, TrafficAggregate, TrafficDeviceAggregate, TrafficDeviceMonitoring,
    TrafficDeviceMonitoringPeriod, TrafficInterface, TrafficSource, VLAN,
)
from app.services.network_traffic_reporting import device_report, report_window, wan_report


def session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_report_window_selects_one_canonical_resolution():
    assert report_window("24h")[2] == 300
    assert report_window("7d")[2] == 3600
    assert report_window("30d")[2] == 86400


def test_wan_report_does_not_mix_resolutions_or_directions():
    factory = session_factory()
    with factory() as db:
        source = TrafficSource(name="Fixture", provider_key="snmpv3", source_category="interface_polling", is_deleted=False)
        db.add(source); db.flush()
        interface = TrafficInterface(source_id=source.id, interface_key="wan", display_name="WAN", is_enabled=True, is_wan=True, inbound_direction="download", outbound_direction="upload")
        db.add(interface); db.flush()
        now = datetime.utcnow()
        db.add_all([
            TrafficAggregate(source_id=source.id, interface_id=interface.id, bucket_start=now - timedelta(minutes=5), bucket_seconds=300, direction="download", traffic_class="interface_total", bytes_total=100, is_approximate=False),
            TrafficAggregate(source_id=source.id, interface_id=interface.id, bucket_start=now - timedelta(minutes=5), bucket_seconds=300, direction="upload", traffic_class="interface_total", bytes_total=40, is_approximate=False),
            TrafficAggregate(source_id=source.id, interface_id=interface.id, bucket_start=now - timedelta(minutes=5), bucket_seconds=3600, direction="download", traffic_class="interface_total", bytes_total=9999, is_approximate=False),
        ])
        db.commit()
        result = wan_report(db, report_range="24h", now=now)
        assert result["summary"]["total_bytes"] == 140
        assert result["history"][0]["download_bytes"] == 100


def test_device_report_only_returns_current_opted_in_rows():
    factory = session_factory()
    with factory() as db:
        vlan = VLAN(name="Fixture VLAN")
        db.add(vlan); db.flush()
        enabled = IPAddress(vlan_id=vlan.id, address="192.0.2.20", name="Enabled")
        disabled = IPAddress(vlan_id=vlan.id, address="192.0.2.21", name="Disabled")
        db.add_all([enabled, disabled]); db.flush()
        db.add_all([
            TrafficDeviceMonitoring(ip_address_id=enabled.id, is_enabled=True),
            TrafficDeviceMonitoring(ip_address_id=disabled.id, is_enabled=False),
        ])
        db.flush()
        period = TrafficDeviceMonitoringPeriod(monitoring_id=1, ip_address_id=enabled.id, started_at=datetime.utcnow() - timedelta(hours=1))
        db.add(period); db.flush()
        db.add(TrafficDeviceAggregate(period_id=period.id, ip_address_id=enabled.id, source_id=1, interface_id=None, bucket_start=datetime.utcnow() - timedelta(minutes=5), bucket_seconds=300, direction="download", bytes_total=123, packets_total=1, attribution_confidence="high"))
        db.commit()
        result = device_report(db, report_range="24h")
        assert [item["address"] for item in result["devices"]] == ["192.0.2.20"]
        assert result["devices"][0]["total_bytes"] == 123
