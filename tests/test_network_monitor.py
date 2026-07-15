from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import IPAddress, NetworkMonitor, NetworkMonitorCheck, NetworkMonitorEvent, NetworkMonitorOutage
from app.services import network_monitor


def session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def add_monitor(factory, **values):
    with factory() as db:
        address = IPAddress(address="192.0.2.10", name="Test target")
        db.add(address)
        db.flush()
        monitor = NetworkMonitor(ip_address_id=address.id, failure_threshold=2, **values)
        db.add(monitor)
        db.commit()
        return monitor.id


def test_failure_threshold_opens_outage_and_recovery_closes_it(monkeypatch):
    factory = session_factory()
    monitor_id = add_monitor(factory)
    monkeypatch.setattr(network_monitor, "ping_ipv4_samples", lambda *_: (False, None, 100, "Timed out"))

    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.run_monitor_check(db, monitor)
        assert monitor.last_status == "warning"
        network_monitor.run_monitor_check(db, monitor)
        assert monitor.last_status == "down"
        assert db.query(NetworkMonitorOutage).filter_by(monitor_id=monitor_id, ended_at=None).count() == 1

    monkeypatch.setattr(network_monitor, "ping_ipv4_samples", lambda *_: (True, 12, 0, None))
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.run_monitor_check(db, monitor)
        assert monitor.last_status == "up"
        assert monitor.consecutive_failures == 0
        assert db.query(NetworkMonitorOutage).filter_by(monitor_id=monitor_id, ended_at=None).count() == 0
        assert [row.event_type for row in db.query(NetworkMonitorEvent).order_by(NetworkMonitorEvent.id)] == ["threshold", "outage_started", "recovered"]


def test_latency_thresholds_are_recorded_without_request_time_collection(monkeypatch):
    factory = session_factory()
    monitor_id = add_monitor(factory, latency_warning_ms=100, latency_critical_ms=300)
    monkeypatch.setattr(network_monitor, "ping_ipv4_samples", lambda *_: (True, 350, 0, None))

    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.run_monitor_check(db, monitor)
        check = db.query(NetworkMonitorCheck).one()
        assert monitor.last_status == "critical"
        assert check.latency_ms == 350
        assert check.packet_loss_percent == 0
        assert check.response_time_ms == 350


def test_dashboard_collection_leases_override_record_schedules_per_client():
    network_monitor._dashboard_override_leases.clear()
    network_monitor.set_dashboard_override("first-dashboard", 30)
    network_monitor.set_dashboard_override("second-dashboard", 30)
    assert network_monitor.dashboard_override_active() is True

    network_monitor.set_dashboard_override("first-dashboard", None)
    assert network_monitor.dashboard_override_active() is True

    network_monitor.set_dashboard_override("second-dashboard", None)
    assert network_monitor.dashboard_override_active() is False


def test_dashboard_exposes_requested_collection_rates():
    template = (Path(__file__).resolve().parents[1] / "app" / "templates" / "network_monitor.html").read_text(encoding="utf-8")
    for value in ("live", "5000", "10000", "60000", "300000"):
        assert f'value="{value}"' in template
