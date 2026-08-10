import asyncio
import inspect
import json
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2 import Environment, FileSystemLoader
from fastapi import HTTPException

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.session import Base
from app.models.models import (
    IPAddress,
    NetworkMonitor,
    NetworkMonitorCheck,
    NetworkMonitorEvent,
    NetworkMonitorOutage,
    NetworkMonitorStatistic,
    NetworkMonitorTransition,
    NotificationDeliveryAttempt,
    NotificationEvent,
    NotificationOutbox,
    RemoteManagerSetting,
    User,
    UserModulePermission,
    UserNotification,
)
from app.services import network_monitor, network_monitor_history
from app.services.notification_outbox import process_outbox
from app.routers import network_monitor as network_monitor_router, notifications as notification_router
from app.routers.auth import require_admin, require_editor


def session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def add_monitor(factory, **values):
    values.setdefault("failure_threshold", 2)
    values.setdefault("use_default_thresholds", False)
    with factory() as db:
        address = IPAddress(address="192.0.2.10", name="Test target")
        db.add(address)
        db.flush()
        monitor = NetworkMonitor(ip_address_id=address.id, **values)
        db.add(monitor)
        db.commit()
        return monitor.id


def add_monitor_recipient(factory):
    with factory() as db:
        recipient = User(
            email="monitor-recipient@example.invalid",
            password_hash="clearly-fake-hash",
            role="admin",
            is_active=True,
        )
        db.add(recipient)
        db.flush()
        db.add(
            UserModulePermission(
                user_id=recipient.id,
                module_key="network_monitor",
                allowed=True,
                created_by=recipient.id,
            )
        )
        db.commit()
        return recipient.id


def test_monitor_transition_creates_in_app_notification_without_vapid_or_legacy_flag():
    factory = session_factory()
    recipient_id = add_monitor_recipient(factory)
    monitor_id = add_monitor(
        factory,
        failure_threshold=1,
        recovery_threshold=1,
        notify_enabled=False,
    )

    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.record_monitor_result(
            db, monitor, False, None, 100, "Synthetic timeout"
        )
        assert db.query(NetworkMonitorTransition).filter_by(
            monitor_id=monitor_id, new_state="offline"
        ).count() == 1
        assert db.query(NotificationOutbox).filter_by(
            event_type="ipwan.host.offline", status="pending"
        ).count() == 1
        db.commit()
        process_outbox(session_factory=factory)
        db.expire_all()
        offline = db.query(NotificationEvent).filter_by(
            event_type="ipwan.host.offline"
        ).one()
        user_notification = db.query(UserNotification).filter_by(
            notification_event_id=offline.id, user_id=recipient_id
        ).one()
        assert user_notification.read_at is None
        assert db.query(NotificationDeliveryAttempt).count() == 0
        assert notification_router.unread_count(db=db, user=db.get(User, recipient_id)) == {
            "count": 1,
            "critical": True,
        }
        listed = notification_router.list_notifications(
            limit=10, db=db, user=db.get(User, recipient_id)
        )
        assert [item["event_type"] for item in listed["notifications"]] == [
            "ipwan.host.offline"
        ]

        offline.created_at = datetime.utcnow() - timedelta(days=1)
        db.commit()
        network_monitor.record_monitor_result(
            db, monitor, False, None, 100, "Synthetic timeout"
        )
        assert db.query(NotificationEvent).filter_by(
            event_type="ipwan.host.offline"
        ).count() == 1

        network_monitor.record_monitor_result(db, monitor, True, 8, 0, None)
        process_outbox(session_factory=factory)
        db.expire_all()
        assert db.query(NotificationEvent).filter_by(
            event_type="ipwan.host.recovered"
        ).count() == 1
        assert db.query(UserNotification).filter_by(user_id=recipient_id).count() == 2


def test_existing_offline_monitor_is_reconciled_once():
    factory = session_factory()
    add_monitor_recipient(factory)
    monitor_id = add_monitor(
        factory,
        last_status="offline",
        consecutive_failures=20,
        notify_enabled=False,
    )
    with factory() as db:
        first = network_monitor.reconcile_offline_notifications(db)
        second = network_monitor.reconcile_offline_notifications(db)
        assert first == {"candidates": 1, "created": 1, "existing": 0}
        assert second == {"candidates": 1, "created": 0, "existing": 1}
        process_outbox(session_factory=factory)
        db.expire_all()
        assert db.query(NotificationEvent).filter_by(
            source_entity_id=str(monitor_id), event_type="ipwan.host.offline"
        ).count() == 1


def test_monitor_transition_and_outbox_rollback_together():
    factory = session_factory()
    add_monitor_recipient(factory)
    monitor_id = add_monitor(factory, failure_threshold=1)
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.record_monitor_result(
            db, monitor, False, None, 100, "Synthetic timeout"
        )
        assert db.query(NetworkMonitorTransition).count() == 1
        assert db.query(NotificationOutbox).count() == 1

    rollback_factory = session_factory()
    rollback_id = add_monitor(rollback_factory, failure_threshold=1)
    with rollback_factory() as db:
        monitor = db.get(NetworkMonitor, rollback_id)
        original_commit = db.commit
        db.commit = lambda: (_ for _ in ()).throw(RuntimeError("synthetic rollback"))
        with pytest.raises(RuntimeError, match="synthetic rollback"):
            network_monitor.record_monitor_result(
                db, monitor, False, None, 100, "Synthetic timeout"
            )
        db.rollback()
        db.commit = original_commit
        assert db.query(NetworkMonitorTransition).count() == 0
        assert db.query(NotificationOutbox).count() == 0


def test_failure_threshold_opens_outage_and_recovery_closes_it(monkeypatch):
    factory = session_factory()
    monitor_id = add_monitor(factory)
    monkeypatch.setattr(network_monitor, "ping_ipv4_samples", lambda *_: (False, None, 100, "Timed out"))

    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.run_monitor_check(db, monitor)
        assert monitor.last_status == "warning"
        network_monitor.run_monitor_check(db, monitor)
        assert monitor.last_status == "offline"
        assert db.query(NetworkMonitorOutage).filter_by(monitor_id=monitor_id, ended_at=None).count() == 1

    monkeypatch.setattr(network_monitor, "ping_ipv4_samples", lambda *_: (True, 12, 0, None))
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.run_monitor_check(db, monitor)
        assert monitor.last_status == "recovering"
        assert monitor.consecutive_failures == 0
        assert db.query(NetworkMonitorOutage).filter_by(monitor_id=monitor_id, ended_at=None).count() == 1
        network_monitor.run_monitor_check(db, monitor)
        assert monitor.last_status == "recovering"
        network_monitor.run_monitor_check(db, monitor)
        assert db.query(NetworkMonitorOutage).filter_by(monitor_id=monitor_id, ended_at=None).count() == 0
        assert monitor.last_status == "healthy"
        event_types = [row.event_type for row in db.query(NetworkMonitorEvent).order_by(NetworkMonitorEvent.id)]
        assert "incident_started" in event_types and "recovered" in event_types


def test_external_probe_runs_after_read_transaction_is_finished(monkeypatch):
    factory = session_factory()
    monitor_id = add_monitor(factory)
    observed = []

    db = None

    def fake_probe(*_args):
        observed.append(db.in_transaction())
        return True, 5, 0, None

    monkeypatch.setattr(network_monitor, "ping_ipv4_samples", fake_probe)
    with factory() as db:
        network_monitor.run_monitor_check(db, db.get(NetworkMonitor, monitor_id))

    assert observed == [False]


def test_latency_thresholds_are_recorded_without_request_time_collection(monkeypatch):
    factory = session_factory()
    monitor_id = add_monitor(factory, latency_warning_ms=100, latency_critical_ms=300)
    monkeypatch.setattr(network_monitor, "ping_ipv4_samples", lambda *_: (True, 350, 0, None))

    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.run_monitor_check(db, monitor)
        assert monitor.last_status == "healthy"
        network_monitor.run_monitor_check(db, monitor)
        check = db.query(NetworkMonitorCheck).order_by(NetworkMonitorCheck.id.desc()).first()
        assert monitor.last_status == "critical"
        assert check.latency_ms == 350
        assert check.packet_loss_percent == 0
        assert check.response_time_ms == 350
        assert monitor.consecutive_successes == 0
        assert db.query(NetworkMonitorOutage).filter_by(monitor_id=monitor_id, ended_at=None).count() == 1


def test_sub_millisecond_latency_is_preserved_and_displayed_without_zero_rounding():
    factory = session_factory()
    monitor_id = add_monitor(factory)
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.record_monitor_result(db, monitor, True, 0.4, 0, None)
        check = db.query(NetworkMonitorCheck).one()
        assert monitor.last_latency_ms == 0.4
        assert check.latency_ms == 0.4
        assert check.response_time_ms == 0.4
    assert network_monitor.latency_label(0.4) == "<1 ms"
    assert network_monitor.latency_label(1.25) == "1.2 ms"
    assert network_monitor.live_latency_label(0.483) == "0.483 ms"
    assert network_monitor.live_latency_label(15.558) == "15.558 ms"


def test_live_dashboard_override_uses_one_genuine_single_ping(monkeypatch):
    network_monitor._dashboard_interval_leases.clear()
    factory = session_factory()
    monitor_id = add_monitor(factory)
    calls = []
    monkeypatch.setattr(
        network_monitor, "ping_ipv4",
        lambda address, timeout: calls.append((address, timeout)) or (True, 0.483, None),
    )
    monkeypatch.setattr(
        network_monitor, "ping_ipv4_samples",
        lambda *_: (_ for _ in ()).throw(AssertionError("Live must use a single ping")),
    )
    try:
        network_monitor.set_dashboard_interval_override("dashboard-live", "live")
        with factory() as db:
            monitor = db.get(NetworkMonitor, monitor_id)
            network_monitor.run_monitor_check(db, monitor)
            check = db.query(NetworkMonitorCheck).one()
            assert check.latency_ms == 0.483
            assert check.packet_loss_percent == 0
        assert calls == [("192.0.2.10", 2000)]
    finally:
        network_monitor._dashboard_interval_leases.clear()


def test_degraded_state_requires_confirmation_and_healthy_resets_count():
    factory = session_factory()
    monitor_id = add_monitor(
        factory, degraded_threshold=2, latency_warning_ms=50, latency_critical_ms=150,
        packet_loss_warning_percent=5, packet_loss_critical_percent=25,
    )
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.record_monitor_result(db, monitor, True, 60, 0, None)
        assert monitor.last_status == "healthy"
        assert db.query(NetworkMonitorCheck).order_by(NetworkMonitorCheck.id.desc()).first().health_state == "warning"
        network_monitor.record_monitor_result(db, monitor, True, 10, 0, None)
        assert monitor.consecutive_degraded == 0
        network_monitor.record_monitor_result(db, monitor, True, 60, 0, None)
        network_monitor.record_monitor_result(db, monitor, True, 70, 0, None)
        assert monitor.last_status == "warning"
        assert "Latency above 50 ms" in monitor.state_reason
        assert db.query(NetworkMonitorOutage).filter_by(incident_type="degraded", ended_at=None).count() == 1


def test_packet_loss_critical_state_is_not_offline():
    factory = session_factory()
    monitor_id = add_monitor(factory, degraded_threshold=1, packet_loss_warning_percent=5, packet_loss_critical_percent=25)
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.record_monitor_result(db, monitor, True, 12, 31, None)
        assert monitor.last_status == "critical"
        assert monitor.state_reason == "Packet loss 31%"
        incident = db.query(NetworkMonitorOutage).one()
        assert incident.incident_type == "degraded"


def test_recovery_progress_resets_after_a_failed_check():
    factory = session_factory()
    monitor_id = add_monitor(factory, failure_threshold=2, recovery_threshold=3)
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.record_monitor_result(db, monitor, False, None, 100, "Timed out")
        network_monitor.record_monitor_result(db, monitor, False, None, 100, "Timed out")
        network_monitor.record_monitor_result(db, monitor, True, 10, 0, None)
        assert monitor.last_status == "recovering"
        assert monitor.consecutive_successes == 1
        network_monitor.record_monitor_result(db, monitor, False, None, 100, "Timed out")
        assert monitor.last_status == "offline"
        assert monitor.consecutive_successes == 0
        assert db.query(NetworkMonitorOutage).filter_by(incident_type="offline", ended_at=None).count() == 1


def test_recovery_state_can_be_hidden_without_skipping_confirmation():
    factory = session_factory()
    monitor_id = add_monitor(factory, failure_threshold=1, recovery_threshold=2, recovery_state_enabled=False)
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.record_monitor_result(db, monitor, False, None, 100, "Timed out")
        network_monitor.record_monitor_result(db, monitor, True, 10, 0, None)
        assert monitor.last_status == "offline"
        network_monitor.record_monitor_result(db, monitor, True, 10, 0, None)
        assert monitor.last_status == "healthy"


def test_maintenance_state_suppresses_incidents():
    factory = session_factory()
    monitor_id = add_monitor(factory, failure_threshold=1, is_in_maintenance=True)
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        network_monitor.record_monitor_result(db, monitor, False, None, 100, "Timed out")
        network_monitor.record_monitor_result(db, monitor, False, None, 100, "Timed out")
        assert monitor.last_status == "maintenance"
        assert db.query(NetworkMonitorOutage).count() == 0
        assert {row.health_state for row in db.query(NetworkMonitorCheck).all()} == {"maintenance"}


def test_inherited_thresholds_follow_site_defaults_but_custom_values_do_not():
    factory = session_factory()
    inherited_id = add_monitor(factory, use_default_thresholds=True, latency_warning_ms=999, latency_critical_ms=1200)
    with factory() as db:
        db.add_all([
            RemoteManagerSetting(key="network_monitor_latency_warning_ms", value="40"),
            RemoteManagerSetting(key="network_monitor_latency_critical_ms", value="90"),
        ])
        db.commit()
        inherited = db.get(NetworkMonitor, inherited_id)
        assert network_monitor.effective_monitor_thresholds(db, inherited)["latency_warning_ms"] == 40
        inherited.use_default_thresholds = False
        db.commit()
        assert network_monitor.effective_monitor_thresholds(db, inherited)["latency_warning_ms"] == 999


def test_threshold_and_timing_validation_reject_invalid_combinations():
    values = network_monitor.MONITOR_THRESHOLD_DEFAULTS.copy()
    values["latency_warning_ms"] = 300
    values["latency_critical_ms"] = 200
    try:
        network_monitor.validate_threshold_values(values)
        assert False, "invalid latency ordering was accepted"
    except ValueError as exc:
        assert "greater than or equal" in str(exc)
    try:
        network_monitor.validate_monitor_timing(5, 10000)
        assert False, "timeout longer than interval was accepted"
    except ValueError as exc:
        assert "must not exceed" in str(exc)


def test_unexpected_probe_errors_are_redacted(monkeypatch):
    factory = session_factory()
    monitor_id = add_monitor(factory)
    monkeypatch.setattr(network_monitor, "SessionLocal", factory)
    monkeypatch.setattr(network_monitor, "run_monitor_check", lambda *_: (_ for _ in ()).throw(RuntimeError("C:/secret/internal/path")))

    network_monitor.run_monitor_check_by_id(monitor_id)

    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        assert monitor.last_error == "Monitor check failed unexpectedly."
        assert "secret" not in db.query(NetworkMonitorCheck).one().error


def test_monitor_lock_skips_overlapping_checks(monkeypatch):
    factory = session_factory()
    monitor_id = add_monitor(factory)
    monkeypatch.setattr(network_monitor, "SessionLocal", factory)
    lock = network_monitor.monitor_check_lock(monitor_id)
    lock.acquire()
    try:
        assert network_monitor.run_monitor_check_by_id(monitor_id) is False
    finally:
        lock.release()
    with factory() as db:
        assert db.query(NetworkMonitorCheck).count() == 0


def test_cancelled_monitor_task_is_reaped_without_cancelling_scheduler():
    async def exercise():
        task = asyncio.create_task(asyncio.sleep(60))
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert network_monitor._reap_finished_monitor_tasks({17: task}) == {}

    asyncio.run(exercise())


def test_watchdog_recreates_a_failed_scheduler_task(monkeypatch):
    async def exercise():
        async def fail():
            raise RuntimeError("synthetic scheduler failure")

        async def replacement():
            await asyncio.Event().wait()

        failed = asyncio.create_task(fail(), name="failed-scheduler")
        await asyncio.gather(failed, return_exceptions=True)
        monkeypatch.setattr(network_monitor, "monitor_loop", replacement)
        network_monitor._scheduler_task = failed
        network_monitor._scheduler_shutdown_requested = False

        recreated = network_monitor.supervise_monitor_scheduler()

        assert recreated is network_monitor._scheduler_task
        assert recreated is not None and not recreated.done()
        assert recreated.get_name().startswith("ip-wan-monitor-scheduler-")
        recreated.cancel()
        await asyncio.gather(recreated, return_exceptions=True)
        network_monitor._scheduler_task = None

    asyncio.run(exercise())


def test_five_second_monitor_becomes_due_without_backlog():
    network_monitor._dashboard_interval_leases.clear()
    factory = session_factory()
    monitor_id = add_monitor(factory, interval_seconds=5)
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        monitor.last_checked_at = datetime.utcnow() - timedelta(seconds=4)
        db.commit()
        assert network_monitor.fallback_due_monitors(db) == []
        monitor.last_checked_at = datetime.utcnow() - timedelta(seconds=6)
        db.commit()
        assert [row.id for row in network_monitor.fallback_due_monitors(db)] == [monitor_id]


def test_dashboard_rate_lease_overrides_saved_interval_and_expires():
    network_monitor._dashboard_interval_leases.clear()
    try:
        assert network_monitor.active_dashboard_interval() is None
        assert network_monitor.set_dashboard_interval_override("dashboard-one", "ten") is True
        assert network_monitor.set_dashboard_interval_override("dashboard-one", "ten") is False
        assert network_monitor.active_dashboard_interval() == 10
        assert network_monitor.set_dashboard_interval_override("dashboard-two", "live") is True
        assert network_monitor.active_dashboard_interval() == 1
        assert network_monitor.set_dashboard_interval_override("dashboard-two", "paused") is True
        assert network_monitor.active_dashboard_interval() == 10
        network_monitor._dashboard_interval_leases["dashboard-one"] = (
            "ten", 10, datetime.utcnow() - timedelta(seconds=1),
        )
        assert network_monitor.active_dashboard_interval() is None
    finally:
        network_monitor._dashboard_interval_leases.clear()


def test_dashboard_rate_makes_monitor_due_before_saved_interval():
    network_monitor._dashboard_interval_leases.clear()
    factory = session_factory()
    monitor_id = add_monitor(factory, interval_seconds=300)
    try:
        network_monitor.set_dashboard_interval_override("dashboard-one", "ten")
        with factory() as db:
            monitor = db.get(NetworkMonitor, monitor_id)
            monitor.last_checked_at = datetime.utcnow() - timedelta(seconds=11)
            db.commit()
            assert [row.id for row in network_monitor.fallback_due_monitors(db)] == [monitor_id]
    finally:
        network_monitor._dashboard_interval_leases.clear()


def test_dashboard_exposes_backend_override_rates_without_browser_probes():
    template = (Path(__file__).resolve().parents[1] / "app" / "templates" / "network_monitor.html").read_text(encoding="utf-8")
    assert network_monitor.DASHBOARD_INTERVALS == {"live": 1, "five": 5, "ten": 10, "sixty": 60}
    for value, label in (("live", "Live"), ("five", "5 seconds"), ("ten", "10 seconds"), ("sixty", "60 seconds")):
        assert f'value="{value}"' in template
        assert f">{label}</option>" in template
    assert 'value="paused"' not in template
    assert "/collect" not in template
    assert "Temporarily overrides backend checks" in template
    assert "data-monitor-csrf" in template
    assert network_monitor.clamp_interval(1) == 5


def test_monitor_network_actions_require_editor_access():
    for action in (network_monitor_router.refresh_monitor, network_monitor_router.set_collection_rate):
        dependency = inspect.signature(action).parameters["user"].default
        assert dependency.dependency is require_editor


def test_scheduler_diagnostics_are_admin_only_and_not_cacheable():
    dependency = inspect.signature(network_monitor_router.scheduler_diagnostics).parameters["user"].default
    assert dependency.dependency is require_admin

    response = network_monitor_router.scheduler_diagnostics(user=object())
    payload = json.loads(response.body)

    assert response.headers["cache-control"] == "no-store"
    assert {
        "scheduler_running", "task_id", "last_scheduler_heartbeat",
        "last_monitor_execution", "last_observation_written", "pending_monitors",
        "pending_monitor_count", "current_loop_iteration", "worker_uptime_seconds",
        "scheduler_task_id", "last_due_scan", "due_monitors_found",
        "active_monitor_tasks", "available_worker_slots", "stuck_monitor_count",
        "oldest_active_monitor", "last_scheduler_exception", "watchdog_restart_count",
    } <= set(payload)


def test_live_feed_returns_only_new_genuine_observations():
    factory = session_factory()
    monitor_id = add_monitor(factory)
    with factory() as db:
        db.add_all([
            NetworkMonitorCheck(monitor_id=monitor_id, status="up", latency_ms=12, packet_loss_percent=0),
            NetworkMonitorCheck(monitor_id=monitor_id, status="down", latency_ms=None, packet_loss_percent=100),
        ])
        monitor = db.get(NetworkMonitor, monitor_id)
        monitor.is_enabled = True
        monitor.interval_seconds = 5
        db.commit()
        first_id = db.query(NetworkMonitorCheck.id).order_by(NetworkMonitorCheck.id).first()[0]
        response = network_monitor_router.live_dashboard_observations(after=first_id, db=db, user=object())
        payload = json.loads(response.body)
        assert [row["latency_ms"] for row in payload["observations"]] == [None]
        assert payload["observations"][0]["id"] > first_id
        assert "jitter_ms" in payload["observations"][0]
        assert payload["summary"]["checks_per_minute"] == 12.0


def test_dashboard_resumes_from_stored_result_outside_live_window():
    factory = session_factory()
    monitor_id = add_monitor(factory)
    with factory() as db:
        monitor = db.get(NetworkMonitor, monitor_id)
        monitor.last_checked_at = datetime.utcnow() - timedelta(minutes=10)
        monitor.last_latency_ms = 15.558
        monitor.last_packet_loss_percent = 0
        monitor.last_status = "healthy"
        db.commit()

        context = network_monitor_router.dashboard_context(db)

        assert context["rows"][0]["chart_points"] == [{
            "id": 0,
            "at": monitor.last_checked_at.isoformat() + "Z",
            "latency": 15.558,
            "loss": 0,
            "status": "healthy",
        }]


def test_dashboard_summary_separates_critical_paused_and_active_incidents():
    factory = session_factory()
    critical_id = add_monitor(factory)
    with factory() as db:
        critical = db.get(NetworkMonitor, critical_id)
        critical.last_status = "critical"
        paused_address = IPAddress(address="192.0.2.11", name="Paused target")
        db.add(paused_address)
        db.flush()
        db.add(NetworkMonitor(ip_address_id=paused_address.id, is_enabled=False, last_status="paused"))
        db.add(NetworkMonitorOutage(monitor_id=critical.id, started_at=datetime.utcnow(), incident_type="degraded"))
        db.commit()

        context = network_monitor_router.dashboard_context(db)

        assert context["total"] == 2
        assert context["critical_count"] == 1
        assert context["warning_count"] == 0
        assert context["paused_count"] == 1
        assert context["active_incidents"] == 1


def test_detail_ranges_are_allowlisted_and_reduce_long_browser_series():
    now = datetime.utcnow()
    points = [{"at": now - timedelta(minutes=index), "latency": 20 + index % 4, "loss": 0, "samples": 1, "up_count": 1} for index in range(1440)]
    reduced = network_monitor_router.display_points(points, "30d")
    assert len(reduced) <= 25
    assert network_monitor_router.range_start("90d") < network_monitor_router.range_start("24h")


def test_detail_checks_are_searchable_and_paginated():
    factory = session_factory()
    monitor_id = add_monitor(factory)
    now = datetime.utcnow()
    with factory() as db:
        db.add_all([
            NetworkMonitorCheck(
                monitor_id=monitor_id,
                status="down" if index == 60 else "up",
                health_state="offline" if index == 60 else "healthy",
                latency_ms=None if index == 60 else 1.25,
                packet_loss_percent=100 if index == 60 else 0,
                error="needle timeout" if index == 60 else None,
                checked_at=now - timedelta(seconds=index),
            )
            for index in range(61)
        ])
        db.commit()
        monitor = db.get(NetworkMonitor, monitor_id)

        second_page = network_monitor_router.monitor_detail_context(db, monitor, "1h", check_page=2)
        searched = network_monitor_router.monitor_detail_context(db, monitor, "1h", check_status="offline", check_q="needle")

        assert second_page["check_pages"] == 2
        assert len(second_page["checks"]) == 11
        assert searched["check_count"] == 1
        assert searched["checks"][0].error == "needle timeout"


def test_csv_text_neutralises_spreadsheet_formula_prefixes():
    assert network_monitor_router.csv_safe("=HYPERLINK(\"https://invalid.test\")").startswith("'")
    assert network_monitor_router.csv_safe("Timed out") == "Timed out"


def test_detail_uses_local_echarts_and_incident_checks_tabs():
    root = Path(__file__).resolve().parents[1]
    template = (root / "app" / "templates" / "network_monitor_detail.html").read_text(encoding="utf-8")
    assert "/static/vendor/echarts/echarts.min.js" in template
    assert 'href="#incidents"' in template
    assert 'href="#checks"' in template
    assert "latency_label(check.latency_ms)" in template
    assert "latency_label(check.response_time_ms)" in template
    assert "latency_label(row.peak_latency)" in template
    assert (root / "app" / "static" / "vendor" / "echarts" / "LICENSE").is_file()


def test_dashboard_uses_rolling_echarts_with_duplicate_and_visibility_guards():
    root = Path(__file__).resolve().parents[1]
    cards = (root / "app" / "templates" / "_network_monitor_cards.html").read_text(encoding="utf-8")
    script = (root / "app" / "static" / "js" / "network_monitor.js").read_text(encoding="utf-8")
    wallboard_script = (root / "app" / "static" / "js" / "network_monitor_wallboard.js").read_text(encoding="utf-8")
    css = (root / "app" / "static" / "css" / "app.css").read_text(encoding="utf-8")
    kaya_css = (root / "app" / "static" / "css" / "kaya.css").read_text(encoding="utf-8")
    assert "data-monitor-card-chart" in cards
    assert "latency-spark" not in cards and "uptime-strip" not in cards
    assert "card.seen.has" in script
    assert 'document.addEventListener("visibilitychange"' in script
    assert "/networking/ip-wan-monitor/collection-rate" in script
    assert "sendBeacon" in script
    assert "renewOverride" in script
    assert "ResizeObserver" in script
    assert "requestAnimationFrame" in script
    assert "containLabel: true" in script
    assert "presentationSeries" in script
    assert "drawLiveTrace" in script
    assert "formatLiveLatency" in script
    assert "monitor-heartbeat" not in script
    assert ".monitor-heartbeat{" not in css
    assert "@keyframes monitor-heartbeat" not in css
    assert script.index('if (state !== previousState)') < script.index('card.element.classList.add(`state-${state}`)')
    assert "data.push([now, latest.latency" in script
    assert "if (beforeWindow) card.points.unshift(beforeWindow)" in script
    assert "animationDurationUpdate" not in script
    assert "animation: false" in script
    assert "chartUpdateOption" in script
    assert "id: `latency-${card.id}`" in script
    assert "MutationObserver" in script
    assert "formatLatency" in script
    assert "max: now + 250" in script
    assert "showSymbol: false, clip: true" in script
    assert "right: 20" in script
    assert "data-monitor-state-reason" in cards
    assert "state-{{ card_state }}" in cards
    assert "monitor-card--offline" in cards
    assert 'data-state="{{ card_state }}"' in cards
    assert "monitor-card-chart-shell" in cards
    assert "monitor-last-result" in cards
    assert '"/networking/ip-wan-monitor/collect"' not in script
    assert ".monitor-live-grid{grid-template-columns:repeat(3" in css
    assert "@media(max-width:1650px)" in css and "@media(max-width:950px)" in css
    assert "@media(prefers-reduced-motion:reduce)" in css
    assert ".monitor-live-card.state-healthy{background:linear-gradient" in css
    assert ".monitor-live-card.state-offline,.monitor-live-card.monitor-card--offline" in css
    assert "rgba(127,29,29,.58)" in css
    assert ".monitor-live-card.state-offline" in kaya_css
    assert "rgba(127,29,29,.72)" in kaya_css
    assert "#14171d!important" in kaya_css
    assert 'classList.toggle("monitor-card--offline", state === "offline")' in script
    assert "html[data-kaya-theme=light-ops] .monitor-live-card.monitor-card--offline" in css
    assert "box-shadow:inset 4px 0 0" in css
    assert ".monitor-live-card.state-warning .monitor-live-footer" not in css
    assert "min-width:calc(100% + 32px)" not in css
    assert ".monitor-live-footer{background:transparent;border:0" in css
    assert 'state.textContent = "● Live"' in script
    assert "stateLabels" not in script
    assert '"incidents", "checks"' in script
    assert "handle.hidden = !enabled; handle.disabled = !enabled" in wallboard_script
    assert "controls.hidden = !enabled" in wallboard_script
    assert "button.disabled = !enabled" in wallboard_script
    assert "rgba(22,163,74,.04)" in css


def test_healthy_monitor_renders_state_on_the_full_card():
    root = Path(__file__).resolve().parents[1]
    environment = Environment(loader=FileSystemLoader(root / "app" / "templates"), autoescape=True)
    template = environment.get_template("_network_monitor_cards.html")
    monitor = SimpleNamespace(
        id=17, is_enabled=True, state_reason="Within configured thresholds", last_latency_ms=1,
        last_checked_at=None, last_error=None, ip_address=SimpleNamespace(address="192.0.2.17"),
    )
    row = SimpleNamespace(
        monitor=monitor, state="healthy", effective_interval=5,
        thresholds=SimpleNamespace(latency_warning_ms=100, latency_critical_ms=250),
        chart_points=[], label="Synthetic healthy host", average_latency=1, uptime=100,
    )
    rendered = template.render(
        rows=[row], total=1, up_count=1, warning_count=0, critical_count=0, down_count=0, paused_count=0,
        average_latency=1, availability_24h=100, checks_per_minute=12,
        active_incidents=0, latest_observation_id=0, latency_label=network_monitor.latency_label,
        live_latency_label=network_monitor.live_latency_label,
        user=SimpleNamespace(role="viewer"), csrf_token="fake-csrf-token",
    )
    assert 'class="monitor-card monitor-live-card state-healthy"' in rendered
    assert "monitor-card--offline" not in rendered
    assert 'data-state="healthy"' in rendered
    assert "● Live" in rendered
    assert rendered.index('class="monitor-live-footer"') < rendered.index('class="monitor-card-actions"')
    assert 'data-monitor-drag-handle hidden disabled' in rendered
    assert 'class="monitor-keyboard-order" aria-label="Keyboard reorder controls" hidden' in rendered
    assert 'data-monitor-move="up" aria-label="Move Synthetic healthy host earlier" disabled' in rendered

    row.state = "warning"
    warning_rendered = template.render(
        rows=[row], total=1, up_count=0, warning_count=1, critical_count=0, down_count=0, paused_count=0,
        average_latency=1, availability_24h=100, checks_per_minute=12,
        active_incidents=0, latest_observation_id=0, latency_label=network_monitor.latency_label,
        live_latency_label=network_monitor.live_latency_label,
        user=SimpleNamespace(role="viewer"), csrf_token="fake-csrf-token",
    )
    assert 'class="monitor-card monitor-live-card state-warning"' in warning_rendered
    assert "monitor-card--offline" not in warning_rendered
    assert ">Warning</span>" in warning_rendered

    row.state = "offline"
    offline_rendered = template.render(
        rows=[row], total=1, up_count=0, warning_count=0, critical_count=0, down_count=1, paused_count=0,
        average_latency=1, availability_24h=0, checks_per_minute=12,
        active_incidents=1, latest_observation_id=0, latency_label=network_monitor.latency_label,
        live_latency_label=network_monitor.live_latency_label,
        user=SimpleNamespace(role="viewer"), csrf_token="fake-csrf-token",
    )
    assert 'class="monitor-card monitor-live-card state-offline monitor-card--offline"' in offline_rendered
    assert 'data-state="offline"' in offline_rendered
    assert "● Live" in warning_rendered


def test_per_host_and_global_threshold_controls_are_present():
    root = Path(__file__).resolve().parents[1]
    fields = (root / "app" / "templates" / "_network_monitor_threshold_fields.html").read_text(encoding="utf-8")
    settings = (root / "app" / "templates" / "settings.html").read_text(encoding="utf-8")
    ip_detail = (root / "app" / "templates" / "ip_address_detail.html").read_text(encoding="utf-8")
    for name in (
        "latency_warning_ms", "latency_critical_ms", "packet_loss_warning_percent",
        "packet_loss_critical_percent", "degraded_threshold", "failure_threshold",
        "recovery_threshold", "recovery_state_enabled",
    ):
        assert name in fields
    assert "Use Kaya default thresholds" in fields
    assert "module-network-monitor" in settings
    assert "_network_monitor_threshold_fields.html" in ip_detail


@pytest.mark.parametrize("selected,expected", [
    ("1h", 0), ("6h", 60), ("24h", 300), ("7d", 1800),
    ("30d", 7200), ("90d", 43200), ("1y", 86400),
])
def test_performance_predefined_ranges_select_expected_buckets(selected, expected):
    factory = session_factory()
    with factory() as db:
        selection = network_monitor_history.resolve_range(db, selected, now=datetime(2026, 7, 29, 12))
        assert selection["bucket_seconds"] == expected
        assert selection["end"] - selection["start"] == network_monitor_history.PERFORMANCE_RANGES[selected][0]


def test_performance_custom_range_uses_site_timezone_and_validates_bounds():
    factory = session_factory()
    with factory() as db:
        db.add(RemoteManagerSetting(key="timezone_region", value="Europe/London"))
        db.commit()
        selection = network_monitor_history.resolve_range(
            db, "custom", "2026-07-29T08:00", "2026-07-29T14:00", now=datetime(2026, 7, 29, 14),
        )
        assert selection["start"] == datetime(2026, 7, 29, 7)
        assert selection["end"] == datetime(2026, 7, 29, 13)
        assert selection["bucket_seconds"] == 60
        with pytest.raises(HTTPException):
            network_monitor_history.resolve_range(db, "custom", "2026-07-29T14:00", "2026-07-29T08:00", now=datetime(2026, 7, 29, 14))
        with pytest.raises(HTTPException):
            network_monitor_history.resolve_range(db, "custom", "2025-01-01T00:00", "2026-07-29T08:00", now=datetime(2026, 7, 29, 14))


def test_performance_raw_summary_incidents_and_thresholds_match_selected_range():
    factory = session_factory()
    monitor_id = add_monitor(
        factory, latency_warning_ms=80, latency_critical_ms=180,
        packet_loss_warning_percent=5, packet_loss_critical_percent=25,
    )
    now = datetime(2026, 7, 29, 12)
    with factory() as db:
        db.add_all([
            NetworkMonitorCheck(monitor_id=monitor_id, status=status, health_state=state, latency_ms=latency,
                                packet_loss_percent=loss, checked_at=now - timedelta(minutes=minutes))
            for minutes, status, state, latency, loss in [
                (50, "up", "healthy", 10, 0), (40, "up", "warning", 20, 5),
                (30, "down", "offline", None, 100), (20, "up", "critical", 40, 10),
            ]
        ])
        db.add(NetworkMonitorCheck(monitor_id=monitor_id, status="up", health_state="healthy", latency_ms=999,
                                   packet_loss_percent=0, checked_at=now - timedelta(hours=2)))
        db.add(NetworkMonitorOutage(
            monitor_id=monitor_id, incident_type="offline", failure_reason="Three fake failed checks",
            started_at=now - timedelta(minutes=35), ended_at=now - timedelta(minutes=25),
        ))
        db.add(NetworkMonitorEvent(monitor_id=monitor_id, event_type="recovered", severity="success",
                                   message="Recovered", occurred_at=now - timedelta(minutes=25)))
        db.commit()
        result = network_monitor_history.performance_history(db, db.get(NetworkMonitor, monitor_id), "1h", now=now)

    assert result["summary"]["total_checks"] == 4
    assert result["summary"]["successful_checks"] == 3
    assert result["summary"]["failed_checks"] == 1
    assert result["summary"]["availability"] == 75
    assert result["summary"]["average_latency"] == pytest.approx(23.333)
    assert result["summary"]["median_latency"] == 20
    assert result["summary"]["minimum_latency"] == 10
    assert result["summary"]["maximum_latency"] == 40
    assert result["summary"]["average_jitter"] == 15
    assert result["summary"]["maximum_jitter"] == 20
    assert result["summary"]["packet_loss"] == 28.75
    assert result["summary"]["downtime_seconds"] == 600
    assert result["summary"]["incident_count"] == 1
    assert result["incidents"][0]["reason"] == "Three fake failed checks"
    assert result["events"][0]["type"] == "recovered"
    assert result["thresholds"] == {
        "latency_warning": 80, "latency_critical": 180,
        "packet_loss_warning": 5, "packet_loss_critical": 25,
    }
    assert all(point["latency_avg"] != 999 for point in result["points"])


def test_performance_aggregated_history_preserves_genuine_range_and_unknown_values():
    factory = session_factory()
    monitor_id = add_monitor(factory)
    now = datetime(2026, 7, 29, 12)
    with factory() as db:
        db.add_all([
            NetworkMonitorStatistic(
                monitor_id=monitor_id, bucket_start=now - timedelta(days=2), bucket_seconds=43200,
                sample_count=12, up_count=11, latency_sample_count=11, avg_latency_ms=22,
                min_latency_ms=8, max_latency_ms=51, jitter_sample_count=10,
                avg_jitter_ms=3, max_jitter_ms=9, loss_sample_count=12,
                avg_packet_loss_percent=4, health_state="warning",
            ),
            NetworkMonitorStatistic(
                monitor_id=monitor_id, bucket_start=now - timedelta(days=1), bucket_seconds=43200,
                sample_count=12, up_count=12, latency_sample_count=12, avg_latency_ms=18,
                min_latency_ms=None, max_latency_ms=25, jitter_sample_count=0,
                avg_jitter_ms=None, max_jitter_ms=None, loss_sample_count=12,
                avg_packet_loss_percent=0, health_state="maintenance",
            ),
        ])
        db.commit()
        result = network_monitor_history.performance_history(db, db.get(NetworkMonitor, monitor_id), "90d", now=now)

    assert result["range"]["bucket_seconds"] == 43200
    assert result["range"]["aggregation"] == "12-hour aggregated observations"
    assert result["summary"]["total_checks"] == 24
    assert result["summary"]["minimum_latency"] == 8
    assert result["summary"]["maximum_latency"] == 51
    assert result["summary"]["packet_loss"] == 2
    assert {point["status"] for point in result["points"]} == {"warning", "maintenance"}
    assert any(point["latency_min"] is None and point["jitter_avg"] is None for point in result["points"])


def test_performance_partial_empty_and_paginated_states():
    factory = session_factory()
    monitor_id = add_monitor(factory)
    empty_id = add_monitor(factory, display_name="Empty monitor")
    now = datetime(2026, 7, 29, 12)
    with factory() as db:
        db.add_all([
            NetworkMonitorCheck(monitor_id=monitor_id, status="up", health_state="healthy", latency_ms=index + 1,
                                packet_loss_percent=0, checked_at=now - timedelta(minutes=20 - index))
            for index in range(12)
        ])
        db.commit()
        first = network_monitor_history.performance_history(
            db, db.get(NetworkMonitor, monitor_id), "1h", page=1, page_size=5,
            sort="latency_avg", direction="desc", now=now,
        )
        third = network_monitor_history.performance_history(
            db, db.get(NetworkMonitor, monitor_id), "1h", page=3, page_size=5, now=now,
        )
        empty = network_monitor_history.performance_history(db, db.get(NetworkMonitor, empty_id), "24h", now=now)

    assert first["range"]["partial"] is True
    assert first["table"]["pages"] == 3 and len(first["table"]["rows"]) == 5
    assert first["table"]["rows"][0]["latency_avg"] == 12
    assert len(third["table"]["rows"]) == 2
    assert empty["points"] == []
    assert empty["summary"]["availability"] is None
    assert empty["summary"]["longest_outage_seconds"] is None
    assert empty["range"]["available_from"] is None


def test_retained_aggregation_records_latency_jitter_and_loss_evidence():
    factory = session_factory()
    monitor_id = add_monitor(factory)
    base = datetime(2026, 7, 29, 10)
    with factory() as db:
        db.add_all([
            NetworkMonitorCheck(monitor_id=monitor_id, status="up", health_state="healthy",
                                latency_ms=value, packet_loss_percent=loss,
                                checked_at=base + timedelta(seconds=index * 10))
            for index, (value, loss) in enumerate([(10, 0), (15, 5), (25, 10)])
        ])
        db.commit()
        network_monitor._aggregate_checks(db, base + timedelta(minutes=10), 300)
        db.commit()
        statistic = db.query(NetworkMonitorStatistic).one()

    assert statistic.sample_count == 3 and statistic.latency_sample_count == 3
    assert statistic.min_latency_ms == 10 and statistic.max_latency_ms == 25
    assert statistic.avg_latency_ms == pytest.approx(16.667)
    assert statistic.jitter_sample_count == 2
    assert statistic.avg_jitter_ms == 7.5 and statistic.max_jitter_ms == 10
    assert statistic.loss_sample_count == 3 and statistic.avg_packet_loss_percent == 5


def test_performance_workspace_uses_one_reusable_theme_aware_chart_without_navigation():
    root = Path(__file__).resolve().parents[1]
    template = (root / "app" / "templates" / "network_monitor_detail.html").read_text(encoding="utf-8")
    script = (root / "app" / "static" / "js" / "network_monitor.js").read_text(encoding="utf-8")
    css = (root / "app" / "static" / "css" / "app.css").read_text(encoding="utf-8")
    assert 'data-monitor-performance' in template and 'data-performance-custom' in template
    assert all(f"'{value}'" in template for value in ("1h", "6h", "24h", "7d", "30d", "90d", "1y", "custom"))
    assert "fetch(`${performance.dataset.endpoint}" in script
    assert "if (!performanceState.chart)" in script
    assert "ResizeObserver" in script and "data-kaya-theme" in script
    assert 'updatePerformanceExportUrl()' in script
    assert 'dataset.exportUrl = `${performance.dataset.exportEndpoint}' in script
    assert 'window.location.assign(`${performance.dataset.endpoint}' not in script
    assert "axisPointer: { type: \"cross\" }" in script
    assert "performanceState.chart.setOption" in script
    assert 'performanceEventAreas(payload.events || [], "paused", "resumed"' in script
    assert 'event_type="resumed" if monitor.is_enabled else "paused"' in (root / "app" / "routers" / "network_monitor.py").read_text(encoding="utf-8")
    assert ".monitor-performance .performance-chart" in css
    assert ".performance-overlays input[type=checkbox]" in css
    assert "flex:0 0 16px;height:16px" in css
    assert template.count('role="button" data-col=') == 10
    assert 'data-table-key="network-monitor-performance"' in template
    assert "performance-sort-button" not in template
    assert '.performance-history-table th[data-performance-sort]{cursor:pointer;user-select:none}' in css
    assert 'if (!["Enter", " "].includes(event.key)) return;' in script
    assert ".monitor-performance-table-panel>.panel-heading{align-items:center" in css
    assert ".performance-table-filter input{flex:0 1 280px;min-width:200px;width:280px}" in css
    assert "html[data-kaya-theme=light-ops] .performance-custom-range" in css


def test_performance_year_range_is_bounded_to_daily_chart_points():
    factory = session_factory()
    monitor_id = add_monitor(factory)
    now = datetime(2026, 7, 29, 12)
    with factory() as db:
        db.add_all([
            NetworkMonitorStatistic(
                monitor_id=monitor_id, bucket_start=now - timedelta(days=index), bucket_seconds=86400,
                sample_count=288, up_count=288, latency_sample_count=288, avg_latency_ms=12,
                min_latency_ms=10, max_latency_ms=14, loss_sample_count=288,
                avg_packet_loss_percent=0, health_state="healthy",
            )
            for index in range(1, 371)
        ])
        db.commit()
        result = network_monitor_history.performance_history(db, db.get(NetworkMonitor, monitor_id), "1y", now=now)

    assert result["range"]["bucket_seconds"] == 86400
    assert len(result["points"]) <= 366
    assert result["table"]["page_size"] == 50
