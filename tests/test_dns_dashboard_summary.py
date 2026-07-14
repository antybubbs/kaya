from datetime import datetime, timedelta
import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import DNSInsight, DNSProviderConfig, DNSStatisticsSnapshot, User
from app.services.dns_dashboard_summary import _provider_status, get_dns_dashboard_summary, get_featured_dns_insight, get_refreshed_dns_dashboard_summary
import app.services.dns_dashboard_summary as dns_dashboard_service


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def add_provider(db, *, status="online"):
    provider = DNSProviderConfig(name="Home DNS", provider_type="pihole", base_url="http://dns.invalid", last_status=status)
    db.add(provider)
    db.flush()
    return provider


def add_snapshot(db, provider, **values):
    now = values.pop("period_end", datetime.utcnow())
    row = DNSStatisticsSnapshot(
        provider_id=provider.id,
        period_start=now.replace(minute=0, second=0, microsecond=0),
        period_end=now,
        provider_connected=True,
        total_queries=values.pop("total_queries", 1000),
        blocked_queries=values.pop("blocked_queries", 100),
        active_clients=values.pop("active_clients", 2),
        capabilities_json=json.dumps(values.pop("capabilities", ["stats", "queries", "clients"])),
        client_aggregates_json=json.dumps(values.pop("clients", {"mac:a": {}, "hostname:b": {}})),
        **values,
    )
    db.add(row)
    db.flush()
    return row


def add_user(db):
    user = User(email="viewer@example.com", password_hash="test", role="viewer", is_active=True)
    db.add(user)
    db.flush()
    return user


def add_insight(db, provider, *, severity, detected, status="active", acknowledged=False, dismissed=False, title=None):
    row = DNSInsight(
        provider_id=provider.id,
        insight_key=f"{severity}:{detected.timestamp()}:{title or ''}",
        rule_key="test",
        category="system",
        severity=severity,
        status=status,
        title=title or severity.title(),
        summary=f"{severity} summary",
        first_detected_at=detected,
        last_detected_at=detected,
        acknowledged_at=detected if acknowledged else None,
        dismissed_at=detected if dismissed else None,
    )
    db.add(row)
    db.flush()
    return row


def test_dashboard_panel_is_between_resources_and_vm_manager():
    template = Path("app/templates/dashboard.html").read_text(encoding="utf-8")
    assert template.index("compute-resource-grid") < template.index("dashboard-dns-summary") < template.index("VM / Docker Manager")


def test_not_configured_summary_does_not_invent_metrics():
    with database() as db:
        summary = get_dns_dashboard_summary(db, add_user(db))
        assert summary.configured is False
        assert summary.provider_status == "not_configured"
        assert summary.queries_today is None
        assert summary.active_clients_24h is None


def test_connected_summary_uses_stored_snapshot_and_calculates_blocked_percentage():
    with database() as db:
        provider = add_provider(db)
        add_snapshot(db, provider, total_queries=2000, blocked_queries=150)
        summary = get_dns_dashboard_summary(db, add_user(db))
        assert summary.provider_status == "connected"
        assert summary.queries_today == 2000
        assert summary.blocked_queries_today == 150
        assert summary.blocked_percentage == 7.5
        assert summary.active_clients_24h == 2


def test_zero_queries_is_safe_and_missing_data_remains_unavailable():
    with database() as db:
        provider = add_provider(db)
        add_snapshot(db, provider, total_queries=0, blocked_queries=0, clients={})
        summary = get_dns_dashboard_summary(db, add_user(db))
        assert summary.blocked_percentage == 0
        assert summary.active_clients_24h == 0


def test_provider_status_connected_degraded_disconnected_and_stale():
    now = datetime.utcnow()
    connected = type("Provider", (), {"last_status": "online"})()
    disconnected = type("Provider", (), {"last_status": "error"})()
    current = type("Snapshot", (), {"period_end": now, "capabilities_json": json.dumps(["stats", "queries", "clients"])})()
    partial = type("Snapshot", (), {"period_end": now, "capabilities_json": json.dumps(["stats"])})()
    stale = type("Snapshot", (), {"period_end": now - timedelta(hours=2), "capabilities_json": json.dumps(["stats", "queries", "clients"])})()
    assert _provider_status(connected, current, now)[0] == "connected"
    assert _provider_status(connected, partial, now)[0] == "degraded"
    assert _provider_status(disconnected, current, now)[0] == "disconnected"
    assert _provider_status(connected, stale, now)[0] == "stale"


def test_dashboard_dns_refresh_uses_last_attempt_to_throttle_offline_retries(monkeypatch):
    with database() as db:
        now = datetime.utcnow()
        provider = add_provider(db, status="error")
        provider.last_checked_at = now
        add_snapshot(db, provider, period_end=now - timedelta(hours=39))
        account = add_user(db)
        calls = []
        monkeypatch.setattr(dns_dashboard_service, "analyse_provider", lambda *args, **kwargs: calls.append((args, kwargs)))
        get_refreshed_dns_dashboard_summary(db, account, max_age_seconds=60)
        assert calls == []

        provider.last_checked_at = now - timedelta(minutes=2)
        get_refreshed_dns_dashboard_summary(db, account, max_age_seconds=60)
        assert len(calls) == 1


def test_dashboard_dns_refresh_never_contacts_provider_in_demo(monkeypatch):
    with database() as db:
        provider = add_provider(db)
        add_snapshot(db, provider, period_end=datetime.utcnow() - timedelta(hours=39))
        account = add_user(db)
        calls = []
        monkeypatch.setattr(dns_dashboard_service, "get_settings", lambda: type("Settings", (), {"demo_mode": True})())
        monkeypatch.setattr(dns_dashboard_service, "analyse_provider", lambda *args, **kwargs: calls.append((args, kwargs)))

        summary = get_refreshed_dns_dashboard_summary(db, account, max_age_seconds=0)

        assert summary.configured is True
        assert calls == []


def test_attention_counts_exclude_info_resolved_acknowledged_and_dismissed():
    with database() as db:
        provider = add_provider(db)
        add_snapshot(db, provider)
        now = datetime.utcnow()
        add_insight(db, provider, severity="critical", detected=now)
        add_insight(db, provider, severity="warning", detected=now - timedelta(minutes=1))
        add_insight(db, provider, severity="information", detected=now - timedelta(minutes=2))
        add_insight(db, provider, severity="warning", detected=now - timedelta(minutes=3), status="resolved", title="resolved")
        add_insight(db, provider, severity="warning", detected=now - timedelta(minutes=4), acknowledged=True, title="ack")
        add_insight(db, provider, severity="critical", detected=now - timedelta(minutes=5), dismissed=True, title="dismissed")
        summary = get_dns_dashboard_summary(db, add_user(db))
        assert summary.critical_insight_count == 1
        assert summary.warning_insight_count == 1
        assert summary.attention_count == 2


def test_featured_insight_priority_is_critical_then_warning_then_information():
    with database() as db:
        provider = add_provider(db)
        now = datetime.utcnow()
        info = add_insight(db, provider, severity="information", detected=now, title="Newest info")
        warning = add_insight(db, provider, severity="warning", detected=now - timedelta(hours=1), title="Warning")
        critical = add_insight(db, provider, severity="critical", detected=now - timedelta(days=1), title="Critical")
        assert get_featured_dns_insight(db, provider.id).id == critical.id
        critical.status = "resolved"
        db.flush()
        assert get_featured_dns_insight(db, provider.id).id == warning.id
        warning.acknowledged_at = now
        db.flush()
        assert get_featured_dns_insight(db, provider.id).id == info.id


def test_dashboard_summary_service_does_not_import_or_call_provider_client():
    source = Path("app/services/dns_dashboard_summary.py").read_text(encoding="utf-8")
    assert "provider_for" not in source
    assert "get_statistics(" not in source
    assert "get_query_log(" not in source


def test_summary_failure_returns_safe_error_state():
    class BrokenSession:
        def query(self, *args, **kwargs):
            raise RuntimeError("database unavailable")

    summary = get_dns_dashboard_summary(BrokenSession(), object())
    assert summary.error is True
    assert summary.provider_status == "unavailable"
    assert summary.queries_today is None
