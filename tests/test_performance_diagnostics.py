import json
from types import SimpleNamespace

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.performance import (
    MAX_SAMPLES,
    clear_diagnostics,
    diagnostics_snapshot,
    log_request_metrics,
    set_diagnostics_enabled,
    begin_request_metrics,
    end_request_metrics,
    external_call,
    performance_phase,
)
from app.db.session import Base
from app.models.models import RemoteManagerSetting
from app.services.site_settings import DEFAULT_SITE_SETTINGS, get_site_setting, get_site_settings


def test_performance_diagnostics_are_disabled_by_default():
    assert Settings().performance_diagnostics is False


def test_bulk_site_settings_use_one_query_and_seed_request_session_cache():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    statements = []
    event.listen(engine, "before_cursor_execute", lambda *args: statements.append(args[2]))
    with Session(engine) as db:
        db.add(RemoteManagerSetting(key="timezone_region", value="Europe/London"))
        db.commit()
        statements.clear()

        values = get_site_settings(db, DEFAULT_SITE_SETTINGS)
        assert values["timezone_region"] == "Europe/London"
        assert get_site_setting(db, "dashboard_poll_interval_seconds") == "10"
        assert len(statements) == 1


def test_structured_diagnostic_logs_only_query_keys(monkeypatch):
    messages = []
    monkeypatch.setattr("app.core.performance.logger.info", messages.append)
    request = SimpleNamespace(
        method="GET",
        url=SimpleNamespace(path="/system/audit-logs"),
        query_params={"q": "sensitive search", "page": "2"},
    )
    response = SimpleNamespace(status_code=200)
    metrics = {
        "database_query_count": 3,
        "database_duration_ms": 4.25,
        "template_duration_ms": 1.5,
        "external_duration_ms": 0.0,
        "external_call_count": 0,
    }

    log_request_metrics(request=request, response=response, metrics=metrics, total_duration_ms=8.0)

    payload = json.loads(messages[0])
    assert payload["path"] == "/system/audit-logs"
    assert payload["query_keys"] == ["page", "q"]
    assert "sensitive search" not in messages[0]
    assert payload["database_query_count"] == 3


def test_dashboard_script_clears_every_interval_and_restarts_only_from_bfcache():
    script = open("app/static/js/dashboard.js", encoding="utf-8").read()
    assert "clearInterval(timer);clearInterval(tickTimer)" in script
    assert "if(event.persisted)start()" in script


def test_diagnostics_buffer_is_disabled_and_bounded():
    clear_diagnostics()
    set_diagnostics_enabled(False)
    request = SimpleNamespace(method="GET", url=SimpleNamespace(path="/assets/123?token=secret"), query_params={})
    response = SimpleNamespace(status_code=200)
    metrics = {"database_query_count": 0, "database_duration_ms": 0, "template_duration_ms": 0, "external_duration_ms": 0, "external_call_count": 0}
    log_request_metrics(request=request, response=response, metrics=metrics, total_duration_ms=1)
    assert diagnostics_snapshot()["samples"] == []

    set_diagnostics_enabled(True, enabled_at="2026-01-01T00:00:00+00:00")
    for index in range(MAX_SAMPLES + 2):
        request.url.path = f"/assets/{index}?token=secret"
        log_request_metrics(request=request, response=response, metrics=metrics, total_duration_ms=index)
    samples = diagnostics_snapshot()["samples"]
    assert len(samples) == MAX_SAMPLES
    assert samples[0]["path"] == "/assets/{id}"
    assert all("secret" not in str(sample) for sample in samples)
    set_diagnostics_enabled(False)


def test_p95_uses_interpolated_percentile_and_clear_keeps_disabled_state():
    clear_diagnostics()
    set_diagnostics_enabled(True)
    request = SimpleNamespace(method="GET", url=SimpleNamespace(path="/healthz"), query_params={})
    response = SimpleNamespace(status_code=200)
    metrics = {"database_query_count": 0, "database_duration_ms": 0, "template_duration_ms": 0, "external_duration_ms": 0, "external_call_count": 0}
    for duration in [100, 200, 300, 400]:
        log_request_metrics(request=request, response=response, metrics=metrics, total_duration_ms=duration)
    assert diagnostics_snapshot()["summary"]["p95_request_duration_ms"] == 385.0
    clear_diagnostics()
    assert diagnostics_snapshot()["state"]["enabled"] is True
    set_diagnostics_enabled(False)


def test_diagnostic_phase_and_external_call_are_structured_and_redacted(monkeypatch):
    token, metrics = begin_request_metrics()
    try:
        with performance_phase("ha.synthetic"):
            with external_call("pihole.GET:/api/auth"):
                pass
        assert metrics["phases"][0]["phase_name"] == "ha.synthetic"
        assert metrics["phases"][0]["executed"] is True
        assert metrics["external_calls"][0]["operation"] == "pihole.GET:/api/auth"
        assert metrics["external_calls"][0]["success"] is True
        assert "password" not in str(metrics)
    finally:
        end_request_metrics(token)


def test_external_call_marks_database_connection_held(monkeypatch):
    import app.core.performance as performance
    token, metrics = begin_request_metrics()
    connection_token = performance._request_connection_count.set(1)
    try:
        with external_call("pihole.GET:/api/dhcp/leases"):
            pass
        assert metrics["db_pool"]["connection_held_during_external_io"] is True
        assert metrics["external_calls"][0]["db_connection_held"] is True
    finally:
        performance._request_connection_count.reset(connection_token)
        end_request_metrics(token)


def test_performance_payload_contains_wait_measurement_boundaries(monkeypatch):
    messages = []
    monkeypatch.setattr("app.core.performance.logger.info", messages.append)
    request = SimpleNamespace(method="POST", url=SimpleNamespace(path="/api/ha/agent/v1/heartbeat"), query_params={})
    response = SimpleNamespace(status_code=200)
    metrics = {
        "database_query_count": 0, "database_duration_ms": 0, "template_duration_ms": 0,
        "external_duration_ms": 0, "external_call_count": 0, "phases": [],
        "db_pool": {"checkout_wait_ms": None, "connection_hold_ms": 0, "checked_out": None, "pool_size": None, "overflow": None, "timeout_count": 0},
        "thread_pool": {"wait_ms": None, "capacity": 40, "borrowed": 0, "wait_measured": False},
        "external_calls": [],
    }
    from app.core.performance import log_request_metrics
    log_request_metrics(request=request, response=response, metrics=metrics, total_duration_ms=10)
    payload = json.loads(messages[0])
    assert payload["db_pool"]["checkout_wait_ms"] is None
    assert payload["thread_pool"]["wait_measured"] is False
