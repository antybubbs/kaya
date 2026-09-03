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
