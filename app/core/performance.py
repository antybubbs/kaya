"""Disabled-by-default, request-scoped performance diagnostics."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
import logging
import os
import re
from urllib.parse import urlsplit
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from time import perf_counter
from typing import Iterator


# Uvicorn configures this logger consistently in both packaged and local runs.
logger = logging.getLogger("uvicorn.error")
_request_metrics: ContextVar[dict | None] = ContextVar("request_performance_metrics", default=None)
_template_timing_installed = False
MAX_SAMPLES = 300
_samples = deque(maxlen=MAX_SAMPLES)
_samples_lock = Lock()
_diagnostics_enabled = False
_diagnostics_enabled_at: str | None = None
_state_lock = Lock()


def diagnostics_enabled() -> bool:
    with _state_lock:
        return _diagnostics_enabled


def set_diagnostics_enabled(enabled: bool, *, enabled_at: str | None = None) -> None:
    global _diagnostics_enabled, _diagnostics_enabled_at
    with _state_lock:
        _diagnostics_enabled = bool(enabled)
        if enabled:
            _diagnostics_enabled_at = enabled_at or _diagnostics_enabled_at or datetime.now(timezone.utc).isoformat()
        else:
            _diagnostics_enabled_at = None
    if not enabled:
        clear_diagnostics()


def diagnostics_state() -> dict:
    with _state_lock:
        enabled, enabled_at = _diagnostics_enabled, _diagnostics_enabled_at
    with _samples_lock:
        count = len(_samples)
    return {"enabled": enabled, "enabled_at": enabled_at, "sample_count": count, "max_samples": MAX_SAMPLES}


def clear_diagnostics() -> None:
    with _samples_lock:
        _samples.clear()


def _safe_route(request) -> str:
    route = getattr(getattr(request, "scope", {}).get("route"), "path", None)
    path = str(route or urlsplit(str(request.url.path or "/")).path or "/")
    path = re.sub(r"/(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,})", "/{id}", path, flags=re.IGNORECASE)
    if len(path) > 300:
        path = path[:300]
    return path


def record_dashboard_widget(name: str, duration_ms: float) -> None:
    metrics = _request_metrics.get()
    if metrics is not None and len(metrics["dashboard_widgets"]) < 50:
        metrics["dashboard_widgets"].append({"name": str(name)[:80], "duration_ms": round(max(0.0, duration_ms), 2)})


def begin_request_metrics():
    metrics = {
        "database_query_count": 0,
        "database_duration_ms": 0.0,
        "template_duration_ms": 0.0,
        "external_duration_ms": 0.0,
        "external_call_count": 0,
        "dashboard_widgets": [],
    }
    return _request_metrics.set(metrics), metrics


def end_request_metrics(token) -> None:
    _request_metrics.reset(token)


def install_engine_timing(engine) -> None:
    """Install one SQLAlchemy listener pair; inactive requests pay almost no cost."""
    if getattr(engine, "_kaya_performance_timing", False):
        return
    from sqlalchemy import event

    @event.listens_for(engine, "before_cursor_execute")
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        if _request_metrics.get() is not None:
            context._kaya_query_started = perf_counter()

    @event.listens_for(engine, "after_cursor_execute")
    def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        metrics = _request_metrics.get()
        started = getattr(context, "_kaya_query_started", None)
        if metrics is not None and started is not None:
            metrics["database_query_count"] += 1
            metrics["database_duration_ms"] += (perf_counter() - started) * 1000

    engine._kaya_performance_timing = True


def install_template_timing() -> None:
    """Time all existing Jinja2Templates instances without changing route APIs."""
    global _template_timing_installed
    if _template_timing_installed:
        return
    from fastapi.templating import Jinja2Templates

    original = Jinja2Templates.TemplateResponse

    def timed_template_response(self, *args, **kwargs):
        metrics = _request_metrics.get()
        if metrics is None:
            return original(self, *args, **kwargs)
        started = perf_counter()
        try:
            return original(self, *args, **kwargs)
        finally:
            metrics["template_duration_ms"] += (perf_counter() - started) * 1000

    Jinja2Templates.TemplateResponse = timed_template_response
    _template_timing_installed = True


@contextmanager
def external_call() -> Iterator[None]:
    """Record bounded network work when it occurs inside an HTTP request."""
    metrics = _request_metrics.get()
    if metrics is None:
        yield
        return
    started = perf_counter()
    try:
        yield
    finally:
        metrics["external_call_count"] += 1
        metrics["external_duration_ms"] += (perf_counter() - started) * 1000


def process_rss_bytes() -> int | None:
    """Return resident memory where the host exposes it without another dependency."""
    try:
        with open("/proc/self/statm", encoding="ascii") as handle:
            resident_pages = int(handle.read().split()[1])
        return resident_pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError, AttributeError):
        return None


def log_request_metrics(*, request, response, metrics: dict, total_duration_ms: float) -> None:
    payload = {
        "event": "request_performance",
        "method": request.method,
        "path": _safe_route(request),
        "query_keys": sorted(request.query_params.keys()),
        "status_code": response.status_code,
        "total_duration_ms": round(total_duration_ms, 2),
        "database_duration_ms": round(metrics["database_duration_ms"], 2),
        "database_query_count": metrics["database_query_count"],
        "template_duration_ms": round(metrics["template_duration_ms"], 2),
        "external_duration_ms": round(metrics["external_duration_ms"], 2),
        "external_call_count": metrics["external_call_count"],
        "process_rss_bytes": process_rss_bytes(),
        "dashboard_widgets": metrics.get("dashboard_widgets", []),
    }
    logger.info(json.dumps(payload, separators=(",", ":")))
    if diagnostics_enabled() and not is_internal_diagnostics_path(request.url.path):
        sample = {key: payload[key] for key in payload if key not in {"event", "query_keys"}}
        sample["timestamp"] = datetime.now(timezone.utc).isoformat()
        with _samples_lock:
            _samples.append(sample)


def is_internal_diagnostics_path(path: str) -> bool:
    return path == "/system/about/performance" or path.startswith("/api/system/about/performance")


def diagnostics_snapshot() -> dict:
    with _samples_lock:
        samples = list(_samples)
    durations = [float(item["total_duration_ms"]) for item in samples]
    sql_durations = [float(item["database_duration_ms"]) for item in samples]
    external_durations = [float(item["external_duration_ms"]) for item in samples if item["external_call_count"]]
    def percentile(values: list[float], fraction: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        index = (len(ordered) - 1) * fraction
        lower, upper = int(index), min(int(index) + 1, len(ordered) - 1)
        return round(ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower), 2)
    summary = {
        "average_request_duration_ms": round(sum(durations) / len(durations), 2) if durations else None,
        "p95_request_duration_ms": percentile(durations, 0.95),
        "slowest_request_duration_ms": max(durations) if durations else None,
        "average_sql_duration_ms": round(sum(sql_durations) / len(sql_durations), 2) if sql_durations else None,
        "highest_sql_query_count": max((item["database_query_count"] for item in samples), default=0),
        "average_external_duration_ms": round(sum(external_durations) / len(external_durations), 2) if external_durations else None,
    }
    return {"state": diagnostics_state(), "summary": summary, "samples": list(reversed(samples))}
