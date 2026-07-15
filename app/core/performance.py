"""Disabled-by-default, request-scoped performance diagnostics."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
import logging
import os
from time import perf_counter
from typing import Iterator


# Uvicorn configures this logger consistently in both packaged and local runs.
logger = logging.getLogger("uvicorn.error")
_request_metrics: ContextVar[dict | None] = ContextVar("request_performance_metrics", default=None)
_template_timing_installed = False


def begin_request_metrics():
    metrics = {
        "database_query_count": 0,
        "database_duration_ms": 0.0,
        "template_duration_ms": 0.0,
        "external_duration_ms": 0.0,
        "external_call_count": 0,
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
        "path": request.url.path,
        "query_keys": sorted(request.query_params.keys()),
        "status_code": response.status_code,
        "total_duration_ms": round(total_duration_ms, 2),
        "database_duration_ms": round(metrics["database_duration_ms"], 2),
        "database_query_count": metrics["database_query_count"],
        "template_duration_ms": round(metrics["template_duration_ms"], 2),
        "external_duration_ms": round(metrics["external_duration_ms"], 2),
        "external_call_count": metrics["external_call_count"],
        "process_rss_bytes": process_rss_bytes(),
    }
    logger.info(json.dumps(payload, separators=(",", ":")))
