"""Disabled-by-default, request-scoped performance diagnostics."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
import logging
import os
import re
import time
from urllib.parse import urlsplit
from collections import deque
from datetime import datetime, timezone
from threading import Event, Lock, Thread
from time import perf_counter
from typing import Iterator
from uuid import uuid4


# Uvicorn configures this logger consistently in both packaged and local runs.
logger = logging.getLogger("uvicorn.error")
_request_metrics: ContextVar[dict | None] = ContextVar("request_performance_metrics", default=None)
_request_connection_count: ContextVar[int] = ContextVar("request_connection_count", default=0)
_template_timing_installed = False
MAX_SAMPLES = 300
_samples = deque(maxlen=MAX_SAMPLES)
_samples_lock = Lock()
_diagnostics_enabled = False
_diagnostics_enabled_at: str | None = None
_state_lock = Lock()
_capture: dict | None = None
_completed_captures: list[dict] = []
_capture_lock = Lock()
CAPTURE_DURATIONS = (15, 30, 60)
CAPTURE_MAX_EVENTS = 500
CAPTURE_MAX_COMPLETED = 4
CAPTURE_RETENTION_SECONDS = 900
CAPTURE_COLLECTORS = {
    "http",
    "postgresql",
    "ha",
    "background",
    "resources",
    "browser",
}


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
        clear_capture()


def diagnostics_state() -> dict:
    with _state_lock:
        enabled, enabled_at = _diagnostics_enabled, _diagnostics_enabled_at
    with _samples_lock:
        count = len(_samples)
    return {"enabled": enabled, "enabled_at": enabled_at, "sample_count": count, "max_samples": MAX_SAMPLES}


def clear_diagnostics() -> None:
    with _samples_lock:
        _samples.clear()


def clear_capture() -> None:
    global _capture
    with _capture_lock:
        if _capture is not None:
            _capture["stop_event"].set()
        _capture = None
        _completed_captures.clear()


def _prune_completed_locked(now: float | None = None) -> None:
    current = now or time.monotonic()
    _completed_captures[:] = [
        capture for capture in _completed_captures
        if current < capture["retention_expires_monotonic"]
    ][-CAPTURE_MAX_COMPLETED:]


def _retain_completed_locked(capture: dict) -> None:
    _prune_completed_locked()
    _completed_captures.append(capture)
    _completed_captures[:] = _completed_captures[-CAPTURE_MAX_COMPLETED:]


def _expire_capture_locked(now: float | None = None) -> None:
    global _capture
    current = now or time.monotonic()
    _prune_completed_locked(current)
    if _capture is not None and current >= _capture["expires_monotonic"]:
        _capture["status"] = "completed"
        _capture["ended_at"] = datetime.now(timezone.utc).isoformat()
        _capture["retention_expires_monotonic"] = current + CAPTURE_RETENTION_SECONDS
        _capture["stop_event"].set()
        _retain_completed_locked(_capture)
        _capture = None


def start_capture(*, owner_session_id: str, duration: int, collectors: list[str]) -> dict:
    global _capture
    if not owner_session_id:
        raise ValueError("A session-scoped capture owner is required")
    if duration not in CAPTURE_DURATIONS:
        raise ValueError("Unsupported capture duration")
    selected = sorted(set(collectors) & CAPTURE_COLLECTORS)
    if not selected:
        raise ValueError("At least one collector is required")
    with _capture_lock:
        _expire_capture_locked()
        if _capture is not None and _capture["status"] == "running":
            raise RuntimeError("A diagnostic capture is already active")
        started_at = datetime.now(timezone.utc).isoformat()
        capture_id = uuid4().hex
        stop_event = Event()
        _capture = {
            "capture_id": capture_id,
            "owner_session_id": owner_session_id,
            "started_at": started_at,
            "expires_monotonic": time.monotonic() + duration,
            "duration_seconds": duration,
            "collectors": selected,
            "status": "running",
            "ended_at": None,
            "events": deque(maxlen=CAPTURE_MAX_EVENTS),
            "postgresql_samples": deque(maxlen=12),
            "collector_errors": {},
            "stop_event": stop_event,
            "retention_expires_monotonic": None,
        }
        result = _capture_status_locked(owner_session_id)
    if "postgresql" in selected:
        Thread(target=_run_postgres_capture, args=(capture_id, duration, stop_event), name="kaya-pg-diagnostic", daemon=True).start()
    return result


def _capture_status_locked(owner_session_id: str) -> dict:
    _expire_capture_locked()
    capture = _capture if _capture is not None and _capture["owner_session_id"] == owner_session_id else None
    owner_captures = [item for item in _completed_captures if item["owner_session_id"] == owner_session_id]
    if capture is None:
        capture = owner_captures[-1] if owner_captures else None
    if capture is None:
        return {"active": False, "status": "unavailable", "reason": "No completed capture is retained in this Kaya process. It may have expired, been discarded, or been lost during an application restart."}
    active = capture["status"] == "running"
    remaining = max(0, round(capture["expires_monotonic"] - time.monotonic(), 2)) if active else 0
    retention_remaining = max(0, round(capture["retention_expires_monotonic"] - time.monotonic(), 2)) if not active and capture.get("retention_expires_monotonic") else None
    result = {
        "active": active,
        "status": capture["status"],
        "capture_id": capture["capture_id"],
        "started_at": capture["started_at"],
        "duration_seconds": capture["duration_seconds"],
        "remaining_seconds": remaining,
        "retention_remaining_seconds": retention_remaining,
        "collectors": list(capture["collectors"]),
        "event_count": len(capture["events"]),
    }
    if active and owner_captures:
        result["completed_available"] = True
        result["completed_capture_id"] = owner_captures[-1]["capture_id"]
    return result


def capture_status(owner_session_id: str) -> dict:
    with _capture_lock:
        return _capture_status_locked(owner_session_id)


def stop_capture(owner_session_id: str) -> dict:
    global _capture
    with _capture_lock:
        _expire_capture_locked()
        if _capture is None or _capture["owner_session_id"] != owner_session_id:
            return {"active": False, "status": "idle"}
        _capture["status"] = "stopped"
        _capture["ended_at"] = datetime.now(timezone.utc).isoformat()
        _capture["stop_event"].set()
        _capture["retention_expires_monotonic"] = time.monotonic() + CAPTURE_RETENTION_SECONDS
        _capture["status"] = "stopped"
        _retain_completed_locked(_capture)
        result = _capture_status_locked(owner_session_id)
        result["active"] = False
        result["status"] = "stopped"
        _capture = None
        return result


def discard_completed_captures(owner_session_id: str) -> bool:
    with _capture_lock:
        _prune_completed_locked()
        before = len(_completed_captures)
        _completed_captures[:] = [
            capture for capture in _completed_captures
            if capture["owner_session_id"] != owner_session_id
        ]
        return len(_completed_captures) != before


def add_capture_events(owner_session_id: str, events: list[dict]) -> dict:
    with _capture_lock:
        _expire_capture_locked()
        if _capture is None or _capture["owner_session_id"] != owner_session_id or _capture["status"] != "running":
            return {"accepted": 0, "active": False}
        accepted = 0
        for event in events[:100]:
            if not isinstance(event, dict):
                continue
            name = str(event.get("name") or "")[:40]
            if name not in {"navigation", "api", "resource", "browser_error"}:
                continue
            item = {"name": name, "captured_at": datetime.now(timezone.utc).isoformat()}
            for key in ("duration_ms", "dom_content_loaded_ms", "load_ms", "error_count"):
                value = event.get(key)
                if isinstance(value, (int, float)) and 0 <= value <= 600000:
                    item[key] = round(float(value), 2)
            item["route"] = _safe_browser_route(event.get("route"))
            _capture["events"].append(item)
            accepted += 1
        return {"accepted": accepted, "active": True}


def _append_postgres_sample(capture_id: str, sample: dict) -> None:
    with _capture_lock:
        if _capture is None or _capture["capture_id"] != capture_id or _capture["status"] != "running":
            return
        _capture["postgresql_samples"].append(json.loads(json.dumps(sample, default=str)))


def _run_postgres_capture(capture_id: str, duration: int, stop_event: Event) -> None:
    try:
        from app.core.config import get_settings
        from scripts.collect_pg_diagnostics import collect

        database_url = get_settings().database_url
        if not database_url.startswith("postgresql"):
            raise RuntimeError("PostgreSQL is not the active database")
        collect(
            database_url,
            seconds=duration,
            interval=min(5, max(1, duration // 6)),
            stop_event=stop_event,
            on_sample=lambda sample: _append_postgres_sample(capture_id, sample),
        )
    except Exception as exc:
        with _capture_lock:
            if _capture is not None and _capture["capture_id"] == capture_id:
                _capture["collector_errors"]["postgresql"] = type(exc).__name__


def _background_snapshot() -> dict:
    snapshot = {}
    try:
        from app.services.network_monitor import monitor_scheduler_diagnostics
        snapshot["uptime_network_monitor"] = monitor_scheduler_diagnostics()
    except Exception as exc:
        snapshot["uptime_network_monitor"] = {"available": False, "error": type(exc).__name__}
    try:
        from app.services.network_traffic_poller import polling_diagnostics
        snapshot["traffic_collection"] = polling_diagnostics()
    except Exception as exc:
        snapshot["traffic_collection"] = {"available": False, "error": type(exc).__name__}
    try:
        from app.services.notification_runtime import notification_worker_snapshot
        snapshot["notification_outbox"] = notification_worker_snapshot()
    except Exception as exc:
        snapshot["notification_outbox"] = {"available": False, "error": type(exc).__name__}
    return json.loads(json.dumps(snapshot, default=str))


def capture_bundle(owner_session_id: str) -> dict | None:
    with _capture_lock:
        _expire_capture_locked()
        owner_captures = [item for item in _completed_captures if item["owner_session_id"] == owner_session_id]
        capture = owner_captures[-1] if owner_captures else None
        if capture is None:
            return None
        status = {
            "capture_id": capture["capture_id"],
            "started_at": capture["started_at"],
        }
        events = list(capture["events"])
        selected = set(capture["collectors"])
        background = _background_snapshot() if "background" in selected else None
        statuses = {
            "http": {"available": "http" in selected, "source": "request instrumentation"},
            "postgresql": ({"available": True, "source": "dedicated read-only diagnostic connection", "sample_count": len(capture["postgresql_samples"])} if capture["postgresql_samples"] else {"available": False, "reason": capture["collector_errors"].get("postgresql", "No PostgreSQL samples were collected.")}),
            "ha": {"available": "ha" in selected, "source": "request phase instrumentation"},
            "background": {"available": background is not None, "source": "existing in-process worker snapshots"},
            "resources": {"available": "resources" in selected, "source": "request resource snapshots"},
            "browser": {"available": any(item["name"] != "request" for item in events), "source": "capture-session browser events"},
        }
        return {
            "schema_version": 1,
            "capture_id": status["capture_id"],
            "capture_start": status["started_at"],
            "capture_end": capture.get("ended_at") or datetime.now(timezone.utc).isoformat(),
            "enabled_collectors": list(capture["collectors"]),
            "collector_status": {name: statuses[name] for name in capture["collectors"]},
            "http": {"events": [item for item in events if item["name"] == "request"]},
            "resources": {"events": [item for item in events if item["name"] == "request" and "process_rss_bytes" in item]},
            "ha": {"events": [item for item in events if item["name"] == "request" and "/ha/" in item.get("route", "")]},
            "browser": {"events": [item for item in events if item["name"] != "request"]},
            "postgresql": {"samples": list(capture["postgresql_samples"]), "error": capture["collector_errors"].get("postgresql")},
            "background": background or {},
            "timeline": sorted(events, key=lambda item: item["captured_at"]),
        }


def _safe_route(request) -> str:
    route = getattr(getattr(request, "scope", {}).get("route"), "path", None)
    path = str(route or urlsplit(str(request.url.path or "/")).path or "/")
    path = re.sub(r"/(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,})", "/{id}", path, flags=re.IGNORECASE)
    if len(path) > 300:
        path = path[:300]
    return path


def _safe_browser_route(value) -> str:
    raw = str(value or "")
    if not raw.startswith("/"):
        return "unknown"
    path = urlsplit(raw).path or "/"
    return re.sub(r"/(?:[0-9]+|[0-9a-f]{8}-[0-9a-f-]{27,})", "/{id}", path, flags=re.IGNORECASE)[:300]


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
        "phases": [],
        "db_pool": {
            "checkout_wait_ms": None,
            "connection_hold_ms": 0.0,
            "checked_out": None,
            "pool_size": None,
            "overflow": None,
            "timeout_count": 0,
            "checkout_count": 0,
            "checkin_count": 0,
            "connection_held_during_external_io": False,
        },
        "thread_pool": {
            "wait_ms": None,
            "capacity": None,
            "borrowed": None,
            "wait_measured": False,
        },
    }
    return _request_metrics.set(metrics), metrics


def capture_thread_pool_state(metrics: dict) -> None:
    """Capture the public AnyIO limiter state without touching dispatch internals.

    AnyIO does not expose the queue wait incurred by Starlette's route wrapper.
    Keep that field unavailable rather than claiming the handler duration is
    token wait time.
    """
    try:
        import anyio.to_thread

        limiter = anyio.to_thread.current_default_thread_limiter()
        metrics["thread_pool"].update({
            "capacity": int(limiter.total_tokens),
            "borrowed": int(limiter.borrowed_tokens),
        })
    except (AttributeError, RuntimeError, TypeError, ValueError):
        pass


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

    @event.listens_for(engine, "checkout")
    def checkout(dbapi_connection, connection_record, connection_proxy):
        metrics = _request_metrics.get()
        if metrics is None:
            return
        pool = engine.pool
        pool_metrics = metrics["db_pool"]
        connection_record.info["kaya_checkout_started"] = perf_counter()
        pool_metrics["checkout_count"] += 1
        _request_connection_count.set(_request_connection_count.get() + 1)
        pool_metrics["checked_out"] = _pool_value(pool, "checkedout")
        pool_metrics["pool_size"] = _pool_value(pool, "size")
        pool_metrics["overflow"] = _pool_value(pool, "overflow")

    @event.listens_for(engine, "checkin")
    def checkin(dbapi_connection, connection_record):
        metrics = _request_metrics.get()
        started = connection_record.info.pop("kaya_checkout_started", None)
        if metrics is None:
            return
        pool_metrics = metrics["db_pool"]
        if started is not None:
            pool_metrics["connection_hold_ms"] += (perf_counter() - started) * 1000
        _request_connection_count.set(max(0, _request_connection_count.get() - 1))
        pool_metrics["checkin_count"] += 1
        pool = engine.pool
        pool_metrics["checked_out"] = _pool_value(pool, "checkedout")
        pool_metrics["pool_size"] = _pool_value(pool, "size")
        pool_metrics["overflow"] = _pool_value(pool, "overflow")

    engine._kaya_performance_timing = True


def _pool_value(pool, method: str):
    try:
        value = getattr(pool, method)()
        return int(value) if value is not None else None
    except (AttributeError, TypeError, ValueError):
        return None


@contextmanager
def performance_phase(name: str) -> Iterator[None]:
    metrics = _request_metrics.get()
    if metrics is None:
        yield
        return
    started = perf_counter()
    try:
        yield
    finally:
        metrics["phases"].append({
            "phase_name": str(name)[:100],
            "duration_ms": round((perf_counter() - started) * 1000, 2),
            "executed": True,
        })

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
def external_call(operation: str = "external") -> Iterator[None]:
    """Record bounded network work when it occurs inside an HTTP request."""
    metrics = _request_metrics.get()
    if metrics is None:
        yield
        return
    started = perf_counter()
    pool_metrics = metrics.get("db_pool", {})
    connection_held = _request_connection_count.get() > 0
    if connection_held:
        pool_metrics["connection_held_during_external_io"] = True
    call = {"operation": str(operation)[:100], "db_connection_held": connection_held, "timeout": False}
    metrics.setdefault("external_calls", []).append(call)
    succeeded = False
    try:
        yield
        succeeded = True
    except BaseException as exc:
        call["timeout"] = isinstance(exc, TimeoutError) or "timed out" in str(exc).lower()
        raise
    finally:
        metrics["external_call_count"] += 1
        metrics["external_duration_ms"] += (perf_counter() - started) * 1000
        call.update({"duration_ms": round((perf_counter() - started) * 1000, 2), "success": succeeded})


def process_rss_bytes() -> int | None:
    """Return resident memory where the host exposes it without another dependency."""
    try:
        with open("/proc/self/statm", encoding="ascii") as handle:
            resident_pages = int(handle.read().split()[1])
        return resident_pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError, AttributeError):
        return None


def log_request_metrics(*, request, response, metrics: dict, total_duration_ms: float) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
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
        "phases": metrics.get("phases", []),
        "db_pool": metrics.get("db_pool", {}),
        "thread_pool": metrics.get("thread_pool", {}),
        "external_calls": metrics.get("external_calls", []),
        "request_id": str(getattr(getattr(request, "state", None), "request_id", ""))[:64],
        "timestamp": timestamp,
    }
    logger.info(json.dumps(payload, separators=(",", ":")))
    if diagnostics_enabled() and not is_internal_diagnostics_path(request.url.path):
        sample = {key: payload[key] for key in payload if key not in {"event", "query_keys"}}
        sample["timestamp"] = timestamp
        with _samples_lock:
            _samples.append(sample)
    with _capture_lock:
        _expire_capture_locked()
        if _capture is not None and {"http", "ha", "resources"}.intersection(_capture["collectors"]):
            _capture["events"].append({
                "name": "request",
                "captured_at": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                "request_id": payload["request_id"],
                "route": payload["path"],
                "method": payload["method"],
                "status_code": payload["status_code"],
                "duration_ms": payload["total_duration_ms"],
                "database_duration_ms": payload["database_duration_ms"],
                "database_query_count": payload["database_query_count"],
                "process_rss_bytes": payload["process_rss_bytes"],
                "phases": payload["phases"][:50],
                "db_pool": payload["db_pool"],
                "thread_pool": payload["thread_pool"],
            })


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
