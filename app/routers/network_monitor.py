import csv
import io
import math
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func
from sqlalchemy.orm import Session, selectinload
from starlette import status

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import NetworkMonitor, NetworkMonitorCheck, NetworkMonitorEvent, NetworkMonitorOutage, NetworkMonitorStatistic, RemoteAccess
from app.routers.auth import require_editor, require_module_access, require_user
from app.services.audit import write_audit
from app.services.network_monitor import (
    DASHBOARD_INTERVALS, active_dashboard_interval, effective_monitor_thresholds,
    monitor_label, run_monitor_check_by_id, set_dashboard_interval_override,
    validate_monitor_timing, validate_threshold_values,
)

router = APIRouter(prefix="/networking/ip-wan-monitor", dependencies=[Depends(require_module_access("network_monitor"))])
templates = Jinja2Templates(directory="app/templates")
RANGES = {
    "1h": timedelta(hours=1), "6h": timedelta(hours=6), "24h": timedelta(hours=24),
    "7d": timedelta(days=7), "30d": timedelta(days=30), "90d": timedelta(days=90),
    "1y": timedelta(days=365),
}


def monitor_state(monitor: NetworkMonitor) -> str:
    if not monitor.is_enabled:
        return "paused"
    return {"up": "healthy", "down": "offline", "pending": "unknown"}.get(
        monitor.last_status, monitor.last_status or "unknown"
    )


def monitor_rows(db: Session) -> tuple[list[dict], int, int, int, int]:
    monitors = db.query(NetworkMonitor).options(selectinload(NetworkMonitor.ip_address)).order_by(NetworkMonitor.display_name.asc(), NetworkMonitor.id.asc()).all()
    since = datetime.utcnow() - timedelta(hours=24)
    monitor_ids = [monitor.id for monitor in monitors]
    stats = {}
    recent_by_monitor = {monitor_id: [] for monitor_id in monitor_ids}
    if monitor_ids:
        stats = {
            monitor_id: (total or 0, up or 0, average_latency)
            for monitor_id, total, up, average_latency in db.query(
                NetworkMonitorCheck.monitor_id,
                func.count(NetworkMonitorCheck.id),
                func.sum(case((NetworkMonitorCheck.status == "up", 1), else_=0)),
                func.avg(NetworkMonitorCheck.latency_ms),
            ).filter(
                NetworkMonitorCheck.monitor_id.in_(monitor_ids),
                NetworkMonitorCheck.checked_at >= since,
            ).group_by(NetworkMonitorCheck.monitor_id).all()
        }
        recent_rank = func.row_number().over(
            partition_by=NetworkMonitorCheck.monitor_id,
            order_by=NetworkMonitorCheck.checked_at.desc(),
        ).label("recent_rank")
        recent_subquery = db.query(NetworkMonitorCheck.id.label("check_id"), recent_rank).filter(
            NetworkMonitorCheck.monitor_id.in_(monitor_ids),
            NetworkMonitorCheck.checked_at >= datetime.utcnow() - timedelta(minutes=5),
        ).subquery()
        recent_checks = db.query(NetworkMonitorCheck).join(
            recent_subquery,
            NetworkMonitorCheck.id == recent_subquery.c.check_id,
        ).filter(
            recent_subquery.c.recent_rank <= 120,
        ).order_by(NetworkMonitorCheck.monitor_id.asc(), NetworkMonitorCheck.checked_at.asc()).all()
        for check in recent_checks:
            recent_by_monitor.setdefault(check.monitor_id, []).append(check)
    rows = []
    up_count = 0
    down_count = 0
    warning_count = 0
    for monitor in monitors:
        thresholds = effective_monitor_thresholds(db, monitor)
        state = monitor_state(monitor)
        total_checks, total_up, average_latency = stats.get(monitor.id, (0, 0, None))
        if state == "healthy":
            up_count += 1
        if state == "offline":
            down_count += 1
        if state in {"warning", "critical", "recovering"}:
            warning_count += 1
        history = recent_by_monitor.get(monitor.id, [])
        rows.append({
            "monitor": monitor,
            "state": state,
            "label": monitor_label(monitor),
            "history": history,
            "thresholds": thresholds,
            "chart_points": [{
                "id": check.id, "at": check.checked_at.isoformat() + "Z",
                "latency": check.latency_ms, "loss": check.packet_loss_percent,
                "status": check.health_state or point_health(thresholds, check.latency_ms, check.packet_loss_percent, check.status == "up"),
            } for check in history],
            "uptime": round((total_up / total_checks) * 100, 1) if total_checks else None,
            "average_latency": round(average_latency) if average_latency is not None else None,
        })
    return rows, len(monitors), up_count, down_count, warning_count


def dashboard_context(db: Session) -> dict:
    rows, total, up_count, down_count, warning_count = monitor_rows(db)
    dashboard_interval = active_dashboard_interval()
    for row in rows:
        row["effective_interval"] = dashboard_interval or row["monitor"].interval_seconds
    since = datetime.utcnow() - timedelta(hours=24)
    total_checks, up_checks, avg_latency = db.query(
        func.count(NetworkMonitorCheck.id),
        func.sum(case((NetworkMonitorCheck.status == "up", 1), else_=0)),
        func.avg(NetworkMonitorCheck.latency_ms),
    ).filter(NetworkMonitorCheck.checked_at >= since).one()
    return {
        "rows": rows, "total": total, "up_count": up_count, "down_count": down_count,
        "warning_count": warning_count, "average_latency": round(avg_latency) if avg_latency is not None else None,
        "availability_24h": round((up_checks / total_checks) * 100, 2) if total_checks else None,
        "checks_per_minute": round(sum(60 / max(row["effective_interval"], 5) for row in rows if row["monitor"].is_enabled), 1),
        "dashboard_interval": dashboard_interval,
        "latest_observation_id": db.query(func.max(NetworkMonitorCheck.id)).scalar() or 0,
    }


def range_start(value: str) -> datetime:
    duration = RANGES.get(value)
    if duration is None:
        raise HTTPException(status_code=400, detail="Unsupported monitoring range")
    return datetime.utcnow() - duration


def percentile(values: list[int], quantile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * quantile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower))


def point_health(thresholds: dict, latency: int | None, loss: int | None, is_up: bool) -> str:
    if not is_up:
        return "offline"
    if (loss is not None and loss >= thresholds["packet_loss_critical_percent"]) or (latency is not None and latency >= thresholds["latency_critical_ms"]):
        return "critical"
    if (loss is not None and loss >= thresholds["packet_loss_warning_percent"]) or (latency is not None and latency >= thresholds["latency_warning_ms"]):
        return "warning"
    return "healthy"


def display_points(points: list[dict], selected_range: str) -> list[dict]:
    bucket_seconds = {"7d": 300, "30d": 3600, "90d": 86400, "1y": 86400}.get(selected_range)
    if not bucket_seconds:
        return points
    buckets: dict[datetime, list[dict]] = {}
    for point in points:
        epoch = int(point["at"].timestamp())
        bucket = datetime.utcfromtimestamp(epoch - (epoch % bucket_seconds))
        buckets.setdefault(bucket, []).append(point)
    result = []
    state_priority = {"unknown": 0, "healthy": 1, "maintenance": 2, "paused": 2, "recovering": 3, "warning": 4, "critical": 5, "offline": 6}
    for bucket, rows in sorted(buckets.items()):
        sample_count = sum(row["samples"] for row in rows)
        latency_rows = [row for row in rows if row["latency"] is not None]
        loss_rows = [row for row in rows if row["loss"] is not None]
        result.append({
            "at": bucket,
            "latency": round(sum(row["latency"] * row["samples"] for row in latency_rows) / sum(row["samples"] for row in latency_rows)) if latency_rows else None,
            "loss": round(sum(row["loss"] * row["samples"] for row in loss_rows) / sum(row["samples"] for row in loss_rows)) if loss_rows else None,
            "samples": sample_count,
            "up_count": sum(row["up_count"] for row in rows),
            "state": max((row.get("state") for row in rows if row.get("state")), key=lambda state: state_priority.get(state, 0), default=None),
        })
    return result


def monitor_detail_context(db: Session, monitor: NetworkMonitor, selected_range: str = "24h") -> dict:
    thresholds = effective_monitor_thresholds(db, monitor)
    start = range_start(selected_range)
    checks = db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.monitor_id == monitor.id, NetworkMonitorCheck.checked_at >= start).order_by(NetworkMonitorCheck.checked_at.asc()).all()
    statistics = db.query(NetworkMonitorStatistic).filter(NetworkMonitorStatistic.monitor_id == monitor.id, NetworkMonitorStatistic.bucket_start >= start).order_by(NetworkMonitorStatistic.bucket_start.asc()).all()
    history = list(reversed(checks[-100:]))
    events = db.query(NetworkMonitorEvent).filter(NetworkMonitorEvent.monitor_id == monitor.id, NetworkMonitorEvent.occurred_at >= start).order_by(NetworkMonitorEvent.occurred_at.desc()).limit(100).all()
    outages = db.query(NetworkMonitorOutage).filter(
        NetworkMonitorOutage.monitor_id == monitor.id,
        (NetworkMonitorOutage.ended_at.is_(None)) | (NetworkMonitorOutage.ended_at >= start),
    ).order_by(NetworkMonitorOutage.started_at.desc()).all()
    latest_incident = db.query(NetworkMonitorOutage).filter(NetworkMonitorOutage.monitor_id == monitor.id).order_by(NetworkMonitorOutage.started_at.desc()).first()
    sample_count = len(checks) + sum(row.sample_count for row in statistics)
    up_count = sum(1 for row in checks if row.status == "up") + sum(row.up_count for row in statistics)
    latencies = [row.latency_ms for row in checks if row.latency_ms is not None]
    statistic_latency_samples = [row for row in statistics if row.avg_latency_ms is not None and row.sample_count]
    latency_total = sum(latencies) + sum(row.avg_latency_ms * row.sample_count for row in statistic_latency_samples)
    latency_count = len(latencies) + sum(row.sample_count for row in statistic_latency_samples)
    graph_points = [{"at": row.checked_at, "latency": row.latency_ms, "loss": row.packet_loss_percent, "samples": 1, "up_count": 1 if row.status == "up" else 0, "state": row.health_state} for row in checks]
    graph_points += [{"at": row.bucket_start, "latency": row.avg_latency_ms, "loss": row.avg_packet_loss_percent, "samples": row.sample_count, "up_count": row.up_count, "state": row.health_state} for row in statistics]
    graph_points.sort(key=lambda row: row["at"])
    graph_points = display_points(graph_points, selected_range)
    for point in graph_points:
        point["status"] = point.get("state") or point_health(thresholds, point["latency"], point["loss"], point["up_count"] == point["samples"])
        point["at"] = point["at"].isoformat() + "Z"
    chart_latencies = [row["latency"] for row in graph_points if row["latency"] is not None]
    jitter_values = [abs(current - previous) for previous, current in zip(chart_latencies, chart_latencies[1:])]
    weighted_loss_count = sum(row.sample_count for row in statistics if row.avg_packet_loss_percent is not None) + sum(1 for row in checks if row.packet_loss_percent is not None)
    weighted_loss_total = sum((row.avg_packet_loss_percent or 0) * row.sample_count for row in statistics if row.avg_packet_loss_percent is not None) + sum(row.packet_loss_percent or 0 for row in checks if row.packet_loss_percent is not None)
    failed_checks = sample_count - up_count
    downtime_seconds = sum((row.sample_count - row.up_count) * row.bucket_seconds for row in statistics) + sum(monitor.interval_seconds for row in checks if row.status != "up")
    incident_durations = [((row.ended_at or datetime.utcnow()) - row.started_at).total_seconds() for row in outages]
    incident_rows = [{
        "incident": row,
        "duration_seconds": round(((row.ended_at or datetime.utcnow()) - row.started_at).total_seconds()),
        "failed_checks": sum(1 for check in checks if check.status != "up" and check.checked_at >= row.started_at and (row.ended_at is None or check.checked_at <= row.ended_at)),
        "peak_latency": max((check.latency_ms for check in checks if check.latency_ms is not None and check.checked_at >= row.started_at and (row.ended_at is None or check.checked_at <= row.ended_at)), default=None),
    } for row in outages]
    chart_payload = {
        "points": graph_points,
        "incidents": [{"id": row.id, "start": row.started_at.isoformat() + "Z", "end": row.ended_at.isoformat() + "Z" if row.ended_at else None} for row in outages],
        "thresholds": {"warning": thresholds["latency_warning_ms"], "critical": thresholds["latency_critical_ms"]},
    }
    return {
        "monitor": monitor, "selected_range": selected_range, "checks": history, "events": events,
        "current_state": monitor_state(monitor),
        "outages": outages, "incident_rows": incident_rows, "graph_points": graph_points, "chart_payload": chart_payload,
        "sample_count": sample_count, "availability": round((up_count / sample_count) * 100, 2) if sample_count else None,
        "average_latency": round(latency_total / latency_count) if latency_count else None,
        "median_latency": percentile(chart_latencies, .5), "minimum_latency": min(chart_latencies, default=None),
        "maximum_latency": max(chart_latencies, default=None), "p95_latency": percentile(chart_latencies, .95),
        "p99_latency": percentile(chart_latencies, .99), "average_jitter": round(sum(jitter_values) / len(jitter_values)) if jitter_values else None,
        "average_packet_loss": round(weighted_loss_total / weighted_loss_count, 1) if weighted_loss_count else None,
        "successful_checks": up_count, "failed_checks": failed_checks, "downtime_seconds": round(downtime_seconds),
        "average_recovery_seconds": round(sum(incident_durations) / len(incident_durations)) if incident_durations else None,
        "last_incident": latest_incident,
        "thresholds": thresholds,
        "outage_count": len(outages),
    }


@router.get("")
def network_monitor(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    return templates.TemplateResponse(request, "network_monitor.html", {
        "user": user,
        **dashboard_context(db),
        **csrf_context(request),
    })


@router.get("/cards")
def network_monitor_cards(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    return templates.TemplateResponse(request, "_network_monitor_cards.html", {
        "user": user,
        **dashboard_context(db),
        **csrf_context(request),
    })


@router.get("/live")
def live_dashboard_observations(after: int = Query(0, ge=0), db: Session = Depends(get_db), user=Depends(require_user)):
    checks = db.query(NetworkMonitorCheck).filter(
        NetworkMonitorCheck.id > after,
        NetworkMonitorCheck.checked_at >= datetime.utcnow() - timedelta(minutes=5),
    ).order_by(NetworkMonitorCheck.id.asc()).limit(1000).all()
    monitor_ids = {check.monitor_id for check in checks}
    monitors = {row.id: row for row in db.query(NetworkMonitor).filter(NetworkMonitor.id.in_(monitor_ids)).all()} if monitor_ids else {}
    context = dashboard_context(db)
    open_incidents = {
        row.monitor_id: row for row in db.query(NetworkMonitorOutage).filter(NetworkMonitorOutage.ended_at.is_(None)).all()
    }
    observations = []
    previous_latency: dict[int, int | None] = {}
    for check in checks:
        monitor = monitors.get(check.monitor_id)
        if not monitor:
            continue
        thresholds = effective_monitor_thresholds(db, monitor)
        prior = previous_latency.get(check.monitor_id)
        jitter = abs(check.latency_ms - prior) if check.latency_ms is not None and prior is not None else None
        observations.append({
            "id": check.id, "monitor_id": check.monitor_id,
            "checked_at": check.checked_at.isoformat() + "Z",
            "status": check.health_state or point_health(thresholds, check.latency_ms, check.packet_loss_percent, check.status == "up"),
            "latency_ms": check.latency_ms, "packet_loss_percent": check.packet_loss_percent,
            "jitter_ms": jitter,
        })
        previous_latency[check.monitor_id] = check.latency_ms
    return JSONResponse({
        "observations": observations,
        "monitors": [{
            "id": row["monitor"].id, "enabled": row["monitor"].is_enabled,
            "status": row["state"], "latency_ms": row["monitor"].last_latency_ms,
            "state_reason": row["monitor"].state_reason,
            "consecutive_successes": row["monitor"].consecutive_successes,
            "recovery_threshold": row["thresholds"]["recovery_threshold"],
            "average_latency_ms": row["average_latency"], "availability": row["uptime"],
            "last_checked_at": row["monitor"].last_checked_at.isoformat() + "Z" if row["monitor"].last_checked_at else None,
            "interval_seconds": row["effective_interval"],
            "incident_started_at": open_incidents[row["monitor"].id].started_at.isoformat() + "Z" if row["monitor"].id in open_incidents else None,
        } for row in context["rows"]],
        "summary": {key: context[key] for key in ("up_count", "down_count", "warning_count", "average_latency", "availability_24h", "checks_per_minute")},
        "has_more": len(checks) == 1000,
    })


@router.post("/collection-rate")
def set_collection_rate(
    request: Request,
    mode: str = Form(..., max_length=20),
    client_id: str = Form(..., min_length=1, max_length=80, pattern=r"^[A-Za-z0-9-]+$"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    if mode not in {*DASHBOARD_INTERVALS, "paused"}:
        raise HTTPException(status_code=400, detail="Unsupported collection rate")
    changed = set_dashboard_interval_override(client_id, mode)
    if changed:
        interval = DASHBOARD_INTERVALS.get(mode)
        detail = f"Dashboard backend interval set to {interval} seconds" if interval else "Dashboard backend interval override released"
        write_audit(db, user, "update", "network_monitor_collection_rate", None, request.client.host if request.client else None, detail=detail)
    return JSONResponse({"ok": True, "mode": mode, "effective_interval_seconds": active_dashboard_interval()})


@router.post("/{monitor_id}/refresh")
def refresh_monitor(request: Request, monitor_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor or not monitor.is_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")
    run_monitor_check_by_id(monitor.id)
    write_audit(db, user, "check_now", "network_monitor", str(monitor.id), request.client.host if request.client else None, detail="Manual monitor check requested")
    if request.headers.get("x-requested-with") == "fetch":
        return JSONResponse({"ok": True})
    return RedirectResponse(f"/networking/ip-wan-monitor/{monitor.id}", status_code=303)


@router.get("/{monitor_id}")
def monitor_detail(request: Request, monitor_id: int, range: str = Query("24h", max_length=8), db: Session = Depends(get_db), user=Depends(require_user)):
    monitor = db.query(NetworkMonitor).options(selectinload(NetworkMonitor.ip_address)).filter(NetworkMonitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    accessible_modules = getattr(user, "_accessible_module_keys", frozenset())
    remote_access = db.query(RemoteAccess).filter(RemoteAccess.ip_address_id == monitor.ip_address_id, RemoteAccess.is_enabled == True).first()  # noqa: E712
    return templates.TemplateResponse(request, "network_monitor_detail.html", {
        "user": user, "remote_access": remote_access,
        "can_remote": "remote_manager" in accessible_modules,
        "can_dns": "dns_manager" in accessible_modules,
        "can_ip_manager": "vlan_ip_manager" in accessible_modules,
        **monitor_detail_context(db, monitor, range), **csrf_context(request),
    })


def csv_safe(value) -> str:
    text_value = "" if value is None else str(value)
    return f"'{text_value}" if text_value.startswith(("=", "+", "-", "@", "\t", "\r")) else text_value


@router.get("/{monitor_id}/checks.csv")
def export_monitor_checks(request: Request, monitor_id: int, range: str = Query("24h", max_length=8), db: Session = Depends(get_db), user=Depends(require_user)):
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    start = range_start(range)
    rows = db.query(NetworkMonitorCheck).filter(
        NetworkMonitorCheck.monitor_id == monitor.id,
        NetworkMonitorCheck.checked_at >= start,
    ).order_by(NetworkMonitorCheck.checked_at.desc()).limit(10000).all()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["timestamp_utc", "status", "latency_ms", "packet_loss_percent", "response_time_ms", "failure_reason"])
    for row in rows:
        writer.writerow([row.checked_at.isoformat() + "Z", row.status, row.latency_ms, row.packet_loss_percent, row.response_time_ms, csv_safe(row.error)])
    write_audit(db, user, "export", "network_monitor_checks", str(monitor.id), request.client.host if request.client else None, detail=f"Exported {len(rows)} checks for {range}")
    filename = f"network-monitor-{monitor.id}-{range}.csv"
    return Response(output.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.post("/{monitor_id}/toggle")
def toggle_monitor(request: Request, monitor_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    monitor.is_enabled = not monitor.is_enabled
    monitor.last_status = "unknown" if monitor.is_enabled else "paused"
    monitor.state_reason = "Awaiting first check" if monitor.is_enabled else "Monitoring disabled"
    monitor.state_changed_at = datetime.utcnow()
    monitor.consecutive_degraded = 0
    monitor.consecutive_failures = 0
    monitor.consecutive_successes = 0
    db.commit()
    write_audit(db, user, "resume" if monitor.is_enabled else "pause", "network_monitor", str(monitor.id), request.client.host if request.client else None, detail="Monitor collection state changed")
    return RedirectResponse(f"/networking/ip-wan-monitor/{monitor.id}", status_code=303)


@router.post("/{monitor_id}/settings")
def update_monitor_settings(
    request: Request,
    monitor_id: int,
    interval_seconds: int = Form(...),
    timeout_ms: int = Form(...),
    maintenance_mode: str = Form(""),
    use_default_thresholds: str = Form(""),
    failure_threshold: int = Form(...),
    recovery_threshold: int = Form(...),
    degraded_threshold: int = Form(...),
    recovery_state_enabled: str = Form(""),
    latency_warning_ms: int = Form(...),
    latency_critical_ms: int = Form(...),
    packet_loss_warning_percent: int = Form(...),
    packet_loss_critical_percent: int = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_editor),
):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    try:
        interval, timeout = validate_monitor_timing(interval_seconds, timeout_ms)
        values = validate_threshold_values({
            "failure_threshold": failure_threshold,
            "recovery_threshold": recovery_threshold,
            "degraded_threshold": degraded_threshold,
            "recovery_state_enabled": recovery_state_enabled == "1",
            "latency_warning_ms": latency_warning_ms,
            "latency_critical_ms": latency_critical_ms,
            "packet_loss_warning_percent": packet_loss_warning_percent,
            "packet_loss_critical_percent": packet_loss_critical_percent,
        })
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    old_values = {
        "interval_seconds": monitor.interval_seconds,
        "timeout_ms": monitor.timeout_ms,
        "use_default_thresholds": monitor.use_default_thresholds,
        "maintenance_mode": monitor.is_in_maintenance,
        **{key: getattr(monitor, key) for key in values},
    }
    monitor.interval_seconds = interval
    monitor.timeout_ms = timeout
    monitor.is_in_maintenance = maintenance_mode == "1"
    if monitor.is_in_maintenance:
        monitor.last_status = "maintenance"
        monitor.state_reason = "Active maintenance window"
        monitor.state_changed_at = datetime.utcnow()
    elif monitor.last_status == "maintenance":
        monitor.last_status = "unknown"
        monitor.state_reason = "Awaiting first check after maintenance"
        monitor.state_changed_at = datetime.utcnow()
    monitor.use_default_thresholds = use_default_thresholds == "1"
    for key, value in values.items():
        setattr(monitor, key, value)
    db.commit()
    new_values = {
        "interval_seconds": monitor.interval_seconds,
        "timeout_ms": monitor.timeout_ms,
        "use_default_thresholds": monitor.use_default_thresholds,
        "maintenance_mode": monitor.is_in_maintenance,
        **{key: getattr(monitor, key) for key in values},
    }
    write_audit(
        db, user, "update", "network_monitor", str(monitor.id),
        request.client.host if request.client else None,
        detail="Updated per-host health thresholds and collection settings",
        metadata={"old": old_values, "new": new_values},
    )
    return RedirectResponse(f"/networking/ip-wan-monitor/{monitor.id}#settings", status_code=303)


@router.post("/{monitor_id}/delete")
def delete_monitor(request: Request, monitor_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")
    label = monitor_label(monitor)
    db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.monitor_id == monitor.id).delete(synchronize_session=False)
    db.query(NetworkMonitorEvent).filter(NetworkMonitorEvent.monitor_id == monitor.id).delete(synchronize_session=False)
    db.query(NetworkMonitorOutage).filter(NetworkMonitorOutage.monitor_id == monitor.id).delete(synchronize_session=False)
    db.query(NetworkMonitorStatistic).filter(NetworkMonitorStatistic.monitor_id == monitor.id).delete(synchronize_session=False)
    db.delete(monitor)
    db.commit()
    write_audit(db, user, "delete", "network_monitor", str(monitor_id), request.client.host if request.client else None, detail=label)
    return RedirectResponse("/networking/ip-wan-monitor", status_code=303)
