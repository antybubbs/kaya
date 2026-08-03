import json
import math
from datetime import datetime, timedelta
from urllib.parse import quote

from fastapi import APIRouter, Body, Depends, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import case, func
from sqlalchemy.orm import Session, selectinload
from starlette import status

from app.core.csrf import csrf_context, validate_csrf_token
from app.core.templating import templates
from app.db.session import get_db
from app.models.models import (
    NetworkMonitor,
    NetworkMonitorCheck,
    NetworkMonitorEvent,
    NetworkMonitorOutage,
    NetworkMonitorStatistic,
    NetworkMonitorTransition,
    NetworkMonitorWallboardSession,
    NotificationDeliveryAttempt,
    NotificationEvent,
    NotificationOutbox,
    RemoteAccess,
    UserNotification,
)
from app.routers.auth import require_admin, require_editor, require_module_access, require_user
from app.services.audit import write_audit
from app.services.client_ip import client_ip as trusted_client_ip
from app.services.network_monitor import (
    DASHBOARD_INTERVALS,
    active_dashboard_interval,
    effective_monitor_thresholds,
    latency_label,
    live_latency_label,
    monitor_label,
    monitor_scheduler_diagnostics,
    run_monitor_check_by_id,
    set_dashboard_interval_override,
    validate_monitor_timing,
    validate_threshold_values,
)
from app.services.network_monitor_history import performance_history
from app.services.table_export import csv_safe, export_row_matches, table_export_response, validate_export_columns, validate_export_filters, validate_export_format
from app.services.network_monitor_wallboard import (
    GENERIC_CREDENTIAL_ERROR,
    VALID_COLUMNS,
    VALID_DENSITIES,
    WALLBOARD_COOKIE,
    active_session,
    allowed_monitor_ids,
    get_wallboard,
    is_locked,
    normalise_display_options,
    reset_user_preferences,
    save_user_preferences,
    start_session,
    user_preferences,
    verify_challenge,
    verify_session_csrf,
    wallboard_display,
    wallboard_for_token,
    wallboard_permissions,
)

router = APIRouter(prefix="/networking/ip-wan-monitor", dependencies=[Depends(require_module_access("network_monitor"))])
wallboard_router = APIRouter(prefix="/monitoring/ip-wan-monitor/wallboard")

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


def monitor_rows(db: Session, allowed_ids: list[int] | None = None) -> tuple[list[dict], dict[str, int]]:
    query = db.query(NetworkMonitor).options(selectinload(NetworkMonitor.ip_address))
    if allowed_ids is not None:
        if not allowed_ids:
            monitors = []
        else:
            found = {item.id: item for item in query.filter(NetworkMonitor.id.in_(allowed_ids)).all()}
            monitors = [found[item] for item in allowed_ids if item in found]
    else:
        monitors = query.order_by(NetworkMonitor.display_name.asc(), NetworkMonitor.id.asc()).all()
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
            recent_subquery.c.recent_rank <= 400,
        ).order_by(NetworkMonitorCheck.monitor_id.asc(), NetworkMonitorCheck.checked_at.asc()).all()
        for check in recent_checks:
            recent_by_monitor.setdefault(check.monitor_id, []).append(check)
    rows = []
    state_counts = {state: 0 for state in ("healthy", "warning", "critical", "recovering", "offline", "paused", "maintenance", "unknown")}
    for monitor in monitors:
        thresholds = effective_monitor_thresholds(db, monitor)
        state = monitor_state(monitor)
        total_checks, total_up, average_latency = stats.get(monitor.id, (0, 0, None))
        state_counts[state if state in state_counts else "unknown"] += 1
        history = recent_by_monitor.get(monitor.id, [])
        chart_points = [{
            "id": check.id, "at": check.checked_at.isoformat() + "Z",
            "latency": check.latency_ms, "loss": check.packet_loss_percent,
            "status": check.health_state or point_health(
                thresholds, check.latency_ms, check.packet_loss_percent,
                check.status == "up",
            ),
        } for check in history]
        if not chart_points and monitor.last_checked_at:
            chart_points.append({
                "id": 0, "at": monitor.last_checked_at.isoformat() + "Z",
                "latency": monitor.last_latency_ms,
                "loss": monitor.last_packet_loss_percent,
                "status": state,
            })
        rows.append({
            "monitor": monitor,
            "state": state,
            "label": monitor_label(monitor),
            "history": history,
            "thresholds": thresholds,
            "chart_points": chart_points,
            "uptime": round((total_up / total_checks) * 100, 1) if total_checks else None,
            "average_latency": round(float(average_latency), 1) if average_latency is not None else None,
        })
    return rows, state_counts


def dashboard_context(db: Session, allowed_ids: list[int] | None = None) -> dict:
    rows, state_counts = monitor_rows(db, allowed_ids)
    dashboard_interval = active_dashboard_interval()
    for row in rows:
        row["effective_interval"] = dashboard_interval or row["monitor"].interval_seconds
    since = datetime.utcnow() - timedelta(hours=24)
    aggregate = db.query(
        func.count(NetworkMonitorCheck.id),
        func.sum(case((NetworkMonitorCheck.status == "up", 1), else_=0)),
        func.avg(NetworkMonitorCheck.latency_ms),
    ).filter(NetworkMonitorCheck.checked_at >= since)
    if allowed_ids is not None:
        aggregate = aggregate.filter(NetworkMonitorCheck.monitor_id.in_(allowed_ids or [-1]))
    total_checks, up_checks, avg_latency = aggregate.one()
    checks_per_minute = round(sum(
        60 / max(row["effective_interval"], 5)
        for row in rows if row["monitor"].is_enabled
    ), 1)
    return {
        "rows": rows, "total": len(rows), "up_count": state_counts["healthy"],
        "warning_count": state_counts["warning"], "critical_count": state_counts["critical"],
        "recovering_count": state_counts["recovering"], "down_count": state_counts["offline"],
        "paused_count": state_counts["paused"], "maintenance_count": state_counts["maintenance"],
        "unknown_count": state_counts["unknown"],
        "active_incidents": db.query(func.count(NetworkMonitorOutage.id)).filter(
            NetworkMonitorOutage.ended_at.is_(None),
            *([NetworkMonitorOutage.monitor_id.in_(allowed_ids or [-1])] if allowed_ids is not None else []),
        ).scalar() or 0,
        "average_latency": round(float(avg_latency), 1) if avg_latency is not None else None,
        "availability_24h": round((up_checks / total_checks) * 100, 2) if total_checks else None,
        "checks_per_minute": int(checks_per_minute) if checks_per_minute.is_integer() else checks_per_minute,
        "dashboard_interval": dashboard_interval,
        "latest_observation_id": db.query(func.max(NetworkMonitorCheck.id)).filter(
            *([NetworkMonitorCheck.monitor_id.in_(allowed_ids or [-1])] if allowed_ids is not None else []),
        ).scalar() or 0,
        "latency_label": latency_label,
        "live_latency_label": live_latency_label,
    }


def range_start(value: str) -> datetime:
    duration = RANGES.get(value)
    if duration is None:
        raise HTTPException(status_code=400, detail="Unsupported monitoring range")
    return datetime.utcnow() - duration


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * quantile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower), 2)


def point_health(thresholds: dict, latency: float | None, loss: int | None, is_up: bool) -> str:
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
            "latency": round(sum(row["latency"] * row["samples"] for row in latency_rows) / sum(row["samples"] for row in latency_rows), 3) if latency_rows else None,
            "loss": round(sum(row["loss"] * row["samples"] for row in loss_rows) / sum(row["samples"] for row in loss_rows)) if loss_rows else None,
            "samples": sample_count,
            "up_count": sum(row["up_count"] for row in rows),
            "state": max((row.get("state") for row in rows if row.get("state")), key=lambda state: state_priority.get(state, 0), default=None),
        })
    return result


def monitor_detail_context(
    db: Session,
    monitor: NetworkMonitor,
    selected_range: str = "24h",
    check_page: int = 1,
    check_status: str = "all",
    check_q: str = "",
) -> dict:
    thresholds = effective_monitor_thresholds(db, monitor)
    start = range_start(selected_range)
    checks = db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.monitor_id == monitor.id, NetworkMonitorCheck.checked_at >= start).order_by(NetworkMonitorCheck.checked_at.asc()).all()
    statistics = db.query(NetworkMonitorStatistic).filter(NetworkMonitorStatistic.monitor_id == monitor.id, NetworkMonitorStatistic.bucket_start >= start).order_by(NetworkMonitorStatistic.bucket_start.asc()).all()
    events = db.query(NetworkMonitorEvent).filter(NetworkMonitorEvent.monitor_id == monitor.id, NetworkMonitorEvent.occurred_at >= start).order_by(NetworkMonitorEvent.occurred_at.desc()).limit(100).all()
    outages = db.query(NetworkMonitorOutage).filter(
        NetworkMonitorOutage.monitor_id == monitor.id,
        (NetworkMonitorOutage.ended_at.is_(None)) | (NetworkMonitorOutage.ended_at >= start),
    ).order_by(NetworkMonitorOutage.started_at.desc()).all()
    latest_incident = db.query(NetworkMonitorOutage).filter(NetworkMonitorOutage.monitor_id == monitor.id).order_by(NetworkMonitorOutage.started_at.desc()).first()
    latest_offline_transition = (
        db.query(NetworkMonitorTransition)
        .filter_by(monitor_id=monitor.id, new_state="offline")
        .order_by(NetworkMonitorTransition.transitioned_at.desc())
        .first()
    )
    notification_timing = {
        "probe_interval_seconds": monitor.interval_seconds,
        "failure_threshold": thresholds["failure_threshold"],
        "expected_alert_delay_seconds": monitor.interval_seconds
        * thresholds["failure_threshold"],
        "last_successful_check": None,
        "first_failed_check": None,
        "marked_offline": latest_offline_transition.transitioned_at
        if latest_offline_transition
        else None,
        "outbox_created": None,
        "event_created": None,
        "user_notification_created": None,
        "push_queued": None,
        "push_accepted": None,
    }
    if latest_offline_transition:
        trigger = db.get(
            NetworkMonitorCheck, latest_offline_transition.triggering_observation_id
        )
        first_failed = (
            db.query(NetworkMonitorCheck)
            .filter(
                NetworkMonitorCheck.monitor_id == monitor.id,
                NetworkMonitorCheck.status == "down",
                NetworkMonitorCheck.checked_at <= latest_offline_transition.transitioned_at,
            )
            .order_by(NetworkMonitorCheck.checked_at.desc())
            .limit(max(1, latest_offline_transition.consecutive_failures))
            .all()
        )
        last_success = (
            db.query(NetworkMonitorCheck)
            .filter(
                NetworkMonitorCheck.monitor_id == monitor.id,
                NetworkMonitorCheck.status == "up",
                NetworkMonitorCheck.checked_at
                < (trigger.checked_at if trigger else latest_offline_transition.transitioned_at),
            )
            .order_by(NetworkMonitorCheck.checked_at.desc())
            .first()
        )
        notification_timing["last_successful_check"] = (
            last_success.checked_at if last_success else None
        )
        notification_timing["first_failed_check"] = min(
            (item.checked_at for item in first_failed), default=None
        )
        outbox = (
            db.query(NotificationOutbox)
            .filter_by(correlation_id=latest_offline_transition.correlation_id)
            .order_by(NotificationOutbox.created_at.asc())
            .first()
        )
        if outbox:
            notification_timing["outbox_created"] = outbox.created_at
            event = (
                db.get(NotificationEvent, outbox.notification_event_id)
                if outbox.notification_event_id
                else None
            )
            if event:
                notification_timing["event_created"] = event.created_at
                notification_timing["user_notification_created"] = (
                    db.query(func.min(UserNotification.created_at))
                    .filter_by(notification_event_id=event.id)
                    .scalar()
                )
                notification_ids = db.query(UserNotification.id).filter_by(
                    notification_event_id=event.id
                )
                notification_timing["push_queued"] = (
                    db.query(func.min(NotificationDeliveryAttempt.created_at))
                    .filter(
                        NotificationDeliveryAttempt.channel == "push",
                        NotificationDeliveryAttempt.user_notification_id.in_(
                            notification_ids
                        ),
                    )
                    .scalar()
                )
                notification_timing["push_accepted"] = (
                    db.query(func.min(NotificationDeliveryAttempt.accepted_at))
                    .filter(
                        NotificationDeliveryAttempt.channel == "push",
                        NotificationDeliveryAttempt.status.in_(
                            ["accepted", "accepted_by_push_service"]
                        ),
                        NotificationDeliveryAttempt.user_notification_id.in_(
                            notification_ids
                        ),
                    )
                    .scalar()
                )
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
    filtered_checks = []
    clean_check_q = check_q.strip().lower()
    for check in reversed(checks):
        health = check.health_state or point_health(
            thresholds, check.latency_ms, check.packet_loss_percent, check.status == "up"
        )
        if check_status != "all" and health != check_status:
            continue
        searchable = " ".join(str(value or "") for value in (
            check.checked_at, health, check.status, check.latency_ms,
            check.packet_loss_percent, check.error,
        )).lower()
        if clean_check_q and clean_check_q not in searchable:
            continue
        filtered_checks.append(check)
    check_page_size = 50
    check_pages = max(1, math.ceil(len(filtered_checks) / check_page_size))
    check_page = min(check_page, check_pages)
    check_offset = (check_page - 1) * check_page_size
    history = filtered_checks[check_offset:check_offset + check_page_size]
    return {
        "monitor": monitor, "selected_range": selected_range, "checks": history, "events": events,
        "current_state": monitor_state(monitor),
        "outages": outages, "incident_rows": incident_rows, "graph_points": graph_points, "chart_payload": chart_payload,
        "sample_count": sample_count, "availability": round((up_count / sample_count) * 100, 2) if sample_count else None,
        "average_latency": round(latency_total / latency_count, 2) if latency_count else None,
        "median_latency": percentile(chart_latencies, .5), "minimum_latency": min(chart_latencies, default=None),
        "maximum_latency": max(chart_latencies, default=None), "p95_latency": percentile(chart_latencies, .95),
        "p99_latency": percentile(chart_latencies, .99), "average_jitter": round(sum(jitter_values) / len(jitter_values)) if jitter_values else None,
        "average_packet_loss": round(weighted_loss_total / weighted_loss_count, 1) if weighted_loss_count else None,
        "successful_checks": up_count, "failed_checks": failed_checks, "downtime_seconds": round(downtime_seconds),
        "average_recovery_seconds": round(sum(incident_durations) / len(incident_durations)) if incident_durations else None,
        "last_incident": latest_incident,
        "notification_timing": notification_timing,
        "thresholds": thresholds,
        "outage_count": len(outages),
        "latency_label": latency_label,
        "check_count": len(filtered_checks), "check_page": check_page,
        "check_pages": check_pages, "check_status": check_status,
        "check_q": check_q.strip(),
    }


@router.get("")
def network_monitor(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    context = dashboard_context(db)
    monitor_ids = [row["monitor"].id for row in context["rows"]]
    preferences = user_preferences(db, user, monitor_ids, wallboard_display(get_wallboard(db)))
    row_map = {row["monitor"].id: row for row in context["rows"]}
    context["rows"] = [row_map[item] for item in preferences["monitor_order"] if item in row_map]
    return templates.TemplateResponse(request, "network_monitor.html", {
        "user": user,
        "wallboard_preferences": preferences,
        **context,
        **csrf_context(request),
    })


@router.get("/cards")
def network_monitor_cards(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    context = dashboard_context(db)
    monitor_ids = [row["monitor"].id for row in context["rows"]]
    preferences = user_preferences(db, user, monitor_ids, wallboard_display(get_wallboard(db)))
    row_map = {row["monitor"].id: row for row in context["rows"]}
    context["rows"] = [row_map[item] for item in preferences["monitor_order"] if item in row_map]
    return templates.TemplateResponse(request, "_network_monitor_cards.html", {
        "user": user,
        **context,
        **csrf_context(request),
    })


@router.get("/live")
def live_dashboard_observations(after: int = Query(0, ge=0), db: Session = Depends(get_db), user=Depends(require_user)):
    return JSONResponse(live_dashboard_payload(db, after))


def live_dashboard_payload(db: Session, after: int, allowed_ids: list[int] | None = None) -> dict:
    checks_query = db.query(NetworkMonitorCheck).filter(
        NetworkMonitorCheck.id > after,
        NetworkMonitorCheck.checked_at >= datetime.utcnow() - timedelta(minutes=5),
    )
    if allowed_ids is not None:
        checks_query = checks_query.filter(NetworkMonitorCheck.monitor_id.in_(allowed_ids or [-1]))
    checks = checks_query.order_by(NetworkMonitorCheck.id.asc()).limit(1000).all()
    monitor_ids = {check.monitor_id for check in checks}
    monitors = {row.id: row for row in db.query(NetworkMonitor).filter(NetworkMonitor.id.in_(monitor_ids)).all()} if monitor_ids else {}
    context = dashboard_context(db, allowed_ids)
    open_incidents = {
        row.monitor_id: row for row in db.query(NetworkMonitorOutage).filter(NetworkMonitorOutage.ended_at.is_(None)).all()
    }
    observations = []
    previous_latency: dict[int, float | None] = {}
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
    return {
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
        "summary": {key: context[key] for key in (
            "total", "up_count", "warning_count", "critical_count", "recovering_count",
            "down_count", "paused_count", "maintenance_count", "unknown_count",
            "active_incidents", "average_latency", "availability_24h", "checks_per_minute",
        )},
        "has_more": len(checks) == 1000,
    }


def _ordered_wallboard_context(db: Session, monitor_ids: list[int], preferences: dict) -> dict:
    order = [item for item in preferences.get("monitor_order", []) if item in set(monitor_ids)]
    order.extend(item for item in monitor_ids if item not in order)
    context = dashboard_context(db, order)
    return {**context, "wallboard_preferences": preferences}


@wallboard_router.get("")
def authenticated_wallboard(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_module_access("network_monitor")),
):
    config = get_wallboard(db)
    monitor_ids = [row.id for row in db.query(NetworkMonitor).order_by(NetworkMonitor.display_name.asc(), NetworkMonitor.id.asc()).all()]
    site_defaults = wallboard_display(config)
    preferences = user_preferences(db, user, monitor_ids, site_defaults)
    return templates.TemplateResponse(request, "network_monitor_wallboard.html", {
        "user": user, "shared": False, "wallboard_name": config.name if config else "IP/WAN Monitor Wallboard",
        "permissions": {"allow_detail_links": True, "allow_check_now": user.role in {"admin", "editor"}, "allow_pause": user.role in {"admin", "editor"}, "allow_reorder": True, "allow_display_changes": True},
        "live_endpoint": "/networking/ip-wan-monitor/live", "preferences_endpoint": "/monitoring/ip-wan-monitor/wallboard/preferences",
        "reset_endpoint": "/monitoring/ip-wan-monitor/wallboard/preferences/reset", "lock_endpoint": None,
        **_ordered_wallboard_context(db, monitor_ids, preferences), **csrf_context(request),
    })


@wallboard_router.put("/preferences")
def save_authenticated_wallboard_preferences(
    request: Request,
    payload: dict = Body(...),
    db: Session = Depends(get_db),
    user=Depends(require_module_access("network_monitor")),
):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    monitor_ids = [row.id for row in db.query(NetworkMonitor.id).order_by(NetworkMonitor.display_name.asc(), NetworkMonitor.id.asc()).all()]
    try:
        preferences = save_user_preferences(
            db, user, payload, monitor_ids, wallboard_display(get_wallboard(db))
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"preferences": preferences}


@wallboard_router.post("/preferences/reset")
def reset_authenticated_wallboard_preferences(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_module_access("network_monitor")),
):
    validate_csrf_token(request, request.headers.get("x-csrf-token"))
    monitor_ids = [row.id for row in db.query(NetworkMonitor.id).order_by(NetworkMonitor.display_name.asc(), NetworkMonitor.id.asc()).all()]
    return {"preferences": reset_user_preferences(db, user, monitor_ids, wallboard_display(get_wallboard(db)))}


def _shared_access(request: Request, db: Session, token: str):
    row = wallboard_for_token(db, token)
    session = active_session(db, row, request.cookies.get(WALLBOARD_COOKIE)) if row else None
    return row, session


def _shared_error(request: Request, message: str, status_code: int = 404):
    return templates.TemplateResponse(request, "network_monitor_wallboard_challenge.html", {
        "wallboard": None, "error": message, "locked": False, **csrf_context(request),
    }, status_code=status_code)


@wallboard_router.get("/shared/{token}")
def shared_wallboard(token: str, request: Request, db: Session = Depends(get_db)):
    row, session = _shared_access(request, db, token)
    if not row or not row.enabled or not row.public_token_hash:
        return _shared_error(request, "This Wallboard link is no longer active.")
    if not session:
        return templates.TemplateResponse(request, "network_monitor_wallboard_challenge.html", {
            "wallboard": row, "error": None, "locked": is_locked(db, row, trusted_client_ip(request)),
            "remember_enabled": row.remember_display_enabled, **csrf_context(request),
        })
    monitor_ids = allowed_monitor_ids(db, row)
    display = wallboard_display(row)
    permissions = wallboard_permissions(row)
    if permissions["allow_display_changes"]:
        try:
            session_display = json.loads(session.display_options_json or "{}")
        except json.JSONDecodeError:
            session_display = {}
        display = {**display, **normalise_display_options(session_display, display)}
        if isinstance(session_display, dict) and session_display.get("columns") in VALID_COLUMNS:
            display["columns"] = session_display["columns"]
        if isinstance(session_display, dict) and session_display.get("density") in VALID_DENSITIES:
            display["density"] = session_display["density"]
        try:
            temporary = json.loads(session.monitor_order_json or "[]")
        except json.JSONDecodeError:
            temporary = []
        if permissions["allow_reorder"] and isinstance(temporary, list):
            order = [item for item in temporary if isinstance(item, int) and item in monitor_ids]
            order.extend(item for item in monitor_ids if item not in order)
            monitor_ids = order
    preferences = {"monitor_order": monitor_ids, **display}
    return templates.TemplateResponse(request, "network_monitor_wallboard.html", {
        "user": None, "shared": True, "wallboard_name": row.name, "permissions": permissions,
        "shared_csrf": _shared_csrf_value(session), "live_endpoint": f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/data",
        "preferences_endpoint": f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/preferences",
        "reset_endpoint": None, "lock_endpoint": f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/lock",
        "forget_endpoint": f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/forget", "remembered": session.remembered,
        "wallboard_token": token, **_ordered_wallboard_context(db, monitor_ids, preferences), **csrf_context(request),
    })


@wallboard_router.get("/shared/{token}/monitors/{monitor_id}/data")
def shared_wallboard_monitor_data(token: str, monitor_id: int, request: Request, after: int = Query(0, ge=0), db: Session = Depends(get_db)):
    row, session = _shared_access(request, db, token)
    if not row or not session or not wallboard_permissions(row).get("allow_detail_links") or monitor_id not in allowed_monitor_ids(db, row):
        raise HTTPException(status_code=404, detail="Monitor not found")
    return JSONResponse(live_dashboard_payload(db, after, [monitor_id]))


@wallboard_router.post("/shared/{token}/authenticate")
def authenticate_shared_wallboard(
    token: str,
    request: Request,
    passcode: str = Form(..., max_length=128),
    remember_display: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf_token(request, csrf_token)
    row = wallboard_for_token(db, token)
    if not row or not row.enabled:
        return _shared_error(request, GENERIC_CREDENTIAL_ERROR, 400)
    valid, locked = verify_challenge(db, row, passcode, trusted_client_ip(request))
    write_audit(db, None, "wallboard_challenge_succeeded" if valid else "wallboard_challenge_failed", "network_monitor_wallboard", str(row.id), trusted_client_ip(request), category="security", severity="info" if valid else "warning")
    if not valid:
        return templates.TemplateResponse(request, "network_monitor_wallboard_challenge.html", {
            "wallboard": row, "error": "Too many attempts. Please try again later." if locked else GENERIC_CREDENTIAL_ERROR,
            "locked": locked, "remember_enabled": row.remember_display_enabled, **csrf_context(request),
        }, status_code=429 if locked else 400)
    raw_token, csrf, session = start_session(db, row, remembered=remember_display == "1")
    session.display_options_json = json.dumps({"csrf": csrf}, separators=(",", ":"))
    db.commit()
    safe_token = quote(token, safe="")
    response = RedirectResponse(f"/monitoring/ip-wan-monitor/wallboard/shared/{safe_token}", status_code=303)
    max_age = 315360000 if session.expires_at is None else max(1, int((session.expires_at - datetime.utcnow()).total_seconds()))
    response.set_cookie(WALLBOARD_COOKIE, raw_token, max_age=max_age, httponly=True, secure=request.url.scheme == "https", samesite="lax", path=f"/monitoring/ip-wan-monitor/wallboard/shared/{safe_token}")
    return response


def _shared_csrf_value(session: NetworkMonitorWallboardSession) -> str:
    try:
        value = json.loads(session.display_options_json or "{}").get("csrf", "")
    except (json.JSONDecodeError, AttributeError):
        value = ""
    return str(value)


@wallboard_router.get("/shared/{token}/data")
def shared_wallboard_data(token: str, request: Request, after: int = Query(0, ge=0), db: Session = Depends(get_db)):
    row, session = _shared_access(request, db, token)
    if not row or not session:
        raise HTTPException(status_code=401, detail="Wallboard session expired")
    return JSONResponse(live_dashboard_payload(db, after, allowed_monitor_ids(db, row)))


@wallboard_router.post("/shared/{token}/collection-rate")
def set_shared_wallboard_collection_rate(
    token: str,
    request: Request,
    mode: str = Form(..., max_length=20),
    client_id: str = Form(..., min_length=1, max_length=80, pattern=r"^[A-Za-z0-9-]+$"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    row, session = _shared_access(request, db, token)
    if not row or not session or not verify_session_csrf(session, csrf_token) or not wallboard_permissions(row).get("allow_display_changes"):
        raise HTTPException(status_code=403, detail="Forbidden")
    if mode not in {*DASHBOARD_INTERVALS, "paused"}:
        raise HTTPException(status_code=400, detail="Unsupported collection rate")
    lease_id = f"wallboard-{row.id}-{session.id}-{client_id}"
    changed = set_dashboard_interval_override(lease_id, mode)
    if changed:
        interval = DASHBOARD_INTERVALS.get(mode)
        detail = f"Shared Wallboard backend interval set to {interval} seconds" if interval else "Shared Wallboard backend interval override released"
        write_audit(db, None, "update", "network_monitor_wallboard", str(row.id), trusted_client_ip(request), detail=detail, metadata={"mode": mode})
    return JSONResponse({"ok": True, "mode": mode, "effective_interval_seconds": active_dashboard_interval()})


@wallboard_router.get("/shared/{token}/monitors/{monitor_id}")
def shared_wallboard_monitor(token: str, monitor_id: int, request: Request, db: Session = Depends(get_db)):
    row, session = _shared_access(request, db, token)
    permissions = wallboard_permissions(row) if row else {}
    if not row or not session or not permissions.get("allow_detail_links") or monitor_id not in allowed_monitor_ids(db, row):
        raise HTTPException(status_code=404, detail="Monitor not found")
    display = {**wallboard_display(row), "show_summary": False, "show_actions": permissions.get("allow_check_now") or permissions.get("allow_pause")}
    return templates.TemplateResponse(request, "network_monitor_wallboard.html", {
        "user": None, "shared": True, "wallboard_name": f"{row.name} - Monitor detail", "permissions": {**permissions, "allow_detail_links": False, "allow_reorder": False, "allow_display_changes": False},
        "shared_csrf": _shared_csrf_value(session), "live_endpoint": f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/monitors/{monitor_id}/data",
        "preferences_endpoint": "", "reset_endpoint": None, "lock_endpoint": f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/lock",
        "forget_endpoint": f"/monitoring/ip-wan-monitor/wallboard/shared/{token}/forget", "remembered": session.remembered,
        "wallboard_token": token, **_ordered_wallboard_context(db, [monitor_id], {"monitor_order": [monitor_id], **display}), **csrf_context(request),
    })


@wallboard_router.put("/shared/{token}/preferences")
def save_shared_wallboard_preferences(token: str, request: Request, payload: dict = Body(...), db: Session = Depends(get_db)):
    row, session = _shared_access(request, db, token)
    if not row or not session or not verify_session_csrf(session, request.headers.get("x-wallboard-csrf")):
        raise HTTPException(status_code=403, detail="Forbidden")
    permissions = wallboard_permissions(row)
    monitor_ids = allowed_monitor_ids(db, row)
    if not permissions["allow_display_changes"] and not permissions["allow_reorder"]:
        raise HTTPException(status_code=403, detail="Display changes are disabled")
    if permissions["allow_display_changes"]:
        columns = payload.get("columns") if payload.get("columns") in VALID_COLUMNS else row.default_columns
        density = payload.get("density") if payload.get("density") in VALID_DENSITIES else row.default_density
        session.display_options_json = json.dumps({"csrf": _shared_csrf_value(session), "columns": columns, "density": density, **normalise_display_options(payload, wallboard_display(row))}, separators=(",", ":"))
    if permissions["allow_reorder"] and isinstance(payload.get("monitor_order"), list):
        order = [item for item in payload["monitor_order"] if isinstance(item, int) and item in monitor_ids]
        order.extend(item for item in monitor_ids if item not in order)
        session.monitor_order_json = json.dumps(order, separators=(",", ":"))
    db.commit()
    return {"ok": True}


@wallboard_router.post("/shared/{token}/lock")
def lock_shared_wallboard(token: str, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    row, session = _shared_access(request, db, token)
    if not row or not session or not verify_session_csrf(session, csrf_token):
        raise HTTPException(status_code=403, detail="Forbidden")
    safe_token = quote(token, safe="")
    response = RedirectResponse(f"/monitoring/ip-wan-monitor/wallboard/shared/{safe_token}", status_code=303)
    response.delete_cookie(WALLBOARD_COOKIE, path=f"/monitoring/ip-wan-monitor/wallboard/shared/{safe_token}")
    return response


@wallboard_router.post("/shared/{token}/forget")
def forget_shared_wallboard(token: str, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    row, session = _shared_access(request, db, token)
    if not row or not session or not verify_session_csrf(session, csrf_token):
        raise HTTPException(status_code=403, detail="Forbidden")
    session.revoked_at = datetime.utcnow()
    db.commit()
    safe_token = quote(token, safe="")
    response = RedirectResponse(f"/monitoring/ip-wan-monitor/wallboard/shared/{safe_token}", status_code=303)
    response.delete_cookie(WALLBOARD_COOKIE, path=f"/monitoring/ip-wan-monitor/wallboard/shared/{safe_token}")
    return response


def _shared_action_access(request: Request, db: Session, token: str, monitor_id: int, permission: str, csrf_token: str):
    row, session = _shared_access(request, db, token)
    if not row or not session or not verify_session_csrf(session, csrf_token) or not wallboard_permissions(row).get(permission):
        raise HTTPException(status_code=403, detail="Forbidden")
    if monitor_id not in allowed_monitor_ids(db, row):
        raise HTTPException(status_code=404, detail="Monitor not found")
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return row, monitor


@wallboard_router.post("/shared/{token}/monitors/{monitor_id}/refresh")
def shared_check_now(token: str, monitor_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    row, monitor = _shared_action_access(request, db, token, monitor_id, "allow_check_now", csrf_token)
    if not monitor.is_enabled:
        raise HTTPException(status_code=409, detail="Monitor is paused")
    run_monitor_check_by_id(monitor.id)
    write_audit(db, None, "check_now", "network_monitor_wallboard", str(row.id), trusted_client_ip(request), detail="Shared Wallboard monitor check requested", metadata={"monitor_id": monitor.id})
    return {"ok": True}


@wallboard_router.post("/shared/{token}/monitors/{monitor_id}/toggle")
def shared_toggle_monitor(token: str, monitor_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    row, monitor = _shared_action_access(request, db, token, monitor_id, "allow_pause", csrf_token)
    monitor.is_enabled = not monitor.is_enabled
    db.commit()
    write_audit(db, None, "resume" if monitor.is_enabled else "pause", "network_monitor_wallboard", str(row.id), trusted_client_ip(request), detail="Shared Wallboard monitor collection state changed", metadata={"monitor_id": monitor.id})
    return {"ok": True}


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
        write_audit(db, user, "update", "network_monitor_collection_rate", None, trusted_client_ip(request), detail=detail)
    return JSONResponse({"ok": True, "mode": mode, "effective_interval_seconds": active_dashboard_interval()})


@router.get("/diagnostics")
def scheduler_diagnostics(user=Depends(require_admin)):
    """Expose non-secret scheduler liveness data to site administrators."""
    return JSONResponse(
        monitor_scheduler_diagnostics(),
        headers={"Cache-Control": "no-store"},
    )


@router.post("/{monitor_id}/refresh")
def refresh_monitor(request: Request, monitor_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor or not monitor.is_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")
    run_monitor_check_by_id(monitor.id)
    write_audit(db, user, "check_now", "network_monitor", str(monitor.id), trusted_client_ip(request), detail="Manual monitor check requested")
    if request.headers.get("x-requested-with") == "fetch":
        return JSONResponse({"ok": True})
    return RedirectResponse(f"/networking/ip-wan-monitor/{monitor.id}", status_code=303)


@router.get("/{monitor_id}")
def monitor_detail(
    request: Request,
    monitor_id: int,
    range: str = Query("24h", max_length=8),
    check_page: int = Query(1, ge=1, le=100000),
    check_status: str = Query("all", max_length=20),
    check_q: str = Query("", max_length=100),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    monitor = db.query(NetworkMonitor).options(selectinload(NetworkMonitor.ip_address)).filter(NetworkMonitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    if check_status not in {"all", "healthy", "warning", "critical", "offline", "maintenance"}:
        raise HTTPException(status_code=400, detail="Unsupported check status")
    accessible_modules = getattr(user, "_accessible_module_keys", frozenset())
    remote_access = db.query(RemoteAccess).filter(RemoteAccess.ip_address_id == monitor.ip_address_id, RemoteAccess.is_enabled == True).first()  # noqa: E712
    return templates.TemplateResponse(request, "network_monitor_detail.html", {
        "user": user, "remote_access": remote_access,
        "can_remote": "remote_manager" in accessible_modules,
        "can_dns": "dns_manager" in accessible_modules,
        "can_ip_manager": "vlan_ip_manager" in accessible_modules,
        **monitor_detail_context(db, monitor, range, check_page, check_status, check_q), **csrf_context(request),
    })


@router.get("/{monitor_id}/performance-data")
def monitor_performance_data(
    monitor_id: int,
    range: str = Query("24h", max_length=10),
    start: str | None = Query(None, max_length=40),
    end: str | None = Query(None, max_length=40),
    page: int = Query(1, ge=1, le=100000),
    page_size: int = Query(50, ge=10, le=100),
    sort: str = Query("time", max_length=20),
    direction: str = Query("desc", max_length=4),
    q: str = Query("", max_length=50),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return JSONResponse(
        performance_history(db, monitor, range, start, end, page, page_size, sort, direction, q),
        headers={"Cache-Control": "no-store"},
    )


@router.get("/{monitor_id}/performance.csv")
def export_monitor_performance(
    request: Request,
    monitor_id: int,
    range: str = Query("24h", max_length=10),
    start: str | None = Query(None, max_length=40),
    end: str | None = Query(None, max_length=40),
    format: str = Query("csv", max_length=8),
    columns: str = Query("", max_length=300),
    filters: str = Query("", max_length=2000),
    sort: str = Query("time", max_length=20),
    direction: str = Query("asc", max_length=4),
    q: str = Query("", max_length=50),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    format = validate_export_format(format)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    column_map = {
        "time": ("Date/time", lambda row: row["at"]),
        "latency-min": ("Latency min", lambda row: row["latency_min"]),
        "latency-avg": ("Latency avg", lambda row: row["latency_avg"]),
        "latency-max": ("Latency max", lambda row: row["latency_max"]),
        "jitter": ("Jitter", lambda row: row["jitter_avg"]),
        "packet-loss": ("Packet loss", lambda row: row["packet_loss"]),
        "availability": ("Availability", lambda row: row["availability"]),
        "successful": ("Successful", lambda row: row["successful"]),
        "failed": ("Failed", lambda row: row["failed"]),
        "status": ("Status", lambda row: row["status"]),
    }
    selected_columns = validate_export_columns(columns, list(column_map))
    active_filters = validate_export_filters(filters, list(column_map))
    payload = performance_history(db, monitor, range, start, end, 1, 1000000, sort, direction, q)
    table_rows = payload["table"]["rows"]
    table_rows = [row for row in table_rows if export_row_matches(row, column_map, active_filters)]
    write_audit(
        db, user, "export", "network_monitor_performance", str(monitor.id), trusted_client_ip(request),
        detail=f"Exported {len(table_rows)} performance rows as {format} for {range}; search applied={bool(q.strip())}",
    )
    return table_export_response(
        table_name=f"ip-wan-monitor-{monitor.id}-performance",
        headers=[column_map[key][0] for key in selected_columns],
        rows=([column_map[key][1](row) for key in selected_columns] for row in table_rows),
        export_format=format,
    )
@router.get("/{monitor_id}/checks.csv")
def export_monitor_checks(
    request: Request, monitor_id: int, range: str = Query("24h", max_length=8),
    check_status: str = Query("all", max_length=20), check_q: str = Query("", max_length=100),
    format: str = Query("csv", max_length=8), columns: str = Query("", max_length=200),
    filters: str = Query("", max_length=2000),
    db: Session = Depends(get_db), user=Depends(require_user),
):
    format = validate_export_format(format)
    if check_status not in {"all", "healthy", "warning", "critical", "offline", "maintenance"}:
        raise HTTPException(status_code=422, detail="Invalid monitor check status filter")
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    start = range_start(range)
    rows = db.query(NetworkMonitorCheck).filter(
        NetworkMonitorCheck.monitor_id == monitor.id,
        NetworkMonitorCheck.checked_at >= start,
    ).order_by(NetworkMonitorCheck.checked_at.desc()).limit(10000).all()
    thresholds = effective_monitor_thresholds(db, monitor)
    filtered_rows = []
    clean_query = check_q.strip().lower()
    for row in rows:
        row.export_health = row.health_state or point_health(thresholds, row.latency_ms, row.packet_loss_percent, row.status == "up")
        searchable = " ".join(str(value or "") for value in (row.checked_at, row.export_health, row.status, row.latency_ms, row.packet_loss_percent, row.error)).lower()
        if (check_status == "all" or row.export_health == check_status) and (not clean_query or clean_query in searchable):
            filtered_rows.append(row)
    column_map = {
        "timestamp": ("Timestamp", lambda row: row.checked_at.isoformat() + "Z"),
        "status": ("Status", lambda row: row.export_health.title()),
        "latency": ("Latency", lambda row: row.latency_ms),
        "packet-loss": ("Packet loss", lambda row: row.packet_loss_percent),
        "response": ("Response", lambda row: row.response_time_ms),
        "failure-reason": ("Failure reason", lambda row: row.error or ""),
    }
    selected_columns = validate_export_columns(columns, list(column_map))
    active_filters = validate_export_filters(filters, list(column_map))
    filtered_rows = [row for row in filtered_rows if export_row_matches(row, column_map, active_filters)]
    write_audit(db, user, "export", "network_monitor_checks", str(monitor.id), trusted_client_ip(request), detail=f"Exported {len(filtered_rows)} checks as {format} for {range}; filters applied={bool(clean_query or check_status != 'all')}")
    return table_export_response(
        table_name=f"ip-wan-monitor-{monitor.id}-checks",
        headers=[column_map[key][0] for key in selected_columns],
        rows=([column_map[key][1](row) for key in selected_columns] for row in filtered_rows),
        export_format=format,
    )


@router.post("/{monitor_id}/toggle")
def toggle_monitor(request: Request, monitor_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    changed_at = datetime.utcnow()
    monitor.is_enabled = not monitor.is_enabled
    monitor.last_status = "unknown" if monitor.is_enabled else "paused"
    monitor.state_reason = "Awaiting first check" if monitor.is_enabled else "Monitoring disabled"
    monitor.state_changed_at = changed_at
    monitor.consecutive_degraded = 0
    monitor.consecutive_failures = 0
    monitor.consecutive_successes = 0
    db.add(NetworkMonitorEvent(
        monitor_id=monitor.id, event_type="resumed" if monitor.is_enabled else "paused",
        severity="info", message="Monitoring resumed" if monitor.is_enabled else "Monitoring paused",
        occurred_at=changed_at,
    ))
    db.commit()
    write_audit(db, user, "resume" if monitor.is_enabled else "pause", "network_monitor", str(monitor.id), trusted_client_ip(request), detail="Monitor collection state changed")
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
    maintenance_changed = old_values["maintenance_mode"] != (maintenance_mode == "1")
    maintenance_changed_at = datetime.utcnow() if maintenance_changed else None
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
    if maintenance_changed:
        monitor.state_changed_at = maintenance_changed_at
    monitor.use_default_thresholds = use_default_thresholds == "1"
    for key, value in values.items():
        setattr(monitor, key, value)
    if maintenance_changed:
        db.add(NetworkMonitorEvent(
            monitor_id=monitor.id,
            event_type="maintenance_started" if monitor.is_in_maintenance else "maintenance_ended",
            severity="info",
            message="Maintenance mode started" if monitor.is_in_maintenance else "Maintenance mode ended",
            occurred_at=maintenance_changed_at,
        ))
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
        trusted_client_ip(request),
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
    write_audit(db, user, "delete", "network_monitor", str(monitor_id), trusted_client_ip(request), detail=label)
    return RedirectResponse("/networking/ip-wan-monitor", status_code=303)
