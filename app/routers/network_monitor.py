from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func
from sqlalchemy.orm import Session, selectinload
from starlette import status

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import NetworkMonitor, NetworkMonitorCheck, NetworkMonitorEvent, NetworkMonitorOutage, NetworkMonitorStatistic
from app.routers.auth import require_editor, require_module_access, require_user
from app.services.audit import write_audit
from app.services.network_monitor import monitor_label, run_dashboard_collection, run_monitor_check_by_id, set_dashboard_override

router = APIRouter(prefix="/networking/ip-wan-monitor", dependencies=[Depends(require_module_access("network_monitor"))])
templates = Jinja2Templates(directory="app/templates")


def monitor_rows(db: Session) -> tuple[list[dict], int, int, int, int]:
    monitors = db.query(NetworkMonitor).options(selectinload(NetworkMonitor.ip_address)).order_by(NetworkMonitor.display_name.asc(), NetworkMonitor.id.asc()).all()
    since = datetime.utcnow() - timedelta(hours=24)
    monitor_ids = [monitor.id for monitor in monitors]
    stats = {}
    recent_by_monitor = {monitor_id: [] for monitor_id in monitor_ids}
    if monitor_ids:
        stats = {
            monitor_id: (total or 0, up or 0)
            for monitor_id, total, up in db.query(
                NetworkMonitorCheck.monitor_id,
                func.count(NetworkMonitorCheck.id),
                func.sum(case((NetworkMonitorCheck.status == "up", 1), else_=0)),
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
            NetworkMonitorCheck.checked_at >= since,
        ).subquery()
        recent_checks = db.query(NetworkMonitorCheck).join(
            recent_subquery,
            NetworkMonitorCheck.id == recent_subquery.c.check_id,
        ).filter(
            recent_subquery.c.recent_rank <= 36,
        ).order_by(NetworkMonitorCheck.monitor_id.asc(), NetworkMonitorCheck.checked_at.asc()).all()
        for check in recent_checks:
            recent_by_monitor.setdefault(check.monitor_id, []).append(check)
    rows = []
    up_count = 0
    down_count = 0
    warning_count = 0
    for monitor in monitors:
        total_checks, total_up = stats.get(monitor.id, (0, 0))
        if monitor.is_enabled and monitor.last_status == "up":
            up_count += 1
        if monitor.is_enabled and monitor.last_status == "down":
            down_count += 1
        if monitor.is_enabled and monitor.last_status in {"warning", "critical"}:
            warning_count += 1
        history = recent_by_monitor.get(monitor.id, [])
        latencies = [check.latency_ms for check in history if check.latency_ms is not None]
        rows.append({
            "monitor": monitor,
            "label": monitor_label(monitor),
            "history": history,
            "uptime": round((total_up / total_checks) * 100, 1) if total_checks else None,
            "average_latency": round(sum(latencies) / len(latencies)) if latencies else None,
        })
    return rows, len(monitors), up_count, down_count, warning_count


def dashboard_context(db: Session) -> dict:
    rows, total, up_count, down_count, warning_count = monitor_rows(db)
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
        "checks_per_minute": round(total_checks / (24 * 60), 2) if total_checks else 0,
    }


def range_start(value: str) -> datetime:
    return datetime.utcnow() - {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "1y": timedelta(days=365)}.get(value, timedelta(hours=24))


def monitor_detail_context(db: Session, monitor: NetworkMonitor, selected_range: str = "24h") -> dict:
    start = range_start(selected_range)
    checks = db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.monitor_id == monitor.id, NetworkMonitorCheck.checked_at >= start).order_by(NetworkMonitorCheck.checked_at.asc()).all()
    statistics = db.query(NetworkMonitorStatistic).filter(NetworkMonitorStatistic.monitor_id == monitor.id, NetworkMonitorStatistic.bucket_start >= start).order_by(NetworkMonitorStatistic.bucket_start.asc()).all()
    history = list(reversed(checks[-100:]))
    events = db.query(NetworkMonitorEvent).filter(NetworkMonitorEvent.monitor_id == monitor.id, NetworkMonitorEvent.occurred_at >= start).order_by(NetworkMonitorEvent.occurred_at.desc()).limit(100).all()
    outages = db.query(NetworkMonitorOutage).filter(NetworkMonitorOutage.monitor_id == monitor.id, NetworkMonitorOutage.started_at >= start).order_by(NetworkMonitorOutage.started_at.desc()).all()
    sample_count = len(checks) + sum(row.sample_count for row in statistics)
    up_count = sum(1 for row in checks if row.status == "up") + sum(row.up_count for row in statistics)
    latencies = [row.latency_ms for row in checks if row.latency_ms is not None]
    statistic_latency_samples = [row for row in statistics if row.avg_latency_ms is not None and row.sample_count]
    latency_total = sum(latencies) + sum(row.avg_latency_ms * row.sample_count for row in statistic_latency_samples)
    latency_count = len(latencies) + sum(row.sample_count for row in statistic_latency_samples)
    graph_points = [{"at": row.checked_at, "latency": row.latency_ms, "loss": row.packet_loss_percent, "up": row.status == "up"} for row in checks]
    graph_points += [{"at": row.bucket_start, "latency": row.avg_latency_ms, "loss": row.avg_packet_loss_percent, "up": row.up_count == row.sample_count} for row in statistics]
    graph_points.sort(key=lambda row: row["at"])
    max_latency = max((row["latency"] or 0 for row in graph_points), default=1) or 1
    return {
        "monitor": monitor, "selected_range": selected_range, "checks": history, "events": events,
        "outages": outages, "graph_points": graph_points[-288:], "max_latency": max_latency,
        "sample_count": sample_count, "availability": round((up_count / sample_count) * 100, 2) if sample_count else None,
        "average_latency": round(latency_total / latency_count) if latency_count else None,
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


@router.post("/collect")
def collect_dashboard_monitors(
    request: Request,
    mode: str = Form(...),
    client_id: str = Form(..., max_length=80),
    csrf_token: str = Form(...),
    user=Depends(require_user),
):
    validate_csrf_token(request, csrf_token)
    ttl_by_mode = {"live": 15, "5000": 15, "10000": 25, "60000": 130, "300000": 610}
    if mode == "default":
        set_dashboard_override(client_id, None)
        return JSONResponse({"ok": True, "collected": False, "mode": mode})
    ttl = ttl_by_mode.get(mode)
    if ttl is None:
        raise HTTPException(status_code=400, detail="Unsupported monitor refresh mode")
    collected = run_dashboard_collection(client_id, ttl)
    return JSONResponse({"ok": True, "collected": collected, "mode": mode})


@router.post("/{monitor_id}/refresh")
def refresh_monitor(request: Request, monitor_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor or not monitor.is_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")
    run_monitor_check_by_id(monitor.id)
    if request.headers.get("x-requested-with") == "fetch":
        return JSONResponse({"ok": True})
    return RedirectResponse(f"/networking/ip-wan-monitor/{monitor.id}", status_code=303)


@router.get("/{monitor_id}")
def monitor_detail(request: Request, monitor_id: int, range: str = "24h", db: Session = Depends(get_db), user=Depends(require_user)):
    monitor = db.query(NetworkMonitor).options(selectinload(NetworkMonitor.ip_address)).filter(NetworkMonitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return templates.TemplateResponse(request, "network_monitor_detail.html", {"user": user, **monitor_detail_context(db, monitor, range), **csrf_context(request)})


@router.post("/{monitor_id}/toggle")
def toggle_monitor(request: Request, monitor_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    monitor.is_enabled = not monitor.is_enabled
    db.commit()
    return RedirectResponse(f"/networking/ip-wan-monitor/{monitor.id}", status_code=303)


@router.post("/{monitor_id}/settings")
def update_monitor_settings(request: Request, monitor_id: int, interval_seconds: int = Form(...), timeout_ms: int = Form(...), failure_threshold: int = Form(...), latency_warning_ms: int = Form(...), latency_critical_ms: int = Form(...), packet_loss_warning_percent: int = Form(...), packet_loss_critical_percent: int = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    monitor.interval_seconds = min(max(interval_seconds, 60), 86400)
    monitor.timeout_ms = min(max(timeout_ms, 500), 10000)
    monitor.failure_threshold = min(max(failure_threshold, 1), 20)
    monitor.latency_warning_ms = min(max(latency_warning_ms, 1), 60000)
    monitor.latency_critical_ms = max(monitor.latency_warning_ms, min(max(latency_critical_ms, 1), 60000))
    monitor.packet_loss_warning_percent = min(max(packet_loss_warning_percent, 1), 100)
    monitor.packet_loss_critical_percent = max(monitor.packet_loss_warning_percent, min(max(packet_loss_critical_percent, 1), 100))
    db.commit()
    write_audit(db, user, "update", "network_monitor", str(monitor.id), request.client.host if request.client else None, detail="Updated thresholds and collection settings")
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
