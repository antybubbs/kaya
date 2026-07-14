from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func
from sqlalchemy.orm import Session, selectinload
from starlette import status

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import NetworkMonitor, NetworkMonitorCheck
from app.routers.auth import require_editor, require_user
from app.services.audit import write_audit
from app.services.network_monitor import monitor_label, run_monitor_check_by_id

router = APIRouter(prefix="/networking/ip-wan-monitor")
templates = Jinja2Templates(directory="app/templates")


def monitor_rows(db: Session) -> tuple[list[dict], int, int, int]:
    monitors = db.query(NetworkMonitor).filter(
        NetworkMonitor.is_enabled == True
    ).options(selectinload(NetworkMonitor.ip_address)).order_by(NetworkMonitor.display_name.asc(), NetworkMonitor.id.asc()).all()
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
    for monitor in monitors:
        total_checks, total_up = stats.get(monitor.id, (0, 0))
        if monitor.last_status == "up":
            up_count += 1
        if monitor.last_status == "down":
            down_count += 1
        rows.append({
            "monitor": monitor,
            "label": monitor_label(monitor),
            "history": recent_by_monitor.get(monitor.id, []),
            "uptime": round((total_up / total_checks) * 100, 1) if total_checks else None,
        })
    return rows, len(monitors), up_count, down_count


@router.get("")
def network_monitor(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    rows, total, up_count, down_count = monitor_rows(db)
    return templates.TemplateResponse(request, "network_monitor.html", {
        "user": user,
        "rows": rows,
        "total": total,
        "up_count": up_count,
        "down_count": down_count,
        **csrf_context(request),
    })


@router.get("/cards")
def network_monitor_cards(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    rows, total, up_count, down_count = monitor_rows(db)
    return templates.TemplateResponse(request, "_network_monitor_cards.html", {
        "user": user,
        "rows": rows,
        "total": total,
        "up_count": up_count,
        "down_count": down_count,
        **csrf_context(request),
    })


@router.post("/{monitor_id}/refresh")
def refresh_monitor(request: Request, monitor_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor or not monitor.is_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")
    run_monitor_check_by_id(monitor.id)
    return JSONResponse({"ok": True})


@router.post("/{monitor_id}/delete")
def delete_monitor(request: Request, monitor_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    monitor = db.get(NetworkMonitor, monitor_id)
    if not monitor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitor not found")
    label = monitor_label(monitor)
    db.query(NetworkMonitorCheck).filter(NetworkMonitorCheck.monitor_id == monitor.id).delete(synchronize_session=False)
    db.delete(monitor)
    db.commit()
    write_audit(db, user, "delete", "network_monitor", str(monitor_id), request.client.host if request.client else None, detail=label)
    return RedirectResponse("/networking/ip-wan-monitor", status_code=303)
