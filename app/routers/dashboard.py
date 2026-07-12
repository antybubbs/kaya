from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.core.csrf import csrf_context
from app.db.session import get_db
from app.routers.auth import require_user
from app.services.compute_monitor import compute_summary
from app.services.dns_dashboard_summary import (get_dns_dashboard_summary,get_refreshed_dns_dashboard_summary,)
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
@router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "compute": compute_summary(db),
            "dns_summary": get_dns_dashboard_summary(db, user),
            **csrf_context(request),
        },
    )

@router.get("/dashboard/api/dns-summary")
def dashboard_dns_summary(
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    summary = get_refreshed_dns_dashboard_summary(
        db,
        user,
        max_age_seconds=60,
    )

    return {
        "configured": summary.configured,
        "provider_id": summary.provider_id,
        "provider_name": summary.provider_name,
        "provider_status": summary.provider_status,
        "provider_status_label": summary.provider_status_label,
        "last_updated_at": (
            summary.last_updated_at.isoformat() + "Z"
            if summary.last_updated_at
            else None
        ),
        "queries_today": summary.queries_today,
        "blocked_queries_today": summary.blocked_queries_today,
        "blocked_percentage": summary.blocked_percentage,
        "active_clients_24h": summary.active_clients_24h,
        "critical_insight_count": summary.critical_insight_count,
        "warning_insight_count": summary.warning_insight_count,
        "attention_count": summary.attention_count,
        "featured_insight": (
            {
                "id": summary.featured_insight.id,
                "severity": summary.featured_insight.severity,
                "severity_label": summary.featured_insight.severity_label,
                "title": summary.featured_insight.title,
                "summary": summary.featured_insight.summary,
                "target": summary.featured_insight.target,
            }
            if summary.featured_insight
            else None
        ),
        "dashboard_target": summary.dashboard_target,
        "settings_target": summary.settings_target,
        "reports_target": summary.reports_target,
        "blocked_target": summary.blocked_target,
        "clients_target": summary.clients_target,
        "attention_target": summary.attention_target,
        "error": summary.error,
    }