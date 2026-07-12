from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.core.csrf import csrf_context
from app.db.session import get_db
from app.routers.auth import require_user
from app.services.compute_monitor import compute_summary
from app.services.dns_dashboard_summary import get_dns_dashboard_summary
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
