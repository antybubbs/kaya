from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.routers.auth import require_module_access, require_user
from app.services.dashboard import config, reset_preferences, save_preferences, snapshot

router = APIRouter(dependencies=[Depends(require_module_access("dashboard"))])
templates = Jinja2Templates(directory="app/templates")

@router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    dashboard_config = config(db, user)
    return templates.TemplateResponse(request, "dashboard.html", {"user": user, "dashboard_config": dashboard_config, **csrf_context(request)})

@router.get("/api/dashboard/config")
def dashboard_config(db: Session = Depends(get_db), user=Depends(require_user)):
    return config(db, user)

@router.get("/api/dashboard/snapshot")
def dashboard_snapshot(response: Response, db: Session = Depends(get_db), user=Depends(require_user)):
    response.headers["Cache-Control"] = "no-store"
    return snapshot(db, user)

def _validate_request_csrf(request: Request):
    validate_csrf_token(request, request.headers.get("X-CSRF-Token"))

@router.put("/api/dashboard/preferences")
def update_dashboard_preferences(request: Request, payload: dict = Body(...), db: Session = Depends(get_db), user=Depends(require_user)):
    _validate_request_csrf(request)
    try: return {"layout": save_preferences(db, user, payload)}
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@router.post("/api/dashboard/preferences/reset")
def reset_dashboard_preferences(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    _validate_request_csrf(request)
    return {"layout": reset_preferences(db, user)}
