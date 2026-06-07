from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.models import Licence
from app.routers.auth import require_user

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    total = db.query(func.count(Licence.id)).scalar() or 0
    products = db.query(func.count(func.distinct(Licence.product))).scalar() or 0
    organisations = db.query(func.count(func.distinct(Licence.organisation))).scalar() or 0
    recent = db.query(Licence).order_by(Licence.created_at.desc()).limit(8).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "total": total, "products": products, "organisations": organisations, "recent": recent})
