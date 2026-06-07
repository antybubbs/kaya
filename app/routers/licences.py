from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session
from app.core.security import decrypt_secret, encrypt_secret, mask_key
from app.db.session import get_db
from app.models.models import Licence
from app.routers.auth import require_user
from app.services.audit import write_audit

router = APIRouter(prefix="/licences")
templates = Jinja2Templates(directory="app/templates")


@router.get("")
def list_licences(request: Request, q: str = "", db: Session = Depends(get_db), user=Depends(require_user)):
    query = db.query(Licence)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Licence.product.ilike(like), Licence.organisation.ilike(like), Licence.licence_type.ilike(like), Licence.licence_id.ilike(like)))
    rows = query.order_by(Licence.product.asc()).limit(500).all()
    return templates.TemplateResponse("licences.html", {"request": request, "user": user, "rows": rows, "q": q, "mask_key": lambda encrypted: mask_key(decrypt_secret(encrypted))})


@router.get("/new")
def new_licence(request: Request, user=Depends(require_user)):
    return templates.TemplateResponse("licence_form.html", {"request": request, "user": user, "licence": None})


@router.post("/new")
def create_licence(request: Request, product: str = Form(...), product_key: str = Form(...), organisation: str = Form(""), licence_type: str = Form(""), seats: int = Form(0), notes: str = Form(""), db: Session = Depends(get_db), user=Depends(require_user)):
    row = Licence(product=product, encrypted_product_key=encrypt_secret(product_key), organisation=organisation or None, licence_type=licence_type or None, seats=seats, notes=notes or None)
    db.add(row)
    db.commit()
    write_audit(db, user, "create", "licence", str(row.id), request.client.host if request.client else None)
    return RedirectResponse("/licences", status_code=303)


@router.get("/{licence_id}")
def detail(request: Request, licence_id: int, reveal: bool = False, db: Session = Depends(get_db), user=Depends(require_user)):
    row = db.get(Licence, licence_id)
    full_key = decrypt_secret(row.encrypted_product_key) if reveal and user.role in ["admin", "editor"] else None
    if reveal:
        write_audit(db, user, "reveal", "licence", str(row.id), request.client.host if request.client else None)
    return templates.TemplateResponse("licence_detail.html", {"request": request, "user": user, "licence": row, "display_key": full_key or mask_key(decrypt_secret(row.encrypted_product_key))})
