from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette import status
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import decrypt_secret, encrypt_secret, mask_key
from app.db.session import get_db
from app.models.models import Licence
from app.routers.auth import require_editor, require_user
from app.services.audit import write_audit
from app.services.custom_fields import active_fields, field_values, option_list, save_custom_values, validate_custom_values
from app.services.managed_lists import list_values

router = APIRouter(prefix="/licences")
templates = Jinja2Templates(directory="app/templates")
MODULE = "licences"
ENTITY_TYPE = "licence"


def clean_list_value(value: str, allowed: list[str], current: str | None = None) -> str | None:
    clean = value.strip()
    if clean in allowed or (current and clean == current):
        return clean
    return None


def form_context(db: Session, request: Request, user, licence=None, product_key="", error=None):
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, licence.id) if licence else {}
    lists = list_values(db, MODULE)
    return {
        "user": user,
        "licence": licence,
        "product_key": product_key,
        "licence_types": lists.get("licence_type", []),
        "custom_fields": fields,
        "custom_values": values,
        "option_list": option_list,
        "error": error,
        **csrf_context(request),
    }


@router.get("")
def list_licences(request: Request, q: str = Query("", max_length=200), licence_type: str = Query("", max_length=120), db: Session = Depends(get_db), user=Depends(require_user)):
    query = db.query(Licence)
    licence_types = list_values(db, MODULE).get("licence_type", [])
    active_licence_type = licence_type.strip()
    if active_licence_type:
        query = query.filter(Licence.licence_type == active_licence_type)
    clean_q = q.strip()
    if clean_q:
        like = f"%{clean_q}%"
        query = query.filter(or_(Licence.product.ilike(like), Licence.licence_type.ilike(like), Licence.licence_id.ilike(like), Licence.vendor.ilike(like)))
    rows = query.order_by(Licence.product.asc()).limit(500).all()
    favourites = db.query(Licence).filter(Licence.is_favourite == True).order_by(Licence.product.asc()).limit(50).all()
    total = db.query(Licence).count()
    return templates.TemplateResponse(request, "licences.html", {"user": user, "rows": rows, "favourites": favourites, "total": total, "q": clean_q, "licence_types": licence_types, "active_licence_type": active_licence_type, "mask_key": lambda encrypted: mask_key(decrypt_secret(encrypted)), **csrf_context(request)})


@router.get("/new")
def new_licence(request: Request, db: Session = Depends(get_db), user=Depends(require_editor)):
    return templates.TemplateResponse(request, "licence_form.html", form_context(db, request, user))


@router.post("/new")
async def create_licence(request: Request, product: str = Form(..., max_length=500), product_key: str = Form(..., max_length=500), licence_type: str = Form("", max_length=120), seats: int = Form(0, ge=0, le=1000000), is_favourite: str = Form(""), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    form = await request.form()
    fields = active_fields(db, MODULE)
    custom_error = validate_custom_values(fields, form)
    if custom_error:
        return templates.TemplateResponse(request, "licence_form.html", form_context(db, request, user, product_key=product_key, error=custom_error), status_code=400)
    product = product.strip()
    product_key = product_key.strip()
    if not product or not product_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Product and product key are required")
    lists = list_values(db, MODULE)
    row = Licence(product=product, encrypted_product_key=encrypt_secret(product_key), organisation=None, licence_type=clean_list_value(licence_type, lists.get("licence_type", [])), seats=seats, is_favourite=bool(is_favourite), notes=notes.strip() or None)
    db.add(row)
    db.commit()
    db.refresh(row)
    save_custom_values(db, fields, form, ENTITY_TYPE, row.id)
    db.commit()
    write_audit(db, user, "create", "licence", str(row.id), request.client.host if request.client else None)
    return RedirectResponse("/licences", status_code=303)


@router.get("/{licence_id}/edit")
def edit_licence(request: Request, licence_id: int, db: Session = Depends(get_db), user=Depends(require_editor)):
    row = db.get(Licence, licence_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Licence not found")
    return templates.TemplateResponse(request, "licence_form.html", form_context(db, request, user, licence=row, product_key=decrypt_secret(row.encrypted_product_key)))


@router.post("/{licence_id}/edit")
async def update_licence(request: Request, licence_id: int, product: str = Form(..., max_length=500), product_key: str = Form("", max_length=500), licence_type: str = Form("", max_length=120), seats: int = Form(0, ge=0, le=1000000), is_favourite: str = Form(""), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(Licence, licence_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Licence not found")
    form = await request.form()
    fields = active_fields(db, MODULE)
    custom_error = validate_custom_values(fields, form)
    if custom_error:
        return templates.TemplateResponse(request, "licence_form.html", form_context(db, request, user, licence=row, product_key=product_key, error=custom_error), status_code=400)
    product = product.strip()
    product_key = product_key.strip()
    if not product:
        return templates.TemplateResponse(request, "licence_form.html", form_context(db, request, user, licence=row, product_key=product_key, error="Product is required."), status_code=400)
    lists = list_values(db, MODULE)
    row.product = product
    if product_key:
        row.encrypted_product_key = encrypt_secret(product_key)
    row.organisation = None
    row.licence_type = clean_list_value(licence_type, lists.get("licence_type", []), row.licence_type)
    row.seats = seats
    row.is_favourite = bool(is_favourite)
    row.notes = notes.strip() or None
    db.commit()
    save_custom_values(db, fields, form, ENTITY_TYPE, row.id)
    db.commit()
    write_audit(db, user, "update", "licence", str(row.id), request.client.host if request.client else None, detail=product)
    return RedirectResponse(f"/licences/{row.id}", status_code=303)


@router.get("/{licence_id}")
def detail(request: Request, licence_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = db.get(Licence, licence_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Licence not found")
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    lists = list_values(db, MODULE)
    return templates.TemplateResponse(request, "licence_detail.html", {"user": user, "licence": row, "display_key": mask_key(decrypt_secret(row.encrypted_product_key)), "product_key_edit": "", "revealed": False, "licence_types": lists.get("licence_type", []), "custom_fields": fields, "custom_values": values, "option_list": option_list, **csrf_context(request)})


@router.post("/{licence_id}/reveal")
def reveal(request: Request, licence_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(Licence, licence_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Licence not found")
    write_audit(db, user, "reveal", "licence", str(row.id), request.client.host if request.client else None)
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    lists = list_values(db, MODULE)
    product_key = decrypt_secret(row.encrypted_product_key)
    return templates.TemplateResponse(request, "licence_detail.html", {"user": user, "licence": row, "display_key": product_key, "product_key_edit": product_key, "revealed": True, "licence_types": lists.get("licence_type", []), "custom_fields": fields, "custom_values": values, "option_list": option_list, **csrf_context(request)})
