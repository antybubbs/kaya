import shutil
from io import BytesIO
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette import status
from PIL import Image, ImageOps, UnidentifiedImageError

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.templating import templates
from app.db.session import get_db
from app.models.models import (
    CustomFieldValue,
    DNSRecognisedDevice,
    HardwareAsset,
    HardwareAssetAttachment,
    RackItem,
)
from app.routers.auth import require_editor, require_module_access, require_user
from app.services.audit import write_audit
from app.services.custom_fields import (
    active_fields,
    field_values,
    option_list,
    save_custom_values,
    validate_custom_values,
)
from app.services.client_ip import client_ip as trusted_client_ip
from app.services.managed_lists import list_values
from app.services.table_export import (
    export_row_matches,
    table_export_response,
    validate_export_columns,
    validate_export_filters,
    validate_export_format,
)

router = APIRouter(prefix="/infrastructure/asset-manager", dependencies=[Depends(require_module_access("asset_manager"))])

MODULE = "hardware_assets"
ENTITY_TYPE = "hardware_asset"
ALLOWED_PHOTO_TYPES = {
    ".gif": ("image/gif", (b"GIF87a", b"GIF89a")),
    ".jpg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".jpeg": ("image/jpeg", (b"\xff\xd8\xff",)),
    ".png": ("image/png", (b"\x89PNG\r\n\x1a\n",)),
    ".webp": ("image/webp", (b"RIFF",)),
}
MAX_PHOTO_DIMENSION = 2400


def validate_photo_upload(filename: str, data: bytes) -> str:
    suffix = Path(filename).suffix.lower()
    allowed = ALLOWED_PHOTO_TYPES.get(suffix)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Photo must be a PNG, JPEG, GIF, or WebP image.")
    content_type, signatures = allowed
    if suffix == ".webp":
        if len(data) < 12 or not data.startswith(b"RIFF") or data[8:12] != b"WEBP":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Photo file content does not match its image type.")
    elif not any(data.startswith(signature) for signature in signatures):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Photo file content does not match its image type.")
    try:
        with Image.open(BytesIO(data)) as image:
            image.verify()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Photo file is not a valid image.") from exc
    return content_type


def process_photo(data: bytes, content_type: str) -> bytes:
    """Normalize camera images while preserving the original supported format."""
    if content_type == "image/gif":
        return data
    try:
        with Image.open(BytesIO(data)) as source:
            image = ImageOps.exif_transpose(source)
            if max(image.size) > MAX_PHOTO_DIMENSION:
                image.thumbnail((MAX_PHOTO_DIMENSION, MAX_PHOTO_DIMENSION), Image.Resampling.LANCZOS)
            output = BytesIO()
            if content_type == "image/jpeg":
                image.convert("RGB").save(output, format="JPEG", quality=88, optimize=True)
            elif content_type == "image/png":
                image.save(output, format="PNG", optimize=True)
            else:
                image.save(output, format="WEBP", quality=88, method=6)
            return output.getvalue()
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Photo could not be processed.") from exc


def parse_date(value: str):
    value = value.strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enter dates as YYYY-MM-DD.") from exc


def asset_upload_dir(asset_id: int, *, create: bool = False) -> Path:
    path = Path(get_settings().upload_dir) / "hardware_assets" / str(asset_id)
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def stored_upload_path(asset_id: int, filename: str) -> Path:
    """Resolve a generated upload name without allowing path traversal."""
    root = asset_upload_dir(asset_id).resolve()
    candidate = (root / filename).resolve()
    if not filename or Path(filename).name != filename or candidate.parent != root:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Uploaded file not found")
    return candidate


async def save_upload(upload: UploadFile | None, asset_id: int, prefix: str, image_only: bool = False) -> tuple[str, str, str | None] | None:
    if not upload or not upload.filename:
        return None
    content_type = upload.content_type or "application/octet-stream"
    data = await upload.read(get_settings().max_upload_mb * 1024 * 1024 + 1)
    if len(data) > get_settings().max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"File is larger than {get_settings().max_upload_mb} MB.")
    suffix = Path(upload.filename).suffix.lower()
    if image_only:
        content_type = validate_photo_upload(upload.filename, data)
        data = process_photo(data, content_type)
    stored = f"{prefix}-{uuid4().hex}{suffix}"
    path = asset_upload_dir(asset_id, create=True) / stored
    path.write_bytes(data)
    return upload.filename, stored, content_type


def template_context(db: Session, request: Request, user, record=None, error=None):
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, record.id) if record else {}
    lists = list_values(db, MODULE)
    return {
        "user": user,
        "record": record,
        "categories": lists.get("category", []),
        "locations": lists.get("location", []),
        "statuses": lists.get("status", []),
        "custom_fields": fields,
        "custom_values": values,
        "option_list": option_list,
        "error": error,
        **csrf_context(request),
    }


def clean_managed_value(value: str, allowed: list[str], current: str | None = None) -> str | None:
    clean = value.strip()
    if clean in allowed or (current and clean == current):
        return clean
    return None


@router.get("")
def list_assets(request: Request, q: str = Query("", max_length=200), category: str = Query("", max_length=120), db: Session = Depends(get_db), user=Depends(require_user)):
    query = db.query(HardwareAsset)
    categories = list_values(db, MODULE).get("category", [])
    active_category = category.strip()
    if active_category:
        query = query.filter(HardwareAsset.category == active_category)
    clean_q = q.strip()
    if clean_q:
        like = f"%{clean_q}%"
        query = query.filter(or_(HardwareAsset.asset_tag.ilike(like), HardwareAsset.name.ilike(like), HardwareAsset.category.ilike(like), HardwareAsset.status.ilike(like), HardwareAsset.manufacturer.ilike(like), HardwareAsset.model.ilike(like), HardwareAsset.serial_number.ilike(like), HardwareAsset.location.ilike(like)))
    rows = query.order_by(HardwareAsset.name.asc()).limit(500).all()
    total = db.query(HardwareAsset).count()
    return templates.TemplateResponse(request, "hardware_assets.html", {"user": user, "rows": rows, "total": total, "q": clean_q, "categories": categories, "active_category": active_category, **csrf_context(request)})


@router.get("/export")
def export_assets_table(
    request: Request,
    q: str = Query("", max_length=200),
    category: str = Query("", max_length=120),
    format: str = Query("csv", max_length=8),
    columns: str = Query("", max_length=300),
    filters: str = Query("", max_length=2000),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    format = validate_export_format(format)
    column_map = {
        "asset-tag": ("Asset Tag", lambda row: row.asset_tag or ""),
        "name": ("Name", lambda row: row.name),
        "category": ("Category", lambda row: row.category or ""),
        "status": ("Status", lambda row: row.status or ""),
        "location": ("Location", lambda row: row.location or ""),
        "warranty": ("Warranty", lambda row: row.warranty_expires.isoformat() if row.warranty_expires else ""),
    }
    selected_columns = validate_export_columns(columns, list(column_map))
    active_filters = validate_export_filters(filters, list(column_map))
    query = db.query(HardwareAsset)
    active_category = category.strip()
    if active_category:
        query = query.filter(HardwareAsset.category == active_category)
    clean_q = q.strip()
    if clean_q:
        like = f"%{clean_q}%"
        query = query.filter(or_(HardwareAsset.asset_tag.ilike(like), HardwareAsset.name.ilike(like), HardwareAsset.category.ilike(like), HardwareAsset.status.ilike(like), HardwareAsset.manufacturer.ilike(like), HardwareAsset.model.ilike(like), HardwareAsset.serial_number.ilike(like), HardwareAsset.location.ilike(like)))
    rows = query.order_by(HardwareAsset.name.asc()).limit(100000).all()
    rows = [row for row in rows if export_row_matches(row, column_map, active_filters)]
    write_audit(
        db, user, "export", "hardware_asset", None, trusted_client_ip(request),
        detail=f"Exported {len(rows)} asset rows as {format}; filters applied={bool(clean_q or active_category)}",
    )
    return table_export_response(
        table_name="hardware-assets",
        headers=[column_map[key][0] for key in selected_columns],
        rows=([column_map[key][1](row) for key in selected_columns] for row in rows),
        export_format=format,
    )


@router.get("/new")
def new_asset(request: Request, db: Session = Depends(get_db), user=Depends(require_editor)):
    return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user))


@router.post("/new")
async def create_asset(request: Request, asset_tag: str = Form("", max_length=120), name: str = Form(..., max_length=255), category: str = Form("", max_length=120), asset_status: str = Form(""), manufacturer: str = Form("", max_length=255), model: str = Form("", max_length=255), serial_number: str = Form("", max_length=255), location: str = Form("", max_length=255), purchase_date: str = Form(""), purchase_cost: str = Form("", max_length=80), warranty_expires: str = Form(""), supplier: str = Form("", max_length=255), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), photo: UploadFile | None = File(None), attachment: UploadFile | None = File(None), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    form = await request.form()
    fields = active_fields(db, MODULE)
    custom_error = validate_custom_values(fields, form)
    if custom_error:
        return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, error=custom_error), status_code=400)
    if not name.strip():
        return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, error="Asset name is required."), status_code=400)
    clean_asset_tag = asset_tag.strip() or None
    if clean_asset_tag and db.query(HardwareAsset).filter(HardwareAsset.asset_tag == clean_asset_tag).first():
        return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, error="That asset tag already exists."), status_code=400)
    lists = list_values(db, MODULE)
    category_value = clean_managed_value(category, lists.get("category", []))
    location_value = clean_managed_value(location, lists.get("location", []))
    status_values = lists.get("status", [])
    status_value = clean_managed_value(asset_status, status_values) or (status_values[0] if status_values else "In use")
    row = HardwareAsset(asset_tag=clean_asset_tag, name=name.strip(), category=category_value, status=status_value, manufacturer=manufacturer.strip() or None, model=model.strip() or None, serial_number=serial_number.strip() or None, location=location_value, assigned_to=None, purchase_date=parse_date(purchase_date), purchase_cost=purchase_cost.strip() or None, warranty_expires=parse_date(warranty_expires), supplier=supplier.strip() or None, notes=notes.strip() or None)
    db.add(row)
    db.commit()
    db.refresh(row)
    saved_photo = await save_upload(photo, row.id, "photo", image_only=True)
    if saved_photo:
        row.photo_filename = saved_photo[1]
    saved_attachment = await save_upload(attachment, row.id, "attachment")
    if saved_attachment:
        db.add(HardwareAssetAttachment(asset_id=row.id, original_filename=saved_attachment[0], stored_filename=saved_attachment[1], content_type=saved_attachment[2]))
    save_custom_values(db, fields, form, ENTITY_TYPE, row.id)
    db.commit()
    write_audit(db, user, "create", "hardware_asset", str(row.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse(f"/infrastructure/asset-manager/{row.id}", status_code=303)


@router.get("/{asset_id}")
def detail_asset(request: Request, asset_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    attachments = db.query(HardwareAssetAttachment).filter(HardwareAssetAttachment.asset_id == row.id).order_by(HardwareAssetAttachment.uploaded_at.desc()).all()
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    lists = list_values(db, MODULE)
    return templates.TemplateResponse(request, "hardware_asset_detail.html", {"user": user, "record": row, "attachments": attachments, "categories": lists.get("category", []), "locations": lists.get("location", []), "statuses": lists.get("status", []), "custom_fields": fields, "custom_values": values, "option_list": option_list, **csrf_context(request)})


@router.get("/{asset_id}/edit")
def edit_asset(request: Request, asset_id: int, db: Session = Depends(get_db), user=Depends(require_editor)):
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, record=row))


@router.post("/{asset_id}/edit")
async def update_asset(request: Request, asset_id: int, asset_tag: str = Form("", max_length=120), name: str = Form(..., max_length=255), category: str = Form("", max_length=120), asset_status: str = Form(""), manufacturer: str = Form("", max_length=255), model: str = Form("", max_length=255), serial_number: str = Form("", max_length=255), location: str = Form("", max_length=255), purchase_date: str = Form(""), purchase_cost: str = Form("", max_length=80), warranty_expires: str = Form(""), supplier: str = Form("", max_length=255), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), photo: UploadFile | None = File(None), attachment: UploadFile | None = File(None), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    form = await request.form()
    fields = active_fields(db, MODULE)
    custom_error = validate_custom_values(fields, form)
    if custom_error:
        return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, record=row, error=custom_error), status_code=400)
    if not name.strip():
        return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, record=row, error="Asset name is required."), status_code=400)
    clean_asset_tag = asset_tag.strip() or None
    if clean_asset_tag and db.query(HardwareAsset).filter(HardwareAsset.asset_tag == clean_asset_tag, HardwareAsset.id != row.id).first():
        return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, record=row, error="That asset tag already exists."), status_code=400)
    lists = list_values(db, MODULE)
    status_values = lists.get("status", [])
    row.asset_tag = clean_asset_tag
    row.name = name.strip()
    row.category = clean_managed_value(category, lists.get("category", []), row.category)
    row.status = clean_managed_value(asset_status, status_values, row.status) or (status_values[0] if status_values else "In use")
    row.manufacturer = manufacturer.strip() or None
    row.model = model.strip() or None
    row.serial_number = serial_number.strip() or None
    row.location = clean_managed_value(location, lists.get("location", []), row.location)
    row.assigned_to = None
    row.purchase_date = parse_date(purchase_date)
    row.purchase_cost = purchase_cost.strip() or None
    row.warranty_expires = parse_date(warranty_expires)
    row.supplier = supplier.strip() or None
    row.notes = notes.strip() or None
    old_photo_filename = row.photo_filename
    saved_photo = await save_upload(photo, row.id, "photo", image_only=True)
    if saved_photo:
        row.photo_filename = saved_photo[1]
    saved_attachment = await save_upload(attachment, row.id, "attachment")
    if saved_attachment:
        db.add(HardwareAssetAttachment(asset_id=row.id, original_filename=saved_attachment[0], stored_filename=saved_attachment[1], content_type=saved_attachment[2]))
    save_custom_values(db, fields, form, ENTITY_TYPE, row.id)
    db.commit()
    if saved_photo and old_photo_filename and old_photo_filename != row.photo_filename:
        stored_upload_path(row.id, old_photo_filename).unlink(missing_ok=True)
    write_audit(db, user, "update", "hardware_asset", str(row.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse(f"/infrastructure/asset-manager/{row.id}", status_code=303)


@router.post("/{asset_id}/attachments")
async def upload_attachment(request: Request, asset_id: int, csrf_token: str = Form(...), attachment: UploadFile = File(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    saved_attachment = await save_upload(attachment, row.id, "attachment")
    if saved_attachment:
        db.add(HardwareAssetAttachment(asset_id=row.id, original_filename=saved_attachment[0], stored_filename=saved_attachment[1], content_type=saved_attachment[2]))
        db.commit()
        write_audit(db, user, "upload_attachment", "hardware_asset", str(row.id), request.client.host if request.client else None, detail=saved_attachment[0])
    return RedirectResponse(f"/infrastructure/asset-manager/{row.id}", status_code=303)


@router.get("/{asset_id}/photo")
def asset_photo(asset_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = db.get(HardwareAsset, asset_id)
    if not row or not row.photo_filename:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Photo not found")
    path = stored_upload_path(row.id, row.photo_filename)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Photo not found")
    return FileResponse(path)


@router.post("/{asset_id}/photo")
async def upload_photo(request: Request, asset_id: int, csrf_token: str = Form(...), photo: UploadFile = File(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    old_photo_filename = row.photo_filename
    saved_photo = await save_upload(photo, row.id, "photo", image_only=True)
    if not saved_photo:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose a photo to upload.")
    row.photo_filename = saved_photo[1]
    try:
        db.commit()
    except Exception:
        stored_upload_path(row.id, saved_photo[1]).unlink(missing_ok=True)
        raise
    if old_photo_filename and old_photo_filename != row.photo_filename:
        stored_upload_path(row.id, old_photo_filename).unlink(missing_ok=True)
    write_audit(db, user, "upload_photo", "hardware_asset", str(row.id), request.client.host if request.client else None)
    return RedirectResponse(f"/infrastructure/asset-manager/{row.id}", status_code=303)


@router.post("/{asset_id}/photo/delete")
def delete_photo(request: Request, asset_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    old_photo_filename = row.photo_filename
    row.photo_filename = None
    db.commit()
    if old_photo_filename:
        stored_upload_path(row.id, old_photo_filename).unlink(missing_ok=True)
    write_audit(db, user, "delete_photo", "hardware_asset", str(row.id), request.client.host if request.client else None)
    return RedirectResponse(f"/infrastructure/asset-manager/{row.id}", status_code=303)


@router.get("/{asset_id}/attachments/{attachment_id}")
def download_attachment(asset_id: int, attachment_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = db.get(HardwareAssetAttachment, attachment_id)
    if not row or row.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment not found")
    path = stored_upload_path(asset_id, row.stored_filename)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment not found")
    return FileResponse(path, media_type="application/octet-stream", filename=row.original_filename)


@router.post("/{asset_id}/attachments/{attachment_id}/delete")
def delete_attachment(request: Request, asset_id: int, attachment_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(HardwareAssetAttachment, attachment_id)
    if not row or row.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment not found")
    filename = row.original_filename
    path = stored_upload_path(asset_id, row.stored_filename)
    db.delete(row)
    db.commit()
    path.unlink(missing_ok=True)
    write_audit(db, user, "delete_attachment", "hardware_asset", str(asset_id), request.client.host if request.client else None, detail=filename)
    return RedirectResponse(f"/infrastructure/asset-manager/{asset_id}", status_code=303)


@router.post("/{asset_id}/delete")
def delete_asset(request: Request, asset_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    name = row.name
    db.query(RackItem).filter(RackItem.hardware_asset_id == row.id).update(
        {RackItem.hardware_asset_id: None}, synchronize_session=False
    )
    db.query(DNSRecognisedDevice).filter(DNSRecognisedDevice.hardware_asset_id == row.id).update(
        {DNSRecognisedDevice.hardware_asset_id: None}, synchronize_session=False
    )
    db.query(CustomFieldValue).filter(
        CustomFieldValue.entity_type == ENTITY_TYPE,
        CustomFieldValue.entity_id == row.id,
    ).delete(synchronize_session=False)
    db.query(HardwareAssetAttachment).filter(HardwareAssetAttachment.asset_id == row.id).delete(synchronize_session=False)
    db.delete(row)
    db.commit()
    shutil.rmtree(Path(get_settings().upload_dir) / "hardware_assets" / str(asset_id), ignore_errors=True)
    write_audit(db, user, "delete", "hardware_asset", str(asset_id), request.client.host if request.client else None, detail=name)
    return RedirectResponse("/infrastructure/asset-manager", status_code=303)
