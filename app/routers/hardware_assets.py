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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette import status
from PIL import Image, ImageOps, UnidentifiedImageError

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.formatting import human_bytes
from app.core.templating import templates
from app.db.session import get_db
from app.models.models import (
    AssetIdentityEvidence,
    AssetNetworkAssignment,
    CustomFieldValue,
    DHCPLeaseHistory,
    DNSRecognisedDevice,
    HardwareAsset,
    HardwareAssetAttachment,
    HardwareAssetPhoto,
    IPAddress,
    RackItem,
    TrafficDiscoveryNetworkMapping,
    TrafficSource,
    VLAN,
    TrafficDiscoveryLink,
)
from app.routers.auth import require_admin, require_editor, require_module_access, require_user
from app.services.audit import write_audit
from app.services.asset_tags import allocate_asset_tag, asset_tag_settings, next_asset_tag_preview
from app.services.asset_identity import (
    MANAGED_HOSTNAME_SOURCE,
    close_network_assignment,
    confirm_existing_identity_evidence,
    confirm_existing_network_assignment,
    assign_network_identity,
    eligible_traffic_contexts,
    revoke_identity_evidence,
)
from app.services.asset_identity_resolution import evidence_for_asset
from app.services.asset_profile_reporting import asset_reporting_context
from app.services.asset_discovery import compose_discovered_devices, get_discovered_device, adopt_discovered_device
from app.services.device_traffic import asset_monitoring_status, set_asset_monitoring
from app.services.custom_fields import (
    active_fields,
    field_values,
    option_list,
    save_custom_values,
    validate_custom_values,
)
from app.services.client_ip import client_ip as trusted_client_ip
from app.services.managed_lists import list_values
from app.services.modules import has_module_access
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
MAX_PHOTO_DIMENSION = 1800
MAX_PHOTO_COUNT = 5
PHOTO_THUMB_DIMENSION = 320


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


def process_photo(data: bytes, content_type: str) -> tuple[bytes, bytes]:
    """Normalize a photo to WebP and generate a compact thumbnail."""
    try:
        with Image.open(BytesIO(data)) as source:
            image = ImageOps.exif_transpose(source)
            if max(image.size) > MAX_PHOTO_DIMENSION:
                image.thumbnail((MAX_PHOTO_DIMENSION, MAX_PHOTO_DIMENSION), Image.Resampling.LANCZOS)
            if image.mode not in {"RGB", "RGBA"}:
                image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
            main = BytesIO()
            image.save(main, format="WEBP", quality=84, method=6)
            thumb_image = image.copy()
            thumb_image.thumbnail((PHOTO_THUMB_DIMENSION, PHOTO_THUMB_DIMENSION), Image.Resampling.LANCZOS)
            thumbnail = BytesIO()
            thumb_image.save(thumbnail, format="WEBP", quality=80, method=6)
            return main.getvalue(), thumbnail.getvalue()
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
    if asset_id <= 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")

    root = (Path(get_settings().upload_dir) / "hardware_assets").resolve()
    path = (root / str(asset_id)).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found") from exc

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


async def save_upload(upload: UploadFile | None, asset_id: int, prefix: str, image_only: bool = False) -> tuple[str, str, str | None, str | None] | None:
    if not upload or not upload.filename:
        return None
    original_filename = Path(upload.filename).name[:255] or "uploaded-file"
    content_type = upload.content_type or "application/octet-stream"
    data = await upload.read(get_settings().max_upload_mb * 1024 * 1024 + 1)
    if len(data) > get_settings().max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"File is larger than {get_settings().max_upload_mb} MB.")
    suffix = Path(upload.filename).suffix.lower()
    if image_only:
        content_type = validate_photo_upload(upload.filename, data)
        data, thumbnail = process_photo(data, content_type)
        stored = f"photo-{uuid4().hex}.webp"
        thumbnail_stored = f"{stored[:-5]}-thumb.webp"
    else:
        thumbnail = None
        stored = f"{prefix}-{uuid4().hex}{suffix}"
        thumbnail_stored = None
    path = asset_upload_dir(asset_id, create=True) / stored
    thumbnail_path = asset_upload_dir(asset_id, create=True) / thumbnail_stored if thumbnail_stored else None
    try:
        path.write_bytes(data)
        if thumbnail_path and thumbnail is not None:
            thumbnail_path.write_bytes(thumbnail)
    except OSError:
        path.unlink(missing_ok=True)
        if thumbnail_path:
            thumbnail_path.unlink(missing_ok=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Photo could not be stored.")
    return original_filename, stored, "image/webp" if image_only else content_type, thumbnail_stored


def add_photo_record(db: Session, asset_id: int, saved_photo: tuple[str, str, str | None, str | None]) -> HardwareAssetPhoto:
    current_count = db.query(HardwareAssetPhoto).filter(HardwareAssetPhoto.asset_id == asset_id).count()
    if current_count >= MAX_PHOTO_COUNT:
        stored_upload_path(asset_id, saved_photo[1]).unlink(missing_ok=True)
        if saved_photo[3]:
            stored_upload_path(asset_id, saved_photo[3]).unlink(missing_ok=True)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Each asset can have up to five photos.")
    photo = HardwareAssetPhoto(
        asset_id=asset_id,
        original_filename=saved_photo[0],
        storage_filename=saved_photo[1],
        content_type=saved_photo[2] or "image/webp",
        thumbnail_filename=saved_photo[3],
        is_primary=current_count == 0,
        sort_order=current_count,
    )
    db.add(photo)
    return photo


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
        "asset_tag_auto_generate": asset_tag_settings(db)["asset_tags_auto_generate"] == "1",
        "asset_tag_preview": next_asset_tag_preview(db),
        "error": error,
        **csrf_context(request),
    }


def clean_managed_value(value: str, allowed: list[str], current: str | None = None) -> str | None:
    clean = value.strip()
    if clean in allowed or (current and clean == current):
        return clean
    return None


def bytes_label(value: int | None) -> str:
    return human_bytes(value, unknown="-")


def preferred_hostname_evidence(identity_rows: list[AssetIdentityEvidence]) -> AssetIdentityEvidence | None:
    """Pick the displayed hostname deterministically from newest-first evidence.

    A confirmed managed IP/VLAN Manager hostname outranks observed DHCP/DNS
    names; otherwise the newest confirmed hostname, then the newest suggestion.
    """
    hosts = [row for row in identity_rows if row.evidence_type == "hostname"]
    confirmed = [row for row in hosts if row.status == "confirmed"]
    managed = [row for row in confirmed if row.source == MANAGED_HOSTNAME_SOURCE]
    return next(iter(managed or confirmed or hosts), None)


def asset_profile_context(db: Session, user, asset: HardwareAsset) -> dict:
    """Build a permission-aware, bounded profile without calling providers."""
    can_dns = has_module_access(db, user, "dns_manager")
    can_network = has_module_access(db, user, "network_monitor")
    can_vlan = has_module_access(db, user, "vlan_ip_manager")
    identity_rows = db.query(AssetIdentityEvidence).filter(
        AssetIdentityEvidence.asset_id == asset.id,
    ).order_by(AssetIdentityEvidence.id.desc()).limit(100).all()
    assignment_rows = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.asset_id == asset.id,
    ).order_by(AssetNetworkAssignment.started_at.desc()).limit(100).all()
    validity = evidence_for_asset(db, asset.id, limit=100)
    valid_assignment_keys = {
        (item.normalised_reference, item.vlan_id, item.exporter_identity)
        for item in validity["current"]
        if item.evidence_type == "network_assignment"
    }
    for row in assignment_rows:
        row.profile_validity = "valid" if (
            row.address,
            row.vlan_id,
            row.exporter_identity,
        ) in valid_assignment_keys else "stale"

    dns_clients = []
    dhcp_leases = []
    managed_ips = []
    discovery_links = []
    if can_dns:
        dns_clients = db.query(DNSRecognisedDevice).filter(
            DNSRecognisedDevice.hardware_asset_id == asset.id,
        ).order_by(DNSRecognisedDevice.last_seen_at.desc()).limit(100).all()
        client_ids = [row.id for row in dns_clients]
        lease_query = db.query(DHCPLeaseHistory).filter(
            DHCPLeaseHistory.dns_client_id.in_(client_ids),
        ) if client_ids else None
        if lease_query is not None:
            dhcp_leases = lease_query.order_by(DHCPLeaseHistory.last_seen_at.desc()).limit(100).all()
    if can_vlan:
        ip_ids = {row.ip_address_id for row in assignment_rows if row.ip_address_id is not None}
        ip_ids.update(row.linked_ip_record_id for row in dns_clients if row.linked_ip_record_id is not None)
        if ip_ids:
            managed_ips = db.query(IPAddress).filter(IPAddress.id.in_(ip_ids)).order_by(IPAddress.address).limit(100).all()
    if can_network and managed_ips:
        managed_ip_ids = [row.id for row in managed_ips]
        discovery_links = db.query(TrafficDiscoveryLink).filter(
            TrafficDiscoveryLink.managed_ip_address_id.in_(managed_ip_ids),
        ).order_by(TrafficDiscoveryLink.updated_at.desc()).limit(100).all()
    if can_dns:
        lease_ids = {row.dhcp_lease_id for row in assignment_rows if row.dhcp_lease_id is not None}
        if lease_ids:
            existing_ids = {row.id for row in dhcp_leases}
            extra_leases = db.query(DHCPLeaseHistory).filter(
                DHCPLeaseHistory.id.in_(lease_ids - existing_ids),
            ).order_by(DHCPLeaseHistory.last_seen_at.desc()).limit(100).all()
            dhcp_leases.extend(extra_leases)
    traffic_monitoring = asset_monitoring_status(db, asset.id) if can_network else None
    traffic_context_options = []
    if can_network and can_vlan and user.role == "admin":
        seen_contexts = set()
        for assignment in assignment_rows:
            if assignment.status == "confirmed" and assignment.ended_at is None:
                for option in eligible_traffic_contexts(db, assignment.address):
                    key = (option["mapping_id"], option["address"])
                    if key not in seen_contexts:
                        seen_contexts.add(key)
                        traffic_context_options.append(option)
    return {
        "identity_rows": identity_rows,
        "preferred_hostname": preferred_hostname_evidence(identity_rows),
        "assignment_rows": assignment_rows,
        "dns_clients": dns_clients if can_dns else None,
        "dhcp_leases": dhcp_leases if can_dns else None,
        "managed_ips": managed_ips if can_vlan else None,
        "discovery_links": discovery_links if can_network else None,
        "can_dns": can_dns,
        "can_network": can_network,
        "can_vlan": can_vlan,
        "traffic_monitoring": traffic_monitoring,
        "traffic_context_options": traffic_context_options,
    }


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


@router.get("/discovered")
def list_discovered_devices(request: Request, q: str = Query("", max_length=120), source: str = Query("", max_length=120), state: str = Query("", max_length=20), page: int = Query(1, ge=1, le=10000), db: Session = Depends(get_db), user=Depends(require_user)):
    result = compose_discovered_devices(db, query=q, source=source, state=state, page=page, page_size=50)
    return templates.TemplateResponse(request, "hardware_discovered_devices.html", {"user": user, "result": result, "q": q.strip(), "source": source.strip(), "state": state.strip(), **csrf_context(request)})


@router.get("/discovered/review")
def review_discovered_device(request: Request, candidate_id: str = Query(..., min_length=3, max_length=255), db: Session = Depends(get_db), user=Depends(require_user)):
    candidate = get_discovered_device(db, candidate_id.strip())
    if not candidate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovered device not found")
    assets = db.query(HardwareAsset).order_by(HardwareAsset.name.asc()).limit(500).all()
    return templates.TemplateResponse(request, "hardware_discovered_device_review.html", {"user": user, "candidate": candidate, "assets": assets, **csrf_context(request)})


def _adoption_review_response(request: Request, candidate_id: str, db: Session, user, *, error: str, asset_id: int | None, new_name: str, category: str, status_code: int):
    candidate = get_discovered_device(db, candidate_id.strip())
    if not candidate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovered device not found")
    assets = db.query(HardwareAsset).order_by(HardwareAsset.name.asc()).limit(500).all()
    return templates.TemplateResponse(
        request,
        "hardware_discovered_device_review.html",
        {
            "user": user,
            "candidate": candidate,
            "assets": assets,
            "error": error,
            "selected_asset_id": asset_id,
            "new_name": new_name,
            "category": category,
            **csrf_context(request),
        },
        status_code=status_code,
    )


@router.post("/discovered/adopt")
def adopt_discovered_device_route(request: Request, candidate_id: str = Form(..., max_length=255), asset_id: int | None = Form(None), new_name: str = Form("", max_length=255), category: str = Form("", max_length=120), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    candidate = get_discovered_device(db, candidate_id.strip())
    if not candidate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovered device not found")
    category = category.strip()
    if category and category not in list_values(db, MODULE).get("category", []):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose a valid managed asset category.")
    try:
        asset = adopt_discovered_device(db, user, candidate, asset_id=asset_id, new_name=new_name, category=category)
    except (ValueError, PermissionError) as exc:
        db.rollback()
        return _adoption_review_response(
            request,
            candidate_id,
            db,
            user,
            error=str(exc),
            asset_id=asset_id,
            new_name=new_name,
            category=category,
            status_code=status.HTTP_409_CONFLICT,
        )
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Adoption could not be completed because the audit record was not saved. Please retry.",
        ) from exc
    return RedirectResponse(f"/infrastructure/asset-manager/{asset.id}", status_code=303)


@router.post("/discovered/dismiss")
def dismiss_discovered_device(request: Request, candidate_id: str = Form(..., max_length=255), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    candidate = get_discovered_device(db, candidate_id.strip())
    if not candidate:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovered device not found")
    if candidate["kind"] != "dns" or not candidate.get("dns_client_id"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This source does not provide a persistent dismissal state.")
    row = db.get(DNSRecognisedDevice, candidate["dns_client_id"])
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery source record not found")
    row.is_ignored = True
    audit = write_audit(db, user, "dismiss", "discovered_device", candidate["id"], request.client.host if request.client else None, detail="Dismissed a DNS discovery from Asset Manager", commit=False)
    if audit is None:
        db.rollback()
        raise HTTPException(status_code=500, detail="The dismissal could not be audited.")
    db.commit()
    return RedirectResponse("/infrastructure/asset-manager/discovered", status_code=303)


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
    try:
        clean_asset_tag = allocate_asset_tag(db, clean_asset_tag)
    except ValueError as exc:
        db.rollback()
        return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, error=str(exc)), status_code=400)
    lists = list_values(db, MODULE)
    category_value = clean_managed_value(category, lists.get("category", []))
    location_value = clean_managed_value(location, lists.get("location", []))
    status_values = lists.get("status", [])
    status_value = clean_managed_value(asset_status, status_values) or (status_values[0] if status_values else "In use")
    row = HardwareAsset(asset_tag=clean_asset_tag, name=name.strip(), category=category_value, status=status_value, manufacturer=manufacturer.strip() or None, model=model.strip() or None, serial_number=serial_number.strip() or None, location=location_value, assigned_to=None, purchase_date=parse_date(purchase_date), purchase_cost=purchase_cost.strip() or None, warranty_expires=parse_date(warranty_expires), supplier=supplier.strip() or None, notes=notes.strip() or None)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, error="That asset tag already exists."), status_code=400)
    db.refresh(row)
    saved_photo = await save_upload(photo, row.id, "photo", image_only=True)
    if saved_photo:
        add_photo_record(db, row.id, saved_photo)
    saved_attachment = await save_upload(attachment, row.id, "attachment")
    if saved_attachment:
        db.add(HardwareAssetAttachment(asset_id=row.id, original_filename=saved_attachment[0], stored_filename=saved_attachment[1], content_type=saved_attachment[2]))
    save_custom_values(db, fields, form, ENTITY_TYPE, row.id)
    db.commit()
    write_audit(db, user, "create", "hardware_asset", str(row.id), request.client.host if request.client else None, detail=row.name)
    return RedirectResponse(f"/infrastructure/asset-manager/{row.id}", status_code=303)


@router.get("/{asset_id}")
def detail_asset(
    request: Request,
    asset_id: int,
    report_period: str = Query("24h", max_length=10),
    report_start: str | None = Query(None, max_length=40),
    report_end: str | None = Query(None, max_length=40),
    report_dns_q: str = Query("", max_length=200),
    report_dns_page: int = Query(1, ge=1, le=10000),
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    attachments = db.query(HardwareAssetAttachment).filter(HardwareAssetAttachment.asset_id == row.id).order_by(HardwareAssetAttachment.uploaded_at.desc()).all()
    photos = db.query(HardwareAssetPhoto).filter(HardwareAssetPhoto.asset_id == row.id).order_by(HardwareAssetPhoto.sort_order, HardwareAssetPhoto.id).all()
    fields = active_fields(db, MODULE)
    values = field_values(db, MODULE, ENTITY_TYPE, row.id)
    lists = list_values(db, MODULE)
    reporting = asset_reporting_context(db, user, row.id, period=report_period, start=report_start, end=report_end, dns_search=report_dns_q, dns_page=report_dns_page)
    return templates.TemplateResponse(request, "hardware_asset_detail.html", {"user": user, "record": row, "attachments": attachments, "photos": photos, "categories": lists.get("category", []), "locations": lists.get("location", []), "statuses": lists.get("status", []), "custom_fields": fields, "custom_values": values, "option_list": option_list, "asset_profile": asset_profile_context(db, user, row), "asset_reporting": reporting, "bytes_label": bytes_label, "now_date": datetime.utcnow().strftime("%Y-%m-%d"), **csrf_context(request)})


@router.post("/{asset_id}/network-traffic")
def update_asset_network_monitoring(
    request: Request,
    asset_id: int,
    enabled: str = Form("0", max_length=8),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    if not has_module_access(db, user, "network_monitor"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Network Traffic access is required.")
    validate_csrf_token(request, csrf_token)
    asset = db.get(HardwareAsset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    requested = enabled.strip().lower() in {"1", "true", "yes", "on"}
    try:
        set_asset_monitoring(db, user, asset, requested)
        db.commit()
    except (ValueError, PermissionError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="The monitoring change could not be audited. Please retry.") from exc
    return RedirectResponse(f"/infrastructure/asset-manager/{asset_id}#asset-traffic", status_code=303)


@router.get("/{asset_id}/profile")
def asset_profile_api(asset_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    """Return the minimum permission-aware profile data for future detail clients."""
    asset = _asset_or_404(db, asset_id)
    profile = asset_profile_context(db, user, asset)
    return {
        "asset": {
            "id": asset.id,
            "asset_tag": asset.asset_tag,
            "name": asset.name,
            "status": asset.status,
        },
        "identity_evidence": [
            {
                "id": row.id,
                "type": row.evidence_type,
                "value": row.normalised_value,
                "source": row.source,
                "source_scope": row.source_scope,
                "status": row.status,
                "first_observed_at": row.first_observed_at,
                "last_observed_at": row.last_observed_at,
            }
            for row in profile["identity_rows"]
        ],
        "network_assignments": [
            {
                "id": row.id,
                "address": row.address,
                "address_family": row.address_family,
                "started_at": row.started_at,
                "ended_at": row.ended_at,
                "provenance": row.provenance,
                "status": row.status,
                "validity": row.profile_validity,
                "vlan_id": row.vlan_id if profile["can_vlan"] else None,
                "ip_address_id": row.ip_address_id if profile["can_vlan"] else None,
            }
            for row in profile["assignment_rows"]
        ],
        "dhcp": None if profile["dhcp_leases"] is None else [
            {
                "id": row.id,
                "ip_address": row.ip_address,
                "hostname": row.hostname,
                "mac_address": row.mac_address,
                "provider_lease_id": row.provider_lease_id,
                "lease_started_at": row.lease_started_at,
                "last_seen_at": row.last_seen_at,
                "expires_at": row.expires_at,
                "ended_at": row.ended_at,
                "is_active": row.is_active,
            }
            for row in profile["dhcp_leases"]
        ],
        "dns": None if profile["dns_clients"] is None else [
            {
                "id": row.id,
                "friendly_name": row.friendly_name,
                "hostname": row.hostname,
                "current_ip": row.current_ip,
                "previous_ip": row.previous_ip,
                "logical_provider_key": row.logical_provider_key,
                "last_seen_at": row.last_seen_at,
            }
            for row in profile["dns_clients"]
        ],
        "managed_ips": None if profile["managed_ips"] is None else [
            {"id": row.id, "address": row.address, "name": row.name, "category": row.category}
            for row in profile["managed_ips"]
        ],
        "network_discovery": None if profile["discovery_links"] is None else [
            {
                "id": row.id,
                "endpoint_ip": row.endpoint_ip,
                "endpoint_role": row.endpoint_role,
                "exporter_identity": row.exporter_identity,
                "state": row.state,
                "reason": row.reason,
                "managed_ip_address_id": row.managed_ip_address_id if profile["can_vlan"] else None,
            }
            for row in profile["discovery_links"]
        ],
        "traffic_monitoring": profile["traffic_monitoring"],
        "permissions": {
            "asset_manager": True,
            "dns_manager": profile["can_dns"],
            "vlan_ip_manager": profile["can_vlan"],
            "network_monitor": profile["can_network"],
        },
    }


def _asset_or_404(db: Session, asset_id: int) -> HardwareAsset:
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    return row


@router.post("/{asset_id}/identity-evidence/{evidence_id}/confirm")
def confirm_asset_identity_evidence(request: Request, asset_id: int, evidence_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    _asset_or_404(db, asset_id)
    row = db.get(AssetIdentityEvidence, evidence_id)
    if not row or row.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity evidence not found")
    try:
        confirm_existing_identity_evidence(db, user, evidence_id)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return RedirectResponse(f"/infrastructure/asset-manager/{asset_id}", status_code=303)


@router.post("/{asset_id}/identity-evidence/{evidence_id}/revoke")
def revoke_asset_identity_evidence(request: Request, asset_id: int, evidence_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    _asset_or_404(db, asset_id)
    row = db.get(AssetIdentityEvidence, evidence_id)
    if not row or row.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity evidence not found")
    try:
        revoke_identity_evidence(db, user, evidence_id)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return RedirectResponse(f"/infrastructure/asset-manager/{asset_id}", status_code=303)


@router.post("/{asset_id}/network-assignment/{assignment_id}/confirm")
def confirm_asset_network_assignment(request: Request, asset_id: int, assignment_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    _asset_or_404(db, asset_id)
    row = db.get(AssetNetworkAssignment, assignment_id)
    if not row or row.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Network assignment not found")
    try:
        confirm_existing_network_assignment(db, user, assignment_id)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return RedirectResponse(f"/infrastructure/asset-manager/{asset_id}", status_code=303)


@router.post("/{asset_id}/network-assignment/{assignment_id}/close")
def close_asset_network_assignment(request: Request, asset_id: int, assignment_id: int, ended_at: str = Form(..., max_length=20), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    _asset_or_404(db, asset_id)
    row = db.get(AssetNetworkAssignment, assignment_id)
    if not row or row.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Network assignment not found")
    try:
        end = datetime.strptime(ended_at.strip(), "%Y-%m-%d")
        close_network_assignment(db, user, assignment_id, end)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return RedirectResponse(f"/infrastructure/asset-manager/{asset_id}", status_code=303)


@router.post("/{asset_id}/network-assignment/source-context")
def confirm_asset_traffic_context(
    request: Request,
    asset_id: int,
    mapping_id: int = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Confirm one explicitly selected flow source context for a static asset."""
    validate_csrf_token(request, csrf_token)
    asset = _asset_or_404(db, asset_id)
    if not has_module_access(db, user, "network_monitor") or not has_module_access(db, user, "vlan_ip_manager"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Required monitoring permissions are not enabled.")
    mapping = db.get(TrafficDiscoveryNetworkMapping, mapping_id)
    if not mapping or not mapping.is_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The selected traffic context is no longer available.")
    source = db.get(TrafficSource, mapping.source_id)
    vlan = db.get(VLAN, mapping.vlan_id)
    if not source or source.is_deleted or not source.is_enabled or source.provider_key not in {"netflow_v9", "cisco_nsel"} or not vlan or not vlan.subnet_cidr:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The selected traffic context is no longer valid.")
    assignments = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.asset_id == asset.id,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
    ).all()
    selected = None
    for assignment in assignments:
        option = next((item for item in eligible_traffic_contexts(db, assignment.address) if item["mapping_id"] == mapping.id), None)
        if option:
            if selected is not None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The selected traffic context is ambiguous for this asset.")
            selected = (assignment, option)
    if selected is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The selected traffic context is invalid or ambiguous for this asset.")
    assignment, _option = selected
    duplicate = db.query(AssetNetworkAssignment).filter(
        AssetNetworkAssignment.asset_id == asset.id,
        AssetNetworkAssignment.address == assignment.address,
        AssetNetworkAssignment.vlan_id == vlan.id,
        AssetNetworkAssignment.source_id == source.id,
        AssetNetworkAssignment.exporter_identity == mapping.exporter_identity,
        AssetNetworkAssignment.status == "confirmed",
        AssetNetworkAssignment.ended_at.is_(None),
    ).first()
    if duplicate:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This traffic context is already confirmed for the asset.")
    try:
        assign_network_identity(
            db,
            user,
            asset_id=asset.id,
            address=assignment.address,
            started_at=datetime.utcnow(),
            vlan_id=vlan.id,
            ip_address_id=assignment.ip_address_id,
            # A context derived from a DHCP assignment stays bound to its lease,
            # so it ends with that lease instead of outliving it.
            dhcp_lease_id=assignment.dhcp_lease_id,
            source_id=source.id,
            exporter_identity=mapping.exporter_identity,
            provenance="administrator traffic context",
        )
    except (ValueError, PermissionError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return RedirectResponse(f"/infrastructure/asset-manager/{asset_id}#network-assignment-heading", status_code=303)


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
    if clean_asset_tag != row.asset_tag:
        try:
            clean_asset_tag = allocate_asset_tag(db, clean_asset_tag)
        except ValueError as exc:
            db.rollback()
            return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, record=row, error=str(exc)), status_code=400)
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
    saved_photo = await save_upload(photo, row.id, "photo", image_only=True)
    if saved_photo:
        add_photo_record(db, row.id, saved_photo)
    saved_attachment = await save_upload(attachment, row.id, "attachment")
    if saved_attachment:
        db.add(HardwareAssetAttachment(asset_id=row.id, original_filename=saved_attachment[0], stored_filename=saved_attachment[1], content_type=saved_attachment[2]))
    save_custom_values(db, fields, form, ENTITY_TYPE, row.id)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return templates.TemplateResponse(request, "hardware_asset_form.html", template_context(db, request, user, record=row, error="That asset tag already exists."), status_code=400)
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
    photo = db.query(HardwareAssetPhoto).filter(HardwareAssetPhoto.asset_id == asset_id, HardwareAssetPhoto.is_primary.is_(True)).order_by(HardwareAssetPhoto.id).first() if row else None
    if not row or not photo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Photo not found")
    path = stored_upload_path(row.id, photo.storage_filename)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Photo not found")
    return FileResponse(path, media_type=photo.content_type)


@router.get("/{asset_id}/photos/{photo_id}")
def asset_photo_file(asset_id: int, photo_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    photo = db.get(HardwareAssetPhoto, photo_id)
    if not photo or photo.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Photo not found")
    path = stored_upload_path(photo.asset_id, photo.storage_filename)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Photo not found")
    return FileResponse(path, media_type=photo.content_type)


@router.get("/{asset_id}/photos/{photo_id}/thumbnail")
def asset_photo_thumbnail(asset_id: int, photo_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    photo = db.get(HardwareAssetPhoto, photo_id)
    if not photo or photo.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Photo not found")
    filename = photo.thumbnail_filename or photo.storage_filename
    path = stored_upload_path(photo.asset_id, filename)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Photo not found")
    return FileResponse(path, media_type="image/webp" if photo.thumbnail_filename else photo.content_type)


@router.post("/{asset_id}/photos")
async def upload_photos(request: Request, asset_id: int, csrf_token: str = Form(...), photos: list[UploadFile] = File(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    row = db.get(HardwareAsset, asset_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    current_count = db.query(HardwareAssetPhoto).filter(HardwareAssetPhoto.asset_id == row.id).count()
    uploads = [photo for photo in photos if photo and photo.filename]
    if not uploads:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose at least one photo to upload.")
    if current_count + len(uploads) > MAX_PHOTO_COUNT:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"This asset can have up to {MAX_PHOTO_COUNT} photos; {MAX_PHOTO_COUNT - current_count} slot(s) remain.")
    saved_photos = []
    try:
        for upload in uploads:
            saved = await save_upload(upload, row.id, "photo", image_only=True)
            if saved:
                saved_photos.append(saved)
                add_photo_record(db, row.id, saved)
        db.commit()
    except Exception:
        db.rollback()
        for saved in saved_photos:
            stored_upload_path(row.id, saved[1]).unlink(missing_ok=True)
            if saved[3]:
                stored_upload_path(row.id, saved[3]).unlink(missing_ok=True)
        raise
    write_audit(db, user, "upload_photo", "hardware_asset", str(row.id), request.client.host if request.client else None, detail=f"Uploaded {len(saved_photos)} photo(s)")
    return RedirectResponse(f"/infrastructure/asset-manager/{row.id}", status_code=303)


@router.post("/{asset_id}/photos/{photo_id}/primary")
def set_primary_photo(request: Request, asset_id: int, photo_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    photo = db.get(HardwareAssetPhoto, photo_id)
    if not photo or photo.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hardware asset not found")
    db.query(HardwareAssetPhoto).filter(HardwareAssetPhoto.asset_id == asset_id).update({HardwareAssetPhoto.is_primary: False}, synchronize_session=False)
    photo.is_primary = True
    db.commit()
    write_audit(db, user, "set_primary_photo", "hardware_asset", str(asset_id), request.client.host if request.client else None)
    return RedirectResponse(f"/infrastructure/asset-manager/{asset_id}", status_code=303)


@router.post("/{asset_id}/photos/{photo_id}/delete")
def delete_photo(request: Request, asset_id: int, photo_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    photo = db.get(HardwareAssetPhoto, photo_id)
    if not photo or photo.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Photo not found")
    was_primary = photo.is_primary
    storage_filename = photo.storage_filename
    thumbnail_filename = photo.thumbnail_filename
    db.delete(photo)
    db.flush()
    if was_primary:
        replacement = db.query(HardwareAssetPhoto).filter(HardwareAssetPhoto.asset_id == asset_id).order_by(HardwareAssetPhoto.sort_order, HardwareAssetPhoto.id).first()
        if replacement:
            replacement.is_primary = True
    db.commit()
    stored_upload_path(photo.asset_id, storage_filename).unlink(missing_ok=True)
    if thumbnail_filename:
        stored_upload_path(photo.asset_id, thumbnail_filename).unlink(missing_ok=True)
    write_audit(db, user, "delete_photo", "hardware_asset", str(asset_id), request.client.host if request.client else None)
    return RedirectResponse("/infrastructure/asset-manager", status_code=303)


@router.get("/{asset_id}/attachments/{attachment_id}")
def download_attachment(asset_id: int, attachment_id: int, db: Session = Depends(get_db), user=Depends(require_user)):
    row = db.get(HardwareAssetAttachment, attachment_id)
    if not row or row.asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment not found")
    path = stored_upload_path(row.asset_id, row.stored_filename)
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
    path = stored_upload_path(row.asset_id, row.stored_filename)
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
    db.query(HardwareAssetPhoto).filter(HardwareAssetPhoto.asset_id == row.id).delete(synchronize_session=False)
    db.delete(row)
    db.commit()
    shutil.rmtree(asset_upload_dir(row.id), ignore_errors=True)
    write_audit(db, user, "delete", "hardware_asset", str(asset_id), request.client.host if request.client else None, detail=name)
    return RedirectResponse("/infrastructure/asset-manager", status_code=303)
