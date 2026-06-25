from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
from starlette import status
from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import HardwareAsset, Rack, RackItem
from app.routers.auth import require_editor, require_user
from app.services.audit import write_audit

router = APIRouter(prefix="/infrastructure/rack-manager")
templates = Jinja2Templates(directory="app/templates")
MOUNT_SIDES = {"front", "rear", "both"}
ITEM_COLORS = {
    "server": "#2563eb",
    "switch": "#059669",
    "storage": "#7c3aed",
    "power": "#dc2626",
    "patch": "#d97706",
    "appliance": "#0f766e",
    "default": "#475569",
}


def clamp_height(value: int) -> int:
    return max(1, min(value, 58))


def clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def rack_context(request: Request, user, **extra):
    return {"user": user, **extra, **csrf_context(request)}


def item_range(start_u: int, height_u: int) -> tuple[int, int]:
    return start_u, start_u + height_u - 1


def ranges_overlap(a_start: int, a_height: int, b_start: int, b_height: int) -> bool:
    a_low, a_high = item_range(a_start, a_height)
    b_low, b_high = item_range(b_start, b_height)
    return a_low <= b_high and b_low <= a_high


def validate_item_position(db: Session, rack: Rack, start_u: int, height_u: int, mount_side: str, item_id: int | None = None) -> str | None:
    if start_u < 1:
        return "Start U must be 1 or higher."
    if height_u < 1:
        return "Device height must be at least 1U."
    if start_u + height_u - 1 > rack.height_u:
        return f"Device must fit within the {rack.height_u}U rack."
    sides = {mount_side}
    if mount_side == "both":
        sides = {"front", "rear", "both"}
    else:
        sides.add("both")
    query = db.query(RackItem).filter(RackItem.rack_id == rack.id, RackItem.mount_side.in_(sides))
    if item_id:
        query = query.filter(RackItem.id != item_id)
    for existing in query.all():
        if ranges_overlap(start_u, height_u, existing.start_u, existing.height_u):
            return f"U{start_u}-U{start_u + height_u - 1} overlaps {existing.name}."
    return None


def asset_options(db: Session):
    return db.query(HardwareAsset).order_by(HardwareAsset.name.asc()).limit(1000).all()


def rack_items_for_view(rack: Rack, side: str = "front"):
    sides = [side, "both"]
    return sorted([item for item in rack.items if item.mount_side in sides], key=lambda item: (-item.start_u, item.name.lower()))


def occupied_units(items):
    occupied = set()
    for item in items:
        for unit in range(item.start_u, item.start_u + item.height_u):
            occupied.add(unit)
    return occupied


def item_color(item: RackItem) -> str:
    if item.color:
        return item.color
    key = (item.category or item.hardware_asset.category if item.hardware_asset else item.category or "").strip().lower()
    for name, color in ITEM_COLORS.items():
        if name in key:
            return color
    return ITEM_COLORS["default"]


@router.get("")
def list_racks(request: Request, db: Session = Depends(get_db), user=Depends(require_user)):
    racks = db.query(Rack).options(joinedload(Rack.items)).order_by(Rack.sort_order.asc(), Rack.name.asc()).all()
    total_items = db.query(RackItem).count()
    return templates.TemplateResponse(request, "rack_manager.html", rack_context(request, user, racks=racks, total_items=total_items))


@router.post("/new")
def create_rack(request: Request, name: str = Form(..., max_length=255), location: str = Form("", max_length=255), height_u: int = Form(42), description: str = Form("", max_length=10000), sort_order: int = Form(0), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    clean_name = name.strip()
    if not clean_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Rack name is required.")
    rack = Rack(name=clean_name, location=clean_text(location), height_u=clamp_height(height_u), description=clean_text(description), sort_order=sort_order)
    db.add(rack)
    db.commit()
    write_audit(db, user, "create", "rack", str(rack.id), request.client.host if request.client else None, detail=rack.name)
    return RedirectResponse(f"/infrastructure/rack-manager/{rack.id}", status_code=303)


@router.get("/{rack_id}")
def rack_detail(request: Request, rack_id: int, side: str = "front", db: Session = Depends(get_db), user=Depends(require_user)):
    rack = db.query(Rack).options(joinedload(Rack.items).joinedload(RackItem.hardware_asset)).filter(Rack.id == rack_id).first()
    if not rack:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rack not found")
    active_side = side if side in {"front", "rear"} else "front"
    visible_items = rack_items_for_view(rack, active_side)
    units = list(range(rack.height_u, 0, -1))
    assets = asset_options(db)
    return templates.TemplateResponse(
        request,
        "rack_detail.html",
        rack_context(
            request,
            user,
            rack=rack,
            assets=assets,
            active_side=active_side,
            visible_items=visible_items,
            occupied_units=occupied_units(visible_items),
            units=units,
            item_color=item_color,
            error=None,
        ),
    )


@router.post("/{rack_id}/edit")
def update_rack(request: Request, rack_id: int, name: str = Form(..., max_length=255), location: str = Form("", max_length=255), height_u: int = Form(42), description: str = Form("", max_length=10000), sort_order: int = Form(0), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    rack = db.get(Rack, rack_id)
    if not rack:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rack not found")
    clean_height = clamp_height(height_u)
    tallest = max((item.start_u + item.height_u - 1 for item in rack.items), default=0)
    if clean_height < tallest:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Rack height cannot be lower than occupied U{tallest}.")
    clean_name = name.strip()
    if not clean_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Rack name is required.")
    rack.name = clean_name
    rack.location = clean_text(location)
    rack.height_u = clean_height
    rack.description = clean_text(description)
    rack.sort_order = sort_order
    db.commit()
    write_audit(db, user, "update", "rack", str(rack.id), request.client.host if request.client else None, detail=rack.name)
    return RedirectResponse(f"/infrastructure/rack-manager/{rack.id}", status_code=303)


@router.post("/{rack_id}/items/new")
def create_item(request: Request, rack_id: int, hardware_asset_id: int = Form(0), name: str = Form("", max_length=255), start_u: int = Form(...), height_u: int = Form(1), mount_side: str = Form("front", max_length=20), category: str = Form("", max_length=120), color: str = Form("", max_length=40), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    rack = db.get(Rack, rack_id)
    if not rack:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rack not found")
    mount_side = mount_side if mount_side in MOUNT_SIDES else "front"
    asset = db.get(HardwareAsset, hardware_asset_id) if hardware_asset_id else None
    clean_name = name.strip() or (asset.name if asset else "")
    if not clean_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device name is required.")
    error = validate_item_position(db, rack, start_u, height_u, mount_side)
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    item = RackItem(
        rack_id=rack.id,
        hardware_asset_id=asset.id if asset else None,
        name=clean_name,
        start_u=start_u,
        height_u=height_u,
        mount_side=mount_side,
        category=clean_text(category) or (asset.category if asset else None),
        color=clean_text(color),
        notes=clean_text(notes),
    )
    db.add(item)
    db.commit()
    write_audit(db, user, "create", "rack_item", str(item.id), request.client.host if request.client else None, detail=f"{item.name} in {rack.name}")
    return RedirectResponse(f"/infrastructure/rack-manager/{rack.id}?side={mount_side if mount_side != 'both' else 'front'}", status_code=303)


@router.post("/{rack_id}/items/{item_id}/edit")
def update_item(request: Request, rack_id: int, item_id: int, hardware_asset_id: int = Form(0), name: str = Form("", max_length=255), start_u: int = Form(...), height_u: int = Form(1), mount_side: str = Form("front", max_length=20), category: str = Form("", max_length=120), color: str = Form("", max_length=40), notes: str = Form("", max_length=10000), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    rack = db.get(Rack, rack_id)
    item = db.get(RackItem, item_id)
    if not rack or not item or item.rack_id != rack.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rack item not found")
    mount_side = mount_side if mount_side in MOUNT_SIDES else "front"
    asset = db.get(HardwareAsset, hardware_asset_id) if hardware_asset_id else None
    clean_name = name.strip() or (asset.name if asset else "")
    if not clean_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device name is required.")
    error = validate_item_position(db, rack, start_u, height_u, mount_side, item.id)
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    item.hardware_asset_id = asset.id if asset else None
    item.name = clean_name
    item.start_u = start_u
    item.height_u = height_u
    item.mount_side = mount_side
    item.category = clean_text(category) or (asset.category if asset else None)
    item.color = clean_text(color)
    item.notes = clean_text(notes)
    db.commit()
    write_audit(db, user, "update", "rack_item", str(item.id), request.client.host if request.client else None, detail=f"{item.name} in {rack.name}")
    return RedirectResponse(f"/infrastructure/rack-manager/{rack.id}?side={mount_side if mount_side != 'both' else 'front'}", status_code=303)


@router.post("/{rack_id}/items/{item_id}/delete")
def delete_item(request: Request, rack_id: int, item_id: int, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_editor)):
    validate_csrf_token(request, csrf_token)
    item = db.get(RackItem, item_id)
    if not item or item.rack_id != rack_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rack item not found")
    name = item.name
    db.delete(item)
    db.commit()
    write_audit(db, user, "delete", "rack_item", None, request.client.host if request.client else None, detail=name)
    return RedirectResponse(f"/infrastructure/rack-manager/{rack_id}", status_code=303)