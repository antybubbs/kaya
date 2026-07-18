from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session, selectinload

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import HACluster
from app.routers.auth import require_user
from app.schemas.high_availability import HAClusterDraftCreate, HAClusterRead
from app.services.audit import write_audit
from app.services.ha_clusters import HADraftError, available_pihole_integrations, create_cluster_draft, validate_cluster_draft
from app.services.ha_registry import SUPPORTED_HA_PROVIDERS
from app.services.site_settings import get_site_setting


router = APIRouter(prefix="/high-availability", tags=["high-availability"])
templates = Jinja2Templates(directory="app/templates")


def require_high_availability(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(require_user),
):
    if get_site_setting(db, "high_availability_enabled") != "1":
        raise HTTPException(status_code=404, detail="Not found")
    return user


def require_ha_admin(user=Depends(require_high_availability)):
    if user.role != "admin":
        raise PermissionError("Administrator access required")
    return user


def require_ha_editor(user=Depends(require_high_availability)):
    if user.role not in {"admin", "editor"}:
        raise PermissionError("Editor access required")
    return user


def ha_context(request: Request, user, active_section: str, **extra) -> dict[str, object]:
    return {
        "user": user,
        "active_section": active_section,
        "providers": SUPPORTED_HA_PROVIDERS,
        **extra,
        **csrf_context(request),
    }


def active_clusters(db: Session) -> list[HACluster]:
    return (
        db.query(HACluster)
        .filter(HACluster.deleted_at.is_(None))
        .options(selectinload(HACluster.nodes))
        .order_by(HACluster.updated_at.desc())
        .all()
    )


def cluster_or_404(db: Session, public_id: str) -> HACluster:
    cluster = (
        db.query(HACluster)
        .filter(HACluster.public_id == public_id, HACluster.deleted_at.is_(None))
        .options(selectinload(HACluster.nodes), selectinload(HACluster.health_checks))
        .first()
    )
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return cluster


@router.get("")
@router.get("/")
def overview(request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    clusters = active_clusters(db)
    return templates.TemplateResponse(
        request,
        "high_availability.html",
        ha_context(request, user, "overview", clusters=clusters),
    )


@router.get("/clusters")
def clusters(request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return templates.TemplateResponse(
        request,
        "high_availability_clusters.html",
        ha_context(request, user, "clusters", clusters=active_clusters(db)),
    )


@router.get("/clusters/new")
def new_cluster(request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    return templates.TemplateResponse(
        request,
        "high_availability_cluster_form.html",
        ha_context(
            request,
            user,
            "clusters",
            integrations=available_pihole_integrations(db),
            error=None,
            form_values={},
        ),
    )


@router.post("/clusters")
async def save_cluster(request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    values = {key: str(value) for key, value in form.items()}
    try:
        draft = HAClusterDraftCreate(
            name=values.get("name", ""),
            description=values.get("description") or None,
            provider_key="pihole",
            primary_integration_id=values.get("primary_integration_id", ""),
            secondary_integration_id=values.get("secondary_integration_id", ""),
            virtual_ip=values.get("virtual_ip") or None,
            prefix_length=values.get("prefix_length") or None,
        )
        cluster = create_cluster_draft(db, draft, user)
    except (ValidationError, HADraftError) as exc:
        message = str(exc) if isinstance(exc, HADraftError) else "Complete every required field with a valid value."
        return templates.TemplateResponse(
            request,
            "high_availability_cluster_form.html",
            ha_context(
                request,
                user,
                "clusters",
                integrations=available_pihole_integrations(db),
                error=message,
                form_values=values,
            ),
            status_code=400,
        )
    write_audit(
        db,
        user,
        "created",
        "ha_cluster",
        entity_id=cluster.public_id,
        detail=f"Saved High Availability draft cluster {cluster.name}.",
        metadata={"provider": "pihole", "status": "DRAFT"},
    )
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}?saved=1", status_code=303)


@router.get("/clusters/{public_id}")
def cluster_detail(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return templates.TemplateResponse(
        request,
        "high_availability_cluster_detail.html",
        ha_context(request, user, "clusters", cluster=cluster_or_404(db, public_id)),
    )


@router.post("/clusters/{public_id}/validate")
async def validate_cluster(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_editor)):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    cluster = cluster_or_404(db, public_id)
    rows = validate_cluster_draft(db, cluster)
    write_audit(
        db,
        user,
        "validated",
        "ha_cluster",
        entity_id=cluster.public_id,
        detail=f"Ran local read-only validation for {cluster.name}.",
        metadata={"check_count": len(rows), "provider_contacted": False},
    )
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}?validated=1", status_code=303)


@router.get("/api/clusters", response_model=list[HAClusterRead])
def clusters_api(db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return active_clusters(db)


@router.get("/api/clusters/{public_id}", response_model=HAClusterRead)
def cluster_api(public_id: str, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return cluster_or_404(db, public_id)


@router.get("/supported-services")
def supported_services(request: Request, user=Depends(require_high_availability)):
    return templates.TemplateResponse(request, "high_availability_services.html", ha_context(request, user, "services"))
