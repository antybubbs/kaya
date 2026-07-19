from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session, selectinload

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import HACluster, HAHealthCheck, HANode
from app.routers.auth import require_user
from app.schemas.high_availability import HAClusterDraftCreate, HAClusterRead, HAConfigurationDifferenceRead, HANodeDraftCreate, HANodeUpdate
from app.services.audit import write_audit
from app.services.ha_clusters import HADraftError, create_cluster_draft, soft_delete_cluster, test_draft_node_connection, update_cluster_node
from app.services.ha_agents import HAAgentError, create_bootstrap_token, revoke_agent
from app.services.ha_registry import SUPPORTED_HA_PROVIDERS, provider_for_key
from app.services.ha_validation import configuration_differences, run_live_validation
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
        .options(selectinload(HACluster.nodes), selectinload(HACluster.health_checks))
        .order_by(HACluster.updated_at.desc())
        .all()
    )


def cluster_or_404(db: Session, public_id: str) -> HACluster:
    cluster = (
        db.query(HACluster)
        .filter(HACluster.public_id == public_id, HACluster.deleted_at.is_(None))
        .options(
            selectinload(HACluster.nodes).selectinload(HANode.integration),
            selectinload(HACluster.nodes).selectinload(HANode.ha_connection),
            selectinload(HACluster.nodes).selectinload(HANode.agent_credential),
            selectinload(HACluster.health_checks).selectinload(HAHealthCheck.node),
            selectinload(HACluster.events),
        )
        .first()
    )
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return cluster


def node_or_404(cluster: HACluster, node_public_id: str) -> HANode:
    node = next((item for item in cluster.nodes if item.public_id == node_public_id), None)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return node


def node_form_values(node: HANode) -> dict[str, str]:
    connection = node.ha_connection if node.ha_connection and node.ha_connection.deleted_at is None else node.integration
    return {
        "name": node.display_name,
        "api_base_url": node.api_base_url,
        "ssl_verify": "1" if connection is None or connection.ssl_verify else "0",
        "timeout_seconds": str(connection.timeout_seconds if connection else 10),
        "network_interface": node.network_interface or "",
    }


def cluster_page(request: Request, user, db: Session, public_id: str, section: str, template_name: str, **extra):
    cluster = cluster_or_404(db, public_id)
    return templates.TemplateResponse(
        request,
        template_name,
        ha_context(request, user, "clusters", cluster=cluster, cluster_section=section, differences=configuration_differences(cluster) if section == "validation" else [], **extra),
    )


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
        "high_availability_provider_picker.html",
        ha_context(request, user, "clusters"),
    )


@router.get("/clusters/new/{provider_key}")
def new_cluster_for_provider(provider_key: str, request: Request, user=Depends(require_ha_admin)):
    provider = provider_for_key(provider_key)
    if not provider or not provider.selectable:
        raise HTTPException(status_code=404, detail="Provider not found")
    return templates.TemplateResponse(
        request,
        "high_availability_cluster_form.html",
        ha_context(request, user, "clusters", provider=provider, error=None, form_values={}),
    )


@router.post("/clusters/test-connection")
async def test_cluster_connection(request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    node_key = str(form.get("node") or "")
    if node_key not in {"primary", "secondary"}:
        return JSONResponse({"ok": False, "message": "Choose a cluster node to test."}, status_code=400)
    provider_key = str(form.get("provider_key") or "")
    try:
        draft_node = {
            "name": str(form.get(f"{node_key}_name") or node_key.title()),
            "api_base_url": str(form.get(f"{node_key}_api_base_url") or ""),
            "secret": str(form.get(f"{node_key}_secret") or "") or None,
            "ssl_verify": str(form.get(f"{node_key}_ssl_verify") or "") == "1",
        }
        result = test_draft_node_connection(db, HANodeDraftCreate(**draft_node), provider_key)
    except (ValidationError, HADraftError) as exc:
        message = str(exc) if isinstance(exc, HADraftError) else "Enter a valid Pi-hole URL and application password before testing."
        return JSONResponse({"ok": False, "message": message}, status_code=400)
    write_audit(db, user, "connection_tested", "ha_draft_node", detail=f"Ran a read-only Pi-hole connection test for the {node_key} draft node.", metadata={"provider": provider_key, "node": node_key, "passed": result.ok, "provider_changed": False, "secret_logged": False})
    return JSONResponse({"ok": result.ok, "message": result.message}, status_code=200 if result.ok else 422)


@router.post("/clusters")
async def save_cluster(request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    values = {key: str(value) for key, value in form.items()}
    safe_values = {key: value for key, value in values.items() if key not in {"primary_secret", "secondary_secret"}}
    provider = provider_for_key(values.get("provider_key", ""))
    if not provider or not provider.selectable:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    try:
        draft = HAClusterDraftCreate(
            name=values.get("name", ""),
            description=values.get("description") or None,
            provider_key=provider.key,
            primary={
                "name": values.get("primary_name", ""),
                "api_base_url": values.get("primary_api_base_url", ""),
                "secret": values.get("primary_secret") or None,
                "ssl_verify": values.get("primary_ssl_verify") == "1",
            },
            secondary={
                "name": values.get("secondary_name", ""),
                "api_base_url": values.get("secondary_api_base_url", ""),
                "secret": values.get("secondary_secret") or None,
                "ssl_verify": values.get("secondary_ssl_verify") == "1",
            },
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
                provider=provider,
                error=message,
                form_values=safe_values,
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
        metadata={"provider": provider.key, "status": "DRAFT"},
    )
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}?saved=1", status_code=303)


@router.get("/clusters/{public_id}")
def cluster_detail(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return cluster_page(request, user, db, public_id, "overview", "high_availability_cluster_detail.html")


@router.get("/clusters/{public_id}/nodes")
def cluster_nodes(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return cluster_page(request, user, db, public_id, "nodes", "high_availability_cluster_nodes.html")


@router.get("/clusters/{public_id}/validation")
def cluster_validation(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return cluster_page(request, user, db, public_id, "validation", "high_availability_cluster_validation.html")


@router.get("/clusters/{public_id}/agents")
def cluster_agents(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return cluster_page(request, user, db, public_id, "agents", "high_availability_cluster_agents.html")


@router.get("/clusters/{public_id}/events")
def cluster_events(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return cluster_page(request, user, db, public_id, "events", "high_availability_cluster_events.html")


@router.post("/clusters/{public_id}/nodes/{node_public_id}/agent/bootstrap")
async def bootstrap_cluster_agent(public_id: str, node_public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    node = node_or_404(cluster, node_public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    credential, token = create_bootstrap_token(db, node)
    write_audit(db, user, "bootstrap_created", "ha_agent", entity_id=credential.agent_id, detail=f"Created one-time agent registration token for {node.display_name}.", metadata={"cluster_id": cluster.public_id, "node_id": node.public_id, "expires_minutes": 15, "secret_logged": False})
    return templates.TemplateResponse(
        request,
        "high_availability_cluster_agents.html",
        ha_context(request, user, "clusters", cluster=cluster_or_404(db, public_id), cluster_section="agents", differences=[], bootstrap_token=token, bootstrap_node=node, bootstrap_expires_at=credential.bootstrap_expires_at),
    )


@router.post("/clusters/{public_id}/nodes/{node_public_id}/agent/revoke")
async def revoke_cluster_agent(public_id: str, node_public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    node = node_or_404(cluster, node_public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    try:
        credential = revoke_agent(db, node)
    except HAAgentError as exc:
        return templates.TemplateResponse(request, "high_availability_cluster_agents.html", ha_context(request, user, "clusters", cluster=cluster, cluster_section="agents", differences=[], agent_error=str(exc)), status_code=400)
    write_audit(db, user, "revoked", "ha_agent", entity_id=credential.agent_id, detail=f"Revoked the High Availability agent for {node.display_name}.", metadata={"cluster_id": cluster.public_id, "node_id": node.public_id})
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/agents?agent_revoked=1", status_code=303)


@router.post("/clusters/{public_id}/delete")
async def delete_cluster(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    try:
        soft_delete_cluster(
            db,
            cluster,
            str(form.get("cluster_name") or ""),
            str(form.get("acknowledge_preservation") or "") == "1",
        )
    except HADraftError as exc:
        return templates.TemplateResponse(
            request,
            "high_availability_cluster_detail.html",
            ha_context(request, user, "clusters", cluster=cluster, cluster_section="overview", differences=[], delete_error=str(exc)),
            status_code=400,
        )
    write_audit(
        db,
        user,
        "deleted",
        "ha_cluster",
        entity_id=cluster.public_id,
        detail=f"Soft-deleted High Availability cluster {cluster.name}.",
        metadata={
            "soft_delete": True,
            "provider_contacted": False,
            "preserved": ["nodes", "provider_connections", "validation_records", "dns_links", "history"],
        },
    )
    return RedirectResponse("/high-availability/clusters?deleted=1", status_code=303)


@router.get("/clusters/{public_id}/nodes/{node_public_id}/edit")
def edit_cluster_node(public_id: str, node_public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    node = node_or_404(cluster, node_public_id)
    return templates.TemplateResponse(
        request,
        "high_availability_node_form.html",
        ha_context(request, user, "clusters", cluster=cluster, node=node, error=None, form_values=node_form_values(node)),
    )


@router.post("/clusters/{public_id}/nodes/{node_public_id}/edit")
async def save_cluster_node(public_id: str, node_public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    node = node_or_404(cluster, node_public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    values = {key: str(value) for key, value in form.items()}
    safe_values = {key: value for key, value in values.items() if key != "secret"}
    previous = node_form_values(node)
    try:
        update = HANodeUpdate(
            name=values.get("name", ""),
            api_base_url=values.get("api_base_url", ""),
            secret=values.get("secret") or None,
            ssl_verify=values.get("ssl_verify") == "1",
            timeout_seconds=values.get("timeout_seconds", "10"),
            network_interface=values.get("network_interface") or None,
        )
        node, credential_changed = update_cluster_node(db, cluster, node, update, user)
    except (ValidationError, HADraftError) as exc:
        message = str(exc) if isinstance(exc, HADraftError) else "Complete every required field with a valid value."
        return templates.TemplateResponse(
            request,
            "high_availability_node_form.html",
            ha_context(request, user, "clusters", cluster=cluster, node=node, error=message, form_values=safe_values),
            status_code=400,
        )
    changed_fields = sorted(
        key
        for key in {"name", "api_base_url", "ssl_verify", "timeout_seconds", "network_interface"}
        if previous.get(key, "") != node_form_values(node).get(key, "")
    )
    if credential_changed:
        changed_fields.append("credential")
    write_audit(
        db,
        user,
        "updated",
        "ha_node",
        entity_id=node.public_id,
        detail=f"Updated High Availability node {node.display_name}.",
        metadata={"cluster_id": cluster.public_id, "changed_fields": changed_fields, "credential_changed": credential_changed},
    )
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/nodes?node_updated=1", status_code=303)


@router.post("/clusters/{public_id}/validate")
async def validate_cluster(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_editor)):
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    cluster = cluster_or_404(db, public_id)
    rows = run_live_validation(db, cluster)
    blocking_count = sum(1 for row in rows if row.severity == "blocking" and row.status != "PASS")
    write_audit(
        db,
        user,
        "validated",
        "ha_cluster",
        entity_id=cluster.public_id,
        detail=f"Ran read-only Pi-hole validation for {cluster.name}.",
        metadata={"check_count": len(rows), "blocking_count": blocking_count, "provider_contacted": True, "provider_changed": False},
    )
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/validation?validated=1", status_code=303)


@router.get("/api/clusters", response_model=list[HAClusterRead])
def clusters_api(db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return active_clusters(db)


@router.get("/api/clusters/{public_id}", response_model=HAClusterRead)
def cluster_api(public_id: str, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return cluster_or_404(db, public_id)


@router.get("/api/clusters/{public_id}/comparison", response_model=list[HAConfigurationDifferenceRead])
def cluster_comparison_api(public_id: str, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    return configuration_differences(cluster_or_404(db, public_id))


@router.get("/supported-services")
def supported_services(request: Request, user=Depends(require_high_availability)):
    return templates.TemplateResponse(request, "high_availability_services.html", ha_context(request, user, "services"))
