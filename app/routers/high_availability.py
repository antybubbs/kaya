import json
import re
import shlex
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session, selectinload

from app.core.csrf import csrf_context, validate_csrf_token
from app.db.session import get_db
from app.models.models import HACluster, HAEvent, HAFailoverRun, HAHealthCheck, HALeaseReplicationState, HANode, HASyncRun
from app.routers.auth import require_module_access, require_user
from app.schemas.high_availability import HAClusterDraftCreate, HAClusterRead, HAConfigurationDifferenceRead, HANodeDraftCreate, HANodeUpdate
from app.services.audit import write_audit
from app.services.ha_clusters import HADraftError, create_cluster_draft, soft_delete_cluster, test_draft_node_connection, update_cluster_node
from app.services.ha_agents import HEARTBEAT_FRESH_SECONDS, HAAgentError, create_bootstrap_token, reconcile_vip_ownership, revoke_agent
from app.services.ha_agent_installer import CURRENT_AGENT_VERSION, agent_version_status, installer_checksum, uninstaller_checksum, updater_checksum
from app.services.ha_registry import SUPPORTED_HA_PROVIDERS, provider_for_key
from app.services.ha_validation import GROUP_LABELS, configuration_differences, run_live_validation
from app.services.ha_keepalived import HAKeepalivedError, deployment_blockers, prepare_deployment, request_manual_vip_move
from app.services.ha_sync import HAStaleSyncPlanError, HASyncError, create_live_sync_plan, execute_sync, sync_plan
from app.services.ha_leases import HALeaseError, latest_snapshot_summary, reconcile_cluster_leases
from app.services.ha_failover import HAFailoverError, automatic_failover_blockers, failover_readiness, failover_status, latest_failover, request_failover_rollback, set_automatic_failover, start_controlled_failover
from app.services.site_settings import get_site_setting


router = APIRouter(prefix="/high-availability", tags=["high-availability"], dependencies=[Depends(require_module_access("high_availability"))])
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


def agent_management_context(request: Request, cluster: HACluster) -> dict[str, object]:
    kaya_url = str(request.base_url).rstrip("/")

    def verified_command(script: str, checksum: str, arguments: str) -> str:
        path = f"/tmp/kaya-ha-{script}"
        url = f"{kaya_url}/api/ha/agent/v1/files/{script}"
        return " && ".join((
            f"curl -fsSL {shlex.quote(url)} -o {shlex.quote(path)}",
            f"echo {shlex.quote(checksum + '  ' + path)} | sha256sum -c -",
            f"sudo sh {shlex.quote(path)} {arguments}",
            f"rm -f {shlex.quote(path)}",
        ))

    return {
        "current_agent_version": CURRENT_AGENT_VERSION,
        "agent_version_statuses": {node.public_id: agent_version_status(node.agent_version) for node in cluster.nodes},
        "agent_update_command": verified_command("update.sh", updater_checksum(), f"--kaya-url {shlex.quote(kaya_url)}"),
        "agent_uninstall_command": verified_command("uninstall.sh", uninstaller_checksum(), "--remove-kaya-ha-config"),
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
            selectinload(HACluster.failover_runs).selectinload(HAFailoverRun.source_node),
            selectinload(HACluster.failover_runs).selectinload(HAFailoverRun.target_node),
        )
        .first()
    )
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return cluster


def sync_operational_summary(db: Session, cluster: HACluster) -> dict[str, object]:
    latest = db.query(HASyncRun).filter(HASyncRun.cluster_id == cluster.id).order_by(HASyncRun.created_at.desc()).first()
    last_applied = db.query(HASyncRun).filter(HASyncRun.cluster_id == cluster.id, HASyncRun.status == "SUCCEEDED").order_by(HASyncRun.completed_at.desc()).first()
    interval = max(30, min(int(cluster.drift_check_interval_seconds or 300), 86400))
    drift_count = 0
    if latest:
        try:
            drift_count = len(json.loads(latest.plan_json).get("groups") or [])
        except (TypeError, ValueError, json.JSONDecodeError):
            drift_count = len(latest.drift_items)
    state_map = {
        "IN_SYNC": ("IN_SYNC", "In sync"),
        "SUCCEEDED": ("IN_SYNC", "In sync"),
        "PLANNED": ("DRIFT", f"{drift_count} change{'s' if drift_count != 1 else ''} found"),
        "RUNNING": ("RUNNING", "Synchronising"),
        "FAILED": ("ATTENTION", "Sync failed"),
        "ROLLED_BACK": ("ATTENTION", "Rolled back safely"),
        "CHECK_FAILED": ("ATTENTION", "Check needs attention"),
    }
    state, label = state_map.get(latest.status if latest else "", ("WAITING", "First check pending"))
    next_check = (latest.created_at + timedelta(seconds=interval)) if latest else datetime.utcnow()
    source = next((node for node in cluster.nodes if node.id == cluster.authoritative_node_id), None)
    target = next((node for node in cluster.nodes if source and node.id != source.id), None)
    return {
        "monitoring": "Active" if cluster.status in {"HEALTHY", "DEGRADED", "ERROR"} else "Starts after setup",
        "automation": "Automatic" if cluster.automatic_sync_enabled else "Approval required",
        "automatic_sync_enabled": bool(cluster.automatic_sync_enabled),
        "automatic_sync_allow_deletions": bool(cluster.automatic_sync_allow_deletions),
        "state": state,
        "state_label": label,
        "drift_count": drift_count,
        "last_checked_at": latest.created_at if latest else None,
        "last_applied_at": last_applied.completed_at if last_applied else None,
        "next_check_at": next_check,
        "interval_seconds": interval,
        "source_name": source.display_name if source else "Not selected",
        "target_name": target.display_name if target else "Not selected",
        "error": latest.error_redacted if latest and latest.status in {"FAILED", "ROLLED_BACK", "CHECK_FAILED"} else None,
    }


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
    if section == "agents":
        extra = {**agent_management_context(request, cluster), **extra}
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
    except (ValidationError, HADraftError):
        message = "Enter a valid Pi-hole URL and application password before testing."
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
    cluster = cluster_or_404(db, public_id)
    return templates.TemplateResponse(request, "high_availability_cluster_detail.html", ha_context(request, user, "clusters", cluster=cluster, cluster_section="overview", failover_readiness=failover_readiness(cluster), failover_run=latest_failover(cluster), automatic_blockers=automatic_failover_blockers(cluster), sync_summary=sync_operational_summary(db, cluster)))


@router.get("/clusters/{public_id}/live")
def cluster_live_status(public_id: str, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    cluster = db.query(HACluster).filter(HACluster.public_id == public_id, HACluster.deleted_at.is_(None)).options(selectinload(HACluster.nodes), selectinload(HACluster.lease_replication), selectinload(HACluster.failover_runs).selectinload(HAFailoverRun.source_node), selectinload(HACluster.failover_runs).selectinload(HAFailoverRun.target_node)).first()
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    reconcile_vip_ownership(db, cluster)
    now = datetime.utcnow()
    current_nodes = [node for node in cluster.nodes if node.last_heartbeat_at and node.last_heartbeat_at >= now - timedelta(seconds=HEARTBEAT_FRESH_SECONDS)]
    active_node = next((node for node in cluster.nodes if node.id == cluster.current_active_node_id), None)
    readiness = failover_readiness(cluster)
    lease = cluster.lease_replication
    run = latest_failover(cluster)
    events = db.query(HAEvent).filter(HAEvent.cluster_id == cluster.id).order_by(HAEvent.occurred_at.desc()).limit(20).all()
    unacknowledged_alerts = db.query(HAEvent.id).filter(HAEvent.cluster_id == cluster.id, HAEvent.severity.in_(["warning", "error", "critical"]), HAEvent.acknowledged_at.is_(None)).count()
    deployment_items = deployment_blockers(cluster, router_id=cluster.vrrp_router_id or 51)
    sync_summary = sync_operational_summary(db, cluster)
    sync_json = {**sync_summary}
    for key in ("last_checked_at", "last_applied_at", "next_check_at"):
        value = sync_json[key]
        sync_json[key] = value.isoformat() + "Z" if value else None
    return JSONResponse({
        "server_time": datetime.utcnow().isoformat() + "Z",
        "cluster": {
            "status": cluster.status,
            "keepalived_status": cluster.keepalived_status,
            "keepalived_generation": cluster.keepalived_generation,
            "automatic_failover": bool(cluster.automatic_failover_enabled),
            "automatic_failback": False,
            "current_agent_version": CURRENT_AGENT_VERSION,
            "active_node": active_node.display_name if active_node else None,
            "standby_node": readiness.target.display_name if readiness.target else None,
            "vip_owner_count": len([node for node in current_nodes if node.vip_owned]),
            "last_failover_at": cluster.last_failover_at.isoformat() + "Z" if cluster.last_failover_at else None,
            "unacknowledged_alerts": unacknowledged_alerts,
        },
        "nodes": [{
            "id": node.public_id, "name": node.display_name, "desired_role": node.desired_role,
            "observed_role": node.observed_role, "agent_version": node.agent_version,
            "agent_version_status": agent_version_status(node.agent_version),
            "last_heartbeat_at": node.last_heartbeat_at.isoformat() + "Z" if node.last_heartbeat_at else None,
            "heartbeat_current": node in current_nodes,
            "dns_healthy": node.dns_healthy, "dhcp_running": node.dhcp_running,
            "vip_owned": node.vip_owned, "peer_reachable": node.peer_reachable,
            "keepalived_status": node.keepalived_status, "keepalived_runtime_state": node.keepalived_runtime_state,
            "network_interface": node.network_interface, "vrrp_priority": node.vrrp_priority,
            "keepalived_config_checksum": node.keepalived_config_checksum, "keepalived_last_error": node.keepalived_last_error,
            "lease_generation": node.lease_generation, "config_generation": node.config_generation,
        } for node in cluster.nodes],
        "lease": None if lease is None else {"status": lease.status, "lease_count": lease.lease_count, "conflict_count": lease.conflict_count, "desired_generation": lease.desired_generation, "applied_generation": lease.applied_generation, "last_applied_at": lease.last_applied_at.isoformat() + "Z" if lease.last_applied_at else None},
        "failover": failover_status(run),
        "readiness": {"ready": readiness.ready, "blockers": readiness.blockers, "target_id": readiness.target.public_id if readiness.target else None, "target_name": readiness.target.display_name if readiness.target else None},
        "deployment": {"ready": not deployment_items, "blockers": deployment_items},
        "sync": sync_json,
        "events": [{"id": event.id, "type": event.event_type, "severity": event.severity, "message": event.message, "node": event.node.display_name if event.node else "Cluster", "occurred_at": event.occurred_at.isoformat() + "Z", "acknowledged": event.acknowledged_at is not None} for event in events[:20]],
    })


@router.get("/clusters/{public_id}/report")
def cluster_report(public_id: str, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    cluster = cluster_or_404(db, public_id)
    payload = cluster_live_status(public_id, db, user).body
    safe_name = re.sub(r"[^a-z0-9-]+", "-", cluster.name.lower()).strip("-") or "cluster"
    filename = f"kaya-ha-{safe_name}-report.json"
    return Response(payload, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.post("/clusters/{public_id}/automatic-failover")
async def configure_automatic_failover(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    enabled = str(form.get("enabled") or "") == "1"
    try:
        set_automatic_failover(db, cluster, enabled=enabled, confirmation=str(form.get("cluster_name") or ""), acknowledged=str(form.get("acknowledge_automatic") or "") == "1")
    except HAFailoverError as exc:
        db.rollback()
        cluster = cluster_or_404(db, public_id)
        return templates.TemplateResponse(request, "high_availability_cluster_detail.html", ha_context(request, user, "clusters", cluster=cluster, cluster_section="overview", failover_readiness=failover_readiness(cluster), failover_run=latest_failover(cluster), automatic_blockers=automatic_failover_blockers(cluster), automatic_error=str(exc)), status_code=409)
    write_audit(db, user, "enabled" if enabled else "disabled", "ha_automatic_failover", entity_id=cluster.public_id, detail=f"{'Enabled' if enabled else 'Disabled'} offline automatic failover for {cluster.name}.", severity="warning" if enabled else "info", metadata={"automatic_failback": False})
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}?automatic={'enabled' if enabled else 'disabled'}", status_code=303)


@router.post("/clusters/{public_id}/events/acknowledge")
async def acknowledge_cluster_events(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_editor)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    now = datetime.utcnow()
    for event in cluster.events:
        if event.acknowledged_at is None:
            event.acknowledged_at = now
            event.acknowledged_by_user_id = user.id
    db.commit()
    write_audit(db, user, "acknowledged", "ha_events", entity_id=cluster.public_id, detail=f"Acknowledged current HA alerts for {cluster.name}.")
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/events?acknowledged=1", status_code=303)


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


def failover_page_context(request: Request, user, cluster: HACluster, error: str | None = None):
    run = latest_failover(cluster)
    return ha_context(request, user, "clusters", cluster=cluster, cluster_section="testing", failover_readiness=failover_readiness(cluster), failover_run=run, failover_state=failover_status(run), failover_error=error)


@router.get("/clusters/{public_id}/testing")
def cluster_testing(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    cluster = cluster_or_404(db, public_id)
    return templates.TemplateResponse(request, "high_availability_cluster_testing.html", failover_page_context(request, user, cluster))


@router.post("/clusters/{public_id}/testing/start")
async def start_cluster_failover(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    target = node_or_404(cluster, str(form.get("target_node_id") or ""))
    try:
        run = start_controlled_failover(db, cluster, target, user, confirmation=str(form.get("cluster_name") or ""), acknowledged=str(form.get("acknowledge_interruption") or "") == "1")
    except HAFailoverError as exc:
        db.rollback()
        cluster = cluster_or_404(db, public_id)
        return templates.TemplateResponse(request, "high_availability_cluster_testing.html", failover_page_context(request, user, cluster, str(exc)), status_code=409)
    write_audit(db, user, "started", "ha_controlled_failover", entity_id=run.public_id, detail=f"Started controlled failover for {cluster.name} to {target.display_name}.", severity="warning", metadata={"cluster_id": cluster.public_id, "target_node_id": target.public_id, "automatic": False, "dhcp_managed": run.dhcp_managed})
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/testing?started=1", status_code=303)


@router.post("/clusters/{public_id}/testing/{run_id}/rollback")
async def rollback_cluster_failover(public_id: str, run_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    run = next((item for item in cluster.failover_runs if item.public_id == run_id), None)
    if run is None: raise HTTPException(404, "Failover run not found")
    try: request_failover_rollback(db, run, acknowledged=str(form.get("acknowledge_rollback") or "") == "1")
    except HAFailoverError as exc:
        return templates.TemplateResponse(request, "high_availability_cluster_testing.html", failover_page_context(request, user, cluster, str(exc)), status_code=409)
    write_audit(db, user, "rollback_requested", "ha_controlled_failover", entity_id=run.public_id, detail=f"Requested safe rollback for {cluster.name}.", severity="warning", metadata={"automatic": False})
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/testing?rollback=1", status_code=303)


@router.get("/clusters/{public_id}/testing/status")
def cluster_failover_status(public_id: str, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    cluster = cluster_or_404(db, public_id)
    return JSONResponse(failover_status(latest_failover(cluster)))


def lease_page_context(request: Request, user, cluster: HACluster, error: str | None = None, notice: str | None = None):
    def version_tuple(value: str | None) -> tuple[int, int, int]:
        try:
            parts = [int(part) for part in str(value or "0").split(".")[:3]]
        except ValueError:
            return (0, 0, 0)
        return tuple((parts + [0, 0, 0])[:3])

    upgrades = [node for node in cluster.nodes if version_tuple(node.agent_version) < (0, 1, 3)]
    return ha_context(request, user, "clusters", cluster=cluster, cluster_section="dhcp", lease_state=cluster.lease_replication, lease_snapshot=latest_snapshot_summary(cluster), lease_error=error, lease_notice=notice, lease_agent_upgrades=upgrades)


@router.get("/clusters/{public_id}/dhcp")
def cluster_dhcp(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    cluster = cluster_or_404(db, public_id)
    return templates.TemplateResponse(request, "high_availability_cluster_dhcp.html", lease_page_context(request, user, cluster))


@router.post("/clusters/{public_id}/dhcp/reconcile")
async def reconcile_cluster_dhcp(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    try:
        state = reconcile_cluster_leases(db, cluster)
    except HALeaseError as exc:
        write_audit(db, user, "blocked", "ha_lease_replication", entity_id=cluster.public_id, detail=f"DHCP lease reconciliation for {cluster.name} was blocked before staging.", severity="warning", metadata={"cluster_id": cluster.public_id, "dhcp_changed": False, "lease_file_changed": False, "error": str(exc)[:300]})
        cluster = cluster_or_404(db, public_id)
        return templates.TemplateResponse(request, "high_availability_cluster_dhcp.html", lease_page_context(request, user, cluster, error=str(exc)), status_code=422)
    applicable = state.status != "NOT_APPLICABLE"
    write_audit(db, user, "reconciled" if applicable else "not_applicable", "ha_lease_replication", entity_id=cluster.public_id, detail=(f"Validated and queued a lease snapshot for {cluster.name}." if applicable else f"Confirmed that {cluster.name} uses external DHCP; no lease replication is required."), metadata={"cluster_id": cluster.public_id, "generation": state.desired_generation, "lease_count": state.lease_count, "dhcp_changed": False, "lease_file_changed": False})
    destination = f"/high-availability/clusters/{cluster.public_id}/dhcp?{'queued=1' if applicable else 'external=1'}"
    return RedirectResponse(destination, status_code=303)


@router.get("/clusters/{public_id}/deployment")
def cluster_deployment(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    cluster = cluster_or_404(db, public_id)
    return templates.TemplateResponse(request, "high_availability_cluster_deployment.html", ha_context(request, user, "clusters", cluster=cluster, cluster_section="deployment", blockers=deployment_blockers(cluster, router_id=cluster.vrrp_router_id or 51), deployment_error=None))


def sync_page_context(request: Request, user, cluster: HACluster, db: Session, error: str | None = None, notice: str | None = None):
    latest = db.query(HASyncRun).filter(HASyncRun.cluster_id == cluster.id).order_by(HASyncRun.created_at.desc()).first()
    try:
        current_plan = sync_plan(cluster)
    except HASyncError as exc:
        current_plan = None
        error = error or str(exc)
    return ha_context(request, user, "clusters", cluster=cluster, cluster_section="synchronisation", sync_plan=current_plan, sync_run=latest, sync_error=error, sync_notice=notice, sync_summary=sync_operational_summary(db, cluster))


@router.get("/clusters/{public_id}/synchronisation")
def cluster_synchronisation(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_high_availability)):
    cluster = cluster_or_404(db, public_id)
    return templates.TemplateResponse(request, "high_availability_cluster_synchronisation.html", sync_page_context(request, user, cluster, db))


@router.post("/clusters/{public_id}/synchronisation/plan")
async def plan_cluster_synchronisation(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_editor)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    try:
        run = create_live_sync_plan(db, cluster, user)
    except HAStaleSyncPlanError as exc:
        write_audit(db, user, "stale", "ha_configuration_sync", entity_id=run.public_id, detail=f"Live Pi-hole configuration changed while reviewing the synchronisation plan for {cluster.name}.", severity="warning", metadata={"cluster_id": cluster.public_id, "changed_groups": exc.changed_groups, "provider_changed": False, "lease_replication": False})
        try:
            refreshed = create_live_sync_plan(db, cluster, user)
        except HASyncError as refresh_exc:
            return templates.TemplateResponse(request, "high_availability_cluster_synchronisation.html", sync_page_context(request, user, cluster, db, f"{exc} Kaya could not create a replacement plan: {refresh_exc}"), status_code=409)
        write_audit(db, user, "planned", "ha_configuration_sync", entity_id=refreshed.public_id, detail=f"Automatically refreshed the read-only synchronisation plan for {cluster.name}.", metadata={"cluster_id": cluster.public_id, "changed_groups": exc.changed_groups, "provider_changed": False, "lease_replication": False})
        return templates.TemplateResponse(request, "high_availability_cluster_synchronisation.html", sync_page_context(request, user, cluster, db, notice=f"Kaya detected a live change in {', '.join(GROUP_LABELS.get(key, key.replace('_', ' ').title()) for key in exc.changed_groups)}. Nothing was written. A fresh plan is ready below; review it again before synchronising."))
    except HASyncError as exc:
        return templates.TemplateResponse(request, "high_availability_cluster_synchronisation.html", sync_page_context(request, user, cluster, db, str(exc)), status_code=400)
    write_audit(db, user, "planned", "ha_configuration_sync", entity_id=run.public_id, detail=f"Created a read-only synchronisation plan for {cluster.name}.", metadata={"cluster_id": cluster.public_id, "provider_changed": False, "lease_replication": False})
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/synchronisation?planned=1", status_code=303)


@router.post("/clusters/{public_id}/synchronisation/automatic")
async def configure_automatic_synchronisation(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    enabled = str(form.get("enabled") or "") == "1"
    if enabled and str(form.get("acknowledge_direction") or "") != "1":
        return templates.TemplateResponse(request, "high_availability_cluster_synchronisation.html", sync_page_context(request, user, cluster, db, "Confirm that the current active Pi-hole will be the configuration source before enabling automatic synchronisation."), status_code=400)
    cluster.automatic_sync_enabled = enabled
    cluster.automatic_sync_allow_deletions = enabled and str(form.get("allow_deletions") or "") == "1"
    cluster.sync_mode = "active_authoritative"
    db.add(HAEvent(
        cluster_id=cluster.id,
        node_id=None,
        event_type="automatic_config_sync_enabled" if enabled else "automatic_config_sync_disabled",
        severity="warning" if enabled else "info",
        source="kaya",
        message=("Automatic configuration synchronisation was enabled. The current VIP owner is the source; the other node is backed up and verified before changes are applied." if enabled else "Automatic configuration synchronisation was disabled. Read-only monitoring remains active."),
        details_json_redacted=json.dumps({"allow_deletions": cluster.automatic_sync_allow_deletions, "sync_mode": cluster.sync_mode}, sort_keys=True),
        occurred_at=datetime.utcnow(),
    ))
    db.commit()
    write_audit(db, user, "enabled" if enabled else "disabled", "ha_automatic_configuration_sync", entity_id=cluster.public_id, detail=f"{'Enabled' if enabled else 'Disabled'} automatic configuration synchronisation for {cluster.name}.", severity="warning" if enabled else "info", metadata={"allow_deletions": cluster.automatic_sync_allow_deletions, "active_node_authoritative": True, "automatic_failback": False})
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/synchronisation?automatic={'enabled' if enabled else 'disabled'}", status_code=303)


@router.post("/clusters/{public_id}/synchronisation/apply")
async def apply_cluster_synchronisation(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    run = db.query(HASyncRun).filter(HASyncRun.cluster_id == cluster.id, HASyncRun.public_id == str(form.get("sync_run_id") or "")).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Synchronisation plan not found")
    if str(form.get("acknowledge_authority") or "") != "1":
        return templates.TemplateResponse(request, "high_availability_cluster_synchronisation.html", sync_page_context(request, user, cluster, db, "Confirm the authoritative-node safety boundary before applying."), status_code=400)
    try:
        execute_sync(db, cluster, run, allow_deletions=str(form.get("acknowledge_deletions") or "") == "1")
    except HASyncError as exc:
        write_audit(db, user, "failed", "ha_configuration_sync", entity_id=run.public_id, detail=f"Configuration synchronisation for {cluster.name} did not complete.", severity="warning", metadata={"cluster_id": cluster.public_id, "error": str(exc)[:300], "backup_preserved": bool(run.backups), "lease_replication": False})
        return templates.TemplateResponse(request, "high_availability_cluster_synchronisation.html", sync_page_context(request, user, cluster, db, str(exc)), status_code=409)
    write_audit(db, user, "completed", "ha_configuration_sync", entity_id=run.public_id, detail=f"Synchronised allowlisted Pi-hole configuration for {cluster.name}.", metadata={"cluster_id": cluster.public_id, "backup_created": True, "verified": True, "lease_replication": False})
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/synchronisation?synchronised=1", status_code=303)


@router.post("/clusters/{public_id}/deployment")
async def deploy_cluster_keepalived(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    try:
        router_id = int(str(form.get("vrrp_router_id") or ""))
        prepare_deployment(db, cluster, router_id, str(form.get("acknowledge_dhcp_boundary") or "") == "1")
    except (ValueError, HAKeepalivedError) as exc:
        db.rollback()
        cluster = cluster_or_404(db, public_id)
        message = str(exc) if isinstance(exc, HAKeepalivedError) else "Enter a VRRP router ID between 1 and 255."
        entered_router_id = str(form.get("vrrp_router_id") or "")
        try:
            blocker_router_id = int(entered_router_id)
        except ValueError:
            blocker_router_id = None
        return templates.TemplateResponse(request, "high_availability_cluster_deployment.html", ha_context(request, user, "clusters", cluster=cluster, cluster_section="deployment", blockers=deployment_blockers(cluster, router_id=blocker_router_id), deployment_error=message, entered_router_id=entered_router_id), status_code=400)
    write_audit(db, user, "deployment_requested", "ha_keepalived", entity_id=cluster.public_id, detail=f"Requested generated Keepalived deployment for {cluster.name}.", metadata={"generation": cluster.keepalived_generation, "vrrp_router_id": cluster.vrrp_router_id, "dhcp_changed": False, "automatic_failover": False})
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/deployment?requested=1", status_code=303)


@router.post("/clusters/{public_id}/deployment/move-vip")
async def move_cluster_vip(public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    target = node_or_404(cluster, str(form.get("target_node_id") or ""))
    previous = next((node for node in cluster.nodes if node.vip_owned), None)
    try:
        request_manual_vip_move(db, cluster, target, str(form.get("acknowledge_manual_move") or "") == "1")
    except HAKeepalivedError as exc:
        db.rollback()
        cluster = cluster_or_404(db, public_id)
        return templates.TemplateResponse(request, "high_availability_cluster_deployment.html", ha_context(request, user, "clusters", cluster=cluster, cluster_section="deployment", blockers=deployment_blockers(cluster), deployment_error=str(exc)), status_code=400)
    write_audit(db, user, "manual_vip_move_requested", "ha_keepalived", entity_id=cluster.public_id, detail=f"Requested manual VIP move to {target.display_name}.", metadata={"generation": cluster.keepalived_generation, "from_node": previous.public_id if previous else None, "to_node": target.public_id, "dhcp_changed": False})
    return RedirectResponse(f"/high-availability/clusters/{cluster.public_id}/deployment?move_requested=1", status_code=303)


@router.post("/clusters/{public_id}/nodes/{node_public_id}/agent/bootstrap")
async def bootstrap_cluster_agent(public_id: str, node_public_id: str, request: Request, db: Session = Depends(get_db), user=Depends(require_ha_admin)):
    cluster = cluster_or_404(db, public_id)
    node = node_or_404(cluster, node_public_id)
    form = await request.form()
    validate_csrf_token(request, str(form.get("csrf_token") or ""))
    credential, token = create_bootstrap_token(db, node)
    kaya_url = str(request.base_url).rstrip("/")
    installer_path = f"/tmp/kaya-ha-install-{node.public_id}.sh"
    installer_url = f"{kaya_url}/api/ha/agent/v1/install.sh"
    install_command = " && ".join((
        f"curl -fsSL {shlex.quote(installer_url)} -o {shlex.quote(installer_path)}",
        f"echo {shlex.quote(installer_checksum() + '  ' + installer_path)} | sha256sum -c -",
        f"sudo sh {shlex.quote(installer_path)} --kaya-url {shlex.quote(kaya_url)} --cluster-id {shlex.quote(cluster.public_id)} --node-id {shlex.quote(node.public_id)}",
        f"rm -f {shlex.quote(installer_path)}",
    ))
    write_audit(db, user, "bootstrap_created", "ha_agent", entity_id=credential.agent_id, detail=f"Created one-time agent registration token for {node.display_name}.", metadata={"cluster_id": cluster.public_id, "node_id": node.public_id, "expires_minutes": 15, "secret_logged": False})
    return templates.TemplateResponse(
        request,
        "high_availability_cluster_agents.html",
        ha_context(request, user, "clusters", cluster=cluster_or_404(db, public_id), cluster_section="agents", differences=[], bootstrap_token=token, bootstrap_node=node, bootstrap_expires_at=credential.bootstrap_expires_at, install_command=install_command, **agent_management_context(request, cluster)),
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
        return templates.TemplateResponse(request, "high_availability_cluster_agents.html", ha_context(request, user, "clusters", cluster=cluster, cluster_section="agents", differences=[], agent_error=str(exc), **agent_management_context(request, cluster)), status_code=400)
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
            ha_context(request, user, "clusters", cluster=cluster, cluster_section="overview", differences=[], delete_error=str(exc), failover_readiness=failover_readiness(cluster), failover_run=latest_failover(cluster), automatic_blockers=automatic_failover_blockers(cluster)),
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
