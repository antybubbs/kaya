"""Periodic, read-only Pi-hole configuration drift monitoring."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from datetime import datetime, timedelta
from time import monotonic

from app.db.session import SessionLocal
from app.models.models import HACluster, HAEvent, HASyncRun
from app.services.audit import write_audit
from app.services.ha_sync import HASyncError, authority_and_target, create_live_sync_plan, execute_sync
from app.services.site_settings import get_site_setting


logger = logging.getLogger(__name__)
STARTUP_DELAY_SECONDS = 30
CHECK_INTERVAL_SECONDS = 15
_pass_lock = threading.Lock()


def _record_failed_check(db, cluster: HACluster, message: str) -> None:
    try:
        source, target = authority_and_target(cluster)
    except HASyncError:
        return
    db.add(HASyncRun(
        cluster_id=cluster.id,
        source_node_id=source.id,
        target_node_id=target.id,
        status="CHECK_FAILED",
        plan_json=json.dumps({"groups": [], "source_name": source.display_name, "target_name": target.display_name}),
        error_redacted=message[:1000],
        completed_at=datetime.utcnow(),
    ))
    db.commit()


def _record_automation_event(db, cluster: HACluster, *, succeeded: bool, message: str, run: HASyncRun) -> None:
    db.add(HAEvent(
        cluster_id=cluster.id,
        node_id=run.target_node_id,
        event_type="automatic_config_sync_completed" if succeeded else "automatic_config_sync_failed",
        severity="info" if succeeded else "error",
        source="kaya",
        message=message[:1000],
        details_json_redacted=json.dumps({"run_id": run.public_id, "source_node_id": run.source_node_id, "target_node_id": run.target_node_id}, sort_keys=True),
        occurred_at=datetime.utcnow(),
    ))
    db.commit()


def run_ha_sync_monitor_pass(session_factory=SessionLocal) -> int:
    """Run due comparisons and apply only explicitly enabled, safety-checked plans."""
    if not _pass_lock.acquire(blocking=False):
        return CHECK_INTERVAL_SECONDS
    try:
        db = session_factory()
        try:
            if get_site_setting(db, "high_availability_enabled") != "1":
                return CHECK_INTERVAL_SECONDS
            now = datetime.utcnow()
            clusters = db.query(HACluster).filter(
                HACluster.deleted_at.is_(None),
                HACluster.provider_key == "pihole",
                HACluster.status.in_(["HEALTHY", "DEGRADED", "ERROR"]),
            ).all()
            for cluster in clusters:
                interval = max(30, min(int(cluster.drift_check_interval_seconds or 300), 86400))
                latest = db.query(HASyncRun).filter(HASyncRun.cluster_id == cluster.id).order_by(HASyncRun.created_at.desc()).first()
                if latest and latest.created_at > now - timedelta(seconds=interval):
                    continue
                try:
                    run = create_live_sync_plan(db, cluster)
                except HASyncError as exc:
                    db.rollback()
                    _record_failed_check(db, cluster, str(exc))
                    logger.warning("HA configuration drift check was safely blocked", extra={"cluster_id": cluster.public_id})
                    continue
                except Exception as exc:
                    db.rollback()
                    _record_failed_check(db, cluster, "Configuration check could not be completed.")
                    logger.exception("HA configuration drift check failed", extra={"cluster_id": cluster.public_id})
                    continue
                if not cluster.automatic_sync_enabled or run.status != "PLANNED" or cluster.maintenance_mode:
                    continue
                plan = json.loads(run.plan_json)
                safe_authority = bool(
                    cluster.status == "HEALTHY"
                    and cluster.current_active_node_id
                    and cluster.current_active_node_id == cluster.authoritative_node_id == run.source_node_id
                )
                deletions_allowed = not plan.get("deletion_count") or cluster.automatic_sync_allow_deletions
                if not safe_authority or plan.get("blocked_groups") or not deletions_allowed:
                    continue
                try:
                    execute_sync(db, cluster, run, allow_deletions=cluster.automatic_sync_allow_deletions)
                    _record_automation_event(db, cluster, succeeded=True, message=f"Automatically synchronised configuration from {run.source_node.display_name} to {run.target_node.display_name}; backup and verification completed.", run=run)
                    write_audit(db, None, "completed", "ha_automatic_configuration_sync", entity_id=run.public_id, detail=f"Automatically synchronised allowlisted Pi-hole configuration for {cluster.name}.", metadata={"cluster_id": cluster.public_id, "backup_created": True, "verified": True, "lease_replication": False})
                except HASyncError as exc:
                    _record_automation_event(db, cluster, succeeded=False, message=f"Automatic configuration synchronisation stopped safely: {exc}", run=run)
                    write_audit(db, None, "failed", "ha_automatic_configuration_sync", entity_id=run.public_id, detail=f"Automatic configuration synchronisation for {cluster.name} did not complete.", severity="warning", metadata={"cluster_id": cluster.public_id, "error": str(exc)[:300], "backup_preserved": bool(run.backups), "lease_replication": False})
        finally:
            db.close()
        return CHECK_INTERVAL_SECONDS
    finally:
        _pass_lock.release()


async def ha_sync_monitor_loop() -> None:
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        started = monotonic()
        delay = await asyncio.to_thread(run_ha_sync_monitor_pass)
        await asyncio.sleep(max(1, delay - (monotonic() - started)))
