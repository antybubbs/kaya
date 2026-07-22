"""Periodic, read-only Pi-hole configuration drift monitoring."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from datetime import datetime, timedelta
from time import monotonic

from app.db.session import SessionLocal
from app.models.models import HACluster, HASyncRun
from app.services.ha_sync import HASyncError, authority_and_target, create_live_sync_plan
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


def run_ha_sync_monitor_pass(session_factory=SessionLocal) -> int:
    """Run due comparisons. This function never applies provider changes."""
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
                    create_live_sync_plan(db, cluster)
                except HASyncError as exc:
                    db.rollback()
                    _record_failed_check(db, cluster, str(exc))
                    logger.warning("HA configuration drift check was safely blocked", extra={"cluster_id": cluster.public_id})
                except Exception as exc:
                    db.rollback()
                    _record_failed_check(db, cluster, "Configuration check could not be completed.")
                    logger.exception("HA configuration drift check failed", extra={"cluster_id": cluster.public_id})
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
