"""Periodic full reconciliation for Pi-hole DHCP lease staging."""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timedelta
from time import monotonic

from app.db.session import SessionLocal
from app.models.models import HACluster
from app.services.ha_leases import HALeaseError, reconcile_cluster_leases
from app.services.site_settings import get_site_setting


logger = logging.getLogger(__name__)
STARTUP_DELAY_SECONDS = 25
CHECK_INTERVAL_SECONDS = 30
_pass_lock = threading.Lock()


def run_ha_lease_reconciliation_pass(session_factory=SessionLocal) -> int:
    if not _pass_lock.acquire(blocking=False):
        return CHECK_INTERVAL_SECONDS
    try:
        db = session_factory()
        try:
            if get_site_setting(db, "high_availability_enabled") != "1":
                return CHECK_INTERVAL_SECONDS
            now = datetime.utcnow()
            clusters = db.query(HACluster).filter(HACluster.deleted_at.is_(None), HACluster.provider_key == "pihole").all()
            for cluster in clusters:
                state = cluster.lease_replication
                interval = max(30, min(int(cluster.sync_interval_seconds or 300), 86400))
                if state and state.last_full_reconciliation_at and state.last_full_reconciliation_at > now - timedelta(seconds=interval):
                    continue
                try:
                    reconcile_cluster_leases(db, cluster)
                except HALeaseError:
                    logger.warning("HA lease reconciliation was safely blocked", extra={"cluster_id": cluster.public_id})
                except Exception:
                    db.rollback()
                    logger.exception("HA lease reconciliation failed", extra={"cluster_id": cluster.public_id})
        finally:
            db.close()
        return CHECK_INTERVAL_SECONDS
    finally:
        _pass_lock.release()


async def ha_lease_reconciliation_loop() -> None:
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        started = monotonic()
        delay = await asyncio.to_thread(run_ha_lease_reconciliation_pass)
        await asyncio.sleep(max(1, delay - (monotonic() - started)))
