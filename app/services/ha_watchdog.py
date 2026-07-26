"""Conservative HA topology watchdog and bounded safe-drift repair."""

from __future__ import annotations

import asyncio
import logging
import threading
from time import monotonic

from app.db.session import SessionLocal
from app.models.models import HACluster
from app.services.ha_failover import advance_failover
from app.services.ha_maintenance import (
    active_maintenance,
    advance_dhcp_self_heal,
    advance_reinitialisation,
    reconcile_cluster_state,
    start_dhcp_self_heal,
)
from app.services.site_settings import get_site_setting


logger = logging.getLogger(__name__)
STARTUP_DELAY_SECONDS = 20
CHECK_INTERVAL_SECONDS = 10
_pass_lock = threading.Lock()


def reconcile_cluster(db, cluster: HACluster) -> None:
    """Observe first; repair only the two explicitly safe DHCP drift states."""
    failover = advance_failover(db, cluster)
    if failover and failover.status in {"RUNNING", "ROLLING_BACK"}:
        return
    maintenance = active_maintenance(cluster)
    if maintenance:
        if maintenance.operation == "DHCP_SELF_HEAL":
            advance_dhcp_self_heal(db, maintenance)
        elif maintenance.operation == "RECONCILE":
            reconcile_cluster_state(db, maintenance)
        elif maintenance.operation == "REINITIALISE":
            advance_reinitialisation(db, maintenance)
        return
    start_dhcp_self_heal(db, cluster)


def run_ha_watchdog_pass(session_factory=SessionLocal) -> int:
    if not _pass_lock.acquire(blocking=False):
        return CHECK_INTERVAL_SECONDS
    try:
        db = session_factory()
        try:
            if get_site_setting(db, "high_availability_enabled") != "1":
                return CHECK_INTERVAL_SECONDS
            clusters = db.query(HACluster).filter(
                HACluster.deleted_at.is_(None),
                HACluster.provider_key == "pihole",
                HACluster.keepalived_status == "DEPLOYED",
            ).all()
            for cluster in clusters:
                try:
                    reconcile_cluster(db, cluster)
                except Exception:
                    db.rollback()
                    logger.exception("HA topology watchdog pass failed safely", extra={"cluster_id": cluster.public_id})
        finally:
            db.close()
        return CHECK_INTERVAL_SECONDS
    finally:
        _pass_lock.release()


async def ha_watchdog_loop() -> None:
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        started = monotonic()
        delay = await asyncio.to_thread(run_ha_watchdog_pass)
        await asyncio.sleep(max(1, delay - (monotonic() - started)))
