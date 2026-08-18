"""Periodic full reconciliation for Pi-hole DHCP lease staging."""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timedelta
from time import monotonic

from app.db.session import (
    SessionLocal,
    database_write_context,
    run_with_sqlite_retry,
    sqlite_lock_error,
)
from app.models.models import HACluster
from app.services.dns_providers import PiHoleProvider
from app.services.ha_leases import HALeaseError, reconcile_cluster_leases
from app.services.site_settings import get_site_setting


logger = logging.getLogger(__name__)
STARTUP_DELAY_SECONDS = 25
CHECK_INTERVAL_SECONDS = 30
_pass_lock = threading.Lock()


def _reconcile_cluster_with_retry(session_factory, cluster_id: int, *, client_factory=PiHoleProvider) -> None:
    """Reconcile one cluster's leases with a bounded, fresh-session retry.

    reconcile_cluster_leases owns its own commit -- including the BLOCKED
    state it persists when it catches HALeaseError -- and the Pi-hole DHCP
    fetch is part of that same atomic unit. A SQLite "database is locked"
    failure anywhere inside it therefore invalidates the whole attempt, not
    just the final commit, so a retry must redo the complete operation
    (fetch included) against a brand new session rather than reuse a
    poisoned one. run_with_sqlite_retry already provides exactly that
    fresh-session-per-attempt contract; HALeaseError is not a lock error, so
    it always propagates on the first attempt without being retried, and its
    BLOCKED-state commit (already durable by the time it is raised) is left
    untouched by the wrapper's rollback.
    """

    def operation(db):
        cluster = db.query(HACluster).filter(HACluster.id == cluster_id).one()
        reconcile_cluster_leases(db, cluster, client_factory=client_factory)

    run_with_sqlite_retry(
        session_factory,
        operation,
        subsystem="ha",
        operation_name="lease_reconciliation",
    )


def run_ha_lease_reconciliation_pass(session_factory=SessionLocal, *, client_factory=PiHoleProvider) -> int:
    if not _pass_lock.acquire(blocking=False):
        logger.debug("HA lease reconciliation pass skipped; a previous pass is still running")
        return CHECK_INTERVAL_SECONDS
    context = database_write_context("ha", "lease_reconciliation")
    context.__enter__()
    try:
        db = session_factory()
        try:
            if get_site_setting(db, "high_availability_enabled") != "1":
                return CHECK_INTERVAL_SECONDS
            now = datetime.utcnow()
            clusters = db.query(HACluster).filter(HACluster.deleted_at.is_(None), HACluster.provider_key == "pihole").all()
            for cluster in clusters:
                state = cluster.lease_replication
                recovering = any(node.recovery_state in {"RECOVERING", "SYNCHRONISING", "VERIFYING"} for node in cluster.nodes)
                interval = 30 if recovering else max(30, min(int(cluster.sync_interval_seconds or 300), 86400))
                if state and state.last_full_reconciliation_at and state.last_full_reconciliation_at > now - timedelta(seconds=interval):
                    continue
                try:
                    _reconcile_cluster_with_retry(session_factory, cluster.id, client_factory=client_factory)
                except HALeaseError:
                    logger.warning("HA lease reconciliation was safely blocked", extra={"cluster_id": cluster.public_id})
                except Exception:
                    logger.exception("HA lease reconciliation failed", extra={"cluster_id": cluster.public_id})
        finally:
            db.close()
        return CHECK_INTERVAL_SECONDS
    finally:
        context.__exit__(None, None, None)
        _pass_lock.release()


async def ha_lease_reconciliation_loop() -> None:
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        started = monotonic()
        try:
            delay = await asyncio.to_thread(run_ha_lease_reconciliation_pass)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if sqlite_lock_error(exc):
                logger.warning(
                    "database.contention subsystem=ha operation=lease_reconciliation "
                    "retry_count=1 worker=ha_lease_reconciliation"
                )
            else:
                logger.exception("HA lease reconciliation pass failed; retrying")
            delay = CHECK_INTERVAL_SECONDS
        await asyncio.sleep(max(1, delay - (monotonic() - started)))
