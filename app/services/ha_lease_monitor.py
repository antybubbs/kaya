"""Periodic full reconciliation for Pi-hole DHCP lease staging."""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timedelta
from time import monotonic

from sqlalchemy.orm import joinedload

from app.db.session import (
    SessionLocal,
    database_write_context,
    run_with_sqlite_retry,
    sqlite_lock_error,
)
from app.models.models import HACluster, HANode
from app.services.dns_providers import PiHoleProvider
from app.services.ha_leases import (
    HALeaseError,
    LeaseInspectionInputs,
    LeasePlan,
    inspect_lease_plan,
    prepare_lease_inspection,
    reconcile_cluster_leases,
)
from app.services.site_settings import get_site_setting


logger = logging.getLogger(__name__)
STARTUP_DELAY_SECONDS = 25
CHECK_INTERVAL_SECONDS = 30
_pass_lock = threading.Lock()


def _load_lease_inspection_inputs(session_factory, cluster_id: int) -> LeaseInspectionInputs:
    """Load the plain data `inspect_lease_plan` needs, then release the connection.

    Eagerly loads `nodes` and each node's `integration`/`ha_connection` so
    `prepare_lease_inspection` can build its result without any further
    lazy-loading query. This is a DB-only read (no Pi-hole network calls),
    so it keeps run_with_sqlite_retry's fresh-session-per-attempt retry
    contract for transient SQLite lock errors, same as the persistence step.
    """

    def operation(db):
        cluster = (
            db.query(HACluster)
            .options(
                joinedload(HACluster.nodes).joinedload(HANode.integration),
                joinedload(HACluster.nodes).joinedload(HANode.ha_connection),
            )
            .filter(HACluster.id == cluster_id)
            .one()
        )
        return prepare_lease_inspection(cluster)

    return run_with_sqlite_retry(
        session_factory,
        operation,
        subsystem="ha",
        operation_name="lease_reconciliation_load",
    )


def _reconcile_cluster_with_retry(session_factory, cluster_id: int, *, client_factory=PiHoleProvider) -> None:
    """Reconcile one cluster's leases without holding a database connection
    checked out from the pool during the Pi-hole HTTP calls.

    Split into three phases, each with its own database session:

    1. Load the immutable, session-independent inputs Pi-hole inspection
       needs (`_load_lease_inspection_inputs`) -- DB-only, no network I/O.
    2. Perform the Pi-hole HTTP calls (`inspect_lease_plan`) using only
       that plain data -- network-only, no database session open.
    3. Persist the reconciliation result (`reconcile_cluster_leases`) with
       a bounded, fresh-session retry -- DB-only, no network I/O.

    Previously, inspection and persistence were one combined operation
    inside a single retried transaction, so the database connection used
    for that transaction stayed checked out from Kaya's shared pool for
    the entire Pi-hole round trip (auth + configuration + DHCP leases,
    each up to `timeout_seconds`, default 10s). Splitting the phases this
    way means no phase holds a database connection while another phase is
    waiting on the network.

    Phase 3 still owns its own commit -- including the BLOCKED state it
    persists when Pi-hole inspection failed -- and reuses
    run_with_sqlite_retry's fresh-session-per-attempt contract for that
    DB-only unit of work. HALeaseError is not a lock error, so it always
    propagates on the first attempt without being retried, and its
    BLOCKED-state commit (already durable by the time it is raised) is left
    untouched by the wrapper's rollback.
    """
    inputs = _load_lease_inspection_inputs(session_factory, cluster_id)

    inspection: LeasePlan | HALeaseError
    try:
        inspection = inspect_lease_plan(inputs, client_factory=client_factory)
    except HALeaseError as exc:
        inspection = exc

    def operation(db):
        cluster = db.query(HACluster).filter(HACluster.id == cluster_id).one()
        reconcile_cluster_leases(db, cluster, client_factory=client_factory, precomputed_inspection=inspection)

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
