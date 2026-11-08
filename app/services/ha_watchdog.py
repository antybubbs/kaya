"""HA coordinator: the single process that makes HA decisions.

Signed heartbeats, agent action results, agent events and administrator
requests only record facts and signal ``ha_evaluation_queue``.  This loop takes
the signalled clusters and, for each, makes every ownership, failover, recovery
and maintenance decision under the per-cluster coordination lock, in the same
order the heartbeat path used to.  A periodic pass (unchanged from the former
watchdog) also advances operations and repairs safe DHCP drift for every
deployed cluster, so progress never depends on a heartbeat arriving.

Local safety actions never depend on this process: Keepalived elects the VIP
owner itself and the agent's transition hook releases or (when automatic
failover is enabled) takes DHCP locally.  See docs/modules/high-availability.md.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep

from app.db.session import (
    SessionLocal,
    database_write_context,
    run_with_sqlite_retry,
    sqlite_lock_error,
)
from sqlalchemy import or_, select

from app.models.models import HACluster, HAMaintenanceRun, HANode
from app.services import ha_evaluation_queue
from app.services.ha_agents import _adopt_verified_automatic_owner, prune_agent_request_history, reconcile_vip_ownership
from app.services.ha_alignment import advance_alignment
from app.services.ha_dhcp_authority import establish_authority
from app.services.ha_keepalived import complete_pending_deployment
from app.services.ha_keepalived_baseline import advance_keepalived_baseline
from app.services.ha_dhcp_handover import start_automatic_dhcp_handover
from app.services.ha_coordination import cluster_coordination, refresh_cluster
from app.services.ha_failover import advance_failover
from app.services.ha_maintenance import (
    active_maintenance,
    advance_dhcp_self_heal,
    advance_reinitialisation,
    reconcile_cluster_state,
    start_dhcp_self_heal,
)
from app.services.ha_recovery import evaluate_recovery
from app.services.site_settings import get_site_setting


logger = logging.getLogger(__name__)
STARTUP_DELAY_SECONDS = 20
CHECK_INTERVAL_SECONDS = 10
_pass_lock = threading.Lock()
_evaluation_lock = threading.Lock()
RETRY_DELAY_SECONDS = 0.25
# Clusters evaluated in parallel (each holds at most two pooled connections).
COORDINATOR_WORKERS = 3
_last_agent_request_cleanup_at: datetime | None = None


def evaluate_cluster(
    db,
    cluster: HACluster,
    *,
    reporting_node_id: int | None = None,
    adoptions: list | None = None,
    refresh: bool = True,
) -> bool:
    """Make every HA decision for one cluster; False if another worker holds it.

    Same steps and order as the former heartbeat path: adopt verified local
    failovers, reconcile ownership, advance failover, evaluate recovery, then
    advance maintenance or consider a safe DHCP self-heal.  ``refresh=False``
    is only for callers that loaded ``cluster`` after taking the lock.
    """
    with cluster_coordination(db, cluster.id, operation="coordinator_evaluation") as acquired:
        if not acquired:
            return False
        if refresh:
            refresh_cluster(db, cluster.id)
        if complete_pending_deployment(cluster):  # recovers a deployment left pending (race or restart)
            db.commit()
        if establish_authority(cluster):  # upgraded clusters: once, from a verified aligned topology only
            db.commit()
        for node_id, event in adoptions or ():
            node = db.get(HANode, node_id)
            if node is not None and node.cluster_id == cluster.id:
                _adopt_verified_automatic_owner(db, node, event)
                db.commit()
        reporting_node = db.get(HANode, reporting_node_id) if reporting_node_id else None
        if reporting_node is not None and reporting_node.cluster_id != cluster.id:
            reporting_node = None
        reconcile_vip_ownership(db, cluster, reporting_node=reporting_node)
        advance_failover(db, cluster)
        evaluate_recovery(db, cluster)
        maintenance = active_maintenance(cluster)
        if maintenance and maintenance.operation == "RECONCILE":
            reconcile_cluster_state(db, maintenance)
        elif maintenance and maintenance.operation == "REINITIALISE":
            advance_reinitialisation(db, maintenance)
        elif maintenance and maintenance.operation == "DHCP_SELF_HEAL":
            advance_dhcp_self_heal(db, maintenance)
        elif maintenance and maintenance.operation == "ALIGN_OWNERSHIP":
            advance_alignment(db, maintenance)
        elif not start_automatic_dhcp_handover(db, cluster):  # verified release only (proposal)
            start_dhcp_self_heal(db, cluster)
        advance_keepalived_baseline(db, cluster)  # no-op unless a restoration is outstanding
        return True


def drain_evaluations(db) -> set[int]:
    """Evaluate every signalled cluster using ``db`` (synchronous callers and tests)."""
    evaluated: set[int] = set()
    for cluster_id, work in ha_evaluation_queue.take_pending().items():
        cluster = db.get(HACluster, cluster_id)
        if cluster is None or cluster.deleted_at is not None:
            ha_evaluation_queue.mark_completed(cluster_id, work.ticket)
            continue
        if evaluate_cluster(db, cluster, reporting_node_id=work.reporting_node_id, adoptions=work.adoptions):
            ha_evaluation_queue.mark_completed(cluster_id, work.ticket)
            evaluated.add(cluster_id)
        else:
            ha_evaluation_queue.requeue(cluster_id, work)
    return evaluated


def evaluate_signalled(session_factory, cluster_id: int, work) -> bool:
    """Evaluate one signalled cluster in its own session; True if it was deferred.

    The lock is taken before the cluster is loaded, so the fresh session needs
    no extra re-read.  A cluster held elsewhere is requeued after a short pause
    (never a busy retry).  Failures release waiters; the next signal or
    periodic pass retries.
    """
    with database_write_context("ha", "coordinator_evaluation"):
        db = session_factory()
        try:
            with cluster_coordination(db, cluster_id, operation="coordinator_evaluation") as acquired:
                if not acquired:
                    ha_evaluation_queue.requeue(cluster_id, work)
                    sleep(RETRY_DELAY_SECONDS)
                    return True
                cluster = db.get(HACluster, cluster_id)
                if cluster is not None and cluster.deleted_at is None:
                    evaluate_cluster(db, cluster, reporting_node_id=work.reporting_node_id, adoptions=work.adoptions, refresh=False)
                ha_evaluation_queue.mark_completed(cluster_id, work.ticket)
                return False
        except Exception:
            db.rollback()
            # Release waiters; a later periodic pass re-signals the cluster.
            ha_evaluation_queue.mark_failed(cluster_id, work.ticket)
            logger.exception("HA coordinator evaluation failed safely", extra={"cluster_id": cluster_id})
            return False
        finally:
            db.close()


def run_pending_evaluations(session_factory=SessionLocal) -> tuple[set[int], bool]:
    """Evaluate signalled clusters sequentially (synchronous callers); returns (evaluated, deferred)."""
    evaluated: set[int] = set()
    deferred = False
    with _evaluation_lock:
        for cluster_id, work in ha_evaluation_queue.take_pending().items():
            if evaluate_signalled(session_factory, cluster_id, work):
                deferred = True
            else:
                evaluated.add(cluster_id)
    return evaluated, deferred


def reconcile_cluster(db, cluster: HACluster) -> None:
    """Periodic pass: advance operations and repair only safe DHCP drift states."""
    with cluster_coordination(db, cluster.id, operation="periodic_watchdog") as acquired:
        if not acquired:
            return
        refresh_cluster(db, cluster.id)
        _reconcile_cluster(db, cluster)


def periodic_clusters(db) -> list[HACluster]:
    """Clusters the periodic pass visits."""
    # A running alignment or baseline restoration changes Keepalived (status PENDING_AGENT), so
    # include it explicitly: its step limits must fire even if an agent stops reporting.  A
    # pending deployment is included so it can never stay pending once every node has applied it.
    aligning = select(HAMaintenanceRun.cluster_id).where(
        HAMaintenanceRun.operation == "ALIGN_OWNERSHIP", HAMaintenanceRun.status == "RUNNING"
    )
    return db.query(HACluster).filter(
        HACluster.deleted_at.is_(None),
        HACluster.provider_key == "pihole",
        or_(HACluster.keepalived_status.in_(["DEPLOYED", "PENDING_AGENT"]), HACluster.id.in_(aligning),
            HACluster.keepalived_restoration_json.isnot(None)),
    ).all()


def _reconcile_cluster(db, cluster: HACluster) -> None:
    # Confirm or clear ownership alerts on the periodic pass too, so a
    # persisting condition is notified even if no heartbeat signals a change.
    from app.services.ha_ownership_alerts import update_ownership_alerts

    from app.services.ha_topology import assigned_active_node

    if complete_pending_deployment(cluster):
        db.commit()
    if establish_authority(cluster):
        db.commit()
    assigned = assigned_active_node(cluster)
    if assigned is not None and cluster.current_active_node_id != assigned.id:
        cluster.current_active_node_id = assigned.id  # follows the authorised roles only (P4/D1)
        db.commit()
    if cluster.keepalived_status == "DEPLOYED":
        update_ownership_alerts(db, cluster)
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
        elif maintenance.operation == "ALIGN_OWNERSHIP":
            advance_alignment(db, maintenance)
        return
    if not start_automatic_dhcp_handover(db, cluster):  # verified release only (proposal)
        start_dhcp_self_heal(db, cluster)
    advance_keepalived_baseline(db, cluster)


def signal_unevaluated_clusters(db) -> list[int]:
    """Signal clusters not evaluated since start (restart) or whose evaluation failed.

    Runs on the periodic pass (after the start-up delay, so live agents have
    normally reported already).  Evaluation is idempotent and coordinated, so
    re-evaluating persisted observations repeats no external action.  Costs one
    query only on the first pass after start or while a failure is outstanding.
    """
    if not ha_evaluation_queue.sweep_due():
        return []
    ids = [row[0] for row in db.query(HACluster.id).filter(HACluster.deleted_at.is_(None), HACluster.provider_key == "pihole").all()]
    due = ha_evaluation_queue.clusters_needing_sweep(ids)
    for cluster_id in due:
        ha_evaluation_queue.request_evaluation(cluster_id)
    if due:
        logger.info("ha.coordinator.sweep signalled=%s", len(due))
    return due


def run_ha_watchdog_pass(session_factory=SessionLocal, *, skip: set[int] | frozenset[int] = frozenset()) -> int:
    if not _pass_lock.acquire(blocking=False):
        return CHECK_INTERVAL_SECONDS
    context = database_write_context("ha", "watchdog_pass")
    context.__enter__()
    try:
        db = session_factory()
        try:
            signal_unevaluated_clusters(db)
            if get_site_setting(db, "high_availability_enabled") != "1":
                return CHECK_INTERVAL_SECONDS
            global _last_agent_request_cleanup_at
            now = datetime.utcnow()
            if (
                _last_agent_request_cleanup_at is None
                or _last_agent_request_cleanup_at < now - timedelta(hours=1)
            ):
                try:
                    deleted = run_with_sqlite_retry(
                        session_factory,
                        lambda cleanup_db: prune_agent_request_history(cleanup_db, now=now),
                        subsystem="ha",
                        operation_name="agent_request_retention",
                    )
                    _last_agent_request_cleanup_at = now
                    if deleted:
                        logger.info(
                            "ha.agent_request_retention.completed deleted=%s",
                            deleted,
                        )
                except Exception:
                    db.rollback()
                    logger.exception(
                        "ha.agent_request_retention.failed; retrying on a later pass"
                    )
            clusters = periodic_clusters(db)
            for cluster in clusters:
                if cluster.id in skip:  # just fully evaluated by the coordinator
                    continue
                try:
                    reconcile_cluster(db, cluster)
                except Exception:
                    db.rollback()
                    logger.exception("HA topology watchdog pass failed safely", extra={"cluster_id": cluster.public_id})
        finally:
            db.close()
        return CHECK_INTERVAL_SECONDS
    finally:
        context.__exit__(None, None, None)
        _pass_lock.release()


async def ha_watchdog_loop(session_factory=SessionLocal) -> None:
    """The HA coordinator loop (the former watchdog loop, now signal-driven).

    Each signalled cluster is evaluated as soon as it is signalled (also during
    the start-up delay) on a small worker pool, so one cluster waiting on a
    slow Pi-hole step never delays another; a cluster is never evaluated by two
    workers at once.  The periodic pass runs every CHECK_INTERVAL_SECONDS after
    STARTUP_DELAY_SECONDS, as before, and skips clusters that are busy.
    """
    loop = asyncio.get_running_loop()
    wake = asyncio.Event()
    ha_evaluation_queue.start(lambda: loop.call_soon_threadsafe(wake.set))
    executor = ThreadPoolExecutor(max_workers=COORDINATOR_WORKERS, thread_name_prefix="ha-coordinator")
    inflight: dict[int, asyncio.Future] = {}
    periodic: asyncio.Future | None = None
    next_periodic = monotonic() + STARTUP_DELAY_SECONDS

    def finished(_future) -> None:
        wake.set()

    try:
        while True:
            for cluster_id, work in ha_evaluation_queue.take_pending().items():
                if cluster_id in inflight:  # evaluated again once the current evaluation ends
                    ha_evaluation_queue.requeue(cluster_id, work)
                    continue
                future = loop.run_in_executor(executor, evaluate_signalled, session_factory, cluster_id, work)
                future.add_done_callback(finished)
                inflight[cluster_id] = future
            if periodic is None and monotonic() >= next_periodic:
                periodic = loop.run_in_executor(executor, run_ha_watchdog_pass, session_factory)
                periodic.add_done_callback(finished)
                next_periodic = monotonic() + CHECK_INTERVAL_SECONDS
            try:
                await asyncio.wait_for(wake.wait(), timeout=max(0.0, next_periodic - monotonic()))
            except TimeoutError:
                pass
            wake.clear()
            for cluster_id, future in list(inflight.items()):
                if future.done():
                    del inflight[cluster_id]
                    if future.exception() is not None:
                        logger.error("HA coordinator evaluation raised", exc_info=future.exception())
            if periodic is not None and periodic.done():
                error = periodic.exception()
                if error is not None:
                    if sqlite_lock_error(error):
                        logger.warning("database.contention subsystem=ha operation=watchdog_pass retry_count=1 worker=ha_watchdog")
                    else:
                        logger.error("HA periodic pass failed; retrying", exc_info=error)
                periodic = None
    finally:
        ha_evaluation_queue.stop()
        executor.shutdown(wait=False, cancel_futures=True)


ha_coordinator_loop = ha_watchdog_loop
