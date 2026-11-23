"""Notifications for the outcome of administrator-approved HA repairs.

Each repair records its own durable outcome (``HAEvent`` rows such as
``service_ownership_aligned`` / ``service_alignment_failed_safe`` and
``keepalived_baseline_restored`` / ``keepalived_restoration_blocked``, plus an
audit entry).  This module queues the matching notification **in the same
transaction** as that outcome, so a crash can never commit the outcome without
its notification (or the other way round):

* **Stopped safely** (``pihole.repair.failed``): one active-condition incident
  per cluster.  A further stop while it is unresolved collapses into the
  pending outbox row or is suppressed by the publisher, so repeated stops never
  flood channels; every stop is still recorded in Activity.
* **Completed** (``pihole.repair.completed``): one notification per repair run
  (keyed by the run or restoration generation).  Its outbox row carries the
  failure key as ``resolve_deduplication_key``, so the open "stopped safely"
  incident is resolved by the same transactional delivery.

The outbox row is added inside a savepoint: if queueing fails, only the
savepoint is rolled back, the failure is logged, and the safety outcome still
commits.  A notification problem never blocks or undoes a repair's outcome.
Messages contain node names and step descriptions only.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models.models import HACluster
from app.services.notification_outbox import enqueue_notification

logger = logging.getLogger(__name__)


def failure_key(cluster: HACluster) -> str:
    return f"pihole:cluster:{cluster.public_id}:repair_failed"


def _route(cluster: HACluster) -> str:
    return f"/high-availability/clusters/{cluster.public_id}/maintenance"


def _bounded(text: str, limit: int = 500) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _queue(db: Session, cluster: HACluster, **kwargs) -> bool:
    """Add the outbox row to the caller's open transaction (no commit); never raises."""
    try:
        with db.begin_nested():
            enqueue_notification(db, target_route=_route(cluster), source_entity_type="ha_cluster",
                                 source_entity_id=cluster.public_id, correlation_id=cluster.public_id, **kwargs)
        return True
    except Exception:  # the outcome must commit regardless
        logger.exception("ha.repair_outcome.notification_not_queued", extra={"cluster_id": cluster.public_id})
        return False


def queue_repair_stopped(db: Session, cluster: HACluster, *, repair: str, reference: str, message: str) -> bool:
    return _queue(
        db, cluster,
        event_type_id="pihole.repair.failed",
        title=f"{repair} stopped safely",
        message=_bounded(f"{cluster.name}: {message} Review it on the Health & Repair page."),
        deduplication_key=failure_key(cluster),
        metadata={"cluster_id": cluster.public_id, "repair": repair, "reference": reference[:64], "outcome": "stopped_safely"},
    )


def queue_repair_completed(db: Session, cluster: HACluster, *, repair: str, reference: str, message: str) -> bool:
    return _queue(
        db, cluster,
        event_type_id="pihole.repair.completed",
        title=f"{repair} completed",
        message=_bounded(f"{cluster.name}: {message}"),
        deduplication_key=f"pihole:cluster:{cluster.public_id}:repair:{reference[:64]}:completed",
        resolve_deduplication_key=failure_key(cluster),
        metadata={"cluster_id": cluster.public_id, "repair": repair, "reference": reference[:64], "outcome": "completed"},
    )
