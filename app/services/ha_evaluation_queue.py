"""In-process signals telling the HA coordinator which clusters need evaluation.

Recording paths (signed heartbeats, agent action results, agent events and
administrator requests) never make HA decisions themselves; they record what
they were told and call ``request_evaluation``.  The coordinator loop in
``ha_watchdog`` takes the pending work and makes every ownership, failover,
recovery and maintenance decision under the per-cluster coordination lock.

A caller that needs the outcome before replying (a heartbeat returning the
agent's desired state) may wait, bounded, for its ticket to be evaluated.
Waiting never happens on the event loop: heartbeat handlers run in the
thread pool.

The queue is memory-only, so nothing here can be lost silently:
* every cluster is evaluated on its first heartbeat after the process starts;
* the coordinator's first periodic pass after start signals every cluster not
  yet evaluated, so an observation persisted just before a restart is evaluated
  without waiting for another heartbeat;
* a failed evaluation is remembered and re-signalled by a later periodic pass.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

_cond = threading.Condition()
_requested: dict[int, int] = {}
_completed: dict[int, int] = {}
_pending: dict[int, "PendingEvaluation"] = {}
_seen_since_start: set[int] = set()
_failed: set[int] = set()
_startup_sweep_done = False
_wake: Callable[[], None] | None = None
_counters = {"requested": 0, "completed": 0, "waits": 0, "wait_timeouts": 0}


@dataclass
class PendingEvaluation:
    ticket: int
    # The node whose heartbeat most recently asked for evaluation (used for the
    # ownership-transition check exactly as the heartbeat path used it); None when
    # the latest request came from an action result, event or administrator.
    reporting_node_id: int | None = None
    # Signed automatic-failover completion events awaiting adoption, oldest first.
    adoptions: list[tuple[int, Any]] = field(default_factory=list)


def request_evaluation(cluster_id: int, *, reporting_node_id: int | None = None, adoption: tuple[int, Any] | None = None) -> int:
    """Ask the coordinator to evaluate ``cluster_id``; returns the ticket to wait for."""
    with _cond:
        ticket = _requested.get(cluster_id, 0) + 1
        _requested[cluster_id] = ticket
        pending = _pending.get(cluster_id)
        if pending is None:
            pending = _pending[cluster_id] = PendingEvaluation(ticket)
        pending.ticket = ticket
        pending.reporting_node_id = reporting_node_id
        if adoption is not None:
            pending.adoptions.append(adoption)
        _counters["requested"] += 1
        wake = _wake
    if wake is not None:
        wake()
    return ticket


def take_pending() -> dict[int, PendingEvaluation]:
    with _cond:
        work = dict(_pending)
        _pending.clear()
        return work


def requeue(cluster_id: int, work: PendingEvaluation) -> None:
    """Return work that could not be evaluated yet (another worker held the cluster)."""
    with _cond:
        current = _pending.get(cluster_id)
        if current is None:
            _pending[cluster_id] = work
        else:  # newer requests arrived meanwhile: keep their ticket, keep older adoptions first
            current.adoptions[:0] = work.adoptions
            if current.reporting_node_id is None:
                current.reporting_node_id = work.reporting_node_id


def has_pending() -> bool:
    with _cond:
        return bool(_pending)


def mark_completed(cluster_id: int, ticket: int) -> None:
    with _cond:
        if ticket > _completed.get(cluster_id, 0):
            _completed[cluster_id] = ticket
        _seen_since_start.add(cluster_id)
        _failed.discard(cluster_id)
        _counters["completed"] += 1
        _cond.notify_all()


def mark_failed(cluster_id: int, ticket: int) -> None:
    """Release waiters for a failed evaluation and remember to retry it."""
    with _cond:
        if ticket > _completed.get(cluster_id, 0):
            _completed[cluster_id] = ticket
        _failed.add(cluster_id)
        _cond.notify_all()


def sweep_due() -> bool:
    """True when a periodic pass should look for unevaluated or failed clusters."""
    with _cond:
        return not _startup_sweep_done or bool(_failed)


def clusters_needing_sweep(cluster_ids) -> list[int]:
    """Clusters not evaluated since start, or whose last evaluation failed."""
    global _startup_sweep_done
    with _cond:
        due = [cluster_id for cluster_id in cluster_ids if cluster_id not in _seen_since_start or cluster_id in _failed]
        _startup_sweep_done = True
        return due


def evaluated_since_start(cluster_id: int) -> bool:
    with _cond:
        return cluster_id in _seen_since_start


def coordinator_running() -> bool:
    with _cond:
        return _wake is not None


def wait_for_evaluation(cluster_id: int, ticket: int, timeout: float) -> bool:
    """Wait (bounded) until ``ticket`` has been evaluated; False if not evaluated in time.

    Returns False immediately when no coordinator runs in this process.  Must
    not be called on the event loop.
    """
    with _cond:
        if _wake is None:
            return False
        _counters["waits"] += 1
        done = _cond.wait_for(lambda: _completed.get(cluster_id, 0) >= ticket, timeout=timeout)
        if not done:
            _counters["wait_timeouts"] += 1
        return done


def request_and_wait(cluster_id: int, timeout: float) -> bool:
    """Signal ``cluster_id`` and wait (bounded) for it to be evaluated.  Thread pool only."""
    return wait_for_evaluation(cluster_id, request_evaluation(cluster_id), timeout)


def counters() -> dict[str, int]:
    with _cond:
        return dict(_counters)


def start(wake: Callable[[], None]) -> None:
    global _wake
    with _cond:
        _wake = wake


def stop() -> None:
    global _wake
    with _cond:
        _wake = None
        _cond.notify_all()


def reset() -> None:
    """Forget all state (tests and process start)."""
    global _wake, _startup_sweep_done
    with _cond:
        _failed.clear()
        _startup_sweep_done = False
        _requested.clear()
        _completed.clear()
        _pending.clear()
        _seen_since_start.clear()
        _wake = None
        for key in _counters:
            _counters[key] = 0
        _cond.notify_all()
