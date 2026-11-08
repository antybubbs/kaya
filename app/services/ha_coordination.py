"""Per-cluster coordination for HA maintenance, recovery and failover state changes.

Heartbeats from both nodes, the coordinator (watchdog), the sync monitor and
administrator requests can all reach the same cluster at once.  Only one of them
may change a cluster's ownership, failover, maintenance or recovery state at a
time; the others skip and leave the work to the holder.

Rules
-----
* One coordination lock per cluster, taken with a non-blocking try.  A caller
  never blocks on it, so it cannot form a lock cycle with database row locks
  and never stalls the event loop.  Callers never take two clusters' locks.
  Administrator requests running in a worker thread may retry the try for a
  few seconds (``coordinated_waiting``); they end their transaction first, so
  they hold no row locks or pooled connection while retrying.
* PostgreSQL: a session-level advisory lock held on a dedicated pooled
  connection.  It is not a row lock, so heartbeats keep writing node and
  cluster rows while a holder waits on a slow Pi-hole request.  The lock
  connection never has a transaction left open.  The lock is released
  explicitly and the release is checked; if the release cannot be confirmed
  the connection is discarded (never returned to the pool), which ends its
  backend session and releases the lock.  PostgreSQL also releases it when
  the holder's process dies.
* SQLite: a per-cluster lock file beside the database file (``flock``), so
  separate Kaya processes sharing one SQLite file are coordinated on POSIX
  hosts; the operating system releases it if the process dies.  Where file
  locks are unavailable (non-POSIX hosts or in-memory databases) only a
  process-local lock is possible: such deployments must run one Kaya process.
* Re-entrant within one thread for the same cluster, because a coordinated
  evaluation calls other coordinated steps.
* After acquiring, callers must re-read the state they act on (see
  ``refresh_cluster``) and re-check that the step still applies.

Assumes direct PostgreSQL connections (session advisory locks do not survive
transaction-mode connection poolers such as PgBouncer in transaction mode).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from app.models.models import HACluster, HAMaintenanceRun, HANode

try:  # POSIX only; the production container is Linux.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on non-POSIX hosts
    fcntl = None

logger = logging.getLogger(__name__)

# First key of the two-key advisory lock form; the second is the cluster id.
# "KHA" in ASCII, chosen to avoid clashing with other advisory lock users.
ADVISORY_NAMESPACE = 0x4B4841
LOCK_DIRECTORY_NAME = "ha-coordination-locks"

LOCK_SQL = text("SELECT pg_try_advisory_lock(:namespace, :cluster_id)")
UNLOCK_SQL = text("SELECT pg_advisory_unlock(:namespace, :cluster_id)")

_held = threading.local()
_local_locks: dict[tuple[int, int], threading.Lock] = {}
_local_locks_guard = threading.Lock()
# Which operation holds each cluster's lock in this process (for "busy" explanations only).
_holders: dict[tuple[int, int], str] = {}


def _engine(db: Session) -> Engine:
    bind = db.get_bind()
    return bind.engine if isinstance(bind, Connection) else bind


def _held_set() -> set[tuple[int, int]]:
    held = getattr(_held, "keys", None)
    if held is None:
        held = _held.keys = set()
    return held


def current_operation(db: Session, cluster_id: int) -> str | None:
    """The operation holding the cluster's lock in this process, if any.

    Informational only (used to explain a busy response); never used for
    safety decisions.  A holder in another Kaya process is not visible.
    """
    return _holders.get((id(_engine(db)), int(cluster_id)))


def holds_coordination(db: Session, cluster_id: int) -> bool:
    """True when this thread currently coordinates ``cluster_id``."""
    return (id(_engine(db)), int(cluster_id)) in _held_set()


def _local_lock(key: tuple[int, int]) -> threading.Lock:
    with _local_locks_guard:
        return _local_locks.setdefault(key, threading.Lock())


def cross_process_protection(engine: Engine) -> bool:
    """Whether coordination also excludes other processes for this database."""
    if engine.dialect.name == "postgresql":
        return True
    return fcntl is not None and _sqlite_lock_directory(engine) is not None


def _sqlite_lock_directory(engine: Engine) -> Path | None:
    database = engine.url.database
    if engine.dialect.name != "sqlite" or database in {None, "", ":memory:"} or str(database).startswith("file::memory:"):
        return None
    return Path(str(database)).resolve().parent / LOCK_DIRECTORY_NAME


@contextmanager
def cluster_coordination(db: Session, cluster_id: int, *, operation: str) -> Iterator[bool]:
    """Yield True when this caller holds the cluster's coordination lock, else False."""
    engine = _engine(db)
    key = (id(engine), int(cluster_id))
    held = _held_set()
    if key in held:  # re-entrant: this thread already coordinates the cluster
        yield True
        return
    if engine.dialect.name == "postgresql":
        lock = _postgres_lock(engine, int(cluster_id), operation)
    else:
        lock = _local_and_file_lock(engine, key, int(cluster_id), operation)
    with lock as acquired:
        if acquired:
            held.add(key)
            _holders[key] = operation
        try:
            yield acquired
        finally:
            if acquired:
                _holders.pop(key, None)
            held.discard(key)


@contextmanager
def _postgres_lock(engine: Engine, cluster_id: int, operation: str) -> Iterator[bool]:
    connection = engine.connect()
    acquired = False
    try:
        acquired = bool(connection.execute(
            LOCK_SQL,
            {"namespace": ADVISORY_NAMESPACE, "cluster_id": cluster_id},
        ).scalar())
        connection.commit()  # leave no transaction open on the lock connection
        if not acquired:
            logger.info("ha.coordination.skipped cluster_id=%s operation=%s", cluster_id, operation)
        yield acquired
    finally:
        try:
            if acquired:
                released = connection.execute(
                    UNLOCK_SQL,
                    {"namespace": ADVISORY_NAMESPACE, "cluster_id": cluster_id},
                ).scalar()
                connection.commit()
                if released is not True:
                    raise RuntimeError("advisory lock release was not confirmed")
        except Exception:
            # Never return a connection that may still hold the lock to the pool:
            # discarding it ends the backend session, which releases the lock.
            logger.exception("ha.coordination.unlock_failed cluster_id=%s; discarding connection", cluster_id)
            connection.invalidate()
        finally:
            connection.close()


@contextmanager
def _local_and_file_lock(engine: Engine, key: tuple[int, int], cluster_id: int, operation: str) -> Iterator[bool]:
    lock = _local_lock(key)
    if not lock.acquire(blocking=False):
        logger.info("ha.coordination.skipped cluster_id=%s operation=%s", cluster_id, operation)
        yield False
        return
    handle = None
    try:
        directory = _sqlite_lock_directory(engine) if fcntl is not None else None
        if directory is not None:
            try:
                directory.mkdir(mode=0o700, exist_ok=True)
                handle = os.open(directory / f"cluster-{cluster_id}.lock", os.O_RDWR | os.O_CREAT, 0o600)
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                logger.info("ha.coordination.skipped cluster_id=%s operation=%s holder=other_process", cluster_id, operation)
                yield False
                return
            except OSError:
                # Fail closed: without the cross-process lock this caller must not act.
                logger.exception("ha.coordination.file_lock_unavailable cluster_id=%s operation=%s", cluster_id, operation)
                yield False
                return
        yield True
    finally:
        if handle is not None:
            try:
                fcntl.flock(handle, fcntl.LOCK_UN)
            finally:
                os.close(handle)
        lock.release()


@contextmanager
def coordinated(db: Session, cluster_id: int, *, operation: str, run: HAMaintenanceRun | None = None) -> Iterator[bool]:
    """Coordinate one step, re-reading state only when the lock is newly acquired.

    Inside a coordinator evaluation (which already holds the cluster and has
    re-read it), nested steps run directly without another lock or re-read.
    """
    if holds_coordination(db, cluster_id):
        yield True
        return
    with cluster_coordination(db, cluster_id, operation=operation) as acquired:
        if acquired:
            refresh_cluster(db, cluster_id, run=run)
        yield acquired


def refresh_cluster(db: Session, cluster_id: int, *, run: HAMaintenanceRun | None = None) -> None:
    """Re-read the rows a coordinated step acts on, replacing any stale copies.

    Uses populate_existing so objects already held by the caller (and their
    relationships' members) reflect the latest committed state.  Pending changes
    are flushed first so the caller's own writes are re-read, never discarded.
    """
    db.flush()
    db.query(HACluster).populate_existing().filter(HACluster.id == cluster_id).one()
    db.query(HANode).populate_existing().filter(HANode.cluster_id == cluster_id).all()
    if run is not None:
        db.query(HAMaintenanceRun).populate_existing().filter(HAMaintenanceRun.id == run.id).one()


@contextmanager
def coordinated_waiting(
    db: Session,
    cluster_id: int,
    *,
    operation: str,
    wait_seconds: float,
    poll_seconds: float = 0.1,
) -> Iterator[bool]:
    """Like ``coordinated``, but retry the non-blocking try for up to ``wait_seconds``.

    For administrator requests running in a worker thread (never on the event
    loop).  The caller's transaction is ended first so no row locks or pooled
    connection are held while retrying, and every object the caller loaded is
    re-read on next access after the lock is acquired.
    """
    if holds_coordination(db, cluster_id):
        yield True
        return
    db.commit()
    deadline = time.monotonic() + max(0.0, float(wait_seconds))
    while True:
        with coordinated(db, cluster_id, operation=operation) as acquired:
            if acquired or time.monotonic() >= deadline:
                yield acquired
                return
        time.sleep(poll_seconds)
