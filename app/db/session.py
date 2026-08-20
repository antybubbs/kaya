import logging
import random
import time
from contextlib import contextmanager
from contextvars import ContextVar
from time import perf_counter

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings, postgres_engine_options, sqlite_database_path
from app.db.dialect import verify_database_connection
from app.core.performance import install_engine_timing
from app.db.sqlite_temp import configure_sqlite_temp_directory
from app.db.phase6_test_hooks import worker_write as record_worker_write

settings = get_settings()
logger = logging.getLogger(__name__)

if settings.database_url.startswith("sqlite"):
    database_path = sqlite_database_path(settings.database_url)
    if database_path is not None:
        configure_sqlite_temp_directory(database_path)

SQLITE_BUSY_TIMEOUT_MS = 5_000
SQLITE_REQUIRED_JOURNAL_MODE = "wal"
SQLITE_REQUIRED_SYNCHRONOUS = "FULL"
SLOW_WRITE_TRANSACTION_MS = 250
_write_context: ContextVar[dict[str, str] | None] = ContextVar(
    "sqlite_write_context", default=None
)


@contextmanager
def database_write_context(
    subsystem: str,
    operation: str,
    *,
    external_io: bool = False,
    retry_count: int = 0,
):
    """Attach safe attribution to a bounded unit of database work."""
    def clean(value: object, maximum: int) -> str:
        return " ".join(str(value).split())[:maximum] or "unattributed"

    token = _write_context.set(
        {
            "subsystem": clean(subsystem, 80),
            "operation": clean(operation, 120),
            "external_io": str(bool(external_io)).lower(),
            "retry_count": retry_count,
        }
    )
    try:
        yield
    finally:
        _write_context.reset(token)


def run_with_sqlite_retry(
    session_factory,
    operation,
    *,
    subsystem: str,
    operation_name: str,
    attempts: int = 3,
):
    """Run an idempotent DB-only operation in a fresh session per attempt.

    The operation must not perform external I/O or depend on ORM state from a
    previous attempt. A fresh session is required because rollback invalidates
    pending ORM state after a failed SQLite write.
    """
    attempts = max(1, min(int(attempts), 3))
    for attempt in range(attempts):
        db = session_factory()
        try:
            with database_write_context(
                subsystem, operation_name, retry_count=attempt
            ):
                result = operation(db)
                db.commit()
            return result
        except Exception as exc:
            db.rollback()
            if not sqlite_lock_error(exc) or attempt + 1 >= attempts:
                raise
            delay = 0.02 * (2**attempt) + random.uniform(0, 0.02)
            logger.warning(
                "database.lock_retry subsystem=%s operation=%s retry_count=%s delay_ms=%.1f",
                subsystem,
                operation_name,
                attempt + 1,
                delay * 1000,
            )
            time.sleep(delay)
        finally:
            db.close()

connect_args = (
    {
        "check_same_thread": False,
        "timeout": SQLITE_BUSY_TIMEOUT_MS / 1_000,
    }
    if settings.database_url.startswith("sqlite")
    else {}
)
engine_options = {"connect_args": connect_args, "pool_pre_ping": True}
if settings.database_url.startswith("postgresql"):
    engine_options.update(postgres_engine_options(settings))
    engine_options.update(
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_recycle=settings.database_pool_recycle_seconds,
    )
engine = create_engine(settings.database_url, **engine_options)


def configure_sqlite_connection(dbapi_connection, connection_record=None):
    """Apply Kaya's SQLite-only connection contract to a DB-API connection."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        cursor.execute("PRAGMA foreign_keys=ON")
        journal_mode = str(
            cursor.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        ).lower()
        if journal_mode != SQLITE_REQUIRED_JOURNAL_MODE:
            raise RuntimeError(
                "Kaya requires SQLite WAL journal mode for concurrent operation."
            )
        cursor.execute(f"PRAGMA synchronous={SQLITE_REQUIRED_SYNCHRONOUS}")
    finally:
        cursor.close()


if settings.database_url.startswith("sqlite"):

    event.listen(engine, "connect", configure_sqlite_connection)

    @event.listens_for(engine, "handle_error")
    def log_sqlite_lock_contention(exception_context):
        original = exception_context.original_exception
        if "locked" not in str(original).lower():
            return
        trace = _write_context.get() or {}
        logger.warning(
            "database.lock_contention subsystem=%s operation=%s retry_count=%s error_type=%s",
            trace.get("subsystem", "unattributed"),
            trace.get("operation", "unattributed"),
            trace.get("retry_count", 0),
            type(original).__name__,
        )


install_engine_timing(engine)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@event.listens_for(Session, "after_begin")
def _track_transaction_start(session, transaction, connection):
    if transaction.nested:
        return
    context = _write_context.get() or {}
    session.info["kaya_transaction_trace"] = {
        "started": perf_counter(),
        "commit_started": None,
        "session_id": id(session),
        "connection_id": id(connection.connection),
        "subsystem": context.get("subsystem", "unattributed"),
        "operation": context.get("operation", "unattributed"),
        "external_io": context.get("external_io", "false"),
        "wrote": False,
        "database_engine": connection.engine.dialect.name,
    }


@event.listens_for(Session, "after_flush")
def _track_transaction_write(session, _flush_context):
    trace = session.info.get("kaya_transaction_trace")
    if trace is not None:
        trace["wrote"] = True
        record_worker_write(trace["subsystem"], trace["database_engine"])


def _finish_transaction_trace(session, outcome: str) -> None:
    trace = session.info.pop("kaya_transaction_trace", None)
    if not trace or not trace["wrote"]:
        return
    duration_ms = (perf_counter() - trace["started"]) * 1000
    if duration_ms < SLOW_WRITE_TRANSACTION_MS:
        return
    logger.warning(
        "database.write.slow subsystem=%s operation=%s session_id=%s connection_id=%s "
        "duration_ms=%.1f commit_duration_ms=%.1f outcome=%s external_io=%s retry_count=%s",
        trace["subsystem"],
        trace["operation"],
        trace["session_id"],
        trace["connection_id"],
        duration_ms,
        ((perf_counter() - trace["commit_started"]) * 1000 if trace["commit_started"] else 0.0),
        outcome,
        trace["external_io"],
        trace.get("retry_count", 0),
    )


@event.listens_for(Session, "after_commit")
def _track_transaction_commit(session):
    _finish_transaction_trace(session, "committed")


@event.listens_for(Session, "before_commit")
def _track_commit_start(session):
    trace = session.info.get("kaya_transaction_trace")
    if trace is not None:
        trace["commit_started"] = perf_counter()


@event.listens_for(Session, "after_rollback")
def _track_transaction_rollback(session):
    _finish_transaction_trace(session, "rolled_back")


class Base(DeclarativeBase):
    pass


def verify_sqlite_pragmas(target_engine: Engine = engine) -> dict[str, int | str]:
    """Verify the required connection-local SQLite reliability settings."""
    if target_engine.dialect.name != "sqlite":
        return {}
    with target_engine.connect() as connection:
        values: dict[str, int | str] = {
            "journal_mode": str(
                connection.exec_driver_sql("PRAGMA journal_mode").scalar_one()
            ).lower(),
            "busy_timeout": int(
                connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one()
            ),
            "synchronous": int(
                connection.exec_driver_sql("PRAGMA synchronous").scalar_one()
            ),
            "foreign_keys": int(
                connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
            ),
        }
    if values["journal_mode"] != SQLITE_REQUIRED_JOURNAL_MODE:
        raise RuntimeError("SQLite WAL journal mode is not active.")
    if values["busy_timeout"] != SQLITE_BUSY_TIMEOUT_MS:
        raise RuntimeError("SQLite busy timeout is not configured consistently.")
    if values["synchronous"] != 2:
        raise RuntimeError("SQLite FULL synchronous durability is not active.")
    if values["foreign_keys"] != 1:
        raise RuntimeError("SQLite foreign-key enforcement is not active.")
    logger.info(
        "database.sqlite.pragmas_verified journal_mode=%s busy_timeout_ms=%s "
        "synchronous=FULL foreign_keys=ON",
        values["journal_mode"],
        values["busy_timeout"],
    )
    return values


def verify_database_engine(target_engine: Engine = engine):
    """Verify connectivity and apply SQLite-only checks by dialect."""
    detected = verify_database_connection(target_engine)
    if detected.is_sqlite:
        verify_sqlite_pragmas(target_engine)
    return detected


def sqlite_lock_error(exc: BaseException) -> bool:
    """Identify SQLite busy/locked failures without inspecting SQL values."""
    import sqlite3

    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, sqlite3.OperationalError) and "locked" in str(
            current
        ).lower():
            return True
        original = getattr(current, "orig", None)
        if isinstance(original, sqlite3.OperationalError) and "locked" in str(
            original
        ).lower():
            return True
        current = current.__cause__ or current.__context__
    return False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
