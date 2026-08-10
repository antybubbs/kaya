import logging
import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from time import perf_counter

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings
from app.core.performance import install_engine_timing

settings = get_settings()
logger = logging.getLogger(__name__)

SQLITE_BUSY_TIMEOUT_MS = 5_000
SQLITE_REQUIRED_JOURNAL_MODE = "wal"
SQLITE_REQUIRED_SYNCHRONOUS = "FULL"
SLOW_WRITE_TRANSACTION_MS = 250
_write_context: ContextVar[dict[str, str] | None] = ContextVar(
    "sqlite_write_context", default=None
)


@contextmanager
def database_write_context(subsystem: str, operation: str, *, external_io: bool = False):
    """Attach safe attribution to a bounded unit of database work."""
    def clean(value: object, maximum: int) -> str:
        return " ".join(str(value).split())[:maximum] or "unattributed"

    token = _write_context.set(
        {
            "subsystem": clean(subsystem, 80),
            "operation": clean(operation, 120),
            "external_io": str(bool(external_io)).lower(),
        }
    )
    try:
        yield
    finally:
        _write_context.reset(token)

connect_args = (
    {
        "check_same_thread": False,
        "timeout": SQLITE_BUSY_TIMEOUT_MS / 1_000,
    }
    if settings.database_url.startswith("sqlite")
    else {}
)
engine = create_engine(
    settings.database_url, connect_args=connect_args, pool_pre_ping=True
)
if settings.database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def configure_sqlite_connection(dbapi_connection, connection_record):
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
            # FULL is intentionally retained: WAL is a concurrency change, not
            # permission to weaken durability for operational records.
            cursor.execute(f"PRAGMA synchronous={SQLITE_REQUIRED_SYNCHRONOUS}")
        finally:
            cursor.close()


install_engine_timing(engine)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@event.listens_for(Session, "after_begin")
def _track_transaction_start(session, transaction, connection):
    if transaction.nested:
        return
    context = _write_context.get() or {}
    session.info["kaya_transaction_trace"] = {
        "started": perf_counter(),
        "session_id": id(session),
        "connection_id": id(connection.connection),
        "subsystem": context.get("subsystem", "unattributed"),
        "operation": context.get("operation", "unattributed"),
        "external_io": context.get("external_io", "false"),
        "wrote": False,
    }


@event.listens_for(Session, "after_flush")
def _track_transaction_write(session, _flush_context):
    trace = session.info.get("kaya_transaction_trace")
    if trace is not None:
        trace["wrote"] = True


def _finish_transaction_trace(session, outcome: str) -> None:
    trace = session.info.pop("kaya_transaction_trace", None)
    if not trace or not trace["wrote"]:
        return
    duration_ms = (perf_counter() - trace["started"]) * 1000
    if duration_ms < SLOW_WRITE_TRANSACTION_MS:
        return
    logger.warning(
        "database.write.slow subsystem=%s operation=%s session_id=%s connection_id=%s "
        "duration_ms=%.1f outcome=%s external_io=%s",
        trace["subsystem"],
        trace["operation"],
        trace["session_id"],
        trace["connection_id"],
        duration_ms,
        outcome,
        trace["external_io"],
    )


@event.listens_for(Session, "after_commit")
def _track_transaction_commit(session):
    _finish_transaction_trace(session, "committed")


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


def sqlite_lock_error(exc: BaseException) -> bool:
    """Identify SQLite busy/locked failures without inspecting SQL values."""
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
