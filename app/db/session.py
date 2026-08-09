import logging
import sqlite3

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import get_settings
from app.core.performance import install_engine_timing

settings = get_settings()
logger = logging.getLogger(__name__)

SQLITE_BUSY_TIMEOUT_MS = 5_000
SQLITE_REQUIRED_JOURNAL_MODE = "wal"
SQLITE_REQUIRED_SYNCHRONOUS = "FULL"

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
        current = current.__cause__ or current.__context__
    return False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
