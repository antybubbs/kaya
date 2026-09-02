"""Database-engine capabilities used to isolate dialect-specific behaviour."""

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class DatabaseCapabilities:
    name: str

    @property
    def is_sqlite(self) -> bool:
        return self.name == "sqlite"

    @property
    def is_postgresql(self) -> bool:
        return self.name == "postgresql"


def capabilities(target: Engine | Session) -> DatabaseCapabilities:
    """Return capabilities from SQLAlchemy's dialect identity."""
    bind = target.get_bind() if isinstance(target, Session) else target
    return DatabaseCapabilities(bind.dialect.name)


def verify_database_connection(engine: Engine) -> DatabaseCapabilities:
    """Verify connectivity without applying engine-specific tuning."""
    detected = capabilities(engine)
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return detected


def begin_initial_setup_transaction(db: Session) -> None:
    """Serialize first-admin creation while preserving each engine's semantics."""
    detected = capabilities(db)
    if detected.is_sqlite:
        db.execute(text("BEGIN IMMEDIATE"))
    elif detected.is_postgresql:
        # A transaction-scoped advisory lock supplies a lock even when no
        # administrator row exists yet, closing the check-then-create race.
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": 739_184_211})
    else:
        raise RuntimeError(f"Unsupported database engine: {detected.name}")
