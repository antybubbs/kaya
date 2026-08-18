"""Add indexes used by DNS client detail history queries."""

from alembic import op
from sqlalchemy import inspect


INDEXES = (
    (
        "dns_client_ip_history",
        "ix_dns_client_ip_history_client_last_seen",
        ("dns_client_id", "last_seen_at"),
    ),
    (
        "dns_client_hostname_history",
        "ix_dns_client_hostname_history_client_last_seen",
        ("dns_client_id", "last_seen_at"),
    ),
    (
        "dns_client_events",
        "ix_dns_client_events_client_created",
        ("dns_client_id", "created_at"),
    ),
    (
        "dns_client_traffic_events",
        "ix_dns_client_traffic_client_observed",
        ("dns_client_id", "observed_at"),
    ),
    (
        "dns_client_traffic_events",
        "ix_dns_client_traffic_client_blocked_observed",
        ("dns_client_id", "is_blocked", "observed_at"),
    ),
)


revision = "20260818_01"
down_revision = "20260813_01"
branch_labels = None
depends_on = None


def _existing_indexes(bind) -> dict[str, tuple[str, tuple[str, ...], bool]]:
    """Return all SQLite indexes, including indexes on unexpected tables."""
    inspector = inspect(bind)
    found = {}
    for table in inspector.get_table_names():
        for index in inspector.get_indexes(table):
            name = index.get("name")
            if name:
                found[name] = (
                    table,
                    tuple(index.get("column_names") or ()),
                    bool(index.get("unique")),
                )
    return found


def _ensure_index(bind, table: str, name: str, columns: tuple[str, ...]) -> None:
    existing = _existing_indexes(bind).get(name)
    expected = (table, columns, False)
    if existing is not None:
        if existing != expected:
            raise RuntimeError(
                f"Migration index collision for {name}: expected "
                f"{table}({', '.join(columns)}) unique=False, found "
                f"{existing[0]}({', '.join(existing[1])}) unique={existing[2]}"
            )
        return
    op.create_index(name, table, list(columns))


def upgrade() -> None:
    bind = op.get_bind()
    for table, name, columns in INDEXES:
        _ensure_index(bind, table, name, columns)


def downgrade() -> None:
    bind = op.get_bind()
    for table, name, columns in reversed(INDEXES):
        existing = _existing_indexes(bind).get(name)
        if existing is None:
            continue
        if existing != (table, columns, False):
            raise RuntimeError(
                f"Cannot downgrade {name}: existing definition does not belong "
                "to this migration."
            )
        op.drop_index(name, table_name=table)
