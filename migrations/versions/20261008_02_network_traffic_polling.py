"""Add SNMP polling diagnostics, rates and scheduler ownership."""

from alembic import op
import sqlalchemy as sa


revision = "20261008_02"
down_revision = "20261008_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name, column in (
        ("last_failed_at", sa.Column("last_failed_at", sa.DateTime())),
        ("last_error_category", sa.Column("last_error_category", sa.String(40))),
        ("last_poll_duration_ms", sa.Column("last_poll_duration_ms", sa.Integer())),
        ("consecutive_failures", sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0")),
        ("backoff_until", sa.Column("backoff_until", sa.DateTime())),
        ("last_counter_observation_at", sa.Column("last_counter_observation_at", sa.DateTime())),
        ("last_rate_in_bps", sa.Column("last_rate_in_bps", sa.BigInteger())),
        ("last_rate_out_bps", sa.Column("last_rate_out_bps", sa.BigInteger())),
    ):
        op.add_column("traffic_sources", column)
        if name in {"last_failed_at", "last_error_category", "backoff_until"}:
            op.create_index(f"ix_traffic_sources_{name}", "traffic_sources", [name])
    op.add_column("traffic_counter_observations", sa.Column("inbound_bps", sa.BigInteger()))
    op.add_column("traffic_counter_observations", sa.Column("outbound_bps", sa.BigInteger()))
    for name, column in (
        ("inbound_direction", sa.Column("inbound_direction", sa.String(20), nullable=False, server_default="download")),
        ("outbound_direction", sa.Column("outbound_direction", sa.String(20), nullable=False, server_default="upload")),
        ("description", sa.Column("description", sa.String(500))),
        ("admin_status", sa.Column("admin_status", sa.Integer())),
        ("oper_status", sa.Column("oper_status", sa.Integer())),
        ("last_discovered_at", sa.Column("last_discovered_at", sa.DateTime())),
    ):
        op.add_column("traffic_interfaces", column)
    op.add_column("traffic_counter_observations", sa.Column("discontinuity_ticks", sa.BigInteger()))
    op.add_column("traffic_aggregates", sa.Column("is_approximate", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "traffic_polling_leases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_token", sa.String(80)),
        sa.Column("lease_until", sa.DateTime()),
        sa.Column("heartbeat_at", sa.DateTime()),
    )
    op.create_index("ix_traffic_polling_leases_lease_until", "traffic_polling_leases", ["lease_until"])


def downgrade() -> None:
    op.drop_index("ix_traffic_polling_leases_lease_until", table_name="traffic_polling_leases")
    op.drop_table("traffic_polling_leases")
    op.drop_column("traffic_counter_observations", "outbound_bps")
    op.drop_column("traffic_counter_observations", "inbound_bps")
    op.drop_column("traffic_counter_observations", "discontinuity_ticks")
    op.drop_column("traffic_aggregates", "is_approximate")
    for name in ("last_discovered_at", "oper_status", "admin_status", "description", "outbound_direction", "inbound_direction"):
        op.drop_column("traffic_interfaces", name)
    for name in ("last_rate_out_bps", "last_rate_in_bps", "last_counter_observation_at", "backoff_until", "consecutive_failures", "last_poll_duration_ms", "last_error_category", "last_failed_at"):
        if name in {"last_failed_at", "last_error_category", "backoff_until"}:
            op.drop_index(f"ix_traffic_sources_{name}", table_name="traffic_sources")
        op.drop_column("traffic_sources", name)
