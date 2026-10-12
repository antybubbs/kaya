"""Add opt-in device monitoring periods and bounded aggregates."""

from alembic import op
import sqlalchemy as sa

revision = "20261012_04"
down_revision = "20261012_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Stage 3B declared an indexed source foreign key in the model but its
    # migration omitted the corresponding SQLite/PostgreSQL index. Repair that
    # schema contract in the next forward migration.
    op.create_index("ix_traffic_flow_accounting_aggregates_source_id", "traffic_flow_accounting_aggregates", ["source_id"])
    op.create_table(
        "traffic_device_monitoring",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ip_address_id", sa.Integer(), sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("enabled_at", sa.DateTime()), sa.Column("disabled_at", sa.DateTime()),
        sa.Column("last_attributed_at", sa.DateTime()),
        sa.Column("last_source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(30), nullable=False, server_default="disabled"),
        sa.Column("status_reason", sa.String(500)),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("ip_address_id", name="uq_traffic_device_monitoring_ip"),
    )
    op.create_index("ix_traffic_device_monitoring_ip_address_id", "traffic_device_monitoring", ["ip_address_id"])
    op.create_index("ix_traffic_device_monitoring_is_enabled", "traffic_device_monitoring", ["is_enabled"])
    op.create_index("ix_traffic_device_monitoring_last_attributed_at", "traffic_device_monitoring", ["last_attributed_at"])
    op.create_index("ix_traffic_device_monitoring_last_source_id", "traffic_device_monitoring", ["last_source_id"])
    op.create_index("ix_traffic_device_monitoring_status", "traffic_device_monitoring", ["status"])
    op.create_table(
        "traffic_device_monitoring_periods",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("monitoring_id", sa.Integer(), sa.ForeignKey("traffic_device_monitoring.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address_id", sa.Integer(), sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("ended_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_traffic_device_monitoring_periods_monitoring_id", "traffic_device_monitoring_periods", ["monitoring_id"])
    op.create_index("ix_traffic_device_monitoring_periods_ip_address_id", "traffic_device_monitoring_periods", ["ip_address_id"])
    op.create_index("ix_traffic_device_monitoring_periods_started_at", "traffic_device_monitoring_periods", ["started_at"])
    op.create_index("ix_traffic_device_monitoring_periods_ended_at", "traffic_device_monitoring_periods", ["ended_at"])
    op.create_index("ix_traffic_device_monitoring_periods_ip_started", "traffic_device_monitoring_periods", ["ip_address_id", "started_at"])
    op.create_table(
        "traffic_device_aggregates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("period_id", sa.Integer(), sa.ForeignKey("traffic_device_monitoring_periods.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address_id", sa.Integer(), sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("interface_id", sa.Integer(), sa.ForeignKey("traffic_interfaces.id", ondelete="SET NULL")),
        sa.Column("bucket_start", sa.DateTime(), nullable=False), sa.Column("bucket_seconds", sa.Integer(), nullable=False),
        sa.Column("direction", sa.String(20), nullable=False),
        sa.Column("bytes_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("packets_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("data_quality", sa.String(20), nullable=False, server_default="complete"),
        sa.Column("attribution_confidence", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("first_observed_at", sa.DateTime()), sa.Column("last_observed_at", sa.DateTime()),
        sa.UniqueConstraint("period_id", "source_id", "interface_id", "bucket_start", "bucket_seconds", "direction", name="uq_traffic_device_aggregate_bucket"),
    )
    op.create_index("ix_traffic_device_aggregates_period_id", "traffic_device_aggregates", ["period_id"])
    op.create_index("ix_traffic_device_aggregates_ip_address_id", "traffic_device_aggregates", ["ip_address_id"])
    op.create_index("ix_traffic_device_aggregates_source_id", "traffic_device_aggregates", ["source_id"])
    op.create_index("ix_traffic_device_aggregates_interface_id", "traffic_device_aggregates", ["interface_id"])
    op.create_index("ix_traffic_device_aggregates_bucket_start", "traffic_device_aggregates", ["bucket_start"])
    op.create_index("ix_traffic_device_aggregates_direction", "traffic_device_aggregates", ["direction"])
    op.create_index("ix_traffic_device_aggregates_ip_time", "traffic_device_aggregates", ["ip_address_id", "bucket_start"])
    op.create_index("ix_traffic_device_aggregates_period_time", "traffic_device_aggregates", ["period_id", "bucket_start"])
    for name, column in (
        ("ix_traffic_flow_reconciliations_source_id", "source_id"),
        ("ix_traffic_flow_reconciliations_interface_id", "interface_id"),
        ("ix_traffic_flow_reconciliations_comparable", "comparable"),
        ("ix_traffic_flow_reconciliations_status", "status"),
    ):
        op.create_index(name, "traffic_flow_reconciliations", [column])


def downgrade() -> None:
    op.drop_table("traffic_device_aggregates")
    op.drop_table("traffic_device_monitoring_periods")
    op.drop_table("traffic_device_monitoring")
    op.drop_index("ix_traffic_flow_accounting_aggregates_source_id", table_name="traffic_flow_accounting_aggregates")
    for name in ("ix_traffic_flow_reconciliations_status", "ix_traffic_flow_reconciliations_comparable", "ix_traffic_flow_reconciliations_interface_id", "ix_traffic_flow_reconciliations_source_id"):
        op.drop_index(name, table_name="traffic_flow_reconciliations")
