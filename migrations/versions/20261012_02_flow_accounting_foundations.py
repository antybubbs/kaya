"""Add topology-aware flow accounting and reconciliation foundations."""

from alembic import op
import sqlalchemy as sa

revision = "20261012_02"
down_revision = "20261012_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "traffic_flow_accounting_aggregates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("exporter_identity", sa.String(45), nullable=False),
        sa.Column("bucket_start", sa.DateTime(), nullable=False),
        sa.Column("bucket_seconds", sa.Integer(), nullable=False),
        sa.Column("traffic_class", sa.String(30), nullable=False),
        sa.Column("bytes_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("packets_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("data_quality", sa.String(20), nullable=False, server_default="complete"),
        sa.Column("classification_confidence", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("attribution_state", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("unresolved_reason", sa.String(80)),
        sa.Column("first_observed_at", sa.DateTime()),
        sa.Column("last_observed_at", sa.DateTime()),
        sa.UniqueConstraint("source_id", "exporter_identity", "bucket_start", "bucket_seconds", "traffic_class", name="uq_traffic_flow_accounting_bucket"),
    )
    op.create_index("ix_traffic_flow_accounting_source_time", "traffic_flow_accounting_aggregates", ["source_id", "bucket_start"])
    op.create_index("ix_traffic_flow_accounting_class_time", "traffic_flow_accounting_aggregates", ["traffic_class", "bucket_start"])
    op.create_table(
        "traffic_flow_reconciliations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("interface_id", sa.Integer(), sa.ForeignKey("traffic_interfaces.id", ondelete="SET NULL")),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("window_end", sa.DateTime(), nullable=False),
        sa.Column("snmp_bytes", sa.BigInteger()), sa.Column("flow_bytes", sa.BigInteger()),
        sa.Column("unattributed_bytes", sa.BigInteger()), sa.Column("unclassified_bytes", sa.BigInteger()),
        sa.Column("comparable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("coverage_percent", sa.Integer()),
        sa.Column("status", sa.String(30), nullable=False, server_default="unavailable"),
        sa.Column("reason", sa.String(500)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("source_id", "interface_id", "window_start", "window_end", name="uq_traffic_flow_reconciliation_window"),
    )
    op.create_index("ix_traffic_flow_reconciliations_source_window", "traffic_flow_reconciliations", ["source_id", "window_start"])


def downgrade() -> None:
    op.drop_table("traffic_flow_reconciliations")
    op.drop_table("traffic_flow_accounting_aggregates")
