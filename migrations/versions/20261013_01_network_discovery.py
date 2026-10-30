"""Add disabled-by-default bounded network discovery storage."""

from alembic import op
import sqlalchemy as sa


revision = "20261013_01"
down_revision = "20261012_07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "traffic_discovery_configurations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("detailed_retention_hours", sa.Integer(), nullable=False, server_default="72"),
        sa.Column("summary_retention_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("max_detail_rows", sa.Integer(), nullable=False, server_default="100000"),
        sa.Column("max_summary_rows", sa.Integer(), nullable=False, server_default="100000"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_traffic_discovery_configurations_is_enabled", "traffic_discovery_configurations", ["is_enabled"])
    op.create_table(
        "traffic_discovery_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("exporter_identity", sa.String(45), nullable=False),
        sa.Column("endpoint_ip", sa.String(45), nullable=False),
        sa.Column("address_family", sa.Integer(), nullable=False),
        sa.Column("endpoint_role", sa.String(32), nullable=False),
        sa.Column("bucket_start", sa.DateTime(), nullable=False),
        sa.Column("bucket_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("classification", sa.String(20), nullable=False, server_default="internal"),
        sa.Column("confidence", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("ambiguity_reason", sa.String(120)),
        sa.UniqueConstraint("source_id", "exporter_identity", "endpoint_ip", "endpoint_role", "bucket_start", name="uq_traffic_discovery_observation_bucket"),
    )
    op.create_index("ix_traffic_discovery_observations_source_id", "traffic_discovery_observations", ["source_id"])
    op.create_index("ix_traffic_discovery_observations_endpoint_ip", "traffic_discovery_observations", ["endpoint_ip"])
    op.create_index("ix_traffic_discovery_observations_bucket_start", "traffic_discovery_observations", ["bucket_start"])
    op.create_index("ix_traffic_discovery_observations_source_time", "traffic_discovery_observations", ["source_id", "bucket_start"])
    op.create_index("ix_traffic_discovery_observations_endpoint_time", "traffic_discovery_observations", ["endpoint_ip", "bucket_start"])
    op.create_index("ix_traffic_discovery_observations_last_seen", "traffic_discovery_observations", ["last_seen_at"])
    op.create_table(
        "traffic_discovery_summaries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("exporter_identity", sa.String(45), nullable=False),
        sa.Column("endpoint_ip", sa.String(45), nullable=False),
        sa.Column("address_family", sa.Integer(), nullable=False),
        sa.Column("endpoint_role", sa.String(32), nullable=False),
        sa.Column("bucket_start", sa.DateTime(), nullable=False),
        sa.Column("bucket_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("classification", sa.String(20), nullable=False, server_default="internal"),
        sa.Column("confidence", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("ambiguity_reason", sa.String(120)),
        sa.UniqueConstraint("source_id", "exporter_identity", "endpoint_ip", "endpoint_role", "bucket_start", name="uq_traffic_discovery_summary_bucket"),
    )
    op.create_index("ix_traffic_discovery_summaries_source_id", "traffic_discovery_summaries", ["source_id"])
    op.create_index("ix_traffic_discovery_summaries_endpoint_ip", "traffic_discovery_summaries", ["endpoint_ip"])
    op.create_index("ix_traffic_discovery_summaries_bucket_start", "traffic_discovery_summaries", ["bucket_start"])
    op.create_index("ix_traffic_discovery_summaries_source_time", "traffic_discovery_summaries", ["source_id", "bucket_start"])
    op.create_index("ix_traffic_discovery_summaries_endpoint_time", "traffic_discovery_summaries", ["endpoint_ip", "bucket_start"])
    op.create_index("ix_traffic_discovery_summaries_last_seen", "traffic_discovery_summaries", ["last_seen_at"])


def downgrade() -> None:
    op.drop_table("traffic_discovery_summaries")
    op.drop_table("traffic_discovery_observations")
    op.drop_index("ix_traffic_discovery_configurations_is_enabled", table_name="traffic_discovery_configurations")
    op.drop_table("traffic_discovery_configurations")
