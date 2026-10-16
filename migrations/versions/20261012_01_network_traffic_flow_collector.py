"""Add bounded flow collector state and separate flow aggregates."""

from alembic import op
import sqlalchemy as sa


revision = "20261012_01"
down_revision = "20261008_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "traffic_flow_collector_global_states",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("listener_state", sa.String(30), nullable=False, server_default="stopped"),
        sa.Column("last_datagram_at", sa.DateTime()),
        sa.Column("packets_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unknown_exporter_packets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rate_limited_packets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("oversized_packets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_traffic_flow_collector_global_states_listener_state", "traffic_flow_collector_global_states", ["listener_state"])
    op.create_index("ix_traffic_flow_collector_global_states_last_datagram_at", "traffic_flow_collector_global_states", ["last_datagram_at"])
    op.create_table(
        "traffic_flow_collector_states",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("listener_state", sa.String(30), nullable=False, server_default="stopped"),
        sa.Column("last_datagram_at", sa.DateTime()), sa.Column("last_valid_flow_at", sa.DateTime()),
        sa.Column("packets_accepted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("packets_rejected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unknown_exporter_packets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("malformed_packets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unknown_templates", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("template_cache_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("queue_depth", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("queue_drops", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duplicate_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("out_of_order_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("persistence_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_aggregate_write_at", sa.DateTime()),
        sa.Column("last_error_category", sa.String(40)),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("source_id", name="uq_traffic_flow_collector_states_source"),
    )
    for name, columns in {
        "ix_traffic_flow_collector_states_source_id": ["source_id"],
        "ix_traffic_flow_collector_states_listener_state": ["listener_state"],
        "ix_traffic_flow_collector_states_last_datagram_at": ["last_datagram_at"],
        "ix_traffic_flow_collector_states_last_valid_flow_at": ["last_valid_flow_at"],
    }.items():
        op.create_index(name, "traffic_flow_collector_states", columns)

    op.create_table(
        "traffic_flow_deduplication",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_key", sa.String(64), nullable=False),
        sa.Column("processed_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("event_key", name="uq_traffic_flow_deduplication_key"),
    )
    op.create_index("ix_traffic_flow_deduplication_source_id", "traffic_flow_deduplication", ["source_id"])
    op.create_index("ix_traffic_flow_deduplication_processed_at", "traffic_flow_deduplication", ["processed_at"])
    op.create_index("ix_traffic_flow_deduplication_expiry", "traffic_flow_deduplication", ["expires_at"])

    op.create_table(
        "traffic_flow_counter_states",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("exporter_identity", sa.String(45), nullable=False),
        sa.Column("connection_id", sa.String(80), nullable=False),
        sa.Column("last_event_at", sa.DateTime()), sa.Column("last_bytes", sa.BigInteger()), sa.Column("last_packets", sa.BigInteger()),
        sa.Column("last_event_type", sa.String(30)), sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("source_id", "exporter_identity", "connection_id", name="uq_traffic_flow_counter_state_identity"),
    )
    op.create_index("ix_traffic_flow_counter_states_source_id", "traffic_flow_counter_states", ["source_id"])
    op.create_index("ix_traffic_flow_counter_state_expiry", "traffic_flow_counter_states", ["expires_at"])

    op.create_table(
        "traffic_flow_aggregates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("exporter_identity", sa.String(45), nullable=False),
        sa.Column("bucket_start", sa.DateTime(), nullable=False),
        sa.Column("bucket_seconds", sa.Integer(), nullable=False),
        sa.Column("direction", sa.String(20), nullable=False),
        sa.Column("traffic_class", sa.String(30), nullable=False, server_default="flow_total"),
        sa.Column("bytes_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("packets_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("data_quality", sa.String(20), nullable=False, server_default="complete"),
        sa.Column("first_observed_at", sa.DateTime()), sa.Column("last_observed_at", sa.DateTime()),
        sa.UniqueConstraint("source_id", "exporter_identity", "bucket_start", "bucket_seconds", "direction", "traffic_class", name="uq_traffic_flow_aggregates_bucket"),
    )
    op.create_index("ix_traffic_flow_aggregates_source_id", "traffic_flow_aggregates", ["source_id"])
    op.create_index("ix_traffic_flow_aggregates_bucket_start", "traffic_flow_aggregates", ["bucket_start"])
    op.create_index("ix_traffic_flow_aggregates_source_time", "traffic_flow_aggregates", ["source_id", "bucket_start"])


def downgrade() -> None:
    op.drop_table("traffic_flow_aggregates")
    op.drop_table("traffic_flow_counter_states")
    op.drop_table("traffic_flow_deduplication")
    op.drop_table("traffic_flow_collector_states")
    op.drop_table("traffic_flow_collector_global_states")
