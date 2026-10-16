"""Add disabled-by-default Network Traffic foundations."""

from alembic import op
import sqlalchemy as sa


revision = "20261008_01"
down_revision = "20260902_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "traffic_monitoring_configurations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("high_resolution_retention_hours", sa.Integer(), nullable=False, server_default="24"),
        sa.Column("five_minute_retention_days", sa.Integer(), nullable=False, server_default="7"),
        sa.Column("hourly_retention_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("daily_retention_days", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_traffic_monitoring_configurations_is_enabled", "traffic_monitoring_configurations", ["is_enabled"])
    op.create_table(
        "traffic_sources",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(120), nullable=False),
        sa.Column("provider_key", sa.String(60), nullable=False), sa.Column("source_category", sa.String(30), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("configuration_state", sa.String(30), nullable=False, server_default="unconfigured"), sa.Column("health_state", sa.String(30), nullable=False, server_default="unconfigured"),
        sa.Column("health_reason", sa.String(500)), sa.Column("destination_ip", sa.String(45)), sa.Column("destination_port", sa.Integer(), nullable=False, server_default="161"),
        sa.Column("security_name", sa.String(128)), sa.Column("snmp_auth_protocol", sa.String(20)), sa.Column("snmp_privacy_protocol", sa.String(20)),
        sa.Column("encrypted_snmp_authentication", sa.Text()), sa.Column("encrypted_snmp_privacy", sa.Text()), sa.Column("exporter_allowlist_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("collector_port", sa.Integer()), sa.Column("polling_interval_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("last_success_at", sa.DateTime()), sa.Column("last_received_at", sa.DateTime()), sa.Column("created_at", sa.DateTime(), nullable=False), sa.Column("updated_at", sa.DateTime(), nullable=False), sa.Column("deleted_at", sa.DateTime()),
        sa.UniqueConstraint("name", name="uq_traffic_sources_name"),
    )
    for name, cols in {
        "ix_traffic_sources_provider_key": ["provider_key"], "ix_traffic_sources_source_category": ["source_category"], "ix_traffic_sources_is_enabled": ["is_enabled"], "ix_traffic_sources_is_deleted": ["is_deleted"], "ix_traffic_sources_configuration_state": ["configuration_state"], "ix_traffic_sources_health_state": ["health_state"], "ix_traffic_sources_last_success_at": ["last_success_at"], "ix_traffic_sources_last_received_at": ["last_received_at"], "ix_traffic_sources_deleted_at": ["deleted_at"], "ix_traffic_sources_active_state": ["is_deleted", "is_enabled", "configuration_state"],
    }.items(): op.create_index(name, "traffic_sources", cols)
    op.create_table(
        "traffic_interfaces",
        sa.Column("id", sa.Integer(), primary_key=True), sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False), sa.Column("interface_key", sa.String(120), nullable=False), sa.Column("interface_index", sa.Integer()), sa.Column("display_name", sa.String(255), nullable=False), sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("is_wan", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("speed_bps", sa.BigInteger()), sa.Column("created_at", sa.DateTime(), nullable=False), sa.Column("updated_at", sa.DateTime(), nullable=False), sa.UniqueConstraint("source_id", "interface_key", name="uq_traffic_interfaces_source_key"),
    )
    for name, cols in {"ix_traffic_interfaces_source_id": ["source_id"], "ix_traffic_interfaces_is_enabled": ["is_enabled"], "ix_traffic_interfaces_is_wan": ["is_wan"], "ix_traffic_interfaces_source_wan": ["source_id", "is_wan", "is_enabled"]}.items(): op.create_index(name, "traffic_interfaces", cols)
    op.create_table("traffic_local_networks", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(120), nullable=False), sa.Column("network_cidr", sa.String(80), nullable=False), sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("created_at", sa.DateTime(), nullable=False), sa.Column("updated_at", sa.DateTime(), nullable=False), sa.UniqueConstraint("network_cidr", name="uq_traffic_local_networks_cidr"))
    op.create_index("ix_traffic_local_networks_network_cidr", "traffic_local_networks", ["network_cidr"])
    op.create_index("ix_traffic_local_networks_is_enabled", "traffic_local_networks", ["is_enabled"])
    op.create_table("traffic_counter_observations", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False), sa.Column("interface_id", sa.Integer(), sa.ForeignKey("traffic_interfaces.id", ondelete="CASCADE"), nullable=False), sa.Column("observation_key", sa.String(180), nullable=False), sa.Column("observed_at", sa.DateTime(), nullable=False), sa.Column("inbound_counter", sa.BigInteger()), sa.Column("outbound_counter", sa.BigInteger()), sa.Column("counter_bits", sa.Integer(), nullable=False, server_default="64"), sa.Column("reset_detected", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("exporter_epoch", sa.String(120)), sa.UniqueConstraint("observation_key", name="uq_traffic_counter_observations_key"))
    op.create_index("ix_traffic_counter_observations_source_id", "traffic_counter_observations", ["source_id"]); op.create_index("ix_traffic_counter_observations_interface_id", "traffic_counter_observations", ["interface_id"]); op.create_index("ix_traffic_counter_observations_observed_at", "traffic_counter_observations", ["observed_at"]); op.create_index("ix_traffic_counter_observations_interface_time", "traffic_counter_observations", ["interface_id", "observed_at"]); op.create_index("ix_traffic_counter_observations_source_time", "traffic_counter_observations", ["source_id", "observed_at"])
    op.create_table("traffic_aggregates", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False), sa.Column("interface_id", sa.Integer(), sa.ForeignKey("traffic_interfaces.id", ondelete="CASCADE"), nullable=False), sa.Column("bucket_start", sa.DateTime(), nullable=False), sa.Column("bucket_seconds", sa.Integer(), nullable=False), sa.Column("direction", sa.String(20), nullable=False), sa.Column("traffic_class", sa.String(30), nullable=False), sa.Column("bytes_total", sa.BigInteger(), nullable=False, server_default="0"), sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("first_observed_at", sa.DateTime()), sa.Column("last_observed_at", sa.DateTime()), sa.UniqueConstraint("source_id", "interface_id", "bucket_start", "bucket_seconds", "direction", "traffic_class", name="uq_traffic_aggregates_bucket"))
    op.create_index("ix_traffic_aggregates_source_id", "traffic_aggregates", ["source_id"]); op.create_index("ix_traffic_aggregates_interface_id", "traffic_aggregates", ["interface_id"]); op.create_index("ix_traffic_aggregates_bucket_start", "traffic_aggregates", ["bucket_start"]); op.create_index("ix_traffic_aggregates_source_time", "traffic_aggregates", ["source_id", "bucket_start"]); op.create_index("ix_traffic_aggregates_interface_time", "traffic_aggregates", ["interface_id", "bucket_start"])


def downgrade() -> None:
    op.drop_table("traffic_aggregates")
    op.drop_table("traffic_counter_observations")
    op.drop_table("traffic_local_networks")
    op.drop_table("traffic_interfaces")
    op.drop_table("traffic_sources")
    op.drop_index("ix_traffic_monitoring_configurations_is_enabled", table_name="traffic_monitoring_configurations")
    op.drop_table("traffic_monitoring_configurations")
