"""Add assignment-backed monitoring targets without rewriting legacy traffic data."""

from alembic import op
import sqlalchemy as sa


revision = "20261017_01"
down_revision = "20261016_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("traffic_device_monitoring") as batch:
        batch.alter_column("ip_address_id", existing_type=sa.Integer(), nullable=True)
        batch.add_column(sa.Column("asset_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("assignment_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_traffic_device_monitoring_asset", "hardware_assets", ["asset_id"], ["id"], ondelete="CASCADE")
        batch.create_foreign_key("fk_traffic_device_monitoring_assignment", "asset_network_assignments", ["assignment_id"], ["id"], ondelete="CASCADE")
        batch.drop_constraint("uq_traffic_device_monitoring_ip", type_="unique")
        batch.create_check_constraint("ck_traffic_device_monitoring_one_target", "(ip_address_id IS NOT NULL AND assignment_id IS NULL AND asset_id IS NULL) OR (ip_address_id IS NULL AND assignment_id IS NOT NULL AND asset_id IS NOT NULL)")
    op.create_index("uq_traffic_device_monitoring_ip", "traffic_device_monitoring", ["ip_address_id"], unique=True, postgresql_where=sa.text("ip_address_id IS NOT NULL"), sqlite_where=sa.text("ip_address_id IS NOT NULL"))
    op.create_index("uq_traffic_device_monitoring_assignment", "traffic_device_monitoring", ["assignment_id"], unique=True, postgresql_where=sa.text("assignment_id IS NOT NULL"), sqlite_where=sa.text("assignment_id IS NOT NULL"))
    op.create_index("ix_traffic_device_monitoring_asset_id", "traffic_device_monitoring", ["asset_id"])
    op.create_index("ix_traffic_device_monitoring_assignment_id", "traffic_device_monitoring", ["assignment_id"])

    with op.batch_alter_table("traffic_device_monitoring_periods") as batch:
        batch.alter_column("ip_address_id", existing_type=sa.Integer(), nullable=True)
        batch.add_column(sa.Column("asset_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("assignment_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("endpoint_address", sa.String(80), nullable=True))
        batch.add_column(sa.Column("address_family", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("exporter_identity", sa.String(45), nullable=True))
        batch.create_foreign_key("fk_traffic_device_period_asset", "hardware_assets", ["asset_id"], ["id"], ondelete="CASCADE")
        batch.create_foreign_key("fk_traffic_device_period_assignment", "asset_network_assignments", ["assignment_id"], ["id"], ondelete="CASCADE")
        batch.create_check_constraint("ck_traffic_device_period_one_target", "(ip_address_id IS NOT NULL AND assignment_id IS NULL AND asset_id IS NULL) OR (ip_address_id IS NULL AND assignment_id IS NOT NULL AND asset_id IS NOT NULL)")
    op.create_index("ix_traffic_device_monitoring_periods_assignment_started", "traffic_device_monitoring_periods", ["assignment_id", "started_at"])
    for column in ("asset_id", "assignment_id", "endpoint_address", "address_family", "exporter_identity"):
        op.create_index(f"ix_traffic_device_monitoring_periods_{column}", "traffic_device_monitoring_periods", [column])

    with op.batch_alter_table("traffic_device_aggregates") as batch:
        batch.alter_column("ip_address_id", existing_type=sa.Integer(), nullable=True)
        batch.add_column(sa.Column("asset_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("assignment_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("endpoint_address", sa.String(80), nullable=True))
        batch.add_column(sa.Column("address_family", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("exporter_identity", sa.String(45), nullable=True))
        batch.create_foreign_key("fk_traffic_device_aggregate_asset", "hardware_assets", ["asset_id"], ["id"], ondelete="CASCADE")
        batch.create_foreign_key("fk_traffic_device_aggregate_assignment", "asset_network_assignments", ["assignment_id"], ["id"], ondelete="CASCADE")
        batch.drop_constraint("uq_traffic_device_aggregate_bucket", type_="unique")
    op.create_index("uq_traffic_device_aggregate_legacy_bucket", "traffic_device_aggregates", ["period_id", "source_id", "interface_id", "bucket_start", "bucket_seconds", "direction"], unique=True, postgresql_where=sa.text("assignment_id IS NULL"), sqlite_where=sa.text("assignment_id IS NULL"))
    op.create_index("uq_traffic_device_aggregate_assignment_bucket", "traffic_device_aggregates", ["period_id", "assignment_id", "source_id", "interface_id", "bucket_start", "bucket_seconds", "direction"], unique=True, postgresql_where=sa.text("assignment_id IS NOT NULL"), sqlite_where=sa.text("assignment_id IS NOT NULL"))
    for column in ("asset_id", "assignment_id", "endpoint_address", "address_family", "exporter_identity"):
        op.create_index(f"ix_traffic_device_aggregates_{column}", "traffic_device_aggregates", [column])


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("traffic_device_aggregates", "traffic_device_monitoring_periods", "traffic_device_monitoring"):
        if bind.execute(sa.text(f"SELECT COUNT(*) FROM {table} WHERE assignment_id IS NOT NULL")).scalar():
            raise RuntimeError("Cannot downgrade while assignment-backed traffic monitoring records exist.")
    op.drop_index("uq_traffic_device_aggregate_assignment_bucket", table_name="traffic_device_aggregates")
    op.drop_index("uq_traffic_device_aggregate_legacy_bucket", table_name="traffic_device_aggregates")
    for column in ("asset_id", "assignment_id", "endpoint_address", "address_family", "exporter_identity"):
        op.drop_index(f"ix_traffic_device_aggregates_{column}", table_name="traffic_device_aggregates")
    with op.batch_alter_table("traffic_device_aggregates") as batch:
        batch.create_unique_constraint("uq_traffic_device_aggregate_bucket", ["period_id", "source_id", "interface_id", "bucket_start", "bucket_seconds", "direction"])
        for column in ("exporter_identity", "address_family", "endpoint_address", "assignment_id", "asset_id"):
            batch.drop_column(column)
        batch.alter_column("ip_address_id", existing_type=sa.Integer(), nullable=False)
    op.drop_index("ix_traffic_device_monitoring_periods_assignment_started", table_name="traffic_device_monitoring_periods")
    for column in ("asset_id", "assignment_id", "endpoint_address", "address_family", "exporter_identity"):
        op.drop_index(f"ix_traffic_device_monitoring_periods_{column}", table_name="traffic_device_monitoring_periods")
    with op.batch_alter_table("traffic_device_monitoring_periods") as batch:
        batch.drop_constraint("ck_traffic_device_period_one_target", type_="check")
        batch.drop_constraint("fk_traffic_device_period_assignment", type_="foreignkey")
        batch.drop_constraint("fk_traffic_device_period_asset", type_="foreignkey")
        for column in ("exporter_identity", "address_family", "endpoint_address", "assignment_id", "asset_id"):
            batch.drop_column(column)
        batch.alter_column("ip_address_id", existing_type=sa.Integer(), nullable=False)
    op.drop_index("uq_traffic_device_monitoring_assignment", table_name="traffic_device_monitoring")
    op.drop_index("uq_traffic_device_monitoring_ip", table_name="traffic_device_monitoring")
    op.drop_index("ix_traffic_device_monitoring_assignment_id", table_name="traffic_device_monitoring")
    op.drop_index("ix_traffic_device_monitoring_asset_id", table_name="traffic_device_monitoring")
    with op.batch_alter_table("traffic_device_monitoring") as batch:
        batch.drop_constraint("ck_traffic_device_monitoring_one_target", type_="check")
        batch.drop_constraint("fk_traffic_device_monitoring_assignment", type_="foreignkey")
        batch.drop_constraint("fk_traffic_device_monitoring_asset", type_="foreignkey")
        batch.drop_column("assignment_id")
        batch.drop_column("asset_id")
        batch.alter_column("ip_address_id", existing_type=sa.Integer(), nullable=False)
        batch.create_unique_constraint("uq_traffic_device_monitoring_ip", ["ip_address_id"])
