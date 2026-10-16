"""Add explicit exporter-to-VLAN discovery mappings."""

from alembic import op
import sqlalchemy as sa


revision = "20261014_04"
down_revision = "20261014_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "traffic_discovery_network_mappings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("exporter_identity", sa.String(45), nullable=False),
        sa.Column("vlan_id", sa.Integer(), sa.ForeignKey("vlans.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("source_id", "exporter_identity", "vlan_id", name="uq_traffic_discovery_mapping_identity"),
    )
    op.create_index("ix_traffic_discovery_network_mappings_source_id", "traffic_discovery_network_mappings", ["source_id"])
    op.create_index("ix_traffic_discovery_network_mappings_exporter_identity", "traffic_discovery_network_mappings", ["exporter_identity"])
    op.create_index("ix_traffic_discovery_network_mappings_vlan_id", "traffic_discovery_network_mappings", ["vlan_id"])
    op.create_index("ix_traffic_discovery_network_mappings_is_enabled", "traffic_discovery_network_mappings", ["is_enabled"])
    op.create_index("ix_traffic_discovery_mappings_source_exporter", "traffic_discovery_network_mappings", ["source_id", "exporter_identity", "is_enabled"])


def downgrade() -> None:
    op.drop_index("ix_traffic_discovery_mappings_source_exporter", table_name="traffic_discovery_network_mappings")
    op.drop_index("ix_traffic_discovery_network_mappings_is_enabled", table_name="traffic_discovery_network_mappings")
    op.drop_index("ix_traffic_discovery_network_mappings_vlan_id", table_name="traffic_discovery_network_mappings")
    op.drop_index("ix_traffic_discovery_network_mappings_exporter_identity", table_name="traffic_discovery_network_mappings")
    op.drop_index("ix_traffic_discovery_network_mappings_source_id", table_name="traffic_discovery_network_mappings")
    op.drop_table("traffic_discovery_network_mappings")
