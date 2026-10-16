"""Store the trust context used when a discovery link is approved."""

from alembic import op
import sqlalchemy as sa


revision = "20261014_05"
down_revision = "20261014_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("traffic_discovery_links", sa.Column("mapping_vlan_id", sa.Integer(), nullable=True))
    op.add_column("traffic_discovery_links", sa.Column("mapping_network_cidr", sa.String(80), nullable=True))
    op.create_index(
        "ix_traffic_discovery_links_mapping_vlan_id",
        "traffic_discovery_links",
        ["mapping_vlan_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_traffic_discovery_links_mapping_vlan_id", table_name="traffic_discovery_links")
    op.drop_column("traffic_discovery_links", "mapping_network_cidr")
    op.drop_column("traffic_discovery_links", "mapping_vlan_id")
