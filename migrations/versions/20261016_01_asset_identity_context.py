"""Store the network context used when an asset assignment was confirmed."""

from alembic import op
import sqlalchemy as sa


revision = "20261016_01"
down_revision = "20261015_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("asset_network_assignments", sa.Column("network_cidr", sa.String(length=80), nullable=True))
    op.create_index("ix_asset_network_assignments_network_cidr", "asset_network_assignments", ["network_cidr"])


def downgrade() -> None:
    op.drop_index("ix_asset_network_assignments_network_cidr", table_name="asset_network_assignments")
    op.drop_column("asset_network_assignments", "network_cidr")
