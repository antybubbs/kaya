"""Add controlled administrator decisions for discovered endpoints."""

from alembic import op
import sqlalchemy as sa


revision = "20261014_01"
down_revision = "20261013_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "traffic_discovery_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("exporter_identity", sa.String(45), nullable=False),
        sa.Column("endpoint_ip", sa.String(45), nullable=False),
        sa.Column("managed_ip_address_id", sa.Integer(), sa.ForeignKey("ip_addresses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("state", sa.String(20), nullable=False, server_default="linked"),
        sa.Column("reason", sa.String(255), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("source_id", "exporter_identity", "endpoint_ip", name="uq_traffic_discovery_link_identity"),
    )
    op.create_index("ix_traffic_discovery_links_source_id", "traffic_discovery_links", ["source_id"])
    op.create_index("ix_traffic_discovery_links_endpoint_ip", "traffic_discovery_links", ["endpoint_ip"])
    op.create_index("ix_traffic_discovery_links_managed_ip", "traffic_discovery_links", ["managed_ip_address_id"])
    op.create_index("ix_traffic_discovery_links_state", "traffic_discovery_links", ["state"])


def downgrade() -> None:
    op.drop_table("traffic_discovery_links")
