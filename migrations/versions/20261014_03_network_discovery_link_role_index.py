"""Restore the endpoint-role index required by the discovery link model."""

from alembic import op
import sqlalchemy as sa


revision = "20261014_03"
down_revision = "20261014_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    existing = {index.get("name") for index in sa.inspect(bind).get_indexes("traffic_discovery_links")}
    if "ix_traffic_discovery_links_endpoint_role" not in existing:
        op.create_index(
            "ix_traffic_discovery_links_endpoint_role",
            "traffic_discovery_links",
            ["endpoint_role"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    existing = {index.get("name") for index in sa.inspect(bind).get_indexes("traffic_discovery_links")}
    if "ix_traffic_discovery_links_endpoint_role" in existing:
        op.drop_index("ix_traffic_discovery_links_endpoint_role", table_name="traffic_discovery_links")
