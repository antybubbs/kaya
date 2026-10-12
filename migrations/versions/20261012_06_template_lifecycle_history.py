"""Add a bounded, privacy-safe template lifecycle history."""

from alembic import op
import sqlalchemy as sa


revision = "20261012_06"
down_revision = "20261012_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "traffic_flow_collector_states",
        sa.Column("template_lifecycle_json", sa.Text(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("traffic_flow_collector_states", "template_lifecycle_json")
