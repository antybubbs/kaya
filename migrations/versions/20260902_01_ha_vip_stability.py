"""Persist the HA VIP ownership stability window."""

from alembic import op
import sqlalchemy as sa


revision = "20260902_01"
down_revision = "20260818_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ha_nodes", sa.Column("vip_stable_since", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("ha_nodes", "vip_stable_since")
