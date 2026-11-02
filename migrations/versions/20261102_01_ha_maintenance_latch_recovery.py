"""Add auditable HA maintenance-latch recovery state."""

from alembic import op
import sqlalchemy as sa


revision = "20261102_01"
down_revision = "20261030_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ha_clusters") as batch_op:
        batch_op.add_column(sa.Column("automatic_sync_hold", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("maintenance_latch_acknowledged_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("maintenance_latch_acknowledged_by_user_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("maintenance_latch_acknowledgement_json", sa.Text(), nullable=False, server_default="{}"))
        batch_op.add_column(sa.Column("maintenance_latch_released_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("maintenance_latch_released_by_user_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("maintenance_latch_release_json", sa.Text(), nullable=False, server_default="{}"))
        batch_op.create_foreign_key("fk_ha_clusters_latch_ack_user", "users", ["maintenance_latch_acknowledged_by_user_id"], ["id"], ondelete="SET NULL")
        batch_op.create_foreign_key("fk_ha_clusters_latch_release_user", "users", ["maintenance_latch_released_by_user_id"], ["id"], ondelete="SET NULL")


def downgrade() -> None:
    with op.batch_alter_table("ha_clusters") as batch_op:
        batch_op.drop_constraint("fk_ha_clusters_latch_release_user", type_="foreignkey")
        batch_op.drop_constraint("fk_ha_clusters_latch_ack_user", type_="foreignkey")
        batch_op.drop_column("maintenance_latch_release_json")
        batch_op.drop_column("maintenance_latch_released_by_user_id")
        batch_op.drop_column("maintenance_latch_released_at")
        batch_op.drop_column("maintenance_latch_acknowledgement_json")
        batch_op.drop_column("maintenance_latch_acknowledged_by_user_id")
        batch_op.drop_column("maintenance_latch_acknowledged_at")
        batch_op.drop_column("automatic_sync_hold")
