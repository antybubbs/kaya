"""Record the automation gates each HA agent reports in its signed heartbeat."""

from alembic import op
import sqlalchemy as sa


revision = "20261104_01"
down_revision = "20261102_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ha_nodes") as batch_op:
        batch_op.add_column(sa.Column("agent_automation_gates_json", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ha_nodes") as batch_op:
        batch_op.drop_column("agent_automation_gates_json")
