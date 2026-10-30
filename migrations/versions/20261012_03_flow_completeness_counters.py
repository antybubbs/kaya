"""Add explicit flow decode, sequence and exporter restart counters."""

from alembic import op
import sqlalchemy as sa

revision = "20261012_03"
down_revision = "20261012_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name in ("decode_failures", "sequence_gaps", "exporter_restarts"):
        op.add_column("traffic_flow_collector_states", sa.Column(name, sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    for name in ("exporter_restarts", "sequence_gaps", "decode_failures"):
        op.drop_column("traffic_flow_collector_states", name)
