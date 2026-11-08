"""Track Keepalived baseline restoration and confirm a missing service owner before alerting.

Additive and nullable: NULL means the stable baseline (nopreempt on every node)
is in place or was never departed from, which is every existing cluster.
"""

from alembic import op
import sqlalchemy as sa


revision = "20261105_02"
down_revision = "20261105_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ha_clusters") as batch_op:
        batch_op.add_column(sa.Column("keepalived_restoration_json", sa.Text(), nullable=True))
        # When Kaya first saw no Virtual IP owner or no DHCP server (confirmation before notifying).
        batch_op.add_column(sa.Column("missing_owner_since", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ha_clusters") as batch_op:
        batch_op.drop_column("missing_owner_since")
        batch_op.drop_column("keepalived_restoration_json")
