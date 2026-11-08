"""Record when HA ownership problems began and the last material lease generation.

Additive and nullable only, so existing clusters and agents are unaffected:

* ``ha_clusters.ownership_mismatch_since`` / ``split_brain_since``: when Kaya first
  observed the Virtual IP and DHCP on different nodes, or more than one Virtual
  IP owner.  Used to confirm a condition before notifying, so brief observations
  during a normal local failover do not raise alerts.
* ``ha_lease_replication_states.material_generation``: the latest lease
  generation whose lease set (ignoring renewal expiry times) changed.  NULL
  means "unknown" and is treated as the desired generation (previous behaviour).
"""

from alembic import op
import sqlalchemy as sa


revision = "20261105_01"
down_revision = "20261104_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ha_clusters") as batch_op:
        batch_op.add_column(sa.Column("ownership_mismatch_since", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("split_brain_since", sa.DateTime(), nullable=True))
    with op.batch_alter_table("ha_lease_replication_states") as batch_op:
        batch_op.add_column(sa.Column("material_generation", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ha_lease_replication_states") as batch_op:
        batch_op.drop_column("material_generation")
    with op.batch_alter_table("ha_clusters") as batch_op:
        batch_op.drop_column("split_brain_since")
        batch_op.drop_column("ownership_mismatch_since")
