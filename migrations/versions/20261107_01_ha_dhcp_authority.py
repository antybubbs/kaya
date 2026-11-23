"""Record which node holds DHCP authority (DHCP handover protocol PROPOSAL; not approved for release).

Additive and nullable: NULL means no authority has been established yet, which is every existing
cluster.  Kaya establishes it once from a fully verified, aligned topology, or grants it when it
promotes a node after verified release.  It is never derived from roles.

``ha_nodes.dhcp_authority_epoch`` is the newest epoch each node reports having seen (NULL for
agents that do not report it).  A reported epoch newer than Kaya's record means Kaya's database is
older than the cluster (for example restored from a backup); Kaya then re-establishes authority.
``ha_nodes.dhcp_guard_mode`` is "dns_only" while a node's Pi-hole FTL runs with DHCP forced off.
"""

from alembic import op
import sqlalchemy as sa


revision = "20261107_01"
down_revision = "20261105_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ha_clusters") as batch_op:
        batch_op.add_column(sa.Column("dhcp_authority_json", sa.Text(), nullable=True))
    with op.batch_alter_table("ha_nodes") as batch_op:
        batch_op.add_column(sa.Column("dhcp_authority_epoch", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("dhcp_guard_mode", sa.String(length=20), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ha_nodes") as batch_op:
        batch_op.drop_column("dhcp_guard_mode")
        batch_op.drop_column("dhcp_authority_epoch")
    with op.batch_alter_table("ha_clusters") as batch_op:
        batch_op.drop_column("dhcp_authority_json")
