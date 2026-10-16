"""Keep discovery link identity separate for original and translated endpoints."""

from alembic import op
import sqlalchemy as sa


revision = "20261014_02"
down_revision = "20261014_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("traffic_discovery_links", recreate="always") as batch:
        batch.add_column(sa.Column("endpoint_role", sa.String(32), nullable=True))
    op.execute(
        sa.text(
            "UPDATE traffic_discovery_links "
            "SET endpoint_role = 'legacy_unknown' WHERE endpoint_role IS NULL"
        )
    )
    with op.batch_alter_table("traffic_discovery_links", recreate="always") as batch:
        batch.alter_column("endpoint_role", existing_type=sa.String(32), nullable=False)
        batch.drop_constraint("uq_traffic_discovery_link_identity", type_="unique")
        batch.create_unique_constraint(
            "uq_traffic_discovery_link_identity_role",
            ["source_id", "exporter_identity", "endpoint_ip", "endpoint_role"],
        )


def downgrade() -> None:
    duplicate = op.get_bind().exec_driver_sql(
        "SELECT source_id, exporter_identity, endpoint_ip, COUNT(*) "
        "FROM traffic_discovery_links "
        "GROUP BY source_id, exporter_identity, endpoint_ip "
        "HAVING COUNT(*) > 1"
    ).first()
    if duplicate:
        raise RuntimeError(
            "Cannot downgrade discovery links while endpoint-role identities collide."
        )
    with op.batch_alter_table("traffic_discovery_links", recreate="always") as batch:
        batch.drop_constraint("uq_traffic_discovery_link_identity_role", type_="unique")
        batch.create_unique_constraint(
            "uq_traffic_discovery_link_identity",
            ["source_id", "exporter_identity", "endpoint_ip"],
        )
        batch.drop_column("endpoint_role")
