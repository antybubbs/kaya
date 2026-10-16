"""Add automatic per-endpoint flow usage aggregates.

Additive only: existing traffic, monitoring and device aggregate tables are
unchanged. Downgrade drops the new table and its derived usage rows only.
"""

from alembic import op
import sqlalchemy as sa


revision = "20261018_01"
down_revision = "20261017_01"
branch_labels = None
depends_on = None

BYTE_COUNT = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "traffic_endpoint_aggregates",
        sa.Column("endpoint_ip", sa.String(45), nullable=False),
        sa.Column("bucket_seconds", sa.Integer(), nullable=False),
        sa.Column("bucket_start", sa.DateTime(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("exporter_identity", sa.String(45), nullable=False),
        sa.Column("direction", sa.String(8), nullable=False),
        sa.Column("address_family", sa.Integer(), nullable=False),
        sa.Column("bytes_total", BYTE_COUNT, nullable=False, server_default="0"),
        sa.Column("packets_total", BYTE_COUNT, nullable=False, server_default="0"),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("data_quality", sa.String(10), nullable=False, server_default="complete"),
        sa.Column("last_observed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("endpoint_ip", "bucket_seconds", "bucket_start", "source_id", "exporter_identity", "direction"),
    )
    op.create_index("ix_traffic_endpoint_aggregates_time", "traffic_endpoint_aggregates", ["bucket_seconds", "bucket_start"])


def downgrade() -> None:
    op.drop_index("ix_traffic_endpoint_aggregates_time", table_name="traffic_endpoint_aggregates")
    op.drop_table("traffic_endpoint_aggregates")
