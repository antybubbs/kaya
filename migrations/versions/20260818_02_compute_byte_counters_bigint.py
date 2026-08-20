"""Use BIGINT for compute and inventory byte counters."""

from alembic import op
import sqlalchemy as sa


revision = "20260818_02"
down_revision = "20260818_01"
branch_labels = None
depends_on = None


_BYTE_COLUMNS = (
    ("compute_hosts", "memory_used"),
    ("compute_hosts", "memory_total"),
    ("compute_hosts", "storage_used"),
    ("compute_hosts", "storage_total"),
    ("compute_workloads", "memory_used"),
    ("compute_workloads", "memory_total"),
    ("compute_workloads", "storage_used"),
    ("compute_workloads", "storage_total"),
    ("compute_inventory_items", "size_bytes"),
    ("compute_metrics", "memory_used"),
    ("compute_metrics", "memory_total"),
    ("compute_metrics", "storage_used"),
    ("compute_metrics", "storage_total"),
)


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table_name, column_name in _BYTE_COLUMNS:
        op.alter_column(
            table_name,
            column_name,
            existing_type=sa.Integer(),
            type_=sa.BigInteger(),
            existing_nullable=True,
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table_name, column_name in _BYTE_COLUMNS:
        op.alter_column(
            table_name,
            column_name,
            existing_type=sa.BigInteger(),
            type_=sa.Integer(),
            existing_nullable=True,
        )
