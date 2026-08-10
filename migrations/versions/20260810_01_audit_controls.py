"""Add audit capture classification for configurable filtering."""

from alembic import op
import sqlalchemy as sa

revision = "20260810_01"
down_revision = "20260804_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("audit_logs") as batch:
        batch.add_column(sa.Column("capture_tier", sa.String(length=20), nullable=False, server_default="standard"))
        batch.create_index("ix_audit_logs_capture_tier", ["capture_tier"])


def downgrade() -> None:
    with op.batch_alter_table("audit_logs") as batch:
        batch.drop_index("ix_audit_logs_capture_tier")
        batch.drop_column("capture_tier")
