"""Enable strict per-host RDP certificate trust.

Revision ID: 20260804_02
Revises: 20260804_01
"""

from alembic import op
import sqlalchemy as sa


revision = "20260804_02"
down_revision = "20260804_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("remote_access") as batch:
        batch.add_column(sa.Column("rdp_cert_fingerprints", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("remote_access") as batch:
        batch.drop_column("rdp_cert_fingerprints")
