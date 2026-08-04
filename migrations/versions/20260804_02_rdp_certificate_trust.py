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
        batch.add_column(sa.Column("rdp_trust_invalidated_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("rdp_trust_invalidated_reason", sa.String(40), nullable=True))
        batch.create_index("ix_remote_access_rdp_trust_invalidated_at", ["rdp_trust_invalidated_at"])


def downgrade() -> None:
    raise RuntimeError(
        "RDP certificate-trust downgrade is blocked because older Kaya releases universally bypass certificate validation. "
        "Remain on this revision or a later security-equivalent release."
    )
