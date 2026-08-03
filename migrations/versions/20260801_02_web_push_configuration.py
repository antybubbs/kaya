"""Add encrypted UI-managed Web Push configuration.

Revision ID: 20260801_02
Revises: 20260801_01
"""

from alembic import op
import sqlalchemy as sa

revision = "20260801_02"
down_revision = "20260801_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "web_push_configurations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("encrypted_private_key", sa.Text(), nullable=False),
        sa.Column("public_key", sa.String(180), nullable=False),
        sa.Column("public_key_fingerprint", sa.String(120), nullable=False),
        sa.Column("subject", sa.String(500), nullable=False),
        sa.Column("installation_label", sa.String(120)),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("generated_at", sa.DateTime(), nullable=False),
        sa.Column("rotated_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("web_push_configurations")
