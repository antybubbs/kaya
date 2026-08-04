"""Bind administrator OIDC link invitations to authenticated recipients.

Revision ID: 20260804_01
Revises: 20260803_02
"""

from alembic import op
import sqlalchemy as sa


revision = "20260804_01"
down_revision = "20260803_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("oidc_link_invitations") as batch:
        batch.add_column(sa.Column("recipient_binding_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("provider_binding_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("redemption_session_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("revoked_at", sa.DateTime(), nullable=True))
    # Legacy bearer-only invitations cannot meet the new recipient-binding contract.
    op.execute(
        "UPDATE oidc_link_invitations "
        "SET recipient_binding_hash = 'legacy-revoked', provider_binding_hash = 'legacy-revoked', revoked_at = CURRENT_TIMESTAMP "
        "WHERE recipient_binding_hash IS NULL"
    )
    with op.batch_alter_table("oidc_link_invitations") as batch:
        batch.alter_column("recipient_binding_hash", existing_type=sa.String(64), nullable=False)
        batch.alter_column("provider_binding_hash", existing_type=sa.String(64), nullable=False)
        batch.create_index("ix_oidc_link_invitations_redemption_session_hash", ["redemption_session_hash"])
        batch.create_index("ix_oidc_link_invitations_revoked_at", ["revoked_at"])

    with op.batch_alter_table("oidc_transactions") as batch:
        batch.add_column(sa.Column("link_invitation_id", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            "fk_oidc_transactions_link_invitation_id",
            "oidc_link_invitations",
            ["link_invitation_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index("ix_oidc_transactions_link_invitation_id", ["link_invitation_id"])


def downgrade() -> None:
    with op.batch_alter_table("oidc_transactions") as batch:
        batch.drop_index("ix_oidc_transactions_link_invitation_id")
        batch.drop_constraint("fk_oidc_transactions_link_invitation_id", type_="foreignkey")
        batch.drop_column("link_invitation_id")
    with op.batch_alter_table("oidc_link_invitations") as batch:
        batch.drop_index("ix_oidc_link_invitations_revoked_at")
        batch.drop_index("ix_oidc_link_invitations_redemption_session_hash")
        batch.drop_column("revoked_at")
        batch.drop_column("redemption_session_hash")
        batch.drop_column("recipient_binding_hash")
        batch.drop_column("provider_binding_hash")
