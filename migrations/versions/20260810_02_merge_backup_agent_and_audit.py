"""Merge the backup-agent and audit-control migration branches."""

revision = "20260810_02"
down_revision = ("20260804_03", "20260810_01")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    raise RuntimeError(
        "Migration downgrade is blocked: this merge revision cannot be downgraded "
        "because it would recreate multiple migration heads."
    )
