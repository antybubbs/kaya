"""Add backup-agent protocol-v2 identity and dispatch state.

Revision ID: 20260804_03
Revises: 20260804_02
"""

from alembic import op
import sqlalchemy as sa


revision = "20260804_03"
down_revision = "20260804_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "backup_agent_identities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("compute_hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("scopes_json", sa.Text(), nullable=False),
        sa.Column("envelope_public_key", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("activated_at", sa.DateTime()),
        sa.Column("revoked_at", sa.DateTime()),
        sa.UniqueConstraint("host_id"),
    )
    op.create_index("ix_backup_agent_identities_host_id", "backup_agent_identities", ["host_id"])
    op.create_index("ix_backup_agent_identities_state", "backup_agent_identities", ["state"])
    op.create_index("ix_backup_agent_identities_revoked_at", "backup_agent_identities", ["revoked_at"])
    op.create_table(
        "backup_agent_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("identity_id", sa.String(36), sa.ForeignKey("backup_agent_identities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key_id", sa.String(36), nullable=False, unique=True),
        sa.Column("signing_public_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("retired_at", sa.DateTime()),
    )
    op.create_index("ix_backup_agent_keys_identity_id", "backup_agent_keys", ["identity_id"])
    op.create_index("ix_backup_agent_keys_key_id", "backup_agent_keys", ["key_id"], unique=True)
    op.create_index("ix_backup_agent_keys_status", "backup_agent_keys", ["status"])
    op.create_table(
        "backup_agent_bootstraps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("compute_hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime()),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_backup_agent_bootstraps_host_id", "backup_agent_bootstraps", ["host_id"])
    op.create_index("ix_backup_agent_bootstraps_token_hash", "backup_agent_bootstraps", ["token_hash"], unique=True)
    op.create_index("ix_backup_agent_bootstraps_expires_at", "backup_agent_bootstraps", ["expires_at"])
    op.create_index("ix_backup_agent_bootstraps_used_at", "backup_agent_bootstraps", ["used_at"])
    op.create_table(
        "backup_agent_requests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("identity_id", sa.String(36), sa.ForeignKey("backup_agent_identities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("identity_id", "request_id", name="uq_backup_agent_request_replay"),
    )
    op.create_index("ix_backup_agent_requests_identity_id", "backup_agent_requests", ["identity_id"])
    op.create_index("ix_backup_agent_requests_request_id", "backup_agent_requests", ["request_id"])
    op.create_index("ix_backup_agent_requests_received_at", "backup_agent_requests", ["received_at"])
    op.create_table(
        "backup_agent_dispatches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("backup_job_id", sa.Integer(), sa.ForeignKey("backup_jobs.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("identity_id", sa.String(36), sa.ForeignKey("backup_agent_identities.id", ondelete="SET NULL")),
        sa.Column("claim_id", sa.String(36)),
        sa.Column("state", sa.String(30), nullable=False),
        sa.Column("grant_hash", sa.String(64), unique=True),
        sa.Column("grant_expires_at", sa.DateTime()),
        sa.Column("envelope_json", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_at", sa.DateTime()),
        sa.Column("finished_at", sa.DateTime()),
    )
    for column in ("backup_job_id", "identity_id", "claim_id", "state", "grant_hash", "grant_expires_at"):
        op.create_index(f"ix_backup_agent_dispatches_{column}", "backup_agent_dispatches", [column], unique=column in {"backup_job_id", "grant_hash"})
    op.create_table(
        "backup_agent_server_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key_id", sa.String(36), nullable=False, unique=True),
        sa.Column("public_key", sa.String(64), nullable=False),
        sa.Column("wrapped_private_key", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_backup_agent_server_keys_key_id", "backup_agent_server_keys", ["key_id"], unique=True)
    op.create_index("ix_backup_agent_server_keys_status", "backup_agent_server_keys", ["status"])
    op.create_table(
        "backup_agent_migration_window",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("cutoff_at", sa.DateTime(), nullable=False),
        sa.Column("legacy_hashes_cleared_at", sa.DateTime()),
    )
    op.create_index("ix_backup_agent_migration_window_cutoff_at", "backup_agent_migration_window", ["cutoff_at"])


def downgrade() -> None:
    raise RuntimeError("Protocol-v2 downgrade is blocked because it could restore bearer-token secret delivery.")
