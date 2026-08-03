"""Add durable reconciliation failure tracking.

Revision ID: 20260803_02
Revises: 20260803_01
"""

from alembic import op
import sqlalchemy as sa


revision = "20260803_02"
down_revision = "20260803_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_reconciliation_failures",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("item_type", sa.String(80), nullable=False),
        sa.Column("item_id", sa.String(120), nullable=False),
        sa.Column("operation", sa.String(80), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("next_retry_at", sa.DateTime()),
        sa.Column("last_exception_type", sa.String(120)),
        sa.Column("last_error_code", sa.String(80)),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.Column("quarantined_at", sa.DateTime()),
        sa.Column("resolved_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "item_type",
            "item_id",
            "operation",
            name="uq_notification_reconciliation_failure_item",
        ),
    )
    for name, columns in {
        "ix_notification_reconciliation_failures_item_type": ["item_type"],
        "ix_notification_reconciliation_failures_item_id": ["item_id"],
        "ix_notification_reconciliation_failures_operation": ["operation"],
        "ix_notification_reconciliation_failures_status": ["status"],
        "ix_notification_reconciliation_failures_correlation_id": [
            "correlation_id"
        ],
        "ix_notification_reconciliation_failures_due": ["status", "next_retry_at"],
    }.items():
        op.create_index(name, "notification_reconciliation_failures", columns)


def downgrade() -> None:
    op.drop_table("notification_reconciliation_failures")
