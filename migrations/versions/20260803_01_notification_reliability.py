"""Add notification outbox and explicit monitor transitions.

Revision ID: 20260803_01
Revises: 20260801_02
"""

from alembic import op
import sqlalchemy as sa


revision = "20260803_01"
down_revision = "20260801_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "network_monitor_transitions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "monitor_id",
            sa.Integer(),
            sa.ForeignKey("network_monitors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("previous_state", sa.String(30), nullable=False),
        sa.Column("new_state", sa.String(30), nullable=False),
        sa.Column("transitioned_at", sa.DateTime(), nullable=False),
        sa.Column(
            "triggering_observation_id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column("consecutive_successes", sa.Integer(), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.UniqueConstraint(
            "correlation_id", name="uq_network_monitor_transitions_correlation_id"
        ),
    )
    for name, columns in {
        "ix_network_monitor_transitions_monitor_id": ["monitor_id"],
        "ix_network_monitor_transitions_new_state": ["new_state"],
        "ix_network_monitor_transitions_transitioned_at": ["transitioned_at"],
        "ix_network_monitor_transitions_triggering_observation_id": [
            "triggering_observation_id"
        ],
        "ix_network_monitor_transitions_correlation_id": ["correlation_id"],
        "ix_network_monitor_transitions_monitor_transitioned": [
            "monitor_id",
            "transitioned_at",
        ],
    }.items():
        op.create_index(name, "network_monitor_transitions", columns)

    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_type", sa.String(120), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("message", sa.String(500), nullable=False),
        sa.Column("target_route", sa.String(500)),
        sa.Column("source_entity_type", sa.String(80)),
        sa.Column("source_entity_id", sa.String(120)),
        sa.Column("deduplication_key", sa.String(255)),
        sa.Column("resolve_deduplication_key", sa.String(255)),
        sa.Column("recipient_ids_json", sa.Text()),
        sa.Column("severity", sa.String(20)),
        sa.Column("metadata_json", sa.Text()),
        sa.Column(
            "created_by_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.Column("resolved", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("next_retry_at", sa.DateTime()),
        sa.Column("claimed_at", sa.DateTime()),
        sa.Column("processed_at", sa.DateTime()),
        sa.Column("quarantined_at", sa.DateTime()),
        sa.Column("failure_reason_code", sa.String(80)),
        sa.Column("result_json", sa.Text()),
        sa.Column(
            "notification_event_id",
            sa.Integer(),
            sa.ForeignKey("notification_events.id", ondelete="SET NULL"),
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    for name, columns in {
        "ix_notification_outbox_event_type": ["event_type"],
        "ix_notification_outbox_correlation_id": ["correlation_id"],
        "ix_notification_outbox_status": ["status"],
        "ix_notification_outbox_next_retry_at": ["next_retry_at"],
        "ix_notification_outbox_notification_event_id": ["notification_event_id"],
        "ix_notification_outbox_created_at": ["created_at"],
        "ix_notification_outbox_due": ["status", "next_retry_at", "created_at"],
        "ix_notification_outbox_dedup_status": ["deduplication_key", "status"],
    }.items():
        op.create_index(name, "notification_outbox", columns)

    with op.batch_alter_table("notification_delivery_attempts") as batch:
        batch.add_column(sa.Column("created_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("processing_started_at", sa.DateTime()))
        batch.add_column(sa.Column("accepted_at", sa.DateTime()))
    op.execute(
        "UPDATE notification_delivery_attempts SET created_at = attempted_at "
        "WHERE created_at IS NULL"
    )
    with op.batch_alter_table("notification_delivery_attempts") as batch:
        batch.alter_column(
            "created_at", existing_type=sa.DateTime(), nullable=False
        )
    op.create_index(
        "ix_notification_delivery_attempts_created_at",
        "notification_delivery_attempts",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_notification_delivery_attempts_created_at",
        table_name="notification_delivery_attempts",
    )
    with op.batch_alter_table("notification_delivery_attempts") as batch:
        batch.drop_column("accepted_at")
        batch.drop_column("processing_started_at")
        batch.drop_column("created_at")
    op.drop_table("notification_outbox")
    op.drop_table("network_monitor_transitions")
