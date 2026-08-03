"""Add the central notification framework.

Revision ID: 20260801_01
Revises: 20260730_01
"""

from alembic import op
import sqlalchemy as sa

revision = "20260801_01"
down_revision = "20260730_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_type", sa.String(120), nullable=False),
        sa.Column("module", sa.String(80), nullable=False),
        sa.Column("category", sa.String(80), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("message", sa.String(500), nullable=False),
        sa.Column("metadata_json", sa.Text()),
        sa.Column("target_route", sa.String(500)),
        sa.Column("source_entity_type", sa.String(80)),
        sa.Column("source_entity_id", sa.String(120)),
        sa.Column("deduplication_key", sa.String(255)),
        sa.Column(
            "created_by_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("correlation_id", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime()),
        sa.Column("expires_at", sa.DateTime()),
    )
    for name, columns in {
        "ix_notification_events_event_type": ["event_type"],
        "ix_notification_events_module": ["module"],
        "ix_notification_events_category": ["category"],
        "ix_notification_events_severity": ["severity"],
        "ix_notification_events_deduplication_key": ["deduplication_key"],
        "ix_notification_events_correlation_id": ["correlation_id"],
        "ix_notification_events_created_at": ["created_at"],
        "ix_notification_events_resolved_at": ["resolved_at"],
        "ix_notification_events_expires_at": ["expires_at"],
        "ix_notification_events_deduplication_active": [
            "deduplication_key",
            "resolved_at",
        ],
    }.items():
        op.create_index(name, "notification_events", columns)

    op.create_table(
        "user_notifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "notification_event_id",
            sa.Integer(),
            sa.ForeignKey("notification_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("read_at", sa.DateTime()),
        sa.Column("acknowledged_at", sa.DateTime()),
        sa.Column("dismissed_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "notification_event_id", "user_id", name="uq_user_notification_event_user"
        ),
    )
    for name, columns in {
        "ix_user_notifications_notification_event_id": ["notification_event_id"],
        "ix_user_notifications_user_id": ["user_id"],
        "ix_user_notifications_read_at": ["read_at"],
        "ix_user_notifications_dismissed_at": ["dismissed_at"],
        "ix_user_notifications_created_at": ["created_at"],
        "ix_user_notifications_user_unread_created": [
            "user_id",
            "read_at",
            "dismissed_at",
            "created_at",
        ],
    }.items():
        op.create_index(name, "user_notifications", columns)

    op.create_table(
        "notification_preferences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(120), nullable=False),
        sa.Column("in_app_enabled", sa.Boolean(), nullable=False),
        sa.Column("push_enabled", sa.Boolean(), nullable=False),
        sa.Column("email_enabled", sa.Boolean(), nullable=False),
        sa.Column("minimum_severity", sa.String(20), nullable=False),
        sa.Column("recovery_enabled", sa.Boolean(), nullable=False),
        sa.Column("quiet_hours_start", sa.String(5)),
        sa.Column("quiet_hours_end", sa.String(5)),
        sa.Column("timezone", sa.String(80), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "user_id", "event_type", name="uq_notification_preference_user_event"
        ),
    )
    op.create_index(
        "ix_notification_preferences_user_id", "notification_preferences", ["user_id"]
    )
    op.create_index(
        "ix_notification_preferences_event_type",
        "notification_preferences",
        ["event_type"],
    )

    op.create_table(
        "notification_category_policies",
        sa.Column("event_type", sa.String(120), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("in_app_allowed", sa.Boolean(), nullable=False),
        sa.Column("push_allowed", sa.Boolean(), nullable=False),
        sa.Column("email_allowed", sa.Boolean(), nullable=False),
        sa.Column("minimum_severity", sa.String(20), nullable=False),
        sa.Column("user_can_opt_out", sa.Boolean(), nullable=False),
        sa.Column("recovery_enabled", sa.Boolean(), nullable=False),
        sa.Column("default_enabled", sa.Boolean(), nullable=False),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False),
        sa.Column("repeat_interval_seconds", sa.Integer()),
        sa.Column("acknowledgement_required", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "push_subscriptions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("endpoint_hash", sa.String(64), nullable=False),
        sa.Column("encrypted_subscription", sa.Text(), nullable=False),
        sa.Column("device_label", sa.String(120), nullable=False),
        sa.Column("browser_family", sa.String(80)),
        sa.Column("operating_system", sa.String(80)),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime()),
        sa.Column("last_success_at", sa.DateTime()),
        sa.Column("last_failure_at", sa.DateTime()),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("revoked_at", sa.DateTime()),
        sa.UniqueConstraint(
            "user_id", "endpoint_hash", name="uq_push_subscription_user_endpoint"
        ),
    )
    for name, columns in {
        "ix_push_subscriptions_user_id": ["user_id"],
        "ix_push_subscriptions_endpoint_hash": ["endpoint_hash"],
        "ix_push_subscriptions_status": ["status"],
        "ix_push_subscriptions_revoked_at": ["revoked_at"],
    }.items():
        op.create_index(name, "push_subscriptions", columns)

    op.create_table(
        "notification_delivery_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_notification_id",
            sa.Integer(),
            sa.ForeignKey("user_notifications.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column(
            "push_subscription_id",
            sa.Integer(),
            sa.ForeignKey("push_subscriptions.id", ondelete="SET NULL"),
        ),
        sa.Column("attempted_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("next_retry_at", sa.DateTime()),
        sa.Column("failure_reason_code", sa.String(80)),
    )
    for name, columns in {
        "ix_notification_delivery_attempts_user_notification_id": [
            "user_notification_id"
        ],
        "ix_notification_delivery_attempts_channel": ["channel"],
        "ix_notification_delivery_attempts_push_subscription_id": [
            "push_subscription_id"
        ],
        "ix_notification_delivery_attempts_attempted_at": ["attempted_at"],
        "ix_notification_delivery_attempts_status": ["status"],
        "ix_notification_delivery_attempts_next_retry_at": ["next_retry_at"],
    }.items():
        op.create_index(name, "notification_delivery_attempts", columns)


def downgrade() -> None:
    op.drop_table("notification_delivery_attempts")
    op.drop_table("push_subscriptions")
    op.drop_table("notification_category_policies")
    op.drop_table("notification_preferences")
    op.drop_table("user_notifications")
    op.drop_table("notification_events")
