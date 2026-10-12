"""Add bounded, privacy-safe unknown-template diagnostics."""

from alembic import op
import sqlalchemy as sa

revision = "20261012_05"
down_revision = "20261012_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name, column in (
        ("last_unknown_template_id", sa.Integer()),
        ("last_unknown_template_exporter", sa.String(45)),
        ("last_unknown_template_source_id", sa.Integer()),
        ("last_template_error_category", sa.String(40)),
        ("last_unknown_template_at", sa.DateTime()),
    ):
        op.add_column("traffic_flow_collector_states", sa.Column(name, column, nullable=True))
    op.execute(
        sa.text(
            "UPDATE traffic_sources SET health_state = 'unconfigured', health_reason = NULL, "
            "last_success_at = NULL, last_received_at = NULL, last_failed_at = NULL, "
            "last_error_category = NULL, last_poll_duration_ms = NULL, consecutive_failures = 0, "
            "backoff_until = NULL WHERE provider_key IN ('netflow_v9', 'cisco_nsel')"
        )
    )


def downgrade() -> None:
    for name in ("last_unknown_template_at", "last_template_error_category", "last_unknown_template_source_id", "last_unknown_template_exporter", "last_unknown_template_id"):
        op.drop_column("traffic_flow_collector_states", name)
