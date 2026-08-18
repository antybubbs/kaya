"""Add indexes used by DNS client detail history queries."""

from alembic import op


revision = "20260818_01"
down_revision = "20260813_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_dns_client_ip_history_client_last_seen",
        "dns_client_ip_history",
        ["dns_client_id", "last_seen_at"],
    )
    op.create_index(
        "ix_dns_client_hostname_history_client_last_seen",
        "dns_client_hostname_history",
        ["dns_client_id", "last_seen_at"],
    )
    op.create_index(
        "ix_dns_client_events_client_created",
        "dns_client_events",
        ["dns_client_id", "created_at"],
    )
    op.create_index(
        "ix_dns_client_traffic_client_observed",
        "dns_client_traffic_events",
        ["dns_client_id", "observed_at"],
    )
    op.create_index(
        "ix_dns_client_traffic_client_blocked_observed",
        "dns_client_traffic_events",
        ["dns_client_id", "is_blocked", "observed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_dns_client_traffic_client_blocked_observed", table_name="dns_client_traffic_events")
    op.drop_index("ix_dns_client_traffic_client_observed", table_name="dns_client_traffic_events")
    op.drop_index("ix_dns_client_events_client_created", table_name="dns_client_events")
    op.drop_index("ix_dns_client_hostname_history_client_last_seen", table_name="dns_client_hostname_history")
    op.drop_index("ix_dns_client_ip_history_client_last_seen", table_name="dns_client_ip_history")
