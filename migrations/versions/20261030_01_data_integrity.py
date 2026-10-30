"""Add Data Integrity audit runs, findings and finding history.

Additive only: no existing asset, identity, assignment, DHCP, DNS, traffic or
audit-log row is read for repair or changed. Existing inconsistencies appear
as findings after the first audit. Existing administrators receive the
``data_integrity.repair`` capability, which can be revoked per user. Downgrade
drops the new tables and that capability only.
"""

from datetime import datetime

from alembic import op
import sqlalchemy as sa


revision = "20261030_01"
down_revision = "20261018_01"
branch_labels = None
depends_on = None

REPAIR_CAPABILITY = "data_integrity.repair"


def upgrade() -> None:
    op.create_table(
        "data_integrity_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_uuid", sa.String(36), nullable=False),
        sa.Column("trigger", sa.String(20), nullable=False),
        sa.Column("initiated_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("active_slot", sa.String(20), nullable=True),
        sa.Column("check_set_version", sa.String(40), nullable=False),
        sa.Column("queued_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("progress_done", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("progress_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_examined", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("new_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("resolved_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("counts_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("errors_json", sa.Text(), nullable=False, server_default="[]"),
        sa.UniqueConstraint("run_uuid", name="uq_data_integrity_runs_run_uuid"),
        sa.UniqueConstraint("active_slot", name="uq_data_integrity_runs_active_slot"),
    )
    op.create_index("ix_data_integrity_runs_initiated_by", "data_integrity_runs", ["initiated_by"])
    op.create_index("ix_data_integrity_runs_status", "data_integrity_runs", ["status"])
    op.create_index("ix_data_integrity_runs_queued_at", "data_integrity_runs", ["queued_at"])
    op.create_index("ix_data_integrity_runs_completed_at", "data_integrity_runs", ["completed_at"])

    op.create_table(
        "data_integrity_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_key", sa.String(64), nullable=False),
        sa.Column("finding_type", sa.String(60), nullable=False),
        sa.Column("category", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("required_modules", sa.String(255), nullable=False, server_default=""),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("affected_label", sa.String(255), nullable=False),
        sa.Column("search_text", sa.String(1000), nullable=False, server_default=""),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("hardware_assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("mac", sa.String(17), nullable=True),
        sa.Column("ip_address", sa.String(80), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("evidence_fingerprint", sa.String(64), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("repairable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("bulk_repairable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("first_detected_at", sa.DateTime(), nullable=False),
        sa.Column("last_detected_at", sa.DateTime(), nullable=False),
        sa.Column("last_run_id", sa.Integer(), sa.ForeignKey("data_integrity_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_run_id", sa.Integer(), sa.ForeignKey("data_integrity_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("resolution", sa.String(60), nullable=True),
        sa.Column("ignored_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ignored_at", sa.DateTime(), nullable=True),
        sa.Column("ignore_reason", sa.String(500), nullable=True),
        sa.Column("ignored_fingerprint", sa.String(64), nullable=True),
        sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("notified_fingerprint", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("finding_key", name="uq_data_integrity_findings_finding_key"),
    )
    op.create_index("ix_data_integrity_findings_category", "data_integrity_findings", ["category"])
    op.create_index("ix_data_integrity_findings_asset_id", "data_integrity_findings", ["asset_id"])
    op.create_index("ix_data_integrity_findings_mac", "data_integrity_findings", ["mac"])
    op.create_index("ix_data_integrity_findings_ip_address", "data_integrity_findings", ["ip_address"])
    op.create_index("ix_data_integrity_findings_last_detected_at", "data_integrity_findings", ["last_detected_at"])
    op.create_index("ix_data_integrity_findings_status_severity", "data_integrity_findings", ["status", "severity"])
    op.create_index("ix_data_integrity_findings_type_status", "data_integrity_findings", ["finding_type", "status"])

    op.create_table(
        "data_integrity_finding_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("data_integrity_findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("data_integrity_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("event", sa.String(40), nullable=False),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("detail_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_data_integrity_finding_events_run_id", "data_integrity_finding_events", ["run_id"])
    op.create_index("ix_data_integrity_finding_events_created_at", "data_integrity_finding_events", ["created_at"])
    op.create_index("ix_data_integrity_finding_events_finding_created", "data_integrity_finding_events", ["finding_id", "created_at"])

    bind = op.get_bind()
    admin_ids = [row[0] for row in bind.execute(sa.text(
        "SELECT users.id FROM users WHERE users.role = 'admin' AND NOT EXISTS ("
        "SELECT 1 FROM user_module_permissions existing "
        "WHERE existing.user_id = users.id AND existing.module_key = :capability) ORDER BY users.id"
    ), {"capability": REPAIR_CAPABILITY})]
    if admin_ids:
        now = datetime.utcnow()  # noqa: DTZ003
        permissions = sa.table(
            "user_module_permissions",
            sa.column("user_id", sa.Integer()),
            sa.column("module_key", sa.String(80)),
            sa.column("allowed", sa.Boolean()),
            sa.column("created_at", sa.DateTime()),
            sa.column("updated_at", sa.DateTime()),
        )
        op.bulk_insert(permissions, [
            {"user_id": user_id, "module_key": REPAIR_CAPABILITY, "allowed": True, "created_at": now, "updated_at": now}
            for user_id in admin_ids
        ])


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM user_module_permissions WHERE module_key = :capability"),
        {"capability": REPAIR_CAPABILITY},
    )
    op.drop_index("ix_data_integrity_finding_events_finding_created", table_name="data_integrity_finding_events")
    op.drop_index("ix_data_integrity_finding_events_created_at", table_name="data_integrity_finding_events")
    op.drop_index("ix_data_integrity_finding_events_run_id", table_name="data_integrity_finding_events")
    op.drop_table("data_integrity_finding_events")
    for name in (
        "ix_data_integrity_findings_type_status",
        "ix_data_integrity_findings_status_severity",
        "ix_data_integrity_findings_last_detected_at",
        "ix_data_integrity_findings_ip_address",
        "ix_data_integrity_findings_mac",
        "ix_data_integrity_findings_asset_id",
        "ix_data_integrity_findings_category",
    ):
        op.drop_index(name, table_name="data_integrity_findings")
    op.drop_table("data_integrity_findings")
    for name in (
        "ix_data_integrity_runs_completed_at",
        "ix_data_integrity_runs_queued_at",
        "ix_data_integrity_runs_status",
        "ix_data_integrity_runs_initiated_by",
    ):
        op.drop_index(name, table_name="data_integrity_runs")
    op.drop_table("data_integrity_runs")
