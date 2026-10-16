"""Add reviewed asset identity evidence and network assignments."""

from alembic import op
import sqlalchemy as sa


revision = "20261015_01"
down_revision = "20261014_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_identity_evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("hardware_assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("evidence_type", sa.String(40), nullable=False),
        sa.Column("normalised_value", sa.String(255), nullable=False),
        sa.Column("source", sa.String(80), nullable=False),
        sa.Column("source_scope", sa.String(255), nullable=True),
        sa.Column("first_observed_at", sa.DateTime(), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("confirmed_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("conflict_reason", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_asset_identity_evidence_asset_id", "asset_identity_evidence", ["asset_id"])
    op.create_index("ix_asset_identity_evidence_asset_status", "asset_identity_evidence", ["asset_id", "status"])
    op.create_index("ix_asset_identity_evidence_evidence_type", "asset_identity_evidence", ["evidence_type"])
    op.create_index("ix_asset_identity_evidence_type_value", "asset_identity_evidence", ["evidence_type", "normalised_value"])
    op.create_index("ix_asset_identity_evidence_source_scope", "asset_identity_evidence", ["source_scope"])
    op.create_index("ix_asset_identity_evidence_status", "asset_identity_evidence", ["status"])
    op.create_index("ix_asset_identity_evidence_confirmed_by", "asset_identity_evidence", ["confirmed_by"])

    op.create_table(
        "asset_network_assignments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("hardware_assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("address", sa.String(80), nullable=False),
        sa.Column("address_family", sa.Integer(), nullable=False),
        sa.Column("vlan_id", sa.Integer(), sa.ForeignKey("vlans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ip_address_id", sa.Integer(), sa.ForeignKey("ip_addresses.id", ondelete="SET NULL"), nullable=True),
        sa.Column("dhcp_lease_id", sa.Integer(), sa.ForeignKey("dhcp_lease_history.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("traffic_sources.id", ondelete="SET NULL"), nullable=True),
        sa.Column("exporter_identity", sa.String(255), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("provenance", sa.String(80), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("confirmed_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(), nullable=True),
        sa.Column("conflict_reason", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    for name, columns in {
        "ix_asset_network_assignments_asset_id": ["asset_id"],
        "ix_asset_network_assignments_asset_interval": ["asset_id", "started_at", "ended_at"],
        "ix_asset_network_assignments_address": ["address"],
        "ix_asset_network_assignments_address_family": ["address_family"],
        "ix_asset_network_assignments_vlan_id": ["vlan_id"],
        "ix_asset_network_assignments_ip_address_id": ["ip_address_id"],
        "ix_asset_network_assignments_dhcp_lease_id": ["dhcp_lease_id"],
        "ix_asset_network_assignments_source_id": ["source_id"],
        "ix_asset_network_assignments_exporter_identity": ["exporter_identity"],
        "ix_asset_network_assignments_address_context": ["address", "address_family", "vlan_id", "source_id", "exporter_identity"],
        "ix_asset_network_assignments_status": ["status"],
        "ix_asset_network_assignments_confirmed_by": ["confirmed_by"],
    }.items():
        op.create_index(name, "asset_network_assignments", columns)


def downgrade() -> None:
    op.drop_table("asset_network_assignments")
    op.drop_table("asset_identity_evidence")
