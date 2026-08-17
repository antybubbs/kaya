"""Add the database-backed Asset Tag allocator."""

import re

from alembic import op
import sqlalchemy as sa


revision = "20260813_01"
down_revision = "20260811_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hardware_asset_tag_sequences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("next_number", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    bind = op.get_bind()
    settings = {
        "prefix": "HAL",
        "separator": "-",
        "start": 1,
    }
    for key in ("asset_tags_prefix", "asset_tags_separator", "asset_tags_start_number"):
        value = bind.execute(
            sa.text("SELECT value FROM remote_manager_settings WHERE key = :key"),
            {"key": key},
        ).scalar_one_or_none()
        if value is not None:
            if key.endswith("prefix"):
                settings["prefix"] = value
            elif key.endswith("separator"):
                settings["separator"] = value
            else:
                try:
                    settings["start"] = max(1, int(value))
                except (TypeError, ValueError):
                    pass
    pattern = re.compile(
        rf"^{re.escape(settings['prefix'])}{re.escape(settings['separator'])}(\d+)$"
    )
    highest = 0
    for (asset_tag,) in bind.execute(
        sa.text("SELECT asset_tag FROM hardware_assets WHERE asset_tag IS NOT NULL")
    ):
        match = pattern.fullmatch(asset_tag)
        if match:
            highest = max(highest, int(match.group(1)))
    next_number = max(settings["start"], highest + 1)
    bind.execute(
        sa.text(
            "INSERT INTO hardware_asset_tag_sequences "
            "(id, next_number, updated_at) VALUES (1, :next_number, CURRENT_TIMESTAMP)"
        ),
        {"next_number": next_number},
    )


def downgrade() -> None:
    op.drop_table("hardware_asset_tag_sequences")
