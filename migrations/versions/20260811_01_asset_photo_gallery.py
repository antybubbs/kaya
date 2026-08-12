"""Add the bounded hardware-asset photo gallery and preserve legacy photos."""

from pathlib import PurePath
import mimetypes

from alembic import op
import sqlalchemy as sa


revision = "20260811_01"
down_revision = "20260810_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hardware_asset_photos",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("hardware_assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=True),
        sa.Column("storage_filename", sa.String(length=255), nullable=False),
        sa.Column("thumbnail_filename", sa.String(length=255), nullable=True),
        sa.Column("content_type", sa.String(length=120), nullable=False, server_default="image/webp"),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_hardware_asset_photos_asset_id", "hardware_asset_photos", ["asset_id"])
    op.create_index("ix_hardware_asset_photos_is_primary", "hardware_asset_photos", ["is_primary"])
    op.create_index(
        "uq_hardware_asset_photos_primary",
        "hardware_asset_photos",
        ["asset_id"],
        unique=True,
        sqlite_where=sa.text("is_primary = 1"),
    )
    op.execute(sa.text(
        """
        CREATE TRIGGER hardware_asset_photos_max_five
        BEFORE INSERT ON hardware_asset_photos
        WHEN (SELECT COUNT(*) FROM hardware_asset_photos WHERE asset_id = NEW.asset_id) >= 5
        BEGIN
            SELECT RAISE(ABORT, 'hardware asset photo limit exceeded');
        END
        """
    ))

    connection = op.get_bind()
    legacy_rows = connection.execute(
        sa.text("SELECT id, photo_filename FROM hardware_assets WHERE photo_filename IS NOT NULL AND TRIM(photo_filename) <> ''")
    ).mappings()
    for row in legacy_rows:
        suffix = PurePath(row["photo_filename"]).suffix.lower()
        content_type = mimetypes.guess_type(row["photo_filename"])[0] or "application/octet-stream"
        connection.execute(
            sa.text(
                """
                INSERT INTO hardware_asset_photos
                    (asset_id, original_filename, storage_filename, thumbnail_filename,
                     content_type, is_primary, sort_order, uploaded_at)
                VALUES (:asset_id, :original_filename, :storage_filename, NULL,
                        :content_type, 1, 0, CURRENT_TIMESTAMP)
                """
            ),
            {
                "asset_id": row["id"],
                "original_filename": row["photo_filename"],
                "storage_filename": row["photo_filename"],
                "content_type": content_type if content_type.startswith("image/") else "application/octet-stream",
            },
        )


def downgrade() -> None:
    op.execute(sa.text("DROP TRIGGER IF EXISTS hardware_asset_photos_max_five"))
    op.drop_index("uq_hardware_asset_photos_primary", table_name="hardware_asset_photos")
    op.drop_index("ix_hardware_asset_photos_is_primary", table_name="hardware_asset_photos")
    op.drop_index("ix_hardware_asset_photos_asset_id", table_name="hardware_asset_photos")
    op.drop_table("hardware_asset_photos")
