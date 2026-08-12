from pathlib import Path

def test_asset_photo_detail_has_authenticated_controls_and_mobile_input():
    router = Path("app/routers/hardware_assets.py").read_text(encoding="utf-8")
    template = Path("app/templates/hardware_asset_detail.html").read_text(encoding="utf-8")
    migration = Path("migrations/versions/20260811_01_asset_photo_gallery.py").read_text(encoding="utf-8")
    assert "Image.open(BytesIO(data))" in router
    assert "image.verify()" in router
    assert "MAX_PHOTO_DIMENSION = 1800" in router
    assert "ImageOps.exif_transpose" in router
    assert "MAX_PHOTO_COUNT = 5" in router
    assert "thumbnail_filename" in router
    assert "@router.post(\"/{asset_id}/photos\")" in router
    assert "@router.post(\"/{asset_id}/photos/{photo_id}/primary\")" in router
    assert "@router.post(\"/{asset_id}/photos/{photo_id}/delete\")" in router
    assert 'name="photos"' in template
    assert "multiple" in template
    assert 'accept="image/*"' in template
    assert "asset-photo-empty" in template
    assert "asset-photo-lightbox" in template
    assert '"hardware_asset_photos"' in migration
    assert "photo_filename" in migration
    assert "hardware_asset_photos_max_five" in migration
