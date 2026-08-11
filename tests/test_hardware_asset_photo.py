from pathlib import Path

def test_asset_photo_detail_has_authenticated_controls_and_mobile_input():
    router = Path("app/routers/hardware_assets.py").read_text(encoding="utf-8")
    template = Path("app/templates/hardware_asset_detail.html").read_text(encoding="utf-8")
    assert "Image.open(BytesIO(data))" in router
    assert "image.verify()" in router
    assert "MAX_PHOTO_DIMENSION = 2400" in router
    assert "ImageOps.exif_transpose" in router
    assert "@router.post(\"/{asset_id}/photo\")" in router
    assert "@router.post(\"/{asset_id}/photo/delete\")" in router
    assert 'action="/infrastructure/asset-manager/{{ record.id }}/photo"' in template
    assert 'action="/infrastructure/asset-manager/{{ record.id }}/photo/delete"' in template
    assert 'accept="image/*"' in template
    assert "asset-photo-empty" in template
