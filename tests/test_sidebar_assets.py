from pathlib import Path


def test_sidebar_illustration_has_core_theme_fallback_and_valid_asset():
    core_theme = Path("app/static/css/kaya.css").read_text(encoding="utf-8")
    sidebar_theme = Path("app/static/css/sidebar.css").read_text(encoding="utf-8")
    asset = Path("app/static/images/sidebar/sidebar-infrastructure-bg.webp").read_bytes()

    reference = 'url("../images/sidebar/sidebar-infrastructure-bg.webp")'
    assert reference in core_theme
    assert reference in sidebar_theme
    assert asset.startswith(b"RIFF")
    assert asset[8:12] == b"WEBP"


def test_sidebar_assets_rotate_and_precache_with_service_worker():
    worker = Path("app/static/service-worker.js").read_text(encoding="utf-8")

    assert 'CACHE_VERSION = "kaya-static-v2"' in worker
    assert "`${staticPath}/css/sidebar.css`" in worker
    assert "`${staticPath}/images/sidebar/sidebar-infrastructure-bg.webp`" in worker
