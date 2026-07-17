from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"


def test_sidebar_treatment_is_loaded_and_uses_local_optimized_artwork():
    base = (ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    styles = (STATIC / "css" / "sidebar.css").read_text(encoding="utf-8")
    artwork = STATIC / "images" / "sidebar" / "sidebar-infrastructure-bg.webp"

    assert "css/sidebar.css" in base
    assert "sidebar-infrastructure-bg.webp" in styles
    assert artwork.is_file()
    assert artwork.stat().st_size < 250_000
    with Image.open(artwork) as image:
        assert image.format == "WEBP"
        assert image.size == (1152, 768)


def test_sidebar_treatment_preserves_responsive_and_fallback_states():
    styles = (STATIC / "css" / "sidebar.css").read_text(encoding="utf-8")

    assert ".sidebar::before" in styles
    assert ".sidebar::after" in styles
    assert "linear-gradient(180deg, #0b111b" in styles
    assert "body.sidebar-collapsed .sidebar::before" in styles
    assert "@media (max-width:1023px)" in styles
    assert 'html[data-kaya-theme="light-ops"] .sidebar' in styles
    assert "pointer-events: none" in styles
