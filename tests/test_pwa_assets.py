import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "app" / "static"


def test_manifest_is_installable_and_icons_exist():
    manifest = json.loads((STATIC / "manifest.webmanifest").read_text(encoding="utf-8"))
    assert manifest["name"] == "Kaya"
    assert manifest["display"] == "standalone"
    assert manifest["start_url"] == "./"
    assert manifest["scope"] == "./"
    assert {"192x192", "512x512"}.issubset({icon["sizes"] for icon in manifest["icons"]})
    assert any("maskable" in icon["purpose"] for icon in manifest["icons"])
    for icon in manifest["icons"]:
        assert (ROOT / "app" / icon["src"]).is_file()


def test_service_worker_only_caches_safe_get_assets():
    worker = (STATIC / "service-worker.js").read_text(encoding="utf-8")
    assert 'request.method !== "GET"' in worker
    assert 'request.mode === "navigate"' in worker
    assert "caches.match(OFFLINE_URL)" in worker
    assert "CACHE_VERSION" in worker
    assert "caches.delete" in worker
    assert "/api/" not in worker
    assert "login" not in worker.lower()
    assert "session" not in worker.lower()


def test_mobile_shell_and_pwa_metadata_are_global():
    base = (ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    responsive = (STATIC / "css" / "responsive.css").read_text(encoding="utf-8")
    assert 'viewport-fit=cover' in base
    assert 'rel="manifest"' in base
    assert "data-mobile-nav-toggle" in base
    assert "data-mobile-nav-overlay" in base
    assert "data-install-kaya" in base
    assert "@media (max-width:1023px)" in responsive
    assert "transform:translateX(-105%)" in responsive
    assert ".table-scroll" in responsive
    assert "font-size:16px!important" in responsive


def test_offline_page_contains_no_infrastructure_data_or_inline_script():
    offline = (STATIC / "offline.html").read_text(encoding="utf-8")
    assert "requires a network connection" not in offline  # wording may change
    assert "needs a network connection" in offline
    assert "No saved infrastructure data" in offline
    assert "<script" not in offline
    assert "onclick=" not in offline
