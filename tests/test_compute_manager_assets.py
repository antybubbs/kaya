from pathlib import Path


COMPUTE_MANAGER_SCRIPT = Path("app/static/js/compute_manager.js")


def test_compute_manager_poll_uses_only_its_canonical_summary_endpoint():
    script = COMPUTE_MANAGER_SCRIPT.read_text(encoding="utf-8")

    assert 'fetch("/infrastructure/vm-docker-manager/api/summary"' in script
    assert "/dashboard/api/dns-summary" not in script
    assert "dashboard-dns-summary" not in script
