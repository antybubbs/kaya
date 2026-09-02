from pathlib import Path

import pytest

from scripts.phase7d_http_smoke import dns_client_detail_path, route_status_is_acceptable


def test_phase7d_http_smoke_accepts_intentional_route_redirects_only():
    assert route_status_is_acceptable(200)
    assert route_status_is_acceptable(303)
    assert route_status_is_acceptable(307)
    assert not route_status_is_acceptable(302)
    assert not route_status_is_acceptable(500)


def test_phase7d_http_smoke_builds_detail_path_from_discovered_id():
    assert dns_client_detail_path("42") == "/networking/dns-manager/clients/42"
    with pytest.raises(ValueError):
        dns_client_detail_path("1.0")


def test_phase7d_http_smoke_has_no_hard_coded_dns_client_detail_id():
    source = Path("scripts/phase7d_http_smoke.py").read_text(encoding="utf-8")
    assert '"/networking/dns-manager/clients/1"' not in source
