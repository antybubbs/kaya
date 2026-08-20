from scripts.phase7d_http_smoke import route_status_is_acceptable


def test_phase7d_http_smoke_accepts_intentional_route_redirects_only():
    assert route_status_is_acceptable(200)
    assert route_status_is_acceptable(303)
    assert route_status_is_acceptable(307)
    assert not route_status_is_acceptable(302)
    assert not route_status_is_acceptable(500)
