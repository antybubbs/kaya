from pathlib import Path


def test_oidc_secret_is_never_rendered_back_to_browser():
    template = Path("app/templates/authentication_settings.html").read_text(encoding="utf-8")
    assert "encrypted_client_secret" not in template
    assert "Saved secret" in template
    assert 'type="password"' in template


def test_login_template_supports_all_modes_and_emergency_route():
    template = Path("app/templates/login.html").read_text(encoding="utf-8")
    assert "local_and_oidc" in template
    assert "oidc_preferred" in template
    assert "oidc_required" in template
    assert "/auth/local" in template


def test_oidc_temporary_secrets_are_server_side_and_not_browser_storage():
    source = Path("app/services/oidc_client.py").read_text(encoding="utf-8")
    router = Path("app/routers/oidc.py").read_text(encoding="utf-8")
    assert "encrypted_code_verifier" in source
    assert 'request.session["oidc_transaction"] = opaque' in router
    assert 'request.session["code_verifier"]' not in router
    assert "localStorage" not in router
    assert "sessionStorage" not in router


def test_session_cookie_uses_oidc_compatible_lax_same_site():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert 'same_site="lax"' in source
