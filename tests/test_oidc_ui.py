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


def test_authentication_uses_site_administration_sidebar_pages():
    template = Path("app/templates/authentication_settings.html").read_text(encoding="utf-8")
    stylesheet = Path("app/static/css/authentication.css").read_text(encoding="utf-8")

    assert 'class="settings-layout"' in template
    assert 'class="panel settings-internal-sidebar"' in template
    assert 'class="settings-content-panel"' in template
    assert 'class="settings-side-link active">Authentication' in template
    assert "'active' if tab == 'general'" in template
    assert "'active' if tab == 'oidc'" in template
    assert "'active' if tab == 'mapping'" in template
    assert "'active' if tab == 'links'" in template
    assert '<nav class="tabs"' not in template
    assert "authentication-status-grid" in stylesheet
    assert "authentication-form-grid" in stylesheet


def test_obsolete_idp_integration_sidebar_item_is_removed():
    base = Path("app/templates/base.html").read_text(encoding="utf-8")
    assert "IDP Integration" not in base


def test_login_redesign_keeps_accessible_auth_controls_and_local_assets():
    template = Path("app/templates/login.html").read_text(encoding="utf-8")
    script = Path("app/static/js/login.js").read_text(encoding="utf-8")
    stylesheet = Path("app/static/css/login.css").read_text(encoding="utf-8")

    assert 'name="csrf_token"' in template
    assert 'name="email"' in template
    assert 'name="password"' in template
    assert 'autocomplete="username"' in template
    assert 'autocomplete="current-password"' in template
    assert 'data-password-toggle' in template
    assert 'aria-label="Show password"' in template
    assert 'data-login-form' in template
    assert 'data-submit-button' in template
    assert 'role="alert"' in template
    assert "/static/js/login.js" in template

    assert 'input.type = reveal ? "text" : "password"' in script
    assert 'button.setAttribute("aria-label", reveal ? "Hide password" : "Show password")' in script
    assert 'event.preventDefault()' in script
    assert 'button.disabled = true' in script

    assert Path("app/static/brand/Login page image.png").is_file()
    assert Path("app/static/brand/kaya-favicon-192-transparent.png").is_file()
    assert "Login%20page%20image.png" in stylesheet


def test_login_mobile_layout_is_single_column_without_horizontal_overflow():
    stylesheet = Path("app/static/css/login.css").read_text(encoding="utf-8")

    assert "overflow-x: hidden" in stylesheet
    assert "@media (max-width: 820px)" in stylesheet
    assert "grid-template-columns: 1fr" in stylesheet
    assert "max(14px, env(safe-area-inset-left))" in stylesheet
    assert "min-height: 44px" in stylesheet


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


def test_profile_link_has_progressive_submit_feedback():
    template = Path("app/templates/profile.html").read_text(encoding="utf-8")
    script = Path("app/static/js/profile.js").read_text(encoding="utf-8")
    assert "data-oidc-link-form" in template
    assert "profile.js" in template
    assert 'form.addEventListener("submit"' in script
    assert "button.disabled = true" in script
