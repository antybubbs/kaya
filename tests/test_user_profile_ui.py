from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core.security import hash_password
from app.db.session import Base
from app.main import app
from app.models.models import User
from app.routers.admin import create_user
from app.services.user_names import first_name_contains_last_name, user_display_name


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def request():
    return Request({
        "type": "http", "method": "POST", "scheme": "https", "path": "/team/users/new",
        "raw_path": b"/team/users/new", "query_string": b"", "headers": [],
        "client": ("198.51.100.2", 1234), "server": ("kaya.example.com", 443),
        "session": {"csrf_token": "csrf"}, "app": app,
    })


def test_display_name_handles_legacy_combined_first_name_without_hiding_normal_names():
    assert user_display_name("Anthony Hales", "Hales", "fallback@example.com") == "Anthony Hales"
    assert user_display_name("Anthony", "Hales", "fallback@example.com") == "Anthony Hales"
    assert user_display_name(None, None, "fallback@example.com") == "fallback@example.com"
    assert first_name_contains_last_name("Anthony Hales", "Hales") is True
    assert first_name_contains_last_name("Anthony", "Hales") is False


def test_new_user_rejects_a_surname_duplicated_inside_first_name():
    with database() as db:
        admin = User(email="admin@example.com", password_hash=hash_password("correct horse battery staple"), role="admin", is_active=True)
        db.add(admin); db.commit()
        response = create_user(
            request(), email="new@example.com", first_name="Anthony Hales", last_name="Hales",
            password="correct horse battery staple", role="viewer", csrf_token="csrf", db=db, user=admin,
        )
        assert response.status_code == 400
        assert b"surname is already in the last name field" in response.body
        assert db.query(User).filter_by(email="new@example.com").first() is None


def test_user_editor_is_sectioned_responsive_and_uses_human_readable_oidc_time():
    template = Path("app/templates/user_form.html").read_text(encoding="utf-8")
    stylesheet = Path("app/static/css/kaya.css").read_text(encoding="utf-8")
    assert "user-editor-shell" in template
    assert "Account details" in template
    assert "Access and authentication" in template
    assert "OpenID Connect identity" in template
    assert "Leave blank to keep the current password." in template
    assert "Allows this account to sign in locally" in template
    assert "local_time(external.last_login_at, 'friendly', 'Never')" in template
    assert "data-confirm-action" in template
    assert "max-width:1040px" in stylesheet
    assert ".user-editor-fields,.user-identity-list{grid-template-columns:1fr}" in stylesheet
    assert "overflow-wrap:anywhere" in stylesheet


def test_profile_dropdown_uses_theme_tokens_for_all_interaction_states():
    template = Path("app/templates/base.html").read_text(encoding="utf-8")
    stylesheet = Path("app/static/css/kaya.css").read_text(encoding="utf-8")
    assert "{{ user.display_name }}" in template
    assert 'class="account-link ghost"' in template
    assert 'class="account-link ghost logout-link"' in template
    assert ".account-heading strong{color:var(--text)}" in stylesheet
    assert ".account-heading span{color:var(--muted)}" in stylesheet
    assert ".account-popover .account-link:focus-visible" in stylesheet
    assert ".account-popover .account-link:active" in stylesheet
    assert ".account-popover .account-link:disabled" in stylesheet
    assert "background:var(--panel2)" in stylesheet


def test_actual_user_profile_page_is_contained_sectioned_and_responsive():
    template = Path("app/templates/profile.html").read_text(encoding="utf-8")
    stylesheet = Path("app/static/css/kaya.css").read_text(encoding="utf-8")
    assert "profile-page-shell" in template
    assert "profile-page-hero" in template
    assert "profile-signin-grid" in template
    assert "profile-settings-grid" in template
    assert "Profile details" in template
    assert "Two-factor authentication" in template
    assert 'for="profile-current-password"' in template
    assert 'for="profile-twofa-password"' in template
    assert "max-width:1160px" in stylesheet
    assert ".profile-form-grid{align-items:start" in stylesheet
    assert ".profile-form-grid>label{align-content:start;align-self:start}" in stylesheet
    assert ".profile-settings-grid{grid-template-columns:1fr}" in stylesheet
    assert ".profile-signin-grid,.profile-form-grid,.profile-twofa-form{grid-template-columns:1fr}" in stylesheet
