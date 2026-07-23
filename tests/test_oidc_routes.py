import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core.security import hash_password
from app.db.session import Base
from app.main import app
from app.models.models import ExternalIdentity, OIDCProvider, OIDCTransaction, RemoteManagerSetting, User
from app.routers.auth import login, login_page, profile
from app.routers.oidc import _complete_vault_assurance, callback_error_context, emergency_login_submit, profile_identity_link, save_authentication_general, save_oidc_provider
from app.services.oidc_client import OIDCFlowError
from app.services.oidc_identity import OIDCIdentityError
from app.services.site_settings import get_site_setting


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def request(path="/login", method="GET"):
    route_path, _, query = path.partition("?")
    scope = {
        "type": "http", "method": method, "scheme": "https", "path": route_path, "raw_path": route_path.encode(),
        "query_string": query.encode(), "headers": [], "client": ("198.51.100.2", 1234), "server": ("kaya.example.com", 443),
        "session": {"csrf_token": "csrf"},
        "app": app,
    }
    return Request(scope)


def add_user(db, email="admin@example.com", password="correct horse battery staple", **values):
    row = User(email=email, password_hash=hash_password(password) if password else None, role=values.pop("role", "admin"), is_active=True, **values)
    db.add(row); db.commit(); return row


def setting(db, key, value):
    db.add(RemoteManagerSetting(key=key, value=value)); db.commit()


def test_login_page_modes_preserve_local_form_and_required_redirect():
    with database() as db:
        add_user(db)
        local = login_page(request(), db=db)
        assert b'action="/login"' in local.body
        assert b"/auth/oidc/login" not in local.body

        db.add(OIDCProvider(name="Company SSO", issuer="https://id.example.com", client_id="kaya", is_enabled=True))
        setting(db, "authentication_mode", "local_and_oidc")
        combined = login_page(request(), db=db)
        assert b"/auth/oidc/login" in combined.body
        assert b'action="/login"' in combined.body

        db.query(RemoteManagerSetting).filter_by(key="authentication_mode").first().value = "oidc_required"
        db.commit()
        required = login_page(request(), db=db)
        assert required.status_code == 303
        assert required.headers["location"] == "/auth/oidc/login"

        logged_out = login_page(request("/login?logged_out=1"), logged_out="1", db=db)
        assert logged_out.status_code == 200
        assert b'name="email"' not in logged_out.body
        assert b'href="/auth/oidc/login"' in logged_out.body


def test_required_mode_without_an_active_provider_shows_safe_sso_error():
    with database() as db:
        add_user(db)
        setting(db, "authentication_mode", "oidc_required")
        response = login_page(request(), db=db)
        assert response.status_code == 503
        assert b"Single sign-on is currently unavailable" in response.body
        assert b'name="email"' not in response.body
        assert b'href="/auth/local"' not in response.body


@pytest.mark.parametrize(
    ("mode", "show_preferred", "local_visible", "oidc_visible"),
    [
        ("local_only", "1", True, False),
        ("local_and_oidc", "1", True, True),
        ("oidc_preferred", "1", True, True),
        ("oidc_preferred", "", False, True),
        ("oidc_required", "1", False, True),
    ],
)
def test_complete_login_page_mode_matrix(mode, show_preferred, local_visible, oidc_visible):
    with database() as db:
        add_user(db)
        db.add(OIDCProvider(name="Company SSO", issuer="https://id.example.com", client_id="kaya", is_enabled=True))
        setting(db, "authentication_mode", mode)
        setting(db, "oidc_show_local_preferred", show_preferred)
        setting(db, "oidc_auto_redirect_required", "")
        response = login_page(request(), db=db)
        body = response.body
        assert (b'name="email"' in body) is local_visible
        assert (b'name="password"' in body) is local_visible
        assert (b'href="/auth/oidc/login"' in body) is oidc_visible
        assert b'href="/auth/local"' not in body


@pytest.mark.parametrize(
    ("mode", "show_preferred", "allowed"),
    [
        ("local_only", "1", True),
        ("local_and_oidc", "1", True),
        ("oidc_preferred", "1", True),
        ("oidc_preferred", "", False),
        ("oidc_required", "1", False),
    ],
)
def test_normal_local_post_is_enforced_for_every_mode(mode, show_preferred, allowed):
    with database() as db:
        user = add_user(db)
        setting(db, "authentication_mode", mode)
        setting(db, "oidc_show_local_preferred", show_preferred)
        incoming = request(method="POST")
        response = login(incoming, email=user.email, password="correct horse battery staple", totp_code="", csrf_token="csrf", db=db)
        assert response.status_code == (303 if allowed else 403)
        if not allowed:
            assert b"Email and password sign-in is disabled" in response.body
            assert "user_id" not in incoming.session


def test_oidc_only_user_gets_generic_local_login_failure():
    with database() as db:
        add_user(db)
        add_user(db, "oidc@example.com", password=None, role="viewer", authentication_type="oidc")
        response = login(request(method="POST"), email="oidc@example.com", password="anything", totp_code="", csrf_token="csrf", db=db)
        assert response.status_code == 401
        assert b"Invalid email or password" in response.body


def test_existing_local_login_still_creates_normal_kaya_session():
    with database() as db:
        user = add_user(db)
        incoming = request(method="POST")
        response = login(incoming, email=user.email, password="correct horse battery staple", totp_code="", csrf_token="csrf", db=db)
        assert response.status_code == 303
        assert incoming.session["user_id"] == user.id


def test_break_glass_allows_only_explicit_active_local_administrator():
    with database() as db:
        regular = add_user(db, "regular@example.com")
        incoming = request("/auth/local", "POST")
        rejected = emergency_login_submit(incoming, email=regular.email, password="correct horse battery staple", totp_code="", csrf_token="csrf", db=db)
        assert rejected.status_code == 401

        break_glass = add_user(db, "emergency@example.com", is_break_glass=True)
        incoming = request("/auth/local", "POST")
        accepted = emergency_login_submit(incoming, email=break_glass.email, password="correct horse battery staple", totp_code="", csrf_token="csrf", db=db)
        assert accepted.status_code == 303
        assert incoming.session["user_id"] == break_glass.id


@pytest.mark.parametrize(
    "attributes",
    [
        {"role": "viewer", "is_break_glass": True},
        {"role": "admin", "is_break_glass": False},
        {"role": "admin", "is_break_glass": True, "is_active": False},
    ],
)
def test_emergency_login_rejects_ordinary_non_break_glass_and_disabled_users(attributes):
    with database() as db:
        role = attributes.pop("role")
        active = attributes.pop("is_active", True)
        user = User(email="candidate@example.com", password_hash=hash_password("correct horse battery staple"), role=role, is_active=active, **attributes)
        db.add(user); db.commit()
        incoming = request("/auth/local", "POST")
        response = emergency_login_submit(incoming, email=user.email, password="correct horse battery staple", totp_code="", csrf_token="csrf", db=db)
        assert response.status_code == 401
        assert "user_id" not in incoming.session


def test_emergency_login_post_redirects_when_emergency_access_is_disabled():
    with database() as db:
        user = add_user(db, is_break_glass=True)
        setting(db, "oidc_emergency_local_enabled", "")
        response = emergency_login_submit(request("/auth/local", "POST"), email=user.email, password="correct horse battery staple", totp_code="", csrf_token="csrf", db=db)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_emergency_login_enforces_totp_when_enabled(monkeypatch):
    monkeypatch.setattr("app.routers.oidc.decrypted_totp_secret", lambda value: "totp-secret")
    monkeypatch.setattr("app.routers.oidc.verify_totp", lambda secret, code: False)
    with database() as db:
        user = add_user(db, is_break_glass=True, totp_enabled=True, totp_secret="encrypted")
        incoming = request("/auth/local", "POST")
        challenge = emergency_login_submit(incoming, email=user.email, password="correct horse battery staple", totp_code="", csrf_token="csrf", db=db)
        assert challenge.status_code == 200
        assert incoming.session["pending_break_glass_user_id"] == user.id

        rejected = emergency_login_submit(incoming, email="", password="", totp_code="000000", csrf_token="csrf", db=db)
        assert rejected.status_code == 401
        assert "user_id" not in incoming.session


def save_provider(db, user, **changes):
    values = {
        "name": "Company SSO", "issuer": "https://id.example.com", "client_id": "kaya", "client_secret": "",
        "scopes": "openid profile email", "is_enabled": "1", "verify_tls": "1", "verify_tls_acknowledged": "",
        "timeout_seconds": 10, "use_userinfo": "1", "require_verified_email": "1", "allow_jit_provisioning": "",
        "jit_acknowledged": "", "email_matching_mode": "disabled", "email_matching_acknowledged": "",
        "allowed_email_domains": "", "default_role": "viewer", "sync_roles_on_login": "", "role_sync_acknowledged": "",
        "update_names_on_login": "1", "update_email_on_login": "", "end_session_on_logout": "",
    }
    values.update(changes)
    return save_oidc_provider(request("/system/site-administration/authentication/provider", "POST"), csrf_token="csrf", db=db, user=user, **values)


def validated_provider(db):
    row = OIDCProvider(
        name="Company SSO", issuer="https://id.example.com", client_id="kaya", encrypted_client_secret="saved",
        scopes="openid profile email", is_enabled=True, verify_tls=True, use_userinfo=True, require_verified_email=True,
        discovery_status="ok", metadata_json='{"issuer":"https://id.example.com"}',
        metadata_fetched_at=datetime.utcnow(), test_login_succeeded_at=datetime.utcnow(),
    )
    db.add(row); db.commit(); return row


def test_cosmetic_provider_name_change_preserves_successful_validation():
    with database() as db:
        admin = add_user(db)
        provider = validated_provider(db)
        response = save_provider(db, admin, name="Authentik")
        db.refresh(provider)
        assert response.status_code == 303
        assert provider.name == "Authentik"
        assert provider.discovery_status == "ok"
        assert provider.test_login_succeeded_at is not None


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "https://new-id.example.com"},
        {"client_id": "new-client"},
        {"client_secret": "replacement-secret"},
    ],
)
def test_security_sensitive_provider_changes_invalidate_discovery_and_real_login(monkeypatch, change):
    monkeypatch.setattr("app.routers.oidc.encrypt_secret", lambda value: f"encrypted:{value}")
    with database() as db:
        admin = add_user(db)
        provider = validated_provider(db)
        response = save_provider(db, admin, **change)
        db.refresh(provider)
        assert response.status_code == 303
        assert provider.discovery_status is None
        assert provider.metadata_json is None
        assert provider.test_login_succeeded_at is None


def oidc_ready_rows(db):
    admin = add_user(db, is_break_glass=True)
    provider = validated_provider(db)
    db.add(ExternalIdentity(user_id=admin.id, provider_id=provider.id, issuer=provider.issuer, subject="admin", link_method="self_service"))
    db.commit()
    return admin, provider


def enable_oidc_only(db, admin, *, emergency="1", acknowledgement="1"):
    return save_authentication_general(
        request("/system/site-administration/authentication/general", "POST"),
        authentication_mode="oidc_required", oidc_button_label="Sign in with Authentik",
        oidc_post_login_path="/dashboard", oidc_post_logout_path="/login",
        oidc_auto_redirect_required="1", oidc_show_local_preferred="",
        oidc_emergency_local_enabled=emergency, oidc_required_risk_acknowledged=acknowledgement,
        csrf_token="csrf", db=db, user=admin,
    )


@pytest.mark.parametrize("missing", ["provider", "discovery", "test_login", "break_glass", "emergency", "acknowledgement", "current_link"])
def test_oidc_only_activation_rechecks_every_lockout_prerequisite(missing):
    with database() as db:
        admin, provider = oidc_ready_rows(db)
        emergency = "1"
        acknowledgement = "1"
        if missing == "provider":
            provider.is_enabled = False
        elif missing == "discovery":
            provider.discovery_status = None
        elif missing == "test_login":
            provider.test_login_succeeded_at = None
        elif missing == "break_glass":
            admin.is_break_glass = False
        elif missing == "emergency":
            emergency = ""
        elif missing == "acknowledgement":
            acknowledgement = ""
        elif missing == "current_link":
            db.query(ExternalIdentity).delete()
        db.commit()

        response = enable_oidc_only(db, admin, emergency=emergency, acknowledgement=acknowledgement)

        assert response.status_code == 303
        assert "error=required_safety" in response.headers["location"]
        assert get_site_setting(db, "authentication_mode") == "local_only"


def test_oidc_only_activation_succeeds_only_when_all_readiness_checks_pass():
    with database() as db:
        admin, _ = oidc_ready_rows(db)
        response = enable_oidc_only(db, admin)
        assert response.status_code == 303
        assert "saved=1" in response.headers["location"]
        assert get_site_setting(db, "authentication_mode") == "oidc_required"


def test_profile_surfaces_oidc_link_errors_instead_of_silently_reloading(monkeypatch):
    monkeypatch.setattr("app.core.csrf.version_status", lambda: None)
    with database() as db:
        user = add_user(db)
        response = profile(request("/profile?identity_error=configuration_not_ready"), db=db, user=user)
        assert b"must pass its configuration test" in response.body


def test_profile_link_rejects_incomplete_provider_with_visible_error_redirect():
    with database() as db:
        user = add_user(db)
        db.add(OIDCProvider(name="Company SSO", issuer="https://id.example.com", client_id="", is_enabled=True, discovery_status="ok"))
        db.commit()
        response = asyncio.run(profile_identity_link(request("/profile/identity/link", "POST"), csrf_token="csrf", db=db, user=user))
        assert response.status_code == 303
        assert response.headers["location"] == "/profile?identity_error=incomplete_provider"


def test_authenticated_link_callback_shows_safe_actionable_failure_reason():
    with database() as db:
        user = add_user(db)
        incoming = request("/auth/oidc/callback")
        incoming.session["user_id"] = user.id
        transaction = OIDCTransaction(flow_type="self_link", initiated_by_user_id=user.id, target_user_id=user.id)
        actor, message, return_url, return_label = callback_error_context(db, incoming, transaction, OIDCIdentityError("unverified_email"))
        assert actor.id == user.id
        assert "did not mark your email address as verified" in message
        assert (return_url, return_label) == ("/profile", "Return to profile")


def vault_assurance_rows(db):
    user = add_user(db, "oidc@example.com", password=None, role="viewer", authentication_type="oidc")
    provider = OIDCProvider(name="Company SSO", issuer="https://id.example.com", client_id="kaya", is_enabled=True)
    db.add(provider); db.flush()
    db.add(ExternalIdentity(user_id=user.id, provider_id=provider.id, issuer=provider.issuer, subject="subject-1", link_method="jit"))
    setting(db, "secret_vault_oidc_mfa_policy", "either")
    transaction = OIDCTransaction(
        transaction_hash="a" * 64, state_hash="b" * 64, encrypted_nonce="nonce", encrypted_code_verifier="verifier",
        provider_id=provider.id, flow_type="vault_setup", target_user_id=user.id, initiated_by_user_id=user.id,
        return_path="/security/secret-vault", expires_at=datetime.utcnow() + timedelta(minutes=5), used_at=datetime.utcnow(),
    )
    db.add(transaction); db.commit()
    return user, provider, transaction


def test_vault_oidc_assurance_is_bound_fresh_mfa_and_one_purpose():
    with database() as db:
        user, provider, transaction = vault_assurance_rows(db)
        incoming = request("/auth/oidc/callback")
        incoming.session["user_id"] = user.id
        transaction_id = transaction.id
        response = _complete_vault_assurance(incoming, db, provider, transaction, {
            "iss": provider.issuer, "sub": "subject-1", "auth_time": int(datetime.now(timezone.utc).timestamp()), "amr": ["pwd", "mfa"],
        })
        assert response.status_code == 303
        assert incoming.session["vault_oidc_approval"]["purpose"] == "setup"
        assert db.get(OIDCTransaction, transaction_id) is None


def test_vault_oidc_assurance_rejects_login_without_mfa_evidence():
    with database() as db:
        user, provider, transaction = vault_assurance_rows(db)
        incoming = request("/auth/oidc/callback")
        incoming.session["user_id"] = user.id
        with pytest.raises(OIDCFlowError) as exc:
            _complete_vault_assurance(incoming, db, provider, transaction, {
                "iss": provider.issuer, "sub": "subject-1", "auth_time": int(datetime.now(timezone.utc).timestamp()), "amr": ["pwd"],
            })
        assert exc.value.category == "mfa_assurance_required"
        assert "vault_oidc_approval" not in incoming.session
