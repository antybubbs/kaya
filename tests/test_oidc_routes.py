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
from app.routers.oidc import _complete_vault_assurance, callback_error_context, emergency_login_submit, profile_identity_link
from app.services.oidc_client import OIDCFlowError
from app.services.oidc_identity import OIDCIdentityError


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
