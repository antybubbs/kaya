from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import ExternalIdentity, OIDCProvider, OIDCTransaction, User
from app.services.oidc_identity import OIDCIdentityError, confirm_transaction_link, resolve_login, unlink_identity


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def add_provider(db, **values):
    row = OIDCProvider(name="SSO", issuer="https://id.example.com", client_id="kaya", is_enabled=True, **values)
    db.add(row); db.flush(); return row


def add_user(db, email="user@example.com", **values):
    row = User(email=email, password_hash=values.pop("password_hash", "local-hash"), role=values.pop("role", "viewer"), is_active=values.pop("is_active", True), **values)
    db.add(row); db.flush(); return row


def transaction(db, provider, **values):
    transaction_hash = values.pop("transaction_hash", "a" * 64)
    state_hash = values.pop("state_hash", "b" * 64)
    row = OIDCTransaction(transaction_hash=transaction_hash, state_hash=state_hash, encrypted_nonce="x", encrypted_code_verifier="x", provider_id=provider.id, expires_at=datetime.utcnow(), **values)
    db.add(row); db.flush(); return row


def claims(email="user@example.com", subject="subject-1", groups=None):
    return {"iss": "https://id.example.com", "sub": subject, "email": email, "email_verified": True, "given_name": "Test", "family_name": "User", "groups": groups or []}


def test_existing_link_resolves_by_issuer_and_subject_not_changed_email():
    with database() as db:
        provider = add_provider(db)
        user = add_user(db, email="local@example.com")
        db.add(ExternalIdentity(user_id=user.id, provider_id=provider.id, issuer=provider.issuer, subject="subject-1", current_email="old@example.com", link_method="admin"))
        db.flush()
        result = resolve_login(db, provider, transaction(db, provider), claims(email="new@example.com"))
        assert result.user.id == user.id
        assert result.user.email == "local@example.com"


def test_jit_is_disabled_by_default_and_creates_oidc_only_viewer_when_enabled():
    with database() as db:
        provider = add_provider(db)
        with pytest.raises(OIDCIdentityError) as blocked:
            resolve_login(db, provider, transaction(db, provider), claims(email="new@example.com"))
        assert blocked.value.category == "provisioning_disabled"
    with database() as db:
        provider = add_provider(db, allow_jit_provisioning=True)
        result = resolve_login(db, provider, transaction(db, provider), claims(email="new@example.com"))
        assert result.provisioned is True
        assert result.user.password_hash is None
        assert result.user.authentication_type == "oidc"
        assert result.user.role == "viewer"


def test_unverified_and_disallowed_email_are_rejected():
    with database() as db:
        provider = add_provider(db, allow_jit_provisioning=True, allowed_email_domains="example.com")
        unverified = claims(); unverified["email_verified"] = False
        with pytest.raises(OIDCIdentityError) as failure:
            resolve_login(db, provider, transaction(db, provider), unverified)
        assert failure.value.category == "unverified_email"
        with pytest.raises(OIDCIdentityError) as failure:
            resolve_login(db, provider, transaction(db, provider, transaction_hash="c" * 64, state_hash="d" * 64), claims(email="user@fakeexample.com"))
        assert failure.value.category == "disallowed_email_domain"


def test_explicit_self_link_requires_target_owner_and_prevents_identity_conflict():
    with database() as db:
        provider = add_provider(db)
        user = add_user(db)
        other = add_user(db, "other@example.com")
        tx = transaction(db, provider, flow_type="self_link", target_user_id=user.id, initiated_by_user_id=user.id)
        resolution = resolve_login(db, provider, tx, claims())
        assert resolution.confirmation_required
        with pytest.raises(OIDCIdentityError):
            confirm_transaction_link(db, tx, other)
        identity = confirm_transaction_link(db, tx, user)
        assert identity.user_id == user.id
        assert user.authentication_type == "local_and_oidc"


def test_oidc_only_user_cannot_unlink_and_local_user_can():
    with database() as db:
        provider = add_provider(db)
        oidc_user = add_user(db, password_hash=None, authentication_type="oidc")
        identity = ExternalIdentity(user_id=oidc_user.id, provider_id=provider.id, issuer=provider.issuer, subject="one", current_email=oidc_user.email, link_method="jit_provisioning")
        db.add(identity); db.flush()
        with pytest.raises(OIDCIdentityError) as failure:
            unlink_identity(db, identity, oidc_user)
        assert failure.value.category == "no_remaining_login_method"

        local = add_user(db, "local@example.com", authentication_type="local_and_oidc")
        linked = ExternalIdentity(user_id=local.id, provider_id=provider.id, issuer=provider.issuer, subject="two", current_email=local.email, link_method="self_service")
        db.add(linked); db.commit()
        unlink_identity(db, linked, local)
        assert local.authentication_type == "local"


def test_role_sync_cannot_demote_last_active_administrator():
    with database() as db:
        provider = add_provider(db, sync_roles_on_login=True, role_mappings_json='[{"group":"Users","role":"viewer"}]')
        admin = add_user(db, role="admin", role_source="oidc")
        identity = ExternalIdentity(user_id=admin.id, provider_id=provider.id, issuer=provider.issuer, subject="subject-1", current_email=admin.email, link_method="admin", role_management="oidc")
        db.add(identity); db.flush()
        with pytest.raises(OIDCIdentityError) as failure:
            resolve_login(db, provider, transaction(db, provider), claims(groups=["Users"]))
        assert failure.value.category == "last_administrator_protection"
