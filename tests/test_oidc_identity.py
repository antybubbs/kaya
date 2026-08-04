from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.models import ExternalIdentity, OIDCLinkInvitation, OIDCProvider, OIDCTransaction, User
from app.services.oidc_identity import OIDCIdentityError, claim_admin_link_invitation, confirm_transaction_link, invitation_provider_binding, invitation_recipient_binding, resolve_login, unlink_identity


def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def add_provider(db, **values):
    row = OIDCProvider(name="SSO", issuer="https://id.example.com", client_id="kaya", is_enabled=True, **values)
    db.add(row)
    db.flush()
    return row


def add_user(db, email="user@example.com", **values):
    row = User(email=email, password_hash=values.pop("password_hash", "local-hash"), role=values.pop("role", "viewer"), is_active=values.pop("is_active", True), **values)
    db.add(row)
    db.flush()
    return row


def transaction(db, provider, **values):
    transaction_hash = values.pop("transaction_hash", "a" * 64)
    state_hash = values.pop("state_hash", "b" * 64)
    row = OIDCTransaction(transaction_hash=transaction_hash, state_hash=state_hash, encrypted_nonce="x", encrypted_code_verifier="x", provider_id=provider.id, expires_at=datetime.utcnow(), **values)
    db.add(row)
    db.flush()
    return row


def claims(email="user@example.com", subject="subject-1", groups=None):
    return {"iss": "https://id.example.com", "sub": subject, "email": email, "email_verified": True, "given_name": "Test", "family_name": "User", "groups": groups or []}


def admin_link_transaction(db, provider, target, creator, **invitation_values):
    invitation = OIDCLinkInvitation(
        token_hash="f" * 64,
        user_id=target.id,
        provider_id=provider.id,
        created_by_user_id=creator.id,
        recipient_binding_hash=invitation_recipient_binding(target),
        provider_binding_hash=invitation_provider_binding(provider),
        expires_at=invitation_values.pop("expires_at", datetime.utcnow() + timedelta(minutes=30)),
        used_at=invitation_values.pop("used_at", datetime.utcnow()),
        **invitation_values,
    )
    db.add(invitation)
    db.flush()
    return transaction(
        db, provider, flow_type="admin_link", target_user_id=target.id,
        initiated_by_user_id=target.id, link_invitation_id=invitation.id,
    ), invitation


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
        unverified = claims()
        unverified["email_verified"] = False
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


def test_admin_invitation_requires_exact_recipient_and_verified_matching_email():
    with database() as db:
        provider = add_provider(db, require_verified_email=False)
        creator = add_user(db, "admin@example.com", role="admin")
        target = add_user(db)
        attacker = add_user(db, "attacker@example.com")
        tx, _ = admin_link_transaction(db, provider, target, creator)

        wrong_email = claims(email=attacker.email)
        with pytest.raises(OIDCIdentityError) as mismatch:
            resolve_login(db, provider, tx, wrong_email)
        assert mismatch.value.category == "invitation_identity_mismatch"

        unverified = claims(email=target.email)
        unverified["email_verified"] = False
        with pytest.raises(OIDCIdentityError) as mismatch:
            resolve_login(db, provider, tx, unverified)
        assert mismatch.value.category == "invitation_identity_mismatch"

        resolution = resolve_login(db, provider, tx, claims(email=target.email))
        assert resolution.confirmation_required
        with pytest.raises(OIDCIdentityError) as wrong_owner:
            confirm_transaction_link(db, tx, attacker)
        assert wrong_owner.value.category == "invalid_link_owner"
        identity = confirm_transaction_link(db, tx, target)
        assert identity.user_id == target.id
        assert identity.link_method == "admin_invitation"
        assert identity.linked_by_user_id == creator.id


@pytest.mark.parametrize("change", ["expired", "revoked", "account_changed", "provider_changed"])
def test_admin_invitation_fails_closed_when_security_binding_is_stale(change):
    with database() as db:
        provider = add_provider(db)
        creator = add_user(db, "admin@example.com", role="admin")
        target = add_user(db)
        values = {"expires_at": datetime.utcnow() - timedelta(seconds=1)} if change == "expired" else {}
        tx, invitation = admin_link_transaction(db, provider, target, creator, **values)
        if change == "revoked":
            invitation.revoked_at = datetime.utcnow()
        elif change == "account_changed":
            target.role = "editor"
        elif change == "provider_changed":
            provider.client_id = "replacement-client"
        db.flush()
        with pytest.raises(OIDCIdentityError) as failure:
            resolve_login(db, provider, tx, claims(email=target.email))
        assert failure.value.category == "invalid_link_invitation"


def test_existing_provider_link_blocks_admin_invitation_rebinding():
    with database() as db:
        provider = add_provider(db)
        creator = add_user(db, "admin@example.com", role="admin")
        target = add_user(db)
        db.add(ExternalIdentity(
            user_id=target.id, provider_id=provider.id, issuer=provider.issuer,
            subject="existing-subject", current_email=target.email, link_method="self_service",
        ))
        tx, _ = admin_link_transaction(db, provider, target, creator)
        resolve_login(db, provider, tx, claims(email=target.email, subject="different-subject"))
        with pytest.raises(OIDCIdentityError) as failure:
            confirm_transaction_link(db, tx, target)
        assert failure.value.category == "user_identity_conflict"

        tx.validated_claims_json = None
        with pytest.raises(OIDCIdentityError) as failure:
            resolve_login(db, provider, tx, claims(email=target.email, subject="existing-subject"))
        assert failure.value.category == "identity_conflict"


def test_concurrent_sessions_can_claim_an_invitation_only_once(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'concurrent.sqlite3').as_posix()}")
    Base.metadata.create_all(engine)
    with Session(engine) as seed:
        provider = add_provider(seed)
        creator = add_user(seed, "admin@example.com", role="admin")
        target = add_user(seed)
        _, invitation = admin_link_transaction(seed, provider, target, creator)
        invitation.used_at = None
        invitation.redemption_session_hash = "e" * 64
        seed.commit()
        invitation_id, target_id = invitation.id, target.id

    first = Session(engine)
    second = Session(engine)
    try:
        first_invitation, first_user = first.get(OIDCLinkInvitation, invitation_id), first.get(User, target_id)
        second_invitation, second_user = second.get(OIDCLinkInvitation, invitation_id), second.get(User, target_id)
        assert claim_admin_link_invitation(first, first_invitation, first_user) is True
        assert claim_admin_link_invitation(second, second_invitation, second_user) is False
    finally:
        first.close()
        second.close()


def test_oidc_only_user_cannot_unlink_and_local_user_can():
    with database() as db:
        provider = add_provider(db)
        oidc_user = add_user(db, password_hash=None, authentication_type="oidc")
        identity = ExternalIdentity(user_id=oidc_user.id, provider_id=provider.id, issuer=provider.issuer, subject="one", current_email=oidc_user.email, link_method="jit_provisioning")
        db.add(identity)
        db.flush()
        with pytest.raises(OIDCIdentityError) as failure:
            unlink_identity(db, identity, oidc_user)
        assert failure.value.category == "no_remaining_login_method"

        local = add_user(db, "local@example.com", authentication_type="local_and_oidc")
        linked = ExternalIdentity(user_id=local.id, provider_id=provider.id, issuer=provider.issuer, subject="two", current_email=local.email, link_method="self_service")
        db.add(linked)
        db.commit()
        unlink_identity(db, linked, local)
        assert local.authentication_type == "local"


def test_role_sync_cannot_demote_last_active_administrator():
    with database() as db:
        provider = add_provider(db, sync_roles_on_login=True, role_mappings_json='[{"group":"Users","role":"viewer"}]')
        admin = add_user(db, role="admin", role_source="oidc")
        identity = ExternalIdentity(user_id=admin.id, provider_id=provider.id, issuer=provider.issuer, subject="subject-1", current_email=admin.email, link_method="admin", role_management="oidc")
        db.add(identity)
        db.flush()
        with pytest.raises(OIDCIdentityError) as failure:
            resolve_login(db, provider, transaction(db, provider), claims(groups=["Users"]))
        assert failure.value.category == "last_administrator_protection"
