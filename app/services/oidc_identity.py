from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.models import ExternalIdentity, OIDCProvider, OIDCTransaction, User
from app.services.oidc_role_mapping import (
    claim_bool,
    claim_groups,
    claim_text,
    email_is_allowed,
    initial_role,
    mapped_role,
    normalise_email,
)


class OIDCIdentityError(RuntimeError):
    def __init__(self, category: str, message: str = "Your identity was verified, but your Kaya account is not authorised."):
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class LoginResolution:
    user: User | None
    confirmation_required: bool = False
    provisioned: bool = False
    linked: bool = False


def normalised_identity_claims(provider: OIDCProvider, claims: dict) -> dict:
    issuer = str(claims.get("iss") or "").strip()
    subject = str(claims.get("sub") or "").strip()
    email = normalise_email(claim_text(claims, provider.email_claim))
    verified = claim_bool(claims, provider.email_verified_claim)
    if not issuer or not subject:
        raise OIDCIdentityError("missing_security_identity")
    if not email:
        raise OIDCIdentityError("missing_or_invalid_email")
    if provider.require_verified_email and not verified:
        raise OIDCIdentityError("unverified_email")
    if not email_is_allowed(provider, email):
        raise OIDCIdentityError("disallowed_email_domain")
    return {
        "iss": issuer,
        "sub": subject,
        "email": email,
        "email_verified": verified,
        "name": claim_text(claims, provider.name_claim),
        "first_name": claim_text(claims, provider.first_name_claim),
        "last_name": claim_text(claims, provider.last_name_claim),
        "preferred_username": claim_text(claims, provider.preferred_username_claim),
        "groups": claim_groups(claims, provider.group_claim),
    }


def claims_summary(value: dict) -> str:
    return json.dumps(
        {key: value.get(key) for key in ("email", "email_verified", "name", "preferred_username", "groups")},
        separators=(",", ":"),
    )


def create_identity(
    db: Session,
    provider: OIDCProvider,
    user: User,
    value: dict,
    *,
    link_method: str,
    linked_by_user_id: int | None = None,
) -> ExternalIdentity:
    conflict = db.query(ExternalIdentity).filter_by(provider_id=provider.id, issuer=value["iss"], subject=value["sub"]).first()
    if conflict and conflict.user_id != user.id:
        raise OIDCIdentityError("identity_conflict")
    existing = db.query(ExternalIdentity).filter_by(provider_id=provider.id, user_id=user.id).first()
    if existing:
        if existing.issuer != value["iss"] or existing.subject != value["sub"]:
            raise OIDCIdentityError("user_identity_conflict")
        return existing
    row = ExternalIdentity(
        user_id=user.id,
        provider_id=provider.id,
        issuer=value["iss"],
        subject=value["sub"],
        email_at_link_time=value["email"],
        current_email=value["email"],
        preferred_username=value.get("preferred_username"),
        claims_summary_json=claims_summary(value),
        role_management="oidc" if provider.sync_roles_on_login else "local",
        linked_by_user_id=linked_by_user_id,
        link_method=link_method,
        last_login_at=datetime.utcnow(),
    )
    db.add(row)
    user.authentication_type = "local_and_oidc" if user.password_hash else "oidc"
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise OIDCIdentityError("identity_conflict") from exc
    return row


def _apply_profile(db: Session, provider: OIDCProvider, user: User, identity: ExternalIdentity, value: dict) -> tuple[str | None, str | None]:
    identity.current_email = value["email"]
    identity.preferred_username = value.get("preferred_username")
    identity.claims_summary_json = claims_summary(value)
    identity.last_login_at = datetime.utcnow()
    if provider.update_names_on_login:
        if value.get("first_name"):
            user.first_name = value["first_name"][:120]
        if value.get("last_name"):
            user.last_name = value["last_name"][:120]
    old_email = None
    if provider.update_email_on_login and value["email"] != user.email:
        if db.query(User).filter(User.email == value["email"], User.id != user.id).first():
            raise OIDCIdentityError("email_conflict")
        old_email = user.email
        user.email = value["email"]
    old_role = None
    if provider.sync_roles_on_login and identity.role_management == "oidc":
        role = mapped_role(provider, value["groups"])
        if role and role != user.role:
            if user.role == "admin" and role != "admin" and db.query(User).filter_by(role="admin", is_active=True).count() <= 1:
                raise OIDCIdentityError("last_administrator_protection")
            old_role = user.role
            user.role = role
            user.role_source = "oidc"
    db.commit()
    return old_email, old_role


def resolve_login(db: Session, provider: OIDCProvider, transaction: OIDCTransaction, claims: dict) -> LoginResolution:
    value = normalised_identity_claims(provider, claims)
    identity = db.query(ExternalIdentity).filter_by(provider_id=provider.id, issuer=value["iss"], subject=value["sub"]).first()
    if identity:
        user = db.get(User, identity.user_id)
        if not user or not user.is_active:
            raise OIDCIdentityError("inactive_user")
        _apply_profile(db, provider, user, identity, value)
        return LoginResolution(user=user)

    if transaction.flow_type in {"self_link", "admin_link"}:
        target = db.get(User, transaction.target_user_id)
        if not target or not target.is_active:
            raise OIDCIdentityError("invalid_link_target")
        transaction.validated_claims_json = json.dumps(value, separators=(",", ":"))
        db.commit()
        return LoginResolution(user=None, confirmation_required=True)

    matches = db.query(User).filter(User.email == value["email"], User.is_active == True).all()  # noqa: E712
    if provider.email_matching_mode == "automatic" and len(matches) == 1:
        user = matches[0]
        identity = create_identity(db, provider, user, value, link_method="verified_email_match")
        _apply_profile(db, provider, user, identity, value)
        return LoginResolution(user=user, linked=True)
    if provider.email_matching_mode == "confirmation" and len(matches) == 1:
        transaction.target_user_id = matches[0].id
        transaction.flow_type = "email_match"
        transaction.validated_claims_json = json.dumps(value, separators=(",", ":"))
        db.commit()
        return LoginResolution(user=None, confirmation_required=True)
    if matches:
        raise OIDCIdentityError("existing_email_requires_link")
    if not provider.allow_jit_provisioning:
        raise OIDCIdentityError("provisioning_disabled")
    role = initial_role(provider, value["groups"])
    user = User(
        email=value["email"],
        password_hash=None,
        first_name=(value.get("first_name") or "")[:120] or None,
        last_name=(value.get("last_name") or "")[:120] or None,
        role=role,
        is_active=True,
        authentication_type="oidc",
        role_source="oidc",
    )
    db.add(user)
    try:
        db.flush()
        create_identity(db, provider, user, value, link_method="jit_provisioning")
    except IntegrityError as exc:
        db.rollback()
        raise OIDCIdentityError("provisioning_conflict") from exc
    return LoginResolution(user=user, provisioned=True, linked=True)


def confirm_transaction_link(db: Session, transaction: OIDCTransaction, current_user: User | None, password_verified: bool = False) -> ExternalIdentity:
    if not transaction.validated_claims_json or transaction.flow_type not in {"self_link", "admin_link", "email_match"}:
        raise OIDCIdentityError("invalid_link_transaction")
    target = db.get(User, transaction.target_user_id)
    provider = db.get(OIDCProvider, transaction.provider_id)
    if not target or not provider:
        raise OIDCIdentityError("invalid_link_target")
    if transaction.flow_type == "self_link" and (not current_user or current_user.id != target.id):
        raise OIDCIdentityError("invalid_link_owner")
    if transaction.flow_type == "email_match" and not password_verified:
        raise OIDCIdentityError("local_proof_required", "Confirm the link with your current Kaya password.")
    value = json.loads(transaction.validated_claims_json)
    return create_identity(
        db,
        provider,
        target,
        value,
        link_method="self_service" if transaction.flow_type == "self_link" else "verified_email_match" if transaction.flow_type == "email_match" else "admin",
        linked_by_user_id=transaction.initiated_by_user_id,
    )


def unlink_identity(db: Session, identity: ExternalIdentity, actor: User) -> User:
    user = db.get(User, identity.user_id)
    if not user:
        raise OIDCIdentityError("missing_user")
    if not user.password_hash:
        raise OIDCIdentityError("no_remaining_login_method", "Set a local password before unlinking this identity.")
    if user.role == "admin" and user.is_active and db.query(User).filter_by(role="admin", is_active=True).count() <= 1 and not user.password_hash:
        raise OIDCIdentityError("last_administrator_protection")
    db.delete(identity)
    user.authentication_type = "local"
    user.role_source = "local"
    db.commit()
    return user
