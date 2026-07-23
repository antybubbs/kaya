from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import decrypt_secret, encrypt_secret, verify_password
from app.core.totp import decrypted_totp_secret, verify_totp
from app.db.session import get_db
from app.models.models import ExternalIdentity, OIDCLinkInvitation, OIDCProvider, OIDCTransaction, RemoteManagerSetting, User
from app.routers.auth import client_key, login_is_limited, record_login_failure, require_admin, require_user
from app.services.audit import write_audit
from app.services.authentication_policy import AUTHENTICATION_MODES, get_authentication_policy, oidc_only_readiness
from app.services.oidc_client import OIDCFlowError, authorization_redirect, claims_preview, consume_transaction, exchange_and_validate, safe_return_path
from app.services.oidc_discovery import OIDCDiscoveryError, test_and_store_discovery
from app.services.oidc_identity import OIDCIdentityError, confirm_transaction_link, resolve_login, unlink_identity
from app.services.sessions import start_user_session
from app.services.site_settings import get_site_setting
from app.services.modules import has_module_access, module_for_path, module_landing_url


router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
settings = get_settings()
ACTION_ATTEMPTS: dict[str, list[datetime]] = {}
LINK_ERROR_MESSAGES = {
    "unverified_email": "Your identity provider did not mark your email address as verified. Verify the address there or update its email scope mapping.",
    "missing_or_invalid_email": "Your identity provider did not provide a usable email claim for this identity.",
    "disallowed_email_domain": "Your identity-provider email domain is not permitted by this Kaya provider configuration.",
    "identity_conflict": "This external identity is already linked to another Kaya account.",
    "user_identity_conflict": "This Kaya account is already linked to a different external identity.",
    "invalid_link_target": "The Kaya account selected for linking is no longer available.",
    "inactive_user": "The Kaya account linked to this identity is disabled.",
}


def _rate_limited(key: str, limit: int = 10, minutes: int = 10) -> bool:
    now = datetime.utcnow()
    values = [value for value in ACTION_ATTEMPTS.get(key, []) if now - value < timedelta(minutes=minutes)]
    ACTION_ATTEMPTS[key] = values
    if len(values) >= limit:
        return True
    values.append(now)
    return False


def _save_setting(db: Session, key: str, value: str) -> None:
    row = db.query(RemoteManagerSetting).filter_by(key=key).first()
    if not row:
        row = RemoteManagerSetting(key=key, value=value)
        db.add(row)
    else:
        row.value = value


def active_provider(db: Session) -> OIDCProvider | None:
    return db.query(OIDCProvider).filter_by(is_enabled=True).order_by(OIDCProvider.id.asc()).first()


def callback_url(db: Session) -> str:
    return f"{get_site_setting(db, 'base_url').rstrip('/')}/auth/oidc/callback"


def post_logout_url(db: Session) -> str:
    return f"{get_site_setting(db, 'base_url').rstrip('/')}{safe_return_path(get_site_setting(db, 'oidc_post_logout_path'), '/login')}"


def _start_session(request: Request, db: Session, user: User, *, method: str, id_token_hint: str | None = None) -> None:
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["authentication_method"] = method
    row = start_user_session(db, request, user)
    if id_token_hint:
        row.encrypted_oidc_id_token = encrypt_secret(id_token_hint)
        db.commit()


def _audit_oidc(db: Session, user: User | None, action: str, request: Request, provider: OIDCProvider | None, *, category: str | None = None, severity: str | None = None, detail: str | None = None):
    hostname = urlsplit(provider.issuer).hostname if provider and provider.issuer else None
    return write_audit(
        db, user, action, "oidc", str(provider.id) if provider else None,
        request.client.host if request.client else None,
        detail=detail, category=category or "authentication", severity=severity,
        metadata={"provider_id": provider.id if provider else None, "issuer_host": hostname, "failure_category": category if category and category != "authentication" else None},
    )


def _oidc_error_context(request: Request, db: Session, message: str, **values) -> dict:
    policy = get_authentication_policy(db)
    return {
        "message": message,
        "authentication_mode": policy.authentication_mode,
        **values,
        **csrf_context(request, include_version=False),
    }


def callback_error_context(db: Session, request: Request, transaction: OIDCTransaction | None, exc: Exception) -> tuple[User | None, str, str, str]:
    actor = None
    if transaction and transaction.initiated_by_user_id:
        actor = db.get(User, transaction.initiated_by_user_id)
    authorised_link_owner = bool(
        transaction
        and transaction.flow_type in {"self_link", "admin_link"}
        and transaction.initiated_by_user_id
        and request.session.get("user_id") == transaction.initiated_by_user_id
    )
    category = getattr(exc, "category", "callback_failed")
    authorised_vault_owner = bool(
        transaction and transaction.flow_type in {"vault_setup", "vault_unlock", "vault_recovery", "vault_sensitive"}
        and transaction.initiated_by_user_id and request.session.get("user_id") == transaction.initiated_by_user_id
    )
    message = LINK_ERROR_MESSAGES.get(category, str(exc)) if authorised_link_owner else str(exc)
    if authorised_vault_owner:
        return actor, message, transaction.return_path, "Return to Secret Vault"
    return actor, message, "/profile" if authorised_link_owner else "/login", "Return to profile" if authorised_link_owner else "Return to sign in"


async def _begin(request: Request, db: Session, provider: OIDCProvider, *, flow_type="login", target_user_id=None, initiated_by_user_id=None, return_path="/dashboard", authorization_params=None):
    actor = db.get(User, initiated_by_user_id) if initiated_by_user_id else None
    start_action = "oidc_link_started" if flow_type in {"self_link", "admin_link"} else "oidc_login_started"
    if _rate_limited(f"oidc:{client_key(request)}"):
        _audit_oidc(db, actor, "oidc_login_rejected", request, provider, category="rate_limited", severity="warning")
        return templates.TemplateResponse(request, "oidc_error.html", _oidc_error_context(request, db, "Too many sign-in attempts. Try again later."), status_code=429)
    _audit_oidc(db, actor, start_action, request, provider)
    try:
        url, opaque = await asyncio.wait_for(
            authorization_redirect(
                db, provider, callback_url=callback_url(db), flow_type=flow_type,
                target_user_id=target_user_id, initiated_by_user_id=initiated_by_user_id, return_path=return_path,
                authorization_params=authorization_params,
            ),
            timeout=max(4, min(provider.timeout_seconds, 30) + 2),
        )
    except (TimeoutError, OIDCDiscoveryError, OIDCFlowError):
        _audit_oidc(db, actor, "oidc_login_failed", request, provider, category="initiation_failed", severity="warning")
        return templates.TemplateResponse(request, "oidc_error.html", _oidc_error_context(request, db, "Single sign-on is currently unavailable."), status_code=503)
    request.session["oidc_transaction"] = opaque
    return RedirectResponse(url, status_code=302)


def _complete_vault_assurance(request: Request, db: Session, provider: OIDCProvider, transaction: OIDCTransaction, claims: dict):
    """Turn a fresh, matching IdP MFA event into a one-use vault approval."""
    purpose = transaction.flow_type.removeprefix("vault_")
    user_id = request.session.get("user_id")
    if purpose not in {"setup", "unlock", "recovery", "sensitive"} or not user_id:
        raise OIDCFlowError("invalid_vault_assurance")
    if transaction.initiated_by_user_id != user_id or transaction.target_user_id != user_id:
        raise OIDCFlowError("invalid_vault_assurance")
    if get_site_setting(db, "secret_vault_oidc_mfa_policy") not in {"idp_mfa", "either"}:
        raise OIDCFlowError("oidc_vault_assurance_disabled", "Identity-provider MFA is not enabled for Secret Vault.")
    identity = db.query(ExternalIdentity).filter_by(user_id=user_id, provider_id=provider.id).first()
    if not identity or identity.issuer != str(claims.get("iss") or "") or identity.subject != str(claims.get("sub") or ""):
        raise OIDCFlowError("identity_mismatch", "The identity provider returned a different linked account.")
    try:
        auth_time = int(claims.get("auth_time"))
    except (TypeError, ValueError):
        raise OIDCFlowError("fresh_authentication_required", "The identity provider did not confirm when authentication occurred.")
    now = int(datetime.now(timezone.utc).timestamp())
    if auth_time > now + 60 or now - auth_time > 300:
        raise OIDCFlowError("fresh_authentication_required", "A fresh identity-provider authentication is required.")
    accepted_acr = {
        value.strip() for value in get_site_setting(db, "secret_vault_oidc_accepted_acr").replace(",", " ").split() if value.strip()
    }
    acr = str(claims.get("acr") or "")
    amr_claim = claims.get("amr")
    amr = {str(value).lower() for value in amr_claim} if isinstance(amr_claim, list) else set()
    if not ((accepted_acr and acr in accepted_acr) or "mfa" in amr):
        raise OIDCFlowError("mfa_assurance_required", "The identity provider did not confirm the required multi-factor authentication assurance.")
    request.session["vault_oidc_approval"] = {
        "user_id": user_id, "purpose": purpose, "issued_at": now,
        "provider_id": provider.id, "method": "oidc_mfa",
    }
    return_path = transaction.return_path
    db.delete(transaction)
    db.commit()
    _audit_oidc(db, db.get(User, user_id), "vault_oidc_assurance_succeeded", request, provider, detail=f"purpose={purpose}")
    return RedirectResponse(return_path, status_code=303)


@router.get("/auth/oidc/login")
async def oidc_login(request: Request, return_to: str = Query("/dashboard"), db: Session = Depends(get_db)):
    policy = get_authentication_policy(db)
    provider = policy.provider
    if settings.demo_mode or not policy.show_oidc_login:
        return templates.TemplateResponse(request, "oidc_error.html", _oidc_error_context(request, db, "Single sign-on is not enabled."), status_code=404)
    return await _begin(request, db, provider, return_path=safe_return_path(return_to, get_site_setting(db, "oidc_post_login_path")))


@router.get("/auth/oidc/callback")
async def oidc_callback(request: Request, state: str = "", code: str = "", error: str = "", db: Session = Depends(get_db)):
    opaque = request.session.pop("oidc_transaction", None)
    provider = None
    transaction = None
    try:
        if _rate_limited(f"oidc-callback:{client_key(request)}", limit=20):
            raise OIDCFlowError("callback_rate_limited", "Too many sign-in attempts. Try again later.")
        if error or not code:
            raise OIDCFlowError("provider_rejected")
        transaction = consume_transaction(db, opaque, state)
        provider = db.get(OIDCProvider, transaction.provider_id)
        if not provider or (not provider.is_enabled and transaction.flow_type != "test"):
            raise OIDCFlowError("provider_disabled")
        claims, id_token_hint = await exchange_and_validate(db, provider, transaction, code=code, callback_url=callback_url(db))
        if transaction.flow_type == "test":
            preview = claims_preview(claims, provider)
            provider.test_login_succeeded_at = datetime.utcnow()
            db.delete(transaction)
            db.commit()
            request.session["oidc_test_preview"] = preview
            _audit_oidc(db, db.get(User, transaction.initiated_by_user_id), "oidc_test_login_succeeded", request, provider)
            return RedirectResponse("/system/site-administration/authentication?tab=oidc&test_login=success", status_code=303)
        if transaction.flow_type in {"vault_setup", "vault_unlock", "vault_recovery", "vault_sensitive"}:
            return _complete_vault_assurance(request, db, provider, transaction, claims)
        resolution = resolve_login(db, provider, transaction, claims)
        if resolution.confirmation_required:
            request.session["oidc_transaction"] = opaque
            return RedirectResponse("/auth/oidc/link/confirm", status_code=303)
        user = resolution.user
        if not user:
            raise OIDCIdentityError("unresolved_user")
        return_path = transaction.return_path
        return_module = module_for_path(return_path.split("?", 1)[0])
        if return_module and not has_module_access(db, user, return_module.key):
            return_path = module_landing_url(db, user)
        db.delete(transaction)
        db.commit()
        _start_session(request, db, user, method="oidc", id_token_hint=id_token_hint)
        action = "oidc_user_provisioned" if resolution.provisioned else "oidc_login_succeeded"
        _audit_oidc(db, user, action, request, provider)
        return RedirectResponse(return_path, status_code=303)
    except (OIDCFlowError, OIDCIdentityError, OIDCDiscoveryError) as exc:
        category = getattr(exc, "category", "callback_failed")
        actor, message, return_url, return_label = callback_error_context(db, request, transaction, exc)
        _audit_oidc(db, actor, "oidc_link_failed" if transaction and transaction.flow_type in {"self_link", "admin_link"} else "oidc_login_failed", request, provider, category=category, severity="warning")
        if transaction is not None and transaction.validated_claims_json is None:
            try:
                db.delete(transaction)
                db.commit()
            except Exception:
                db.rollback()
        request.session.pop("oidc_transaction", None)
        return templates.TemplateResponse(request, "oidc_error.html", _oidc_error_context(request, db, message, return_url=return_url, return_label=return_label), status_code=400)


def _pending_transaction(db: Session, request: Request) -> OIDCTransaction | None:
    opaque = request.session.get("oidc_transaction")
    if not opaque:
        return None
    digest = hashlib.sha256(opaque.encode()).hexdigest()
    return db.query(OIDCTransaction).filter_by(transaction_hash=digest).first()


@router.get("/auth/oidc/link/confirm")
def link_confirm_page(request: Request, db: Session = Depends(get_db)):
    transaction = _pending_transaction(db, request)
    if not transaction or not transaction.validated_claims_json:
        return RedirectResponse("/login", status_code=303)
    target = db.get(User, transaction.target_user_id)
    provider = db.get(OIDCProvider, transaction.provider_id)
    claims = json.loads(transaction.validated_claims_json)
    current = db.get(User, request.session.get("user_id")) if request.session.get("user_id") else None
    if transaction.flow_type == "self_link" and (not current or current.id != transaction.target_user_id):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "oidc_link_confirm.html", {"user": current, "target": target, "provider": provider, "claims": claims, "require_password": transaction.flow_type == "email_match", **csrf_context(request)})


@router.post("/auth/oidc/link/confirm")
def link_confirm_submit(request: Request, password: str = Form("", max_length=255), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf_token(request, csrf_token)
    if _rate_limited(f"oidc-link-confirm:{client_key(request)}", limit=10):
        return templates.TemplateResponse(request, "oidc_error.html", _oidc_error_context(request, db, "Too many account-link attempts. Try again later."), status_code=429)
    transaction = _pending_transaction(db, request)
    if not transaction:
        return RedirectResponse("/login", status_code=303)
    current = db.get(User, request.session.get("user_id")) if request.session.get("user_id") else None
    target = db.get(User, transaction.target_user_id)
    password_verified = bool(target and target.password_hash and verify_password(password, target.password_hash))
    try:
        identity = confirm_transaction_link(db, transaction, current, password_verified=password_verified)
    except OIDCIdentityError as exc:
        provider = db.get(OIDCProvider, transaction.provider_id)
        _audit_oidc(db, current, "oidc_link_failed", request, provider, category=exc.category, severity="warning")
        return templates.TemplateResponse(request, "oidc_error.html", _oidc_error_context(request, db, str(exc)), status_code=400)
    user = db.get(User, identity.user_id)
    provider = db.get(OIDCProvider, identity.provider_id)
    request.session.pop("oidc_transaction", None)
    db.delete(transaction)
    db.commit()
    _audit_oidc(db, user, "oidc_identity_linked", request, provider)
    if not current:
        _start_session(request, db, user, method="oidc")
    return RedirectResponse("/profile?identity_linked=1", status_code=303)


@router.post("/profile/identity/link")
async def profile_identity_link(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    provider = active_provider(db)
    if not provider:
        return RedirectResponse("/profile?identity_error=unavailable", status_code=303)
    if provider.discovery_status != "ok":
        return RedirectResponse("/profile?identity_error=configuration_not_ready", status_code=303)
    if not provider.client_id or not provider.encrypted_client_secret:
        return RedirectResponse("/profile?identity_error=incomplete_provider", status_code=303)
    return await _begin(request, db, provider, flow_type="self_link", target_user_id=user.id, initiated_by_user_id=user.id, return_path="/profile")


@router.post("/profile/identity/unlink")
def profile_identity_unlink(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_user)):
    validate_csrf_token(request, csrf_token)
    identity = db.query(ExternalIdentity).filter_by(user_id=user.id).first()
    if not identity:
        return RedirectResponse("/profile", status_code=303)
    provider = db.get(OIDCProvider, identity.provider_id)
    try:
        unlink_identity(db, identity, user)
    except OIDCIdentityError as exc:
        return RedirectResponse(f"/profile?identity_error={exc.category}", status_code=303)
    _audit_oidc(db, user, "oidc_identity_unlinked", request, provider)
    return RedirectResponse("/profile?identity_unlinked=1", status_code=303)


@router.get("/auth/local")
def emergency_login_page(request: Request, db: Session = Depends(get_db)):
    if get_site_setting(db, "oidc_emergency_local_enabled") != "1":
        return RedirectResponse("/login", status_code=303)
    request.session.pop("pending_break_glass_user_id", None)
    return templates.TemplateResponse(request, "emergency_login.html", {"error": None, "requires_2fa": False, **csrf_context(request, include_version=False)})


@router.post("/auth/local")
def emergency_login_submit(request: Request, email: str = Form(""), password: str = Form(""), totp_code: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf_token(request, csrf_token)
    key = client_key(request)
    if get_site_setting(db, "oidc_emergency_local_enabled") != "1":
        write_audit(db, None, "break_glass_login_failed", "user", ip_address=request.client.host if request.client else None, detail="Emergency local login is disabled", severity="error", status_code=403)
        return RedirectResponse("/login", status_code=303)
    if login_is_limited(db, key, email.strip().lower()):
        write_audit(db, None, "break_glass_login_failed", "user", ip_address=request.client.host if request.client else None, detail="Emergency local login blocked by rate limit", severity="error", status_code=429)
        return templates.TemplateResponse(request, "emergency_login.html", {"error": "Invalid email, password, or authentication code.", "requires_2fa": False, **csrf_context(request, include_version=False)}, status_code=401)
    pending = request.session.get("pending_break_glass_user_id")
    user = (
        db.query(User).filter_by(id=pending, is_active=True, role="admin", is_break_glass=True).first()
        if pending
        else db.query(User).filter_by(email=email.strip().lower(), is_active=True, role="admin", is_break_glass=True).first()
    )
    valid = bool(user and user.password_hash and (pending or verify_password(password, user.password_hash)))
    if valid and user.totp_enabled and not pending:
        request.session["pending_break_glass_user_id"] = user.id
        return templates.TemplateResponse(request, "emergency_login.html", {"error": None, "requires_2fa": True, **csrf_context(request, include_version=False)})
    if valid and user.totp_enabled:
        valid = verify_totp(decrypted_totp_secret(user.totp_secret), totp_code)
    if not valid:
        record_login_failure(key)
        write_audit(db, user, "break_glass_login_failed", "user", str(user.id) if user else None, request.client.host if request.client else None, severity="error")
        return templates.TemplateResponse(request, "emergency_login.html", {"error": "Invalid email, password, or authentication code.", "requires_2fa": bool(pending), **csrf_context(request, include_version=False)}, status_code=401)
    _start_session(request, db, user, method="break_glass")
    write_audit(db, user, "break_glass_login_succeeded", "user", str(user.id), request.client.host if request.client else None, severity="error")
    return RedirectResponse(module_landing_url(db, user), status_code=303)


def _provider_status(db: Session, provider: OIDCProvider | None) -> dict:
    return {
        "linked_users": db.query(ExternalIdentity).count(),
        "oidc_only_users": db.query(User).filter_by(authentication_type="oidc").count(),
        "break_glass_admins": db.query(User).filter_by(role="admin", is_active=True, is_break_glass=True).count(),
        "secret_configured": bool(provider and provider.encrypted_client_secret),
    }


@router.get("/system/site-administration/authentication")
def authentication_admin(request: Request, tab: str = Query("general"), db: Session = Depends(get_db), user=Depends(require_admin)):
    provider = db.query(OIDCProvider).order_by(OIDCProvider.id.asc()).first()
    preview = request.session.pop("oidc_test_preview", None)
    invitation = request.session.pop("oidc_invitation_url", None)
    identities = db.query(ExternalIdentity).order_by(ExternalIdentity.created_at.desc()).all()
    readiness = oidc_only_readiness(db, user)
    emergency_url = f"{get_site_setting(db, 'base_url').rstrip('/')}/auth/local"
    return templates.TemplateResponse(request, "authentication_settings.html", {
        "user": user, "tab": tab if tab in {"general", "oidc", "mapping", "links"} else "general",
        "provider": provider, "auth_mode": get_site_setting(db, "authentication_mode"),
        "button_label": get_site_setting(db, "oidc_button_label"),
        "post_login_path": get_site_setting(db, "oidc_post_login_path"), "post_logout_path": get_site_setting(db, "oidc_post_logout_path"),
        "emergency_enabled": get_site_setting(db, "oidc_emergency_local_enabled") == "1",
        "auto_redirect": get_site_setting(db, "oidc_auto_redirect_required") == "1",
        "show_local_preferred": get_site_setting(db, "oidc_show_local_preferred") == "1",
        "callback_url": callback_url(db), "post_logout_url": post_logout_url(db), "status": _provider_status(db, provider),
        "identities": identities, "users": db.query(User).order_by(User.email).all(), "test_preview": preview,
        "invitation_url": invitation, "role_mappings": json.loads(provider.role_mappings_json or "[]") if provider else [],
        "oidc_readiness": readiness, "emergency_url": emergency_url,
        **csrf_context(request),
    })


@router.post("/system/site-administration/authentication/general")
def save_authentication_general(
    request: Request, authentication_mode: str = Form("local_only"), oidc_button_label: str = Form("Sign in with SSO", max_length=120),
    oidc_post_login_path: str = Form("/dashboard", max_length=500), oidc_post_logout_path: str = Form("/login", max_length=500),
    oidc_auto_redirect_required: str = Form(""), oidc_show_local_preferred: str = Form(""), oidc_emergency_local_enabled: str = Form(""),
    oidc_required_risk_acknowledged: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)
    mode = authentication_mode if authentication_mode in AUTHENTICATION_MODES else "local_only"
    provider = active_provider(db)
    if mode == "oidc_preferred" and oidc_show_local_preferred != "1" and not provider:
        write_audit(db, user, "oidc_readiness_validation_failed", "oidc", detail="OIDC preferred without local sign-in requires an enabled provider", severity="warning")
        return RedirectResponse("/system/site-administration/authentication?tab=general&error=provider_required", status_code=303)
    if mode == "oidc_required":
        readiness = oidc_only_readiness(db, user, emergency_enabled=oidc_emergency_local_enabled == "1")
        if not readiness["ready"] or oidc_required_risk_acknowledged != "1":
            write_audit(db, user, "oidc_readiness_validation_failed", "oidc", str(provider.id) if provider else None, detail="OIDC-only activation prerequisites were not met", severity="warning")
            return RedirectResponse("/system/site-administration/authentication?tab=general&error=required_safety", status_code=303)
    old_mode = get_site_setting(db, "authentication_mode")
    for key, value in {
        "authentication_mode": mode, "oidc_button_label": oidc_button_label.strip() or "Sign in with SSO",
        "oidc_post_login_path": safe_return_path(oidc_post_login_path), "oidc_post_logout_path": safe_return_path(oidc_post_logout_path, "/login"),
        "oidc_auto_redirect_required": "1" if oidc_auto_redirect_required == "1" else "",
        "oidc_show_local_preferred": (
            "1" if oidc_show_local_preferred == "1" else ""
        ) if mode == "oidc_preferred" else get_site_setting(db, "oidc_show_local_preferred"),
        "oidc_emergency_local_enabled": "1" if oidc_emergency_local_enabled == "1" else "",
        "oidc_required_risk_acknowledged": "1" if oidc_required_risk_acknowledged == "1" else "",
    }.items():
        _save_setting(db, key, value)
    db.commit()
    if old_mode != mode:
        write_audit(db, user, "authentication_mode_changed", "oidc", detail=f"Authentication mode changed from {old_mode} to {mode}", severity="warning" if mode == "oidc_required" else "info")
        if mode == "oidc_required":
            write_audit(db, user, "oidc_only_enabled", "oidc", detail="OIDC-only authentication enabled", severity="error")
        elif old_mode == "oidc_required":
            write_audit(db, user, "oidc_only_disabled", "oidc", detail=f"OIDC-only authentication changed to {mode}", severity="warning")
    return RedirectResponse("/system/site-administration/authentication?tab=general&saved=1", status_code=303)


@router.post("/system/site-administration/authentication/provider")
def save_oidc_provider(
    request: Request, name: str = Form("OpenID Connect", max_length=255), issuer: str = Form("", max_length=1000), client_id: str = Form("", max_length=500), client_secret: str = Form("", max_length=2000),
    scopes: str = Form("openid profile email", max_length=500), is_enabled: str = Form(""), verify_tls: str = Form(""), verify_tls_acknowledged: str = Form(""),
    timeout_seconds: int = Form(10), use_userinfo: str = Form(""), require_verified_email: str = Form(""), allow_jit_provisioning: str = Form(""), jit_acknowledged: str = Form(""),
    email_matching_mode: str = Form("disabled"), email_matching_acknowledged: str = Form(""), allowed_email_domains: str = Form("", max_length=4000), default_role: str = Form("viewer"),
    sync_roles_on_login: str = Form(""), role_sync_acknowledged: str = Form(""), update_names_on_login: str = Form(""), update_email_on_login: str = Form(""), end_session_on_logout: str = Form(""),
    csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)
    if verify_tls != "1" and verify_tls_acknowledged != "1":
        return RedirectResponse("/system/site-administration/authentication?tab=oidc&error=tls_ack", status_code=303)
    if allow_jit_provisioning == "1" and jit_acknowledged != "1":
        return RedirectResponse("/system/site-administration/authentication?tab=oidc&error=jit_ack", status_code=303)
    if email_matching_mode != "disabled" and email_matching_acknowledged != "1":
        return RedirectResponse("/system/site-administration/authentication?tab=oidc&error=email_ack", status_code=303)
    if sync_roles_on_login == "1" and role_sync_acknowledged != "1":
        return RedirectResponse("/system/site-administration/authentication?tab=oidc&error=role_ack", status_code=303)
    provider = db.query(OIDCProvider).order_by(OIDCProvider.id.asc()).first()
    created = provider is None
    if not provider:
        provider = OIDCProvider()
        db.add(provider)
    previous_security = None if created else (
        provider.issuer, provider.client_id, provider.encrypted_client_secret, provider.scopes,
        provider.is_enabled, provider.verify_tls, provider.use_userinfo, provider.require_verified_email,
        provider.email_matching_mode, provider.allowed_email_domains,
    )
    provider.name = name.strip() or "OpenID Connect"
    provider.issuer = issuer.strip()
    provider.client_id = client_id.strip()
    if client_secret:
        provider.encrypted_client_secret = encrypt_secret(client_secret)
    provider.scopes = " ".join(dict.fromkeys((scopes or "openid profile email").split()))
    if "openid" not in provider.scopes.split():
        provider.scopes = f"openid {provider.scopes}".strip()
    provider.is_enabled = is_enabled == "1"
    if provider.is_enabled:
        db.flush()
        db.query(OIDCProvider).filter(OIDCProvider.id != provider.id).update({OIDCProvider.is_enabled: False}, synchronize_session=False)
    provider.verify_tls = verify_tls == "1"
    provider.timeout_seconds = max(2, min(timeout_seconds, 30))
    provider.use_userinfo = use_userinfo == "1"
    provider.require_verified_email = require_verified_email == "1"
    provider.allow_jit_provisioning = allow_jit_provisioning == "1"
    provider.email_matching_mode = email_matching_mode if email_matching_mode in {"disabled", "confirmation", "automatic"} else "disabled"
    provider.allowed_email_domains = allowed_email_domains.strip() or None
    provider.default_role = default_role if default_role in {"viewer", "editor"} else "viewer"
    provider.sync_roles_on_login = sync_roles_on_login == "1"
    provider.update_names_on_login = update_names_on_login == "1"
    provider.update_email_on_login = update_email_on_login == "1"
    provider.end_session_on_logout = end_session_on_logout == "1"
    current_security = (
        provider.issuer, provider.client_id, provider.encrypted_client_secret, provider.scopes,
        provider.is_enabled, provider.verify_tls, provider.use_userinfo, provider.require_verified_email,
        provider.email_matching_mode, provider.allowed_email_domains,
    )
    security_changed = created or previous_security != current_security
    if security_changed and get_site_setting(db, "authentication_mode") == "oidc_required":
        db.rollback()
        return RedirectResponse("/system/site-administration/authentication?tab=oidc&error=disable_oidc_only_first", status_code=303)
    if security_changed:
        provider.discovery_status = None
        provider.discovery_error = None
        provider.metadata_json = None
        provider.metadata_fetched_at = None
        provider.test_login_succeeded_at = None
    db.commit()
    action = "oidc_configuration_created" if created else "oidc_configuration_updated"
    write_audit(db, user, action, "oidc", str(provider.id), detail=f"OIDC provider {provider.name} saved", severity="error" if not provider.verify_tls else "info")
    if security_changed and not created:
        write_audit(db, user, "oidc_provider_retest_required", "oidc", str(provider.id), detail="Security-sensitive provider configuration changed; discovery and real login must be retested", severity="warning")
    return RedirectResponse("/system/site-administration/authentication?tab=oidc&saved=1", status_code=303)


@router.post("/system/site-administration/authentication/provider/delete")
def delete_oidc_provider(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    provider = db.query(OIDCProvider).order_by(OIDCProvider.id.asc()).first()
    if not provider:
        return RedirectResponse("/system/site-administration/authentication?tab=oidc", status_code=303)
    if db.query(ExternalIdentity).filter_by(provider_id=provider.id).first():
        return RedirectResponse("/system/site-administration/authentication?tab=oidc&error=unlink_users_first", status_code=303)
    name = provider.name
    db.query(OIDCTransaction).filter_by(provider_id=provider.id).delete(synchronize_session=False)
    db.query(OIDCLinkInvitation).filter_by(provider_id=provider.id).delete(synchronize_session=False)
    db.delete(provider)
    _save_setting(db, "authentication_mode", "local_only")
    db.commit()
    write_audit(db, user, "oidc_configuration_disabled", "oidc", detail=f"Deleted OIDC provider {name}", severity="warning")
    return RedirectResponse("/system/site-administration/authentication?tab=oidc&deleted=1", status_code=303)


@router.post("/system/site-administration/authentication/provider/test")
async def test_oidc_provider(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    provider = db.query(OIDCProvider).order_by(OIDCProvider.id.asc()).first()
    if not provider or _rate_limited(f"oidc-test:{user.id}", limit=5):
        return RedirectResponse("/system/site-administration/authentication?tab=oidc&test=failed", status_code=303)
    try:
        await test_and_store_discovery(db, provider)
    except OIDCDiscoveryError:
        _audit_oidc(db, user, "oidc_configuration_test_failed", request, provider, category="discovery", severity="warning")
        return RedirectResponse("/system/site-administration/authentication?tab=oidc&test=failed", status_code=303)
    _audit_oidc(db, user, "oidc_configuration_test_succeeded", request, provider)
    return RedirectResponse("/system/site-administration/authentication?tab=oidc&test=success", status_code=303)


@router.post("/system/site-administration/authentication/provider/test-login")
async def test_oidc_login(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    provider = db.query(OIDCProvider).filter_by(discovery_status="ok").first()
    if not provider:
        return RedirectResponse("/system/site-administration/authentication?tab=oidc&error=test_first", status_code=303)
    return await _begin(request, db, provider, flow_type="test", initiated_by_user_id=user.id, return_path="/system/site-administration/authentication?tab=oidc")


@router.post("/system/site-administration/authentication/mapping")
def save_oidc_mapping(
    request: Request, email_claim: str = Form("email"), email_verified_claim: str = Form("email_verified"), name_claim: str = Form("name"),
    first_name_claim: str = Form("given_name"), last_name_claim: str = Form("family_name"), preferred_username_claim: str = Form("preferred_username"), group_claim: str = Form("groups"),
    role_mappings: str = Form(""), group_matching_case_sensitive: str = Form(""), csrf_token: str = Form(...), db: Session = Depends(get_db), user=Depends(require_admin),
):
    validate_csrf_token(request, csrf_token)
    provider = db.query(OIDCProvider).order_by(OIDCProvider.id.asc()).first()
    if not provider:
        return RedirectResponse("/system/site-administration/authentication?tab=mapping&error=no_provider", status_code=303)
    identity_fields = {"email_claim": email_claim, "email_verified_claim": email_verified_claim, "name_claim": name_claim, "first_name_claim": first_name_claim, "last_name_claim": last_name_claim, "preferred_username_claim": preferred_username_claim, "group_claim": group_claim}
    identity_resolution_changed = False
    for field, value in identity_fields.items():
        clean = value.strip()
        if not clean or any(part in {"iss", "sub"} for part in clean.split(".")):
            return RedirectResponse("/system/site-administration/authentication?tab=mapping&error=invalid_claim", status_code=303)
        clean = clean[:255]
        if field in {"email_claim", "email_verified_claim"} and getattr(provider, field) != clean:
            identity_resolution_changed = True
        setattr(provider, field, clean)
    mappings = []
    for line in role_mappings.splitlines():
        if not line.strip():
            continue
        group, separator, role = line.partition("=")
        if not separator or role.strip() not in {"viewer", "editor", "admin"}:
            return RedirectResponse("/system/site-administration/authentication?tab=mapping&error=invalid_mapping", status_code=303)
        mappings.append({"group": group.strip(), "role": role.strip()})
    provider.role_mappings_json = json.dumps(mappings, separators=(",", ":"))
    provider.group_matching_case_sensitive = group_matching_case_sensitive == "1"
    if identity_resolution_changed and get_site_setting(db, "authentication_mode") == "oidc_required":
        db.rollback()
        return RedirectResponse("/system/site-administration/authentication?tab=mapping&error=disable_oidc_only_first", status_code=303)
    if identity_resolution_changed:
        provider.discovery_status = None
        provider.discovery_error = None
        provider.test_login_succeeded_at = None
    db.commit()
    write_audit(db, user, "oidc_configuration_updated", "oidc", str(provider.id), detail="OIDC claim and role mappings updated")
    if identity_resolution_changed:
        write_audit(db, user, "oidc_provider_retest_required", "oidc", str(provider.id), detail="Identity-resolution claim mapping changed; discovery and real login must be retested", severity="warning")
    return RedirectResponse("/system/site-administration/authentication?tab=mapping&saved=1", status_code=303)


@router.post("/system/site-administration/authentication/links/invite")
def create_link_invitation(request: Request, user_id: int = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), admin=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    provider = active_provider(db)
    target = db.get(User, user_id)
    if not provider or not target or _rate_limited(f"oidc-invite:{admin.id}", limit=10):
        return RedirectResponse("/system/site-administration/authentication?tab=links&error=invite", status_code=303)
    db.query(OIDCLinkInvitation).filter_by(user_id=target.id, provider_id=provider.id, used_at=None).delete()
    raw = secrets.token_urlsafe(32)
    db.add(OIDCLinkInvitation(token_hash=hashlib.sha256(raw.encode()).hexdigest(), user_id=target.id, provider_id=provider.id, created_by_user_id=admin.id, expires_at=datetime.utcnow() + timedelta(minutes=30)))
    db.commit()
    request.session["oidc_invitation_url"] = f"{get_site_setting(db, 'base_url').rstrip('/')}/auth/oidc/link/invitation?token={raw}"
    return RedirectResponse("/system/site-administration/authentication?tab=links&invited=1", status_code=303)


@router.get("/auth/oidc/link/invitation")
async def accept_link_invitation(request: Request, token: str = Query(""), db: Session = Depends(get_db)):
    row = db.query(OIDCLinkInvitation).filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest(), used_at=None).first()
    if not row or row.expires_at < datetime.utcnow():
        return templates.TemplateResponse(request, "oidc_error.html", _oidc_error_context(request, db, "This account-link invitation is invalid or expired."), status_code=400)
    provider = db.get(OIDCProvider, row.provider_id)
    row.used_at = datetime.utcnow()
    db.commit()
    return await _begin(request, db, provider, flow_type="admin_link", target_user_id=row.user_id, initiated_by_user_id=row.created_by_user_id, return_path="/profile")


@router.post("/system/site-administration/authentication/links/{identity_id}/unlink")
def admin_unlink_identity(identity_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db), admin=Depends(require_admin)):
    validate_csrf_token(request, csrf_token)
    identity = db.get(ExternalIdentity, identity_id)
    if not identity:
        return RedirectResponse("/system/site-administration/authentication?tab=links", status_code=303)
    provider = db.get(OIDCProvider, identity.provider_id)
    try:
        target = unlink_identity(db, identity, admin)
    except OIDCIdentityError as exc:
        return RedirectResponse(f"/system/site-administration/authentication?tab=links&error={exc.category}", status_code=303)
    _audit_oidc(db, admin, "oidc_identity_unlinked", request, provider, detail=f"Unlinked identity from user {target.id}")
    return RedirectResponse("/system/site-administration/authentication?tab=links&unlinked=1", status_code=303)
