from __future__ import annotations

import base64
from datetime import datetime, timedelta
import hashlib
import json
import secrets
from urllib.parse import urlencode

from authlib.jose import JoseError, JsonWebToken
from authlib.oidc.core import CodeIDToken
import httpx
from sqlalchemy.orm import Session

from app.core.security import decrypt_secret, encrypt_secret
from app.models.models import OIDCProvider, OIDCTransaction
from app.services.oidc_discovery import MAX_METADATA_BYTES, OIDCDiscoveryError, provider_metadata, validate_outbound_url, validate_outbound_url_async


ALLOWED_ID_TOKEN_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
TRANSACTION_TTL_MINUTES = 10
JWKS_CACHE: dict[int, tuple[datetime, dict]] = {}


class OIDCFlowError(RuntimeError):
    def __init__(self, category: str, message: str = "Single sign-on could not be completed."):
        super().__init__(message)
        self.category = category


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def safe_return_path(value: str | None, fallback: str = "/dashboard") -> str:
    clean = str(value or "").strip()
    if not clean.startswith("/") or clean.startswith("//") or "://" in clean or "\\" in clean:
        return fallback
    return clean[:500]


def _pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def create_transaction(
    db: Session,
    provider: OIDCProvider,
    *,
    flow_type: str = "login",
    target_user_id: int | None = None,
    initiated_by_user_id: int | None = None,
    return_path: str = "/dashboard",
) -> tuple[OIDCTransaction, str, str, str, str]:
    opaque = secrets.token_urlsafe(32)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    now = datetime.utcnow()
    db.query(OIDCTransaction).filter(OIDCTransaction.expires_at < now).delete(synchronize_session=False)
    row = OIDCTransaction(
        transaction_hash=_hash(opaque),
        state_hash=_hash(state),
        encrypted_nonce=encrypt_secret(nonce),
        encrypted_code_verifier=encrypt_secret(verifier),
        provider_id=provider.id,
        flow_type=flow_type,
        target_user_id=target_user_id,
        initiated_by_user_id=initiated_by_user_id,
        return_path=safe_return_path(return_path),
        created_at=now,
        expires_at=now + timedelta(minutes=TRANSACTION_TTL_MINUTES),
    )
    db.add(row)
    db.commit()
    return row, opaque, state, nonce, verifier


async def authorization_redirect(
    db: Session,
    provider: OIDCProvider,
    *,
    callback_url: str,
    flow_type: str = "login",
    target_user_id: int | None = None,
    initiated_by_user_id: int | None = None,
    return_path: str = "/dashboard",
    authorization_params: dict[str, str] | None = None,
) -> tuple[str, str]:
    metadata = await provider_metadata(db, provider)
    _, opaque, state, nonce, verifier = create_transaction(
        db,
        provider,
        flow_type=flow_type,
        target_user_id=target_user_id,
        initiated_by_user_id=initiated_by_user_id,
        return_path=return_path,
    )
    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": callback_url,
        "scope": provider.scopes or "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": _pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    if authorization_params:
        # Callers may request provider re-authentication or a configured ACR,
        # but protocol/security parameters remain owned by this client.
        for key in ("prompt", "max_age", "acr_values"):
            value = str(authorization_params.get(key) or "").strip()
            if value:
                params[key] = value
    endpoint = await validate_outbound_url_async(metadata["authorization_endpoint"], timeout=min(provider.timeout_seconds, 5))
    return f"{endpoint}{'&' if '?' in endpoint else '?'}{urlencode(params)}", opaque


def consume_transaction(db: Session, opaque: str | None, state: str | None) -> OIDCTransaction:
    if not opaque or not state:
        raise OIDCFlowError("invalid_state", "The sign-in request expired. Please try again.")
    row = db.query(OIDCTransaction).filter_by(transaction_hash=_hash(opaque), state_hash=_hash(state)).first()
    now = datetime.utcnow()
    if not row or row.used_at is not None or row.expires_at < now:
        raise OIDCFlowError("invalid_state", "The sign-in request expired. Please try again.")
    row.used_at = now
    db.commit()
    return row


async def _json_get(url: str, provider: OIDCProvider, *, bearer: str | None = None) -> dict:
    headers = {"Accept": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    try:
        async with httpx.AsyncClient(verify=bool(provider.verify_tls), timeout=max(2, min(provider.timeout_seconds, 30)), follow_redirects=False) as client:
            response = await client.get(await validate_outbound_url_async(url, timeout=min(provider.timeout_seconds, 5)), headers=headers)
            response.raise_for_status()
    except (httpx.HTTPError, OIDCDiscoveryError) as exc:
        raise OIDCFlowError("provider_unavailable") from exc
    if len(response.content) > MAX_METADATA_BYTES:
        raise OIDCFlowError("provider_response_too_large")
    try:
        value = response.json()
    except ValueError as exc:
        raise OIDCFlowError("invalid_provider_json") from exc
    if not isinstance(value, dict):
        raise OIDCFlowError("invalid_provider_json")
    return value


async def _provider_jwks(provider: OIDCProvider, metadata: dict, *, force: bool = False) -> dict:
    cached = JWKS_CACHE.get(provider.id)
    if not force and cached and datetime.utcnow() - cached[0] < timedelta(minutes=15):
        return cached[1]
    value = await _json_get(metadata["jwks_uri"], provider)
    if not isinstance(value.get("keys"), list):
        raise OIDCFlowError("invalid_jwks")
    JWKS_CACHE[provider.id] = (datetime.utcnow(), value)
    return value


async def exchange_and_validate(
    db: Session,
    provider: OIDCProvider,
    transaction: OIDCTransaction,
    *,
    code: str,
    callback_url: str,
) -> tuple[dict, str]:
    metadata = await provider_metadata(db, provider)
    secret = decrypt_secret(provider.encrypted_client_secret)
    if not secret or secret == "[decryption failed]":
        raise OIDCFlowError("client_secret_unavailable")
    verifier = decrypt_secret(transaction.encrypted_code_verifier)
    nonce = decrypt_secret(transaction.encrypted_nonce)
    advertised_methods = metadata.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    method = "client_secret_basic" if "client_secret_basic" in advertised_methods else "client_secret_post"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": callback_url,
        "client_id": provider.client_id,
        "code_verifier": verifier,
    }
    auth = None
    if method == "client_secret_post":
        data["client_secret"] = secret
    else:
        auth = httpx.BasicAuth(provider.client_id, secret)
    try:
        async with httpx.AsyncClient(verify=bool(provider.verify_tls), timeout=max(2, min(provider.timeout_seconds, 30)), follow_redirects=False) as client:
            endpoint = await validate_outbound_url_async(metadata["token_endpoint"], timeout=min(provider.timeout_seconds, 5))
            response = await client.post(endpoint, data=data, auth=auth, headers={"Accept": "application/json"})
            response.raise_for_status()
    except (httpx.HTTPError, OIDCDiscoveryError) as exc:
        raise OIDCFlowError("token_exchange_failed") from exc
    if len(response.content) > MAX_METADATA_BYTES:
        raise OIDCFlowError("token_response_too_large")
    try:
        token = response.json()
    except ValueError as exc:
        raise OIDCFlowError("invalid_token_response") from exc
    id_token = token.get("id_token") if isinstance(token, dict) else None
    if not id_token:
        raise OIDCFlowError("missing_id_token")
    jwks = await _provider_jwks(provider, metadata)
    try:
        merged = validate_id_token(id_token, jwks, metadata, provider, nonce=nonce, access_token=token.get("access_token"))
    except OIDCFlowError:
        # A provider may rotate signing keys between cache refreshes. Refresh
        # once and retry; all other validation failures remain fatal.
        jwks = await _provider_jwks(provider, metadata, force=True)
        merged = validate_id_token(id_token, jwks, metadata, provider, nonce=nonce, access_token=token.get("access_token"))
    if provider.use_userinfo and metadata.get("userinfo_endpoint") and token.get("access_token"):
        userinfo = await _json_get(metadata["userinfo_endpoint"], provider, bearer=token["access_token"])
        if userinfo.get("sub") != merged.get("sub"):
            raise OIDCFlowError("userinfo_subject_mismatch")
        merged.update(userinfo)
        merged["iss"] = str(metadata.get("issuer") or provider.issuer)
        merged["sub"] = str(merged.get("sub") or "")
    logout_hint = id_token
    token.clear()
    return merged, logout_hint


def validate_id_token(id_token: str, jwks: dict, metadata: dict, provider: OIDCProvider, *, nonce: str, access_token: str | None = None) -> dict:
    algorithms = set(metadata.get("id_token_signing_alg_values_supported") or ALLOWED_ID_TOKEN_ALGORITHMS)
    allowed = tuple(algorithm for algorithm in ALLOWED_ID_TOKEN_ALGORITHMS if algorithm in algorithms)
    if not allowed:
        raise OIDCFlowError("unsupported_signing_algorithm")
    claims_options = {
        "iss": {"essential": True, "value": str(metadata.get("issuer") or provider.issuer)},
        "aud": {"essential": True, "value": provider.client_id},
        "sub": {"essential": True},
        "exp": {"essential": True},
        "iat": {"essential": True},
        "nonce": {"essential": True, "value": nonce},
    }
    try:
        claims = JsonWebToken(allowed).decode(
            id_token,
            jwks,
            claims_cls=CodeIDToken,
            claims_options=claims_options,
            claims_params={"nonce": nonce, "client_id": provider.client_id, "access_token": access_token},
        )
        claims.validate(leeway=60)
    except (JoseError, ValueError, TypeError) as exc:
        raise OIDCFlowError("invalid_id_token") from exc
    return dict(claims)


def claims_preview(claims: dict, provider: OIDCProvider) -> dict:
    from app.services.oidc_role_mapping import claim_bool, claim_groups, claim_text, initial_role, normalise_email

    groups = claim_groups(claims, provider.group_claim)
    subject = str(claims.get("sub") or "")
    return {
        "issuer": str(claims.get("iss") or ""),
        "subject": f"{subject[:6]}...{subject[-4:]}" if len(subject) > 12 else "masked",
        "email": normalise_email(claim_text(claims, provider.email_claim)),
        "email_verified": claim_bool(claims, provider.email_verified_claim),
        "name": claim_text(claims, provider.name_claim),
        "first_name": claim_text(claims, provider.first_name_claim),
        "last_name": claim_text(claims, provider.last_name_claim),
        "preferred_username": claim_text(claims, provider.preferred_username_claim),
        "groups": groups,
        "resolved_role": initial_role(provider, groups),
    }


def provider_logout_redirect(db: Session, id_token_hint: str | None = None) -> str | None:
    from app.services.site_settings import get_site_setting

    provider = db.query(OIDCProvider).filter_by(is_enabled=True, end_session_on_logout=True).first()
    if not provider or not provider.metadata_json:
        return None
    try:
        metadata = json.loads(provider.metadata_json)
        endpoint = validate_outbound_url(metadata.get("end_session_endpoint"))
    except (TypeError, ValueError, OIDCDiscoveryError):
        return None
    redirect_uri = f"{get_site_setting(db, 'base_url').rstrip('/')}{safe_return_path(get_site_setting(db, 'oidc_post_logout_path'), '/login')}"
    params = {"client_id": provider.client_id, "post_logout_redirect_uri": redirect_uri}
    if id_token_hint:
        params["id_token_hint"] = id_token_hint
    return f"{endpoint}?{urlencode(params)}"
