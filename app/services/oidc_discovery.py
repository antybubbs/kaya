from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
import ipaddress
import json
import socket
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from app.models.models import OIDCProvider


MAX_METADATA_BYTES = 1024 * 1024
BLOCKED_HOSTS = {"metadata.google.internal", "metadata.azure.internal"}
BLOCKED_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("fd00:ec2::254")}


class OIDCDiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class DiscoveryResult:
    metadata: dict
    checks: dict[str, str]


def normalise_issuer(value: str) -> str:
    clean = (value or "").strip().rstrip("/")
    parsed = urlsplit(clean)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise OIDCDiscoveryError("Enter a valid issuer URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OIDCDiscoveryError("Issuer URLs cannot contain credentials, a query, or a fragment.")
    localhost = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not localhost:
        raise OIDCDiscoveryError("The issuer must use HTTPS. HTTP is only supported for localhost development.")
    if parsed.hostname.lower() in BLOCKED_HOSTS:
        raise OIDCDiscoveryError("Cloud metadata endpoints cannot be used as an issuer.")
    try:
        literal = ipaddress.ip_address(parsed.hostname)
        if literal in BLOCKED_IPS or literal.is_link_local:
            raise OIDCDiscoveryError("Link-local and cloud metadata addresses cannot be used as an issuer.")
    except ValueError:
        pass
    return clean


def _validate_resolved_host(hostname: str) -> None:
    try:
        addresses = {ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(hostname, None)}
    except OSError as exc:
        raise OIDCDiscoveryError("The issuer hostname could not be resolved.") from exc
    if any(address in BLOCKED_IPS or address.is_link_local for address in addresses):
        raise OIDCDiscoveryError("The issuer resolves to a blocked metadata or link-local address.")


def validate_outbound_url(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise OIDCDiscoveryError("The provider advertised an invalid endpoint URL.")
    if parsed.scheme != "https" and parsed.hostname.lower() not in {"localhost", "127.0.0.1", "::1"}:
        raise OIDCDiscoveryError("Provider endpoints must use HTTPS outside localhost development.")
    _validate_resolved_host(parsed.hostname)
    return parsed.geturl()


async def validate_outbound_url_async(value: str, *, timeout: float = 5.0) -> str:
    """Validate provider DNS without blocking the application's event loop."""
    try:
        return await asyncio.wait_for(asyncio.to_thread(validate_outbound_url, value), timeout=max(1.0, timeout))
    except TimeoutError as exc:
        raise OIDCDiscoveryError("The provider endpoint hostname lookup timed out.") from exc


def validate_metadata(expected_issuer: str, metadata: dict) -> dict[str, str]:
    if not isinstance(metadata, dict):
        raise OIDCDiscoveryError("The discovery response is not a JSON object.")
    discovered = normalise_issuer(str(metadata.get("issuer") or ""))
    if discovered != expected_issuer:
        raise OIDCDiscoveryError("The issuer returned by discovery does not match the configured issuer.")
    checks = {"discovery": "ok", "issuer": "ok", "tls": "ok" if expected_issuer.startswith("https://") else "development-only"}
    for field, label in (("authorization_endpoint", "authorization"), ("token_endpoint", "token"), ("jwks_uri", "signing_keys")):
        if not metadata.get(field):
            raise OIDCDiscoveryError(f"Discovery metadata is missing {field}.")
        validate_outbound_url(str(metadata[field]))
        checks[label] = "ok"
    response_types = metadata.get("response_types_supported") or []
    if response_types and "code" not in response_types:
        raise OIDCDiscoveryError("The provider does not advertise Authorization Code flow support.")
    pkce = metadata.get("code_challenge_methods_supported") or []
    if pkce and "S256" not in pkce:
        raise OIDCDiscoveryError("The provider does not advertise PKCE S256 support.")
    checks["pkce"] = "ok" if "S256" in pkce else "not_advertised"
    algorithms = set(metadata.get("id_token_signing_alg_values_supported") or [])
    if algorithms and not algorithms.intersection({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}):
        raise OIDCDiscoveryError("The provider does not advertise a supported asymmetric ID-token signing algorithm.")
    auth_methods = set(metadata.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"])
    if not auth_methods.intersection({"client_secret_basic", "client_secret_post"}):
        raise OIDCDiscoveryError("The provider does not advertise a supported token endpoint authentication method.")
    checks["userinfo"] = "available" if metadata.get("userinfo_endpoint") else "unavailable"
    checks["logout"] = "available" if metadata.get("end_session_endpoint") else "unavailable"
    return checks


async def discover(provider: OIDCProvider) -> DiscoveryResult:
    issuer = normalise_issuer(provider.issuer)
    _validate_resolved_host(urlsplit(issuer).hostname or "")
    url = f"{issuer}/.well-known/openid-configuration"
    timeout = max(2, min(int(provider.timeout_seconds or 10), 30))
    try:
        async with httpx.AsyncClient(verify=bool(provider.verify_tls), timeout=timeout, follow_redirects=False) as client:
            response = await client.get(url, headers={"Accept": "application/json"})
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        raise OIDCDiscoveryError("The discovery request timed out.") from exc
    except httpx.HTTPError as exc:
        raise OIDCDiscoveryError("The discovery document could not be retrieved.") from exc
    if len(response.content) > MAX_METADATA_BYTES:
        raise OIDCDiscoveryError("The discovery response is too large.")
    try:
        metadata = response.json()
    except ValueError as exc:
        raise OIDCDiscoveryError("The discovery response is not valid JSON.") from exc
    checks = validate_metadata(issuer, metadata)
    advertised_scopes = set(metadata.get("scopes_supported") or [])
    required_scopes = {scope for scope in (provider.scopes or "openid profile email").split() if scope in {"openid", "profile", "email"}}
    if advertised_scopes and not required_scopes.issubset(advertised_scopes):
        raise OIDCDiscoveryError("The provider does not advertise all required OIDC scopes.")
    try:
        async with httpx.AsyncClient(verify=bool(provider.verify_tls), timeout=timeout, follow_redirects=False) as client:
            jwks_response = await client.get(validate_outbound_url(metadata["jwks_uri"]), headers={"Accept": "application/json"})
            jwks_response.raise_for_status()
        if len(jwks_response.content) > MAX_METADATA_BYTES or not isinstance(jwks_response.json().get("keys"), list):
            raise OIDCDiscoveryError("The provider signing-key response is invalid.")
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        raise OIDCDiscoveryError("The provider signing keys could not be retrieved.") from exc
    checks["signing_keys"] = "ok"
    return DiscoveryResult(metadata=metadata, checks=checks)


async def test_and_store_discovery(db: Session, provider: OIDCProvider) -> DiscoveryResult:
    provider.last_tested_at = datetime.utcnow()
    try:
        result = await discover(provider)
    except OIDCDiscoveryError as exc:
        provider.discovery_status = "failed"
        provider.discovery_error = str(exc)[:500]
        db.commit()
        raise
    provider.issuer = str(result.metadata["issuer"])
    provider.discovery_status = "ok"
    provider.discovery_error = None
    provider.metadata_json = json.dumps(result.metadata, separators=(",", ":"))
    provider.metadata_fetched_at = datetime.utcnow()
    db.commit()
    return result


async def provider_metadata(db: Session, provider: OIDCProvider, *, force: bool = False) -> dict:
    fresh = provider.metadata_fetched_at and datetime.utcnow() - provider.metadata_fetched_at < timedelta(hours=24)
    if not force and fresh and provider.discovery_status == "ok" and provider.metadata_json:
        try:
            return json.loads(provider.metadata_json)
        except (TypeError, ValueError):
            pass
    return (await test_and_store_discovery(db, provider)).metadata
