from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import uuid
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import quote_from_bytes, unquote_to_bytes

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from fastapi import HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.models import (
    BackupAgentBootstrap,
    BackupAgentIdentity,
    BackupAgentKey,
    BackupAgentMigrationWindow,
    BackupAgentRequest,
    BackupAgentServerKey,
    ComputeHost,
)

PROTOCOL = "2"
MAX_BODY = 256 * 1024
MAX_SKEW_SECONDS = 300
RATE_LIMIT_PER_MINUTE = 120
BOOTSTRAP_TTL = timedelta(minutes=15)
GRANT_TTL = timedelta(minutes=15)
SERVER_KEY_CONTEXT = b"kaya:backup-agent:dispatch-signing-key:v1"
ALL_SCOPES = ["inventory:write", "backup:poll", "backup:claim", "backup:status"]
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{7,63}$")


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    if not value or "=" in value:
        raise ValueError("invalid unpadded base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json(value: object) -> bytes:
    # Protocol objects are restricted to strings, integers, booleans, null, arrays and maps.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def canonical_query(raw_query: str) -> str:
    if not raw_query:
        return ""
    pairs = []
    for item in raw_query.split("&"):
        if not item:
            raise ValueError("blank query pair")
        key, separator, value = item.partition("=")
        if not key:
            raise ValueError("blank query key")
        pairs.append((_canonical_component(key, allow_slash=False), _canonical_component(value if separator else "", allow_slash=False)))
    encoded = pairs
    encoded.sort()
    return "&".join(f"{key}={value}" for key, value in encoded)


def _canonical_component(value: str, *, allow_slash: bool) -> str:
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("invalid percent escape")
    if "\\" in value or "\x00" in value:
        raise ValueError("invalid path character")
    raw = unquote_to_bytes(value)
    if not allow_slash and b"/" in raw:
        pass
    if b"\\" in raw or b"\x00" in raw or (allow_slash and b"/" in raw):
        raise ValueError("invalid encoded delimiter")
    try:
        normalized = unicodedata.normalize("NFC", raw.decode("utf-8")).encode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8") from exc
    return quote_from_bytes(normalized, safe="~-._")


def canonical_path(raw_path: str) -> str:
    if not raw_path.startswith("/") or len(raw_path.encode("ascii")) > 2048:
        raise ValueError("invalid path")
    segments = raw_path.split("/")
    if any(segment == "" for segment in segments[1:-1]):
        raise ValueError("empty path segment")
    result = []
    for segment in segments[1:]:
        canonical = _canonical_component(segment, allow_slash=True)
        decoded = unquote_to_bytes(canonical).decode("utf-8")
        if decoded in {".", ".."}:
            raise ValueError("dot path segment")
        result.append(canonical)
    return "/" + "/".join(result)


def canonical_request(method: str, path: str, raw_query: str, agent_id: str, key_id: str, request_id: str, timestamp: int, body: bytes) -> bytes:
    lines = (
        "KAYA-AGENT-V2", method.upper(), canonical_path(path), canonical_query(raw_query), agent_id,
        key_id, request_id, str(timestamp), hashlib.sha256(body).hexdigest(),
    )
    return "\n".join(lines).encode("utf-8")


def _uuid4(value: str) -> bool:
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return parsed.version == 4 and str(parsed) == value


def _single_header(request: Request, name: str) -> str:
    values = [v.decode("latin-1") for k, v in request.scope.get("headers", []) if k.decode("latin-1").lower() == name.lower()]
    if len(values) != 1 or not values[0]:
        raise HTTPException(400, f"Exactly one {name} header is required")
    return values[0]


@dataclass(frozen=True)
class AuthenticatedAgent:
    identity: BackupAgentIdentity
    key: BackupAgentKey
    request_id: str


async def authenticate_request(request: Request, db: Session, required_scope: str, *, read_only: bool = False) -> tuple[AuthenticatedAgent, bytes]:
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "Request body too large")
    protocol = _single_header(request, "x-kaya-agent-protocol")
    agent_id = _single_header(request, "x-kaya-agent-id")
    key_id = _single_header(request, "x-kaya-agent-key-id")
    timestamp_text = _single_header(request, "x-kaya-agent-timestamp")
    request_id = _single_header(request, "x-kaya-agent-request-id")
    signature_text = _single_header(request, "x-kaya-agent-signature")
    if protocol != PROTOCOL or not _uuid4(request_id) or not IDENTIFIER_RE.fullmatch(agent_id) or not IDENTIFIER_RE.fullmatch(key_id) or not timestamp_text.isascii() or not timestamp_text.isdecimal():
        raise HTTPException(400, "Invalid protocol metadata")
    try:
        timestamp = int(timestamp_text)
    except ValueError as exc:
        raise HTTPException(400, "Invalid timestamp") from exc
    if abs(int(datetime.utcnow().timestamp()) - timestamp) > MAX_SKEW_SECONDS:
        raise HTTPException(401, "Request timestamp outside allowed skew")
    identity = db.get(BackupAgentIdentity, agent_id)
    key = db.query(BackupAgentKey).filter_by(key_id=key_id, identity_id=agent_id, status="active").first()
    if not identity or identity.state not in {"active", "rotation_pending"} or not key:
        raise HTTPException(401, "Agent authentication failed")
    host = db.get(ComputeHost, identity.host_id)
    if not host or not host.is_enabled:
        raise HTTPException(403, "Agent host is disabled")
    try:
        scopes = json.loads(identity.scopes_json)
    except (TypeError, json.JSONDecodeError):
        scopes = []
    if required_scope not in scopes:
        raise HTTPException(403, "Agent scope denied")
    raw_path = request.scope.get("raw_path", request.url.path.encode("ascii")).decode("ascii")
    raw_query = request.scope.get("query_string", b"").decode("ascii")
    try:
        if canonical_path(raw_path) != raw_path:
            raise ValueError("non-canonical path")
        recent = db.query(BackupAgentRequest).filter(BackupAgentRequest.identity_id == identity.id, BackupAgentRequest.received_at >= datetime.utcnow() - timedelta(minutes=1)).count()
        if recent >= RATE_LIMIT_PER_MINUTE:
            raise HTTPException(429, "Agent request rate exceeded")
        signed = canonical_request(request.method, raw_path, raw_query, agent_id, key_id, request_id, timestamp, body)
        signature = b64u_decode(signature_text)
        if len(signature) != 64:
            raise ValueError("invalid signature length")
        Ed25519PublicKey.from_public_bytes(b64u_decode(key.signing_public_key)).verify(signature, signed)
    except (InvalidSignature, ValueError, UnicodeError) as exc:
        raise HTTPException(401, "Agent authentication failed") from exc
    db.add(BackupAgentRequest(identity_id=identity.id, request_id=request_id))
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Request replay detected") from exc
    if read_only:
        db.commit()
    return AuthenticatedAgent(identity, key, request_id), body


def issue_bootstrap(db: Session, host_id: int, created_by_id: int | None) -> str:
    now = datetime.utcnow()
    db.query(BackupAgentBootstrap).filter_by(host_id=host_id, used_at=None).update({"used_at": now})
    token = secrets.token_urlsafe(32)
    db.add(BackupAgentBootstrap(host_id=host_id, token_hash=hashlib.sha256(token.encode()).hexdigest(), expires_at=now + BOOTSTRAP_TTL, created_by_id=created_by_id))
    return token


def allow_legacy_inventory(db: Session) -> bool:
    now = datetime.utcnow()
    window = db.get(BackupAgentMigrationWindow, 1)
    if not window:
        window = BackupAgentMigrationWindow(id=1, started_at=now, cutoff_at=now + timedelta(days=14))
        db.add(window)
        db.flush()
    if now < window.cutoff_at:
        return True
    if window.legacy_hashes_cleared_at is None:
        from app.models.models import ComputeHost
        db.query(ComputeHost).filter(ComputeHost.agent_token_hash.is_not(None)).update({"agent_token_hash": None}, synchronize_session=False)
        window.legacy_hashes_cleared_at = now
        db.commit()
    return False


def register_identity(db: Session, token: str, signing_public_key: str, envelope_public_key: str) -> tuple[BackupAgentIdentity, BackupAgentKey]:
    now = datetime.utcnow()
    row = db.query(BackupAgentBootstrap).filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest(), used_at=None).first()
    if not row or row.expires_at < now:
        raise HTTPException(401, "Invalid or expired bootstrap token")
    try:
        if len(b64u_decode(signing_public_key)) != 32 or len(b64u_decode(envelope_public_key)) != 32:
            raise ValueError
    except ValueError as exc:
        raise HTTPException(400, "Invalid agent public key") from exc
    if db.query(BackupAgentIdentity).filter_by(host_id=row.host_id).first():
        raise HTTPException(409, "Host already enrolled")
    if db.query(BackupAgentKey).filter_by(signing_public_key=signing_public_key).first() or db.query(BackupAgentIdentity).filter_by(envelope_public_key=envelope_public_key).first():
        raise HTTPException(409, "Agent public key has already been enrolled")
    identity = BackupAgentIdentity(host_id=row.host_id, state="active", scopes_json=json.dumps(ALL_SCOPES), envelope_public_key=envelope_public_key, activated_at=now)
    db.add(identity)
    db.flush()
    key = BackupAgentKey(identity_id=identity.id, key_id=str(uuid.uuid4()), signing_public_key=signing_public_key, status="active")
    db.add(key)
    row.used_at = now
    return identity, key


def consume_rotation_bootstrap(db: Session, host_id: int, token: str) -> None:
    now = datetime.utcnow()
    row = db.query(BackupAgentBootstrap).filter_by(host_id=host_id, token_hash=hashlib.sha256(token.encode()).hexdigest(), used_at=None).first()
    if not row or row.expires_at < now:
        raise HTTPException(401, "Invalid or expired rotation bootstrap")
    row.used_at = now


def _wrapping_key() -> bytes:
    raw = base64.urlsafe_b64decode(get_settings().encryption_key.encode("ascii"))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=SERVER_KEY_CONTEXT).derive(raw)


def create_server_signing_key(db: Session) -> BackupAgentServerKey:
    if db.query(BackupAgentServerKey).filter_by(status="active").first():
        raise ValueError("an active server signing key already exists")
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    nonce = os.urandom(12)
    wrapped = b64u(nonce + AESGCM(_wrapping_key()).encrypt(nonce, raw_private, SERVER_KEY_CONTEXT))
    public = b64u(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    row = BackupAgentServerKey(key_id=str(uuid.uuid4()), public_key=public, wrapped_private_key=wrapped, status="active")
    db.add(row)
    db.flush()
    return row


def _load_server_private(row: BackupAgentServerKey) -> Ed25519PrivateKey:
    wrapped = b64u_decode(row.wrapped_private_key)
    raw = AESGCM(_wrapping_key()).decrypt(wrapped[:12], wrapped[12:], SERVER_KEY_CONTEXT)
    return Ed25519PrivateKey.from_private_bytes(raw)


def seal_dispatch(*, identity: BackupAgentIdentity, server_key: BackupAgentServerKey, aad: dict, plaintext: dict, ephemeral_private: X25519PrivateKey | None = None, salt: bytes | None = None, nonce: bytes | None = None, server_private: Ed25519PrivateKey | None = None) -> dict:
    aad_bytes = canonical_json(aad)
    plaintext_bytes = canonical_json(plaintext)
    if len(plaintext_bytes) > 64 * 1024:
        raise ValueError("dispatch payload too large")
    ephemeral = ephemeral_private or X25519PrivateKey.generate()
    salt = salt or os.urandom(32)
    nonce = nonce or os.urandom(12)
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(b64u_decode(identity.envelope_public_key)))
    info_fields = ["kaya:backup-agent:envelope:v2", aad["agent_id"], aad["agent_encryption_key_id"], aad["host_id"], aad["job_id"], aad["dispatch_id"], aad["claim_id"], aad["operation"], aad["expires_at"], aad["manifest_sha256"]]
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info="\n".join(info_fields).encode()).derive(shared)
    outer = {
        "aad": b64u(aad_bytes), "algorithm": "X25519-HKDF-SHA256+A256GCM",
        "ciphertext": b64u(AESGCM(key).encrypt(nonce, plaintext_bytes, aad_bytes)),
        "ephemeral_public_key": b64u(ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "hkdf_salt": b64u(salt), "nonce": b64u(nonce), "server_signing_key_id": server_key.key_id, "version": 2,
    }
    outer["server_signature"] = b64u((server_private or _load_server_private(server_key)).sign(canonical_json(outer)))
    if len(canonical_json(outer)) > 96 * 1024:
        raise ValueError("dispatch envelope too large")
    return outer
