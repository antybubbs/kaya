# Backup Agent Protocol v2 - Review Draft

**Status:** Design checkpoint only; not implemented
**Finding:** `KAYA-BAK-001`
**ADR:** `ADR-0004`

This document defines the proposed wire contract and verification plan. It is deliberately non-operational until a human security reviewer accepts the open decisions in ADR-0004.

## Trust boundaries and assets

The protocol crosses the administrator-to-Kaya enrollment boundary, agent-to-Kaya HTTPS boundary, TLS-terminating proxy boundary, Kaya database/encryption boundary, backup target boundary and local agent process boundary.

Protected assets are machine identity, authorization scopes, storage credentials, backup data keys, restore artifact locations, job ownership/state, replay records, bootstrap tokens, dispatch grants and server signing keys.

TLS verification remains mandatory. Signed requests provide application-layer identity and replay resistance. The X25519 envelope keeps secret-bearing payloads confidential from intermediaries that terminate TLS. The server envelope signature lets the agent authenticate the dispatch independently of such intermediaries.

## Proposed resources

| Resource | Purpose | Required constraints |
|---|---|---|
| `AgentIdentity` | Host-bound logical agent and lifecycle | Unique host and agent ID; state; protocol; enabled host required |
| `AgentKey` | Versioned Ed25519/X25519 public keys | Unique key IDs; activation/retirement; no private agent keys |
| `AgentBootstrap` | Single-use enrollment | Token hash only; host/scopes/admin/15-minute expiry/used time |
| `AgentRequest` | Durable replay and rate record | Unique identity + request ID; timestamp; outcome/reason only |
| `BackupDispatch` | Offer/claim/grant/envelope state | Unique job offer; identity/claim binding; grant hash; expiry; ciphertext |
| `AgentServerSigningKey` | Authentic server dispatch envelopes | Encrypted private key; public key ID; activation/retirement |

Existing `ComputeHost.agent_token_hash` becomes legacy inventory-only state during migration. Existing `BackupJob.encrypted_backup_key` remains encrypted under Kaya's application key until the minimal value is placed inside an agent-specific envelope.

## Canonical request

All v2 endpoints reject bodies over 256 KiB, unsupported content types, missing headers, unknown key IDs, disabled/revoked/decommissioned identities, wrong scopes and clock skew outside 300 seconds.

The UTF-8 bytes signed by the agent are:

```text
KAYA-AGENT-V2
<UPPERCASE_METHOD>
<NORMALIZED_PATH>
<CANONICAL_QUERY_OR_EMPTY>
<AGENT_ID>
<KEY_ID>
<REQUEST_ID>
<UNIX_TIMESTAMP>
<LOWERCASE_SHA256_BODY_HEX>
```

The normalized path is the exact ASGI path after trusted deployment root-path handling and before routing parameters are decoded into objects. V2 endpoints should avoid query parameters. If a query is later required, keys and values are percent-encoded with RFC 3986 unreserved rules, sorted by encoded key then value, and repeated values are retained.

Request IDs are UUIDv4 strings. The server validates syntax/length, checks durable replay state, verifies Ed25519, then records the request ID with the action transaction. A unique-constraint race returns 409. A request ID is retained for at least 24 hours; timestamp validation limits useful signature lifetime independently.

## Endpoints and scopes

| Method and path | Scope | Secret-bearing | Object rule |
|---|---|---:|---|
| `POST /api/agent/v2/register` | bootstrap only | No | Token host equals requested host; one use |
| `POST /api/agent/v2/checkin` | `inventory:write` | No | Identity host only; bounded allowlisted inventory |
| `GET /api/agent/v2/backup/offers` | `backup:poll` | No | Offers assigned to identity host only |
| `POST /api/agent/v2/backup/dispatches/{id}/claim` | `backup:claim` | Yes, encrypted | Active offer, exact host/identity, atomic claim |
| `POST /api/agent/v2/backup/dispatches/{id}/status` | `backup:status` | No | Exact identity plus hashed dispatch grant; state transition allowlist |
| `POST /api/agent/v2/rotate` | active identity + bootstrap | No | Old-key proof and host-bound new keys |

Registration is the only unsigned request and requires the single-use bootstrap secret in the JSON body, never a URL/header likely to be logged. It returns agent/host/key IDs, accepted scopes, server dispatch-signing public keys and protocol timing limits. It returns no backup target or job secret.

## Offer and claim state machine

```text
queued -> offered -> claimed -> running -> successful
                    |          |          -> failed
                    |          -> expired/requeued
                    -> expired/requeued
```

- Offer creation does not decrypt secrets.
- Claim uses a conditional update on job status, host ID, dispatch state and expiry. At most one claim wins under concurrent SQLite sessions.
- The first successful claim generates and stores one ciphertext envelope and a hash of the grant contained inside it.
- The same identity and `claim_id` may idempotently retrieve that ciphertext after a lost response until expiry. A different identity or claim ID receives a generic conflict/not-found response.
- Expiry before `running` clears the claim/grant/envelope and safely requeues according to bounded retry policy. Once `running`, human-visible reconciliation is required; the server must not assume the agent forgot decrypted secrets.
- Status cannot move backward or skip required states. Duplicate terminal updates are idempotent only when body content matches the recorded result digest.

## Envelope format

Outer JSON contains only public routing/crypto fields:

```json
{
  "version": 2,
  "algorithm": "X25519-HKDF-SHA256+A256GCM",
  "agent_key_id": "agent-enc-key-id",
  "server_signing_key_id": "server-signing-key-id",
  "ephemeral_public_key": "base64url",
  "nonce": "base64url",
  "aad": {"dispatch_id": "opaque-id", "expires_at": "RFC3339", "manifest_sha256": "hex"},
  "ciphertext": "base64url",
  "signature": "base64url"
}
```

HKDF salt is a random 32-byte dispatch value stored with public metadata. HKDF info and AEAD AAD use canonical JSON and bind all identifiers listed in ADR-0004. The server signature covers every outer field except `signature`. The agent verifies the pinned server key and signature before X25519 derivation/decryption, verifies AEAD, checks all IDs/expiry against its signed claim, and rejects unknown fields or algorithms.

Decrypted content is versioned and allowlisted:

```json
{
  "manifest": {"job_id": 123, "operation": "backup", "container": "synthetic", "policy": "full"},
  "target": {"type": "sftp", "host": "backup.example.invalid", "port": 22, "path": "/synthetic", "username": "fake", "password": "fake"},
  "encryption": {"mode": "agent-aes-256-gcm", "data_key": "base64url"},
  "dispatch_grant": "opaque-random-value"
}
```

Only fields required by the selected target/operation are present. Local targets omit network credentials. Restore-only artifact metadata is omitted from backup operations. Unknown target types fail before decryption/dispatch.

## Error, logging and audit contract

Authentication responses use generic 400/401/403/409/413/426/429 status and stable reason categories. They do not echo headers, signature material, request bodies, canonical strings, target data, envelope data or upstream errors.

Application/proxy access logs suppress bootstrap bodies and all authentication headers. Structured logs and audits may include truncated non-secret agent/request IDs, host/job/dispatch IDs, scope, protocol version, key IDs, outcome and safe category. Tracebacks and metrics must never label on tokens, signatures, grants, ciphertext, credentials, paths or data keys.

## Required implementation tests

### Authentication and scope

- Missing/malformed headers, unknown agent/key, wrong protocol and invalid signature.
- Disabled host; pending, revoked and decommissioned identity.
- Missing scope and valid identity used against another host/job.
- Stale/future timestamps at both boundaries.
- Request-ID replay, concurrent duplicate insertion and durable replay after restart.
- Method, path, canonical query and body modification after signing.
- Body-size and per-agent/source rate limits.
- Key rotation overlap, old-key retirement and cross-host public-key reuse.

### Dispatch and concurrency

- Poll returns no credential, data key, artifact path or requester data.
- Wrong host/scope/job/operation cannot claim.
- Two identities and two sessions concurrently claim one offer; exactly one wins.
- Same identity/claim ID safely retries a lost response; changed claim ID fails.
- Grant expiry/replay/cross-job use and every invalid state transition.
- Disable/revoke/decommission between offer, claim and status.
- SQLite process restart and crash between authentication, conditional claim and response.

### Cryptography and minimization

- Agent decrypts a valid synthetic envelope and verifies the server signature/AAD.
- Wrong agent key, wrong server key, modified nonce/AAD/ciphertext/signature and expired envelope fail.
- Rotation with outstanding envelope follows the approved drain/re-encrypt rule.
- Local, SMB and SFTP payloads contain only their allowlisted synthetic fields; FTP remains blocked.
- No plaintext fake credentials/data keys appear in response JSON, database dispatch rows, logs, audits, exceptions or traces.

### Migration and rollback

- Legacy bearer cannot poll or claim a secret-bearing job, including during the grace window.
- Legacy inventory-only check-in expires at the configured deadline.
- Existing queued jobs remain queued and visible while host enrollment is incomplete.
- Pre-cutoff running job status exception, if approved, cannot obtain new secrets or change another job.
- Re-enrollment, token-hash clearing, host disablement and decommission denial.
- Fresh install, historical upgrade, repeated migration, backup/restore and forward-only rollback rehearsal.

### Agent implementation

- Private keys are created with restrictive permissions and are not printed in compose output or logs.
- Bootstrap secret is removed after registration.
- Secrets are held only for the operation lifetime, never passed in process arguments, and best-effort zeroized/removed afterward.
- TLS verification, server signing-key pinning, clock-skew diagnostics, bounded retry/backoff and crash recovery.

## Review checkpoint

Reviewers must resolve every decision in ADR-0004, confirm ownership of the external agent code, and approve this state machine and envelope before any production route, model, migration or agent implementation begins.
