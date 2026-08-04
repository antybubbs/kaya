# Backup Agent Protocol v2 - Approved Design Specification

**Status:** Approved in principle; production implementation not started
**Finding:** `KAYA-BAK-001` remains Critical and open
**ADR:** `ADR-0004`

This is the normative protocol contract for coordinated Kaya server and external Docker-agent implementation. It records approved design decisions and review conditions; it is not operational code.

## Trust boundaries and assets

The protocol crosses administrator-to-Kaya enrollment, agent-to-Kaya HTTPS, TLS-terminating proxy, Kaya database/encryption, backup target and local agent-process boundaries.

Protected assets are machine identity, authorization scopes, storage credentials, backup data keys, restore artifact locations, job ownership/state, replay records, bootstrap tokens, dispatch grants and server signing keys. TLS certificate verification remains mandatory. Signed requests add application-layer identity/replay resistance; the X25519 envelope protects secret-bearing payloads beyond a TLS terminator; the server Ed25519 signature authenticates the envelope to the agent.

## Approved algorithms and limits

| Purpose | Requirement |
|---|---|
| Agent request signature | Ed25519 |
| Agent envelope key agreement | Separate X25519 key |
| Envelope KDF | HKDF-SHA-256 |
| Envelope encryption | AES-256-GCM, 96-bit random nonce |
| Server envelope signature | Separate Ed25519 key |
| Request clock skew | At most 300 seconds |
| Request body | At most 256 KiB |
| Decrypted envelope payload | At most 64 KiB |
| Encoded outer envelope | At most 96 KiB |
| Dispatch grant | At most 15 minutes, subject to earlier invalidation |
| Protocol-v1 migration | Fixed 14 days from v2 deployment |

Only established, maintained cryptographic libraries may implement these operations. Custom cryptographic primitives are forbidden.

## Proposed resources

| Resource | Purpose | Required constraints |
|---|---|---|
| `AgentIdentity` | Host-bound agent lifecycle | Unique host and agent ID; state; protocol; enabled host required |
| `AgentKey` | Versioned Ed25519/X25519 public keys | Unique key IDs; activation/retirement; no agent private keys |
| `AgentBootstrap` | Single-use enrollment | Token hash only; host/scopes/admin/15-minute expiry/used time |
| `AgentRequest` | Durable replay record | Unique identity + request ID; signed/received times; safe outcome only |
| `BackupDispatch` | Offer/claim/grant/envelope state | Unique job offer; identity/claim binding; grant hash; expiry; ciphertext |
| `AgentServerSigningKey` | Server envelope authenticity | Wrapped private seed; public key/key ID; activation/retirement/acknowledgement |
| `AgentMigrationWindow` | Protocol-v1 cutoff | Immutable start/deadline; completion; administrator-visible audit state |

Existing `ComputeHost.agent_token_hash` is legacy inventory-only state during migration. Existing `BackupJob.encrypted_backup_key` remains encrypted under Kaya's application system until its minimal plaintext value is transiently placed inside an agent-specific envelope.

## Request headers and identifier validation

Every signed request includes exactly one value for:

- `X-Kaya-Agent-Protocol: 2`
- `X-Kaya-Agent-ID`
- `X-Kaya-Agent-Key-ID`
- `X-Kaya-Agent-Timestamp` (base-10 Unix seconds, no sign or whitespace)
- `X-Kaya-Agent-Request-ID` (lowercase canonical UUIDv4)
- `X-Kaya-Agent-Signature` (unpadded base64url Ed25519 signature)

Agent IDs and key IDs are opaque ASCII identifiers, 8-64 characters, matching `^[a-z0-9][a-z0-9_-]{7,63}$`. Duplicate security headers, folded values, surrounding whitespace, unknown protocol versions and unknown/retired keys are rejected. The values verified from headers are the exact values placed into the canonical request.

## Canonical request format

The signed UTF-8 byte sequence has nine lines, joined by one LF byte (`0x0a`) with no final LF:

```text
KAYA-AGENT-V2
<UPPERCASE_METHOD>
<CANONICAL_PATH>
<CANONICAL_QUERY_OR_EMPTY>
<AGENT_ID>
<KEY_ID>
<REQUEST_ID>
<UNIX_TIMESTAMP>
<LOWERCASE_SHA256_BODY_HEX>
```

### Method

The method is the ASCII HTTP method converted to uppercase. Only the method registered for the endpoint is accepted. Method override headers and query parameters are rejected.

### Path

Canonicalization starts from the raw request-target path after a trusted, statically configured deployment `root_path` is removed exactly once. Proxy-supplied prefix headers are not trusted unless the deployment has explicitly configured that proxy.

1. The raw path must start with `/`, be at most 2,048 bytes and contain valid `%HH` escapes only.
2. Literal `/` bytes delimit segments. Empty interior segments (`//`) are rejected.
3. Within each segment, percent escapes are decoded to bytes. Encoded `/`, backslash or NUL is rejected. The segment must decode as strict UTF-8 and is normalized to Unicode NFC.
4. Decoded `.` or `..` segments are rejected. Literal or encoded backslashes are rejected.
5. Each normalized segment is UTF-8 encoded. RFC 3986 unreserved bytes (`A-Z a-z 0-9 - . _ ~`) remain literal; every other byte is percent-encoded with uppercase hexadecimal.
6. Segment separators are rejoined as `/`. A final empty segment is preserved, so `/claim` and `/claim/` are distinct signatures. Routes define one accepted form and do not redirect signed requests between them.

The server compares the canonical path to the route's canonical form before authorization. A path whose routing semantics differ after normalization is rejected.

### Query string

V2 endpoints avoid query parameters unless specified. The empty raw query becomes an empty fourth line.

For a permitted non-empty query, split the raw query on `&`, then each pair on its first `=`; a missing `=` means an empty value. Blank keys and empty pairs are rejected. Percent decoding, strict UTF-8, NFC normalization and RFC 3986 re-encoding follow the path-segment rules, except `/` is simply percent-encoded. `+` is a literal plus, never a space.

Duplicate key/value pairs are retained. Pairs are sorted bytewise by encoded key, then encoded value; identical pairs retain their original relative order. Every output pair is `key=value`, joined by `&`. Query order on the wire therefore does not affect the signature, while duplication does.

### Body and JSON

The body digest is lowercase hexadecimal SHA-256 over the exact bytes received after HTTP transfer decoding and before JSON parsing or reserialization. An empty body hashes to `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

JSON endpoints require `application/json`, strict UTF-8 without BOM, a top-level object, no duplicate member names, no non-finite numbers and no trailing data. Unicode strings must be valid and are normalized/validated by the endpoint schema where equality or identifiers matter. The signature still covers the original bytes: UTF-8 `é` and JSON `\u00e9` are semantically equivalent strings but have different body digests/signatures. Agents must sign exactly the bytes they send. Bodies over 256 KiB are rejected before parsing.

### Time, request and identity fields

The timestamp is the validated decimal header value. Its difference from trusted server Unix time must be no more than 300 seconds at authentication. Request ID, agent ID and key ID are validated as above and copied without case conversion. Protocol version is bound both by the fixed first line and required protocol header.

## Authentication and durable replay transaction

The server performs bounded syntax/body checks, identity/key/state/scope lookup, clock-skew validation and Ed25519 verification before the protected action. Errors are generic and do not reveal whether an agent, key, scope or signature was valid.

Every signed request uses a new request ID. The database enforces unique `(agent_identity_id, request_id)`:

- Mutating endpoints insert the replay row and perform the conditional protected state transition in one transaction. Both commit or both roll back.
- Read-only endpoints insert and commit the replay row before selecting/returning protected data. A response failure does not make the request ID reusable.
- A uniqueness race returns generic 409. Restart retains rows and replay rejection.
- Rows are retained for at least 24 hours. Cleanup selects only rows whose signed timestamp is already outside the 300-second acceptance window and whose receipt time is older than 24 hours. Deleting a row therefore cannot make its signed request timely again.
- Cleanup is bounded, audited by counts only and never logs identifiers, signatures, canonical strings, keys or bodies.

Per-identity and trusted-source rate limits apply after cheap size/syntax checks and before expensive signature/crypto work where possible.

## Endpoints and scopes

| Method and path | Scope | Secret-bearing | Object rule |
|---|---|---:|---|
| `POST /api/agent/v2/register` | bootstrap only | No | Bootstrap host equals requested enabled host; one use |
| `POST /api/agent/v2/checkin` | `inventory:write` | No | Identity host only; bounded allowlisted inventory |
| `GET /api/agent/v2/backup/offers` | `backup:poll` | No | Offers assigned to identity host only |
| `POST /api/agent/v2/backup/dispatches/{id}/claim` | `backup:claim` | Yes, encrypted | Active offer, exact host/identity, atomic claim |
| `POST /api/agent/v2/backup/dispatches/{id}/status` | `backup:status` | No secrets | Exact identity plus hashed grant and state allowlist |
| `POST /api/agent/v2/rotate` | active identity + bootstrap | No | Old-key proof and host-bound new keys |

Registration is the only unsigned request. Its single-use bootstrap secret is in the bounded JSON body, never a URL. Bootstrap consumption and identity/key creation commit atomically.

## Offer, claim and status state machine

```text
queued -> offered -> claimed -> running -> successful
                    |          |          -> failed
                    |          -> expired/requeued
                    -> expired/requeued
```

- Offer creation never decrypts secrets.
- Claim conditionally updates job status, assigned host, dispatch state and expiry. Exactly one claimant wins under concurrent SQLite sessions.
- The successful transaction creates one grant, envelope and result digest and persists grant hash/ciphertext before response delivery.
- Same identity plus same `claim_id` returns the identical stored ciphertext until invalidation/expiry. Different identity or claim ID receives generic conflict/not-found and no ciphertext.
- A crash before commit leaves the offer claimable. A crash after commit is recovered only through the idempotent same-identity/same-claim retry; no new nonce, grant or ciphertext is generated.
- Before `running`, expiry may requeue under bounded policy and invalidates the grant/envelope. Once `running`, reconciliation is human-visible because the agent may already hold secrets.
- Concurrent claim, invalidation and status operations use conditional writes and short transactions. SQLite lock contention receives bounded jittered retries only for safe/idempotent transaction boundaries.

The agent may submit only `state` (`running`, `successful`, `failed`), integer `progress_percent` (0-100), allowlisted `result_code`, lowercase SHA-256 `result_digest`, non-negative bounded `bytes_processed`, and RFC 3339 `agent_finished_at`. It never controls user/owner/host/job/target IDs, operation, policy, scope, credentials, data keys, dispatch/claim IDs, grant expiry, server timestamps, retention, source/destination paths or audit actor fields. Duplicate status is idempotent only when the transition and result digest match; conflicting duplicates fail.

## Dispatch-grant invalidation

The grant is stored as a cryptographic hash and placed only inside the encrypted envelope. Every use requires both the raw grant and a valid signed request from the bound active identity. It expires at the earliest of 15 minutes, job cancellation, agent revocation/decommission, host disablement, dispatch replacement, terminal claim failure, explicit administrator invalidation, or job completion/terminal failure when no longer required. The invalidation condition and status transition are checked atomically. A grant never authorizes another job, dispatch, claim, identity, scope or operation.

## Manifest and encrypted payload

The canonical manifest is an RFC 8785 JSON object containing only:

- `job_id`
- `operation` (`backup` or `restore`)
- `workload_ref` (opaque server-selected reference)
- `policy` (allowlisted operation policy)
- `target_type` (`local`, `smb` or `sftp`; FTP remains blocked)

The server controls all manifest fields. Its SHA-256 digest is bound into AEAD data.

The decrypted payload may contain the manifest, minimal target fields allowlisted for its target type, a job data key when required, restore-only artifact metadata when required, and dispatch grant. It is at most 64 KiB. Local targets omit network credentials; backup operations omit restore artifact locations. Unknown fields/target types fail closed.

The encoded outer envelope is at most 96 KiB and contains only version, algorithm, agent encryption-key ID, server signing-key ID, ephemeral public key, HKDF salt, nonce, canonical-AAD encoding, ciphertext/tag and signature.

## Envelope cryptography and binding

1. Generate an ephemeral X25519 key pair and random 32-byte HKDF salt per dispatch.
2. Compute X25519 shared secret with the bound active agent encryption public key.
3. Derive 32 bytes using HKDF-SHA-256. `info` is UTF-8 lines beginning `kaya:backup-agent:envelope:v2` and binding agent ID, agent encryption-key ID, host ID, job ID, dispatch ID, claim ID, operation, expiry and manifest digest.
4. Encode plaintext and AAD using RFC 8785 canonical JSON. AAD contains protocol version, agent identity, agent encryption-key ID, host ID, job ID, dispatch ID, claim ID, operation, expiry and manifest digest.
5. Encrypt with AES-256-GCM and a random 96-bit nonce.
6. RFC 8785-canonicalize every public envelope field except `signature`, then sign those bytes with the active server Ed25519 dispatch-signing key.
7. The agent verifies its pinned server key ID/signature before key derivation/decryption, verifies AEAD, and compares every bound ID/expiry/digest with its signed claim.

All binary fields use unpadded base64url. Key agreement, KDF, AEAD and signatures use established library APIs only.

## Server dispatch-signing key storage and lifecycle

The Ed25519 private seed is wrapped by the application encryption system using purpose context `kaya:backup-agent:dispatch-signing-key:v1`. Context-separated derivation/wrapping uses an established KDF/AEAD implementation. Domain separation limits cross-purpose key reuse but does not survive full compromise of `ENCRYPTION_KEY` or the running process.

Each key has a key ID, activation/retirement timestamps and acknowledgement state. Rotation overlaps old/new public keys until active agents acknowledge the new key and old envelopes drain/expire. Recovery restores database, original `ENCRYPTION_KEY`, wrapped keys and metadata together. Restore validation proves the active key decrypts and matches its stored public key before dispatch resumes. Decryption failure pauses dispatch and preserves queues; Kaya never silently generates a replacement key. Explicit recovery/replacement is administrator-authorized and audited without key material.

## Protocol-v1 migration window

The fixed 14-day window begins when v2 is deployed, with immutable start/deadline visible in the administrator UI. Deployment, milestone warnings, incomplete enrollment, explicit early completion and expiry generate redacted audit events. The deadline cannot be silently extended.

During the window, v1 is inventory-only, with an optional explicitly approved terminal-status exception for pre-cutoff jobs. It never polls/claims new work or returns storage credentials, backup keys or secret-bearing jobs. At the deadline, automatic completion rejects v1 fully; an administrator may complete earlier through an explicit audited action. Legacy hashes are then cleared through the reviewed migration.

Rollback never restores bearer secret delivery. If v2 fails, backup dispatch pauses while queued jobs remain preserved and visible.

## Error, logging and audit contract

Authentication responses use generic 400/401/403/409/413/426/429 status and stable safe categories. They never echo headers, signature material, canonical strings, request bodies, target data, envelopes or upstream errors.

Application/proxy access logs suppress bootstrap bodies and authentication headers. Logs/audits may include truncated non-secret agent/request IDs, host/job/dispatch IDs, scope, protocol, key IDs, outcome and safe category. They never contain tokens, signatures, grants, ciphertext, credentials, paths or data keys.

## Deterministic interoperability vectors

`docs/security/backup-agent-protocol-v2-test-vectors.json` is normative for interoperability. Every private value is synthetic and marked test-only. It contains:

- deterministic Ed25519 agent/server key pairs and signatures;
- deterministic X25519 shared-secret derivation;
- HKDF-SHA-256 inputs/output;
- AES-256-GCM plaintext, AAD, nonce and ciphertext/tag;
- canonical request/body digest and server envelope signature;
- accepted/rejected canonicalization, replay, binding and mutation cases.

Production builds must never load these keys. Server and agent test suites must reproduce the expected values independently with their selected established libraries.

## Required implementation tests

### Authentication, canonicalization and replay

- Every vector, plus method case, trailing slash, percent-escape case, encoded delimiter, duplicate/reordered query, empty query/body, JSON whitespace/escape, Unicode NFC/non-NFC and body modification.
- Missing/duplicate/malformed headers, unknown/retired key, wrong protocol/signature, disabled/revoked/decommissioned identity and missing scope.
- Timestamp boundaries, UUID syntax, replay, concurrent replay insertion, application restart and cleanup safety.
- Transaction rollback/commit placement for replay rows and every protected operation.
- Body/identifier/path/query limits and per-identity/source rate limits.

### Dispatch, SQLite and recovery

- Poll response contains no credentials, data key, artifact path or requester data.
- Wrong host/scope/job/operation, two concurrent claimants with exactly one winner, and lock-contention retry bounds.
- Same identity/claim idempotency; different claim/identity denial; crash before commit, after envelope persistence and before response.
- Every early grant invalidator, signed-request requirement, grant replay/cross-job use and invalid state transition.
- Conditional claims, uniqueness constraints, transaction boundaries, process restart and duplicate/conflicting status updates on supported SQLite deployment.

### Cryptography and minimization

- Reproduce Ed25519, X25519, HKDF-SHA-256, AES-256-GCM and server-signature vectors using established libraries.
- Wrong agent/server key, modified salt/nonce/AAD/ciphertext/signature, expired envelope and bound-field mismatch fail closed.
- Payload/envelope size boundaries and allowlisted local/SMB/SFTP fields; FTP/unknown fields denied.
- No plaintext fake credential/data key in response JSON, dispatch rows, logs, audits, exceptions or traces.
- Server-key rotation acknowledgement/overlap, backup/restore, wrong `ENCRYPTION_KEY`, undecryptable key and no silent replacement.

### Migration and external agent

- Window starts at deployment, is administrator-visible, warns/audits, cannot silently extend, and expires automatically or through audited completion.
- Legacy bearer cannot poll/claim/receive secrets; deadline fully rejects v1; rollback never restores secret delivery.
- Queued jobs remain visible/preserved during enrollment failure and paused dispatch.
- Agent private-key permissions, bootstrap deletion, no secret process arguments/logging, TLS verification, server-key pinning, clock diagnostics, bounded retry and operation-lifetime secret cleanup.

## Implementation checkpoint

Production implementation remains paused. Before it begins, maintainers must assign coordinated server/external-agent owners, select established cryptographic libraries, agree migration/release/rollback rehearsal, and arrange independent implementation review against this specification and its vectors. This document does not close `KAYA-BAK-001` and does not self-approve OIDC or RDP remediation.
