# ADR-0004: Backup-agent machine authentication and secret delivery

**Status:** Approved in principle - implementation checkpoint required
**Date:** 2026-08-04
**Decision owners:** Kaya maintainers

## Context

The current Docker/backup agent authenticates with a long-lived bearer token whose SHA-256 hash is stored on `ComputeHost`. The backup polling endpoint accepts that bearer without request signing, freshness, replay protection, explicit scope or an enabled-host check, then decrypts storage credentials and the job data key into ordinary JSON (`KAYA-BAK-001`). Replaying a stolen bearer can therefore retrieve high-impact secrets.

Kaya's HA agent provides a precedent for bounded bootstrap, Ed25519 request signing, durable request-ID replay detection, timestamps, rotation and revocation. Backup dispatch additionally requires confidential, job-scoped delivery of reusable storage credentials and unique backup data keys. Authentication and secret encryption require separate keys and lifecycles.

The external Docker-agent implementation is not present in this repository. Server and agent changes must be implemented and released as one coordinated protocol migration. This ADR approves the design direction; it does not approve or contain production implementation.

## Approved decision

### Machine identity and enrollment

- Each agent generates an Ed25519 request-signing key and a separate X25519 envelope-decryption key locally. Private keys never leave the agent.
- A 15-minute, single-use bootstrap token is created by an administrator, bound to one active `docker_agent` host and the explicit approved scope set. Only its hash is stored; the raw value is displayed once and is never put in a URL.
- Registration binds agent ID, host ID, signing public key, encryption public key, key IDs, protocol version and scopes. A public key cannot be registered to multiple hosts.
- Identity states are `pending`, `active`, `rotation_pending`, `revoked` and `decommissioned`. Only `active` identities on enabled hosts may poll, claim or update jobs.
- Approved scopes are `inventory:write`, `backup:poll`, `backup:claim` and `backup:status`. Scope checks are endpoint-specific and do not replace host/job object authorization.

### Signed requests and replay protection

- Protocol v2 uses Ed25519 over the canonical request defined normatively in `docs/security/backup-agent-protocol-v2.md`.
- Every request carries protocol version, agent ID, signing-key ID, Unix timestamp, unique UUIDv4 request ID and an unpadded base64url signature.
- The maximum permitted clock skew is 300 seconds. Timestamp validity is necessary but not sufficient.
- The database has a unique `(agent_identity_id, request_id)` constraint. For mutating endpoints, replay-row insertion and the protected state transition commit in the same transaction. For read-only endpoints, the replay row commits before response data is selected; a later failure still burns the request ID.
- Replay rows are retained for at least 24 hours. Cleanup removes a row only when its signed timestamp can no longer pass the 300-second window. Restart does not clear replay protection, and cleanup cannot make an old valid signature current again.
- Authentication failures use generic reason categories. Signatures, canonical strings, keys, bootstrap material and request bodies are never logged or audited.

### Two-step dispatch and grant invalidation

Polling returns bounded non-secret offers only. It does not return target credentials, backup keys, artifact paths or requester data.

The agent claims one offer using a signed POST and agent-generated `claim_id`. A conditional database transition binds the queued job and dispatch to exactly that active identity and claim. The first successful transaction persists the ciphertext envelope and hashed dispatch grant before responding. A retry using the same identity and `claim_id` may return the same stored ciphertext. A different identity or claim ID cannot retrieve it.

A dispatch grant is job-, dispatch-, claim-, identity- and scope-bound, stored only as a hash, and never accepted without a valid signed request from the bound active agent. It expires at the earliest of:

- 15 minutes after issue;
- job cancellation;
- agent revocation or decommission;
- host disablement;
- dispatch replacement;
- terminal claim failure;
- explicit administrator invalidation; or
- job completion or terminal failure once no further authenticated status transition requires it.

Status transitions follow the allowlist in the protocol specification. Revocation/invalidation checks occur in the same transaction as each protected transition.

### Secret envelope and server authenticity

- Kaya uses ephemeral X25519 per dispatch, HKDF-SHA-256 and AES-256-GCM with a random 96-bit nonce. Only established cryptographic libraries are permitted; no custom primitive or handwritten crypto implementation is allowed.
- AEAD additional data binds protocol version, agent identity, agent encryption-key ID, host ID, job ID, dispatch ID, claim ID, operation, expiry and canonical manifest digest.
- The encrypted plaintext contains only the allowed manifest, selected target connection fields required by the operation, job data key when required, restore artifact metadata when required, and scoped dispatch grant.
- Kaya signs the canonical public envelope with a separate Ed25519 server dispatch-signing key. Agents pin allowed server key IDs and public keys.
- The outer envelope is at most 96 KiB encoded; decrypted secret payload is at most 64 KiB. Oversize content fails before dispatch persistence.
- Stored dispatch rows retain ciphertext and public routing/cryptographic metadata only. Plaintext content, raw grants and decrypted credentials/data keys are not stored anew, logged, audited or returned in errors.

### Server dispatch-signing key

The Ed25519 server private seed is wrapped using the application encryption system with the purpose-specific context:

```text
kaya:backup-agent:dispatch-signing-key:v1
```

The implementation must derive/use a context-separated wrapping key through an established KDF/encryption library rather than use raw `ENCRYPTION_KEY` bytes directly for every purpose. This provides domain separation, but it does not protect the dispatch key if `ENCRYPTION_KEY` or the running Kaya process is fully compromised.

Each server key has a non-secret key ID and explicit lifecycle. Rotation introduces a new key, overlaps old/new public keys, waits for active-agent acknowledgement, then retires the old key after outstanding envelopes expire or drain. Recovery documentation must restore the database, original `ENCRYPTION_KEY`, wrapped server keys and key metadata together. Backup validation must prove those keys decrypt before dispatch resumes.

If the active server signing key cannot be decrypted, Kaya fails closed and pauses backup dispatch while preserving queued jobs. It must not silently generate or activate a replacement key. Replacement is an explicit administrator recovery/rotation action with audit records.

### Lifecycle, rotation and decommission

- Agent signing and encryption keys rotate together through a fresh bootstrap or signed old-key rotation ceremony. A new encryption key cannot activate until outstanding envelopes are drained, expired or explicitly re-encrypted under an approved recovery path.
- Revocation or host disablement immediately denies new requests, invalidates grants and expires unstarted dispatches. Decommission is terminal.
- Secrets already decrypted by a compromised/running agent cannot be recalled; incident response includes target-credential and backup-key rotation.
- Security audits contain safe actor/agent/host/job/dispatch IDs, outcome, reason code and key IDs only. They exclude bootstrap tokens, grants, public-key bodies, signatures, canonical requests, ciphertext, credentials, data keys and full upstream errors.

## SQLite transaction contract

- Replay insertion and each mutating state transition share one short transaction.
- Claim uses a conditional update over job status, host, dispatch state and expiry; exactly one concurrent claimant may win.
- Envelope ciphertext and grant hash persist in the successful claim transaction before the response is emitted. A crash after commit is recovered by the same-identity/same-claim idempotent retry.
- A crash before commit leaves no claim or reusable replay row/state transition from a partially completed transaction.
- Lock contention receives bounded jittered retry only around idempotent transaction entry. It never regenerates a claim, grant, nonce or envelope after a committed result.
- Duplicate status updates are idempotent only for the same allowed transition and result digest; conflicting duplicates fail generically.

## Migration and rollback

The 14-day protocol-v1 inventory-only window starts automatically when the protocol-v2 server release is deployed. Its start and fixed deadline are visible to administrators and recorded in audit. It cannot be silently extended.

During the window, legacy bearer authentication may submit bounded inventory and, only if explicitly enabled, terminal status for jobs dispatched before cutoff. It cannot poll, claim, receive storage credentials or backup keys, or receive new secret-bearing work. Warnings and audit events are emitted at deployment, pending milestones and expiry. Completion is automatic at the deadline or an earlier explicit audited administrator action; after completion, protocol v1 is fully rejected and legacy hashes are cleared through the reviewed migration.

If protocol v2 fails, dispatch pauses and queued jobs remain preserved and operator-visible. Rollback must never restore bearer-based secret delivery or silently extend the migration window.

## Alternatives considered

### Mutual TLS

Not required for protocol v2 initially. mTLS adds CA issuance, renewal, revocation and proxy pass-through complexity and does not replace application-level job replay/binding or end-to-end envelopes. It may be added later as defence in depth without changing the signed dispatch contract.

### Reuse HA signing keys only

Rejected. Ed25519 signing keys do not provide X25519 confidentiality, and conflating authentication and secret delivery prevents independent rotation and containment.

### Short-lived bearer tokens only

Rejected. Short lifetime does not bind method/path/body, prevent within-window replay, prove asymmetric machine identity or protect secrets beyond a TLS terminator.

### Trust first agent key automatically

Rejected. Enrollment must be administrator-initiated and host-bound to avoid first-contact identity capture.

## Consequences and implementation checkpoint

- A stolen legacy bearer cannot obtain new backup credentials or data keys after v2 deployment.
- A fully compromised active agent can still decrypt secrets legitimately dispatched to that host; least privilege, short lifetime, credential rotation and detection remain required.
- The database gains durable identities, keys, replay rows, bootstrap rows and dispatch/claim state. SQLite concurrency and crash behavior require the specified tests.
- The coordinated Kaya server and external Docker-agent implementation must use the normative protocol and deterministic test vectors.

Before production implementation starts, maintainers must assign owners for both repositories, agree the coordinated release/rollback rehearsal, identify the established cryptographic libraries on both sides, and obtain implementation review against the protocol vectors. This approved-in-principle ADR does not self-approve OIDC/RDP work and does not remediate `KAYA-BAK-001` by itself.

## References

- `security-review/FINDINGS_REGISTER.md` (`KAYA-BAK-001`)
- `app/services/ha_agents.py`
- `docs/security/backup-agent-protocol-v2.md`
- `docs/security/backup-agent-protocol-v2-test-vectors.json`
- `SECURITY_ENGINEERING.md`
