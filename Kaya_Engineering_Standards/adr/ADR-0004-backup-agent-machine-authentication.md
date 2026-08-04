# ADR-0004: Backup-agent machine authentication and secret delivery

**Status:** Proposed - mandatory human security review before implementation
**Date:** 2026-08-04
**Decision owners:** Kaya maintainers

## Context

The current Docker/backup agent authenticates with a long-lived bearer token whose SHA-256 hash is stored on `ComputeHost`. The backup job polling endpoint accepts that bearer without request signing, freshness, replay protection, explicit scope or an enabled-host check, then decrypts storage credentials and the job data key into ordinary JSON (`KAYA-BAK-001`). Replaying a stolen bearer can therefore retrieve high-impact secrets.

Kaya's HA agent already demonstrates bounded bootstrap, Ed25519 request signing, durable request-ID replay detection, timestamps, rotation and revocation. Backup dispatch additionally requires confidential, job-scoped delivery of reusable storage credentials and unique backup data keys. Authentication and secret encryption must use separate keys and lifecycles.

The implementation for the installed Docker agent is not present in this repository. Server and agent changes must therefore be versioned and released as a coordinated protocol migration.

## Decision proposed for review

### Machine identity

- Each agent generates an Ed25519 request-signing key and a separate X25519 envelope-decryption key locally. Private keys never leave the agent.
- A 15-minute, single-use bootstrap token is created by an administrator, bound to one active `docker_agent` host and an explicit scope set. Only its hash is stored; the raw value is shown once and is never placed in a URL.
- Registration binds the agent ID, host ID, signing public key, encryption public key, key IDs, protocol version and scopes. A public key cannot be registered to two hosts.
- Identity states are `pending`, `active`, `rotation_pending`, `revoked` and `decommissioned`. Only `active`, enabled hosts may poll, claim or update jobs.
- Initial scopes are `inventory:write`, `backup:poll`, `backup:claim` and `backup:status`. Scope checks are endpoint-specific and host/job object checks remain mandatory.

### Signed requests

Protocol v2 signs a canonical request with the agent's Ed25519 key. Required headers are:

- `X-Kaya-Agent-Protocol: 2`
- `X-Kaya-Agent-ID`
- `X-Kaya-Agent-Key-ID`
- `X-Kaya-Agent-Timestamp` as Unix seconds
- `X-Kaya-Agent-Request-ID` as a UUID
- `X-Kaya-Agent-Signature` as unpadded base64url

The signature covers protocol marker, uppercase method, exact normalized path, canonical query string, agent ID, key ID, request ID, timestamp and SHA-256 body digest. Request bodies are bounded at 256 KiB. Timestamps may differ by no more than 300 seconds. A durable unique `(identity_id, request_id)` row is inserted atomically before action; repeats fail with 409. Per-identity and per-source rate limits apply. Authentication errors are generic and never include canonical strings, signatures, bodies or keys.

### Two-step dispatch

Polling returns only bounded, non-secret offers: dispatch ID, operation, workload reference, creation/expiry and required capability. It does not return target credentials, a backup key, artifact paths or requester data.

The agent claims one offer with a signed POST containing an agent-generated UUID `claim_id`. A conditional database transition binds the queued job and dispatch to exactly that active identity and claim. Concurrent or cross-host claims fail. A retry by the same identity and `claim_id` returns the same stored encrypted envelope; no other claim ID can retrieve it.

The returned dispatch grant is random, short-lived (proposed: 15 minutes), job/identity/scope-bound and stored only as a hash. It is placed inside the encrypted envelope and is never sufficient without a valid signed request. Status transitions require both the signed identity and the dispatch grant and follow an allowlisted state machine.

### Secret envelope and server authenticity

- Kaya generates an ephemeral X25519 key per dispatch, derives a 256-bit key with HKDF-SHA-256, and encrypts with AES-256-GCM using a random 96-bit nonce.
- AEAD additional data binds protocol version, agent ID, agent encryption-key ID, host ID, job ID, dispatch ID, claim ID, operation, expiry and a canonical manifest digest.
- The encrypted plaintext contains the minimal signed job manifest, exact selected target connection fields, storage credential if required, job data key if required, source artifact metadata required for restore, and the scoped dispatch grant. No other targets, site settings, users, owners or unrelated metadata are included.
- Kaya signs the canonical envelope with a server Ed25519 dispatch-signing key. Agents pin the allowed server public key IDs during registration. The server private key is encrypted at rest under `ENCRYPTION_KEY`, is independently rotatable, and is never derived from an agent credential or job data key.
- Stored dispatch rows retain ciphertext and public metadata only. Plaintext envelope content, raw grants and decrypted target/data keys are never stored anew, logged, audited or returned in errors.

### Lifecycle, rotation and decommission

- Agent signing and encryption keys rotate together through a fresh bootstrap or a signed old-key rotation ceremony. The new encryption key cannot activate until outstanding envelopes are drained, expired or re-encrypted.
- Server dispatch-signing keys rotate with an explicit overlap window in which agents pin both old and new public keys; old keys are retired after every active agent acknowledges the new key.
- Revocation or host disablement immediately denies new requests and claims, expires unstarted dispatches and clears bootstrap material. Decommission is terminal. Secrets already decrypted by a compromised/running agent cannot be recalled and must be handled through target credential and backup-key incident rotation.
- Security actions audit actor/agent/host/job/dispatch IDs, outcome, reason code and key IDs only. They exclude bootstrap tokens, grants, public-key bodies, signatures, canonical requests, ciphertext, credentials, data keys and full upstream errors.

## Alternatives considered

### Mutual TLS

Rejected for the first v2 proposal. mTLS provides strong transport identity but introduces certificate authority issuance, renewal, revocation and proxy pass-through requirements that are materially harder for Kaya's current homelab deployment. It also does not by itself provide job-scoped replay protection or end-to-end envelope confidentiality past a TLS-terminating proxy. The design may add mTLS later as defense in depth without changing the signed dispatch contract.

### Reuse HA signing keys only

Rejected. Ed25519 signing keys cannot provide X25519 confidentiality, and conflating authentication with data-key delivery prevents independent rotation and containment.

### Short-lived bearer tokens only

Rejected. Short lifetime reduces exposure but does not bind method/path/body, prevent within-window replay, prove an asymmetric machine identity or protect secrets from TLS-terminating intermediaries.

### Trust the first agent key automatically

Rejected. Enrollment must be initiated and host-bound by an administrator; otherwise a race at first contact can durably capture the host identity.

## Consequences

- Stolen legacy bearer tokens cannot obtain backup credentials or data keys from v2 endpoints.
- A fully compromised active agent can still decrypt secrets legitimately dispatched to that host. Least privilege, short dispatch lifetime, target credential rotation and operational detection remain essential.
- Server and external agent changes must ship together. Hosts without v2 identity remain visible but backup dispatch is deliberately paused.
- The database gains durable identities, keys, replay rows, bootstrap rows and dispatch/claim state. SQLite conditional-update and crash/retry behavior require dedicated tests.
- The protocol is more complex than bearer authentication but aligns with the impact of storage credentials and backup encryption keys.

## Compatibility and migration

The rollout is additive but fail-secure:

1. Inventory all `docker_agent` hosts, queued/running jobs and current agent versions. Back up Kaya and verify local administrator recovery.
2. Deploy the coordinated v2 server/agent release with backup dispatch paused for unregistered hosts. The legacy bearer endpoint must not return secret-bearing jobs from the moment this release is active.
3. Allow legacy bearer authentication only for bounded inventory check-in and, if explicitly approved, terminal status updates for jobs dispatched before the cutoff. It cannot poll or claim new backup work.
4. Administrators issue host-bound bootstrap tokens and activate scopes after verifying the agent ID, key IDs and version. Queued jobs remain queued with an operator-visible `agent_upgrade_required` reason until activation.
5. After a proposed 14-day inventory-only window, clear legacy bearer hashes and reject protocol v1 entirely. Hosts not migrated remain disabled for dispatch.

Rollback must never restore bearer secret delivery. If v2 fails, pause dispatch and preserve queued jobs while fixing or rolling forward. Database downgrade may remove only unused v2 rows after an owner-approved backup; it must not silently reactivate legacy agent tokens.

## Human decisions required before implementation

1. Approve Ed25519 request signing plus X25519/AES-256-GCM envelopes, or require mTLS in addition.
2. Approve the proposed scopes and 300-second request window.
3. Approve the 15-minute dispatch grant and 14-day inventory-only migration window.
4. Approve server dispatch-signing key storage under `ENCRYPTION_KEY` and its overlap rotation policy.
5. Confirm ownership and release sequencing for the external Docker agent implementation.

No production implementation may begin until these decisions are recorded through human review of this ADR and the companion protocol specification.

## References

- `security-review/FINDINGS_REGISTER.md` (`KAYA-BAK-001`)
- `app/services/ha_agents.py`
- `docs/security/backup-agent-protocol-v2.md`
- `SECURITY_ENGINEERING.md`
