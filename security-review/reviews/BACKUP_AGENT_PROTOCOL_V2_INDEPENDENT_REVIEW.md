# Backup Agent Protocol v2 Adversarial Review

**Date:** 2026-08-04  
**Kaya branch:** `security/backup-agent-protocol-v2`  
**Agent repository/branch:** `antybubbs/Kaya-Docker-Agent`, `security/protocol-v2`  
**Finding:** `KAYA-BAK-001`  
**Result:** **Verified with conditions**

## Scope and method

The combined server and genuine production-agent implementations were traced across enrollment, request authentication, inventory, offer, claim, status, rotation, lifecycle, migration and encrypted dispatch paths. The review used synthetic keys and credentials only. It included deterministic-vector reproduction, negative mutation tests and a direct cross-repository server-to-agent envelope test.

The adversarial pass found and corrected non-canonical percent/query handling, uncaught signature/tag failures, duplicate JSON member acceptance, non-strict envelope expiry, rotation without a fresh bootstrap, over-broad target payloads, agent-controlled artifact paths and a non-atomic SQLite claim path. The corrected implementation was then re-tested.

## Findings by boundary

- **Enrollment and key ownership:** 15-minute host-bound bootstraps are hashed and single-use. The agent generates distinct Ed25519 and X25519 private keys locally and persists them in a mode-0600 state file. Kaya receives public keys only. Duplicate public-key enrollment fails.
- **Canonicalisation and signatures:** method, canonical path/query, exact body digest, identity/key/request IDs and timestamp are signed. Duplicate security headers, malformed identifiers, invalid escapes, changed path/body, wrong signatures and timestamps outside ±300 seconds fail closed.
- **Replay, scopes and lifecycle:** request IDs are database-unique per identity and survive restart. Per-identity durable request counts bound the expensive path. Active identity, active key, enabled host and endpoint scope are enforced. Revocation/decommission retires keys and invalidates active grants.
- **Offers and claims:** polling returns manifest-only offers. Claim uses a conditional SQLite update, binds identity/host/job/dispatch/claim, persists the exact envelope for same-claim recovery, and conflicts on another identity or claim. Queued work remains queued if signing-key/envelope construction fails.
- **Envelope confidentiality/authenticity:** ephemeral X25519, HKDF-SHA-256, AES-256-GCM and server Ed25519 are implemented with `cryptography`. AAD binds every security-relevant identifier, expiry, operation and manifest digest. The agent verifies a pinned server key/signature before decrypting and rejects ciphertext, AAD, signature, expiry or binding mutations.
- **Grant and status:** only a hash of the short-lived grant is stored. Status requires both the signed identity and bound grant. Terminal transitions clear the grant. Status input is allowlisted and cannot select host, job, operation, target, credentials or artifact path.
- **Rotation and migration:** agent rotation requires old-key proof plus a fresh host bootstrap and is blocked while a dispatch is active. Protocol v1 is inventory-only for a fixed 14-day window; startup enforces the deadline and clears legacy hashes. The migration is non-downgradable and old secret-delivery endpoints remain permanently disabled.
- **Logging and audit:** bootstrap, private keys, signatures, grants, ciphertext, credentials and data keys are not written to audit detail. Security lifecycle and claim events contain identifiers and safe outcomes only.

## Conditions and residual risk

No Critical weakness remains in the reviewed source paths. Verification is conditional on:

1. human review and coordinated deployment approval for both draft PRs;
2. preserving the original `ENCRYPTION_KEY`, database and wrapped server signing key together in backup/restore exercises;
3. deploying behind HTTPS with a correctly configured static root path and trusted proxy boundary;
4. production SQLite contention/kill testing on the intended storage platform before release approval;
5. removing `KAYA_AGENT_BOOTSTRAP_TOKEN` after enrollment and protecting/backing up the agent state volume;
6. adding operational server-signing-key overlap/acknowledgement before the first server signing-key rotation.

A fully compromised active Docker agent can still receive secrets for work legitimately assigned to its host. Docker socket access remains host-equivalent privilege. These are explicit trust assumptions, not a remaining bearer-protocol bypass.

## Decision

**Verified with conditions.** The Critical bearer replay/plaintext-dispatch path is removed, v1 cannot receive secret-bearing work, and coordinated interoperability succeeds. `KAYA-BAK-001` may be recorded resolved at the implementation-review checkpoint, but neither draft PR is approved for merge by this document.
