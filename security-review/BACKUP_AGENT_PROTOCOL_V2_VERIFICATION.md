# Backup Agent Protocol v2 Verification

**Date:** 2026-08-04  
**Environment:** Docker Desktop Linux, Python 3.12 Kaya review image; Windows host orchestration; synthetic data only.

## Implemented boundary

Kaya now has durable agent identities, signing/envelope keys, hashed one-time bootstraps, lifecycle/scopes, signed requests, replay/rate controls, secret-free offers, atomic claims, signed encrypted envelopes, hashed grants, strict status transitions, key rotation and the fixed inventory-only v1 migration. The genuine production agent implements enrollment, local private-key custody, signing, envelope verification/decryption, persistent pinning and rotation.

## Evidence

- Shared Kaya request/envelope vectors: passed; the deterministic ciphertext and signature reproduce exactly.
- Production-agent shared request vector: passed.
- Direct Kaya-envelope to production-agent decrypt: passed.
- Enrollment/authentication/lifecycle/offer/claim negative suite: passed.
- Agent ciphertext/AAD/signature/expiry/binding mutation suite: passed.
- Migration matrix: 32 passed.
- Final focused protocol/migration/OIDC/RDP/demo suite: 160 passed, 878 warnings, zero failures.
- Final full Kaya supported-Linux suite: 748 passed, 11,322 warnings, zero failures.
- Agent suite: 3 passed; Ruff passed.
- Agent container build: passed (`kaya-docker-agent-protocol-v2:test`).
- `pip-audit --no-deps --disable-pip`: no known vulnerabilities in Kaya direct pins.
- Agent direct-pin audit initially found vulnerable `requests 2.32.4` and `cryptography 45.0.5`; upgraded to `requests 2.33.0` and `cryptography 50.0.0`; repeat audit found none.
- Pattern-based secret scan: no credential literals found; matches were variable assignments and synthetic fixtures.

Final post-document suite, focused OIDC/RDP/demo gates, Node syntax, diff checks and GitHub checks are recorded on the draft PR before merge approval. Container CVE tooling (`trivy`/`grype`) was not installed in this environment; the dependency audit and clean container build are not a substitute for registry scanning.

## Recovery and rollback

Upgrade revision `20260804_03` is additive. Backup/restore must preserve the database and original `ENCRYPTION_KEY` together. The migration deliberately refuses downgrade because an older application could restore bearer secret delivery. Operational rollback means stopping v2 dispatch, retaining queued jobs and rolling forward to a security-equivalent build; it does not mean re-enabling v1 jobs.
