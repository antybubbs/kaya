# Initial Remediation and Pull-Request Plan

**State:** Proposed after Phase 1–3 review. Ordering may change after owner/human review. Each item must remain a small reviewable change and cite finding IDs.

**Corrective checkpoint:** `KAYA-OIDC-001` is independently Verified and `KAYA-RDP-002` is independently Verified with conditions; both are resolved and merged through the controlled PR #58 → #61 → #60 sequence. `KAYA-DEM-001` and `KAYA-DEM-002` are resolved through permanent removal. Five findings remain open or blocked. Live certificate checks 1–6 pass; check 7 reconfirms separate High finding `KAYA-RDP-001`. PR #59 remains unmerged.

## Sequence

1. **Retire shared public evaluation mode** — `KAYA-DEM-001`, `KAYA-DEM-002`. Completed through removal of the hosted link, cross-cutting runtime mode, shared accounts, route policy, seed/reset lifecycle, interface and deployment assets.
2. **Administrator invitation containment and migration** — `KAYA-OIDC-001`. Corrective commit `b5f53ce` on PR #61 enforces signed `auth_time`, atomic state consumption and an atomically revocable invitation lifecycle. Fresh adversarial re-verification and the repeated 124-test focused Linux suite pass. Status is resolved and eligible for the controlled stack merge after PR #58.
3. **RDP certificate trust** — `KAYA-RDP-002`. Corrective commit `8ae6fbe` on PR #60 centralizes endpoint-change invalidation, retains a durable fail-closed marker, blocks insecure downgrade, transports validated pins in the supported FreeRDP format and passes fresh adversarial review, the repeated 56-test focused Linux suite and live synthetic certificate checks. Status is resolved with the documented TLS-only and `KAYA-RDP-001` conditions.
4. **RDP opaque one-time grants** — `KAYA-RDP-001`. Remove credential-bearing query tokens across browser, Kaya, and bridge; add server-side encrypted one-use grants, atomic consume, strict expiry/binding and URL/log/replay tests.
5. **Backup agent machine-authentication ADR and protocol** — `KAYA-BAK-001`. Critical and blocked until the genuine production Docker-agent source repository is identified. Do not implement a server-only substitute, replacement, stub or fake agent. After identification, coordinate server and production-agent implementation, migration, interoperability and independent review.
6. **HA transition intent state machine** — `KAYA-HA-001`. Version-gated agent change that releases the lock during hold-down, records/revalidates intent, rejects stale work, reconciles final state and passes concurrency/restart/failure tests.
7. **Common background supervision** — `KAYA-BG-001`. Define shared task health/backoff/cancellation pattern using notification runtime lessons; first convert HA watchdog/lease/sync, then inventory and migrate other critical loops without hiding programming defects.
8. **SQLite deployment qualification and central policy** — `KAYA-DB-001`. Run bind-mount/WAL/backup/migration/crash tests before enabling runtime changes. Centralise connect PRAGMAs, add bounded contention handling, checkpoint/integrity diagnostics and supported-deployment/PostgreSQL threshold documentation.
9. **Wider application review and object-authorisation matrix** — Execute Phase 11 across every router/service/file path, fixing Emergency/Critical/High findings in separate PRs.
10. **Automated controls and dependency/supply-chain gates** — Configure high-signal secret, dependency, static Python, container and SBOM controls; document suppressions; make high-confidence Critical results fail CI.
11. **Final documentation, migration rehearsal and independent verification** — Complete ADRs, deployment/backup/key/incident docs, release checklist and security-focused release notes; run fresh install, upgrade, rollback and restore; complete `VERIFICATION_REPORT.md`; obtain a separate human/adversarial review.

## Required content for every remediation PR

- Finding IDs, exploit/root-cause statement and affected trust boundaries.
- Authentication, role and object-level rules.
- Input, output, secret transport/storage/logging and audit decisions.
- Compatibility, data migration, rollout, rollback and recovery.
- Regression tests that fail against the vulnerable design and negative tests for every unauthorised actor.
- Exact test commands/results and remaining assumptions.
- Engineering Standards and ADR impact.
- The mandatory `Security Impact` completion section.

## Immediate operational guidance pending fixes

- Disable or isolate RDP where certificate identity cannot be independently trusted; assume current RDP WebSocket URLs are sensitive.
- Treat backup-agent bearer tokens as high-impact credentials; rotate suspected tokens and isolate agent/Kaya transport behind trusted TLS/network controls. Disabling a host alone is not proven to revoke current bearer access.
- Revoke or avoid issuing OIDC administrator-link invitations until recipient-bound remediation lands; retain a tested local break-glass administrator.
- Monitor HA watchdog/lease task health externally and restart the Kaya process after a confirmed task death; do not treat this as a software fix.
- Keep SQLite on supported local storage with one Kaya process; preserve database, uploads, recordings and the separate `ENCRYPTION_KEY` in backups.

## Gates for leaving Phase 3

- Human owner reviews severity and operational assumptions.
- Hosted evaluation infrastructure is retired separately through the owner's controlled operational process.
- Critical PR owners and migration choices are assigned.
- No finding is marked fixed solely from this source review.
