# Initial Remediation and Pull-Request Plan

**State:** Proposed after Phase 1–3 review. Ordering may change after owner/human review. Each item must remain a small reviewable change and cite finding IDs.

**Corrective checkpoint:** `KAYA-OIDC-001` is independently verified and resolved; `KAYA-RDP-002` still requires its separate re-verification gate. Six findings remain fully open. Preserve PR order [#58](https://github.com/antybubbs/kaya/pull/58) → [#61](https://github.com/antybubbs/kaya/pull/61) → [#60](https://github.com/antybubbs/kaya/pull/60) → [#59](https://github.com/antybubbs/kaya/pull/59).

## Sequence

1. **Baseline and emergency Vault containment** — `KAYA-DEM-001`, `KAYA-DEM-002`. Land the three Phase 1–3 reports and the focused Secret Vault demo prefix/test. No claim that demo mode is otherwise safe.
2. **Administrator invitation containment and migration** — `KAYA-OIDC-001`. Corrective commit `b5f53ce` on PR #61 enforces signed `auth_time`, atomic state consumption and an atomically revocable invitation lifecycle. Fresh adversarial re-verification and the repeated 124-test focused Linux suite pass. Status is resolved and eligible for the controlled stack merge after PR #58.
3. **RDP certificate trust** — `KAYA-RDP-002`. Secure default first, administrator-only CA/certificate/fingerprint enrollment, legacy-host inventory/warnings, audit and rejection tests. This is separate from grant transport so reviewers can assess trust semantics independently.
4. **RDP opaque one-time grants** — `KAYA-RDP-001`. Remove credential-bearing query tokens across browser, Kaya, and bridge; add server-side encrypted one-use grants, atomic consume, strict expiry/binding and URL/log/replay tests.
5. **Backup agent machine-authentication ADR and protocol** — `KAYA-BAK-001`. Agree signing versus mTLS, enrollment, scopes, replay storage, key lifecycle and migration. Then implement server support, agent support, dual-protocol migration window with no bearer fallback for secret delivery, decommission denial, envelope/minimal secret response and tests.
6. **HA transition intent state machine** — `KAYA-HA-001`. Version-gated agent change that releases the lock during hold-down, records/revalidates intent, rejects stale work, reconciles final state and passes concurrency/restart/failure tests.
7. **Common background supervision** — `KAYA-BG-001`. Define shared task health/backoff/cancellation pattern using notification runtime lessons; first convert HA watchdog/lease/sync, then inventory and migrate other critical loops without hiding programming defects.
8. **SQLite deployment qualification and central policy** — `KAYA-DB-001`. Run bind-mount/WAL/backup/migration/crash tests before enabling runtime changes. Centralise connect PRAGMAs, add bounded contention handling, checkpoint/integrity diagnostics and supported-deployment/PostgreSQL threshold documentation.
9. **Declarative demo deny-by-default policy** — `KAYA-DEM-002`. Classify every HTTP method, side-effecting GET and WebSocket; block unknown sensitive/state operations; permit only documented safe simulations; add exhaustive route enumeration. This is intentionally after immediate Critical containment but before release.
10. **Wider application review and object-authorisation matrix** — Execute Phase 11 across every router/service/file path, fixing Emergency/Critical/High findings in separate PRs.
11. **Automated controls and dependency/supply-chain gates** — Configure high-signal secret, dependency, static Python, container and SBOM controls; document suppressions; make high-confidence Critical results fail CI.
12. **Final documentation, migration rehearsal and independent verification** — Complete ADRs, deployment/backup/key/incident docs, release checklist and security-focused release notes; run fresh install, upgrade, rollback and restore; complete `VERIFICATION_REPORT.md`; obtain a separate human/adversarial review.

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

- Do not expose a demo deployment to real credentials, production integrations, remote hosts, backup targets, HA nodes or durable visitor data.
- Disable or isolate RDP where certificate identity cannot be independently trusted; assume current RDP WebSocket URLs are sensitive.
- Treat backup-agent bearer tokens as high-impact credentials; rotate suspected tokens and isolate agent/Kaya transport behind trusted TLS/network controls. Disabling a host alone is not proven to revoke current bearer access.
- Revoke or avoid issuing OIDC administrator-link invitations until recipient-bound remediation lands; retain a tested local break-glass administrator.
- Monitor HA watchdog/lease task health externally and restart the Kaya process after a confirmed task death; do not treat this as a software fix.
- Keep SQLite on supported local storage with one Kaya process; preserve database, uploads, recordings and the separate `ENCRYPTION_KEY` in backups.

## Gates for leaving Phase 3

- Human owner reviews severity and operational assumptions.
- Emergency Vault containment is reviewed and deployed to any public demo.
- Critical PR owners and migration choices are assigned.
- No finding is marked fixed solely from this source review.
