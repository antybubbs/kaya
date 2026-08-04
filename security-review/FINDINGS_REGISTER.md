# Kaya Initial Findings Register

**State:** v0.27 hardening checkpoint, 2026-08-04
**Scope:** The eight reported starting points plus wider-pattern findings discovered while validating them. Severity follows the hardening programme. “Confirmed” means current source demonstrates the condition; it does not mean a production exploit was attempted.

## Checkpoint totals

- **Total tracked:** 9: 1 Emergency, 3 Critical and 5 High.
- **Contained:** 0.
- **Resolved:** 4 (`KAYA-DEM-001`, `KAYA-DEM-002`, `KAYA-OIDC-001`, `KAYA-RDP-002`).
- **Remediated, pending independent re-verification:** 0.
- **Changes required:** 0.
- **Fully open or blocked:** 5 (`KAYA-RDP-001`, `KAYA-BAK-001`, `KAYA-HA-001`, `KAYA-BG-001`, `KAYA-DB-001`).

## Summary

| ID | Finding | Severity | Confidence | Status |
|---|---|---:|---:|---|
| KAYA-DEM-001 | Public demo allowed Secret Vault mutations | Emergency | High | Resolved through permanent removal of the hosted demo and all demo-mode functionality |
| KAYA-DEM-002 | Demo policy is allowlist-by-path and leaves other mutations unclassified | High | High | Resolved as no longer applicable; the cross-cutting demo policy was removed |
| KAYA-OIDC-001 | Administrator-link invitation is a bearer account-takeover capability | Critical | High | Resolved; independently verified at corrective commit `b5f53ce` in PR [#61](https://github.com/antybubbs/kaya/pull/61) |
| KAYA-RDP-001 | Credential-bearing RDP token is exposed in WebSocket query strings and is replayable | High | High | Confirmed; not remediated |
| KAYA-RDP-002 | RDP certificate verification is hard-disabled | Critical | High | Resolved; independently verified with conditions at corrective commit `8ae6fbe` in PR [#60](https://github.com/antybubbs/kaya/pull/60) |
| KAYA-BAK-001 | Backup-agent bearer protocol returns plaintext credentials and data keys without replay resistance | Critical | High | Blocked; production agent source repository has not been identified |
| KAYA-HA-001 | Keepalived hook holds an exclusive lock during hold-down and slow probes | High | High | Confirmed; not remediated |
| KAYA-BG-001 | HA watchdog and lease reconciliation can terminate permanently on outer-loop exception | High | High | Confirmed; not remediated |
| KAYA-DB-001 | SQLite connection policy is inconsistent and lacks main-engine WAL/busy timeout | High | High | Confirmed configuration defect; deployment impact unverified |

## KAYA-DEM-001 — Public demo allowed Secret Vault mutations

- **Severity:** Emergency.
- **Status:** Resolved through permanent removal.
- **Resolution:** The shared hosted environment, its middleware, path policy, configuration, accounts, seed/reset lifecycle, user-interface behavior and deployment assets were removed. Secret Vault continues to use its normal authentication, module, object-authorisation, fresh-assurance and CSRF controls.
- **Tests:** Production-path regressions cover authentication, audit/session context, dashboard controls, DNS refresh behavior, module enablement and the existing Secret Vault security suites.
- **Residual risk:** None from the retired cross-cutting mode. Ordinary production security controls remain in scope for ongoing review.

## KAYA-DEM-002 — Demo policy is allowlist-by-path and leaves other mutations unclassified

- **Severity:** High.
- **Status:** Resolved as no longer applicable.
- **Resolution:** The manually maintained route allowlist/denylist and its middleware were deleted with the retired product mode. New routes no longer depend on a parallel path-string policy and must satisfy the normal authentication, authorisation, CSRF, validation and audit requirements.
- **Residual risk:** No cross-cutting demo-policy risk remains. This does not reduce the need for repository-wide production route and object-authorisation review.


## KAYA-OIDC-001 — Administrator-link invitation is a bearer account-takeover capability

- **Affected component:** OIDC link invitations and link confirmation.
- **Severity:** Critical.
- **Confidence:** High.
- **Status:** Resolved. Independent re-verification found no remaining Critical weakness at corrective commit `b5f53ceba109a9d7be30931b76932719d9a1ddcc` in PR [#61](https://github.com/antybubbs/kaya/pull/61).
- **Evidence:** `create_link_invitation` creates a 30-minute random token stored by SHA-256. `accept_link_invitation` accepts the unauthenticated query token, marks it used, and starts an `admin_link` transaction targeting the chosen user. `resolve_login` accepts any valid unlinked IdP identity into that transaction. `confirm_transaction_link` checks current-user ownership only for `self_link`, and requires a password only for `email_match`; `admin_link` requires neither. `link_confirm_submit` starts a Kaya session as the target when there was no current user.
- **Safe reproduction:** In a test database, create an administrator target and invitation, redeem it in a clean browser session, complete OIDC with a synthetic valid unlinked subject, confirm without target password, and observe `ExternalIdentity.user_id == target.id` plus a target session. Do not run against a live IdP.
- **Affected files:** `app/routers/oidc.py:292-331, 635-658`, `app/services/oidc_identity.py:139-214`, OIDC models/migrations and templates.
- **Root cause:** Possession of an administrator-created URL is treated as authorisation to bind the target account. The IdP proves control of the new identity, not that the actor is the intended Kaya recipient.
- **Wider pattern search:** Self-link correctly binds the active user; email-match correctly asks for local proof. Invitation is consumed before completion, enabling invitation denial-of-service. There is no explicit revoked state or invalidation on target changes.
- **Remediation:** Recipient session ownership, password/TOTP step-up and verified email/provider binding remain. The corrective commit requires signed ID-token `auth_time` within 60 seconds of the trusted transaction start, atomically consumes state with a conditional database update, and adds pending/claimed/completed/revoked/expired invitation states. Claimed invitations can be atomically revoked; final completion and identity creation commit together. See ADR-0002 and `security-review/reviews/OIDC_INDEPENDENT_REVIEW.md`.
- **Tests:** Focused Linux command `python -m pytest -p no:cacheprovider tests/test_oidc_identity.py tests/test_oidc_routes.py tests/test_oidc_security.py tests/test_database_migrations.py -q` passed 124 tests with 0 failures and 0 skips. Coverage includes malformed/missing/stale/future/tampered `auth_time`, prompt-with-stale-session, file-backed concurrent state consumption, restart/rollback/crash behavior, claimed revocation, revoke-versus-complete concurrency, lifecycle UI state, audit actor/redaction and migration. Ruff passed every changed Python file. Independent re-verification and the final full supported-Linux run remain required.
- **Migration impact:** Existing unused invitations should be revoked on upgrade. Existing linked identities must not be silently removed. Preserve a tested local break-glass administrator and document recovery.
- **Residual risk:** Providers without signed `auth_time` fail closed for this flow and may require operator/provider changes. Real-provider interoperability and reverse-proxy log behavior remain deployment-specific. Email/IdP or recipient-account compromise remains relevant even after binding.

## KAYA-RDP-001 — Credential-bearing RDP token is exposed in WebSocket query strings and is replayable

- **Affected component:** RDP start endpoint, browser client, Kaya RDP WebSocket, and Guacamole bridge.
- **Severity:** High.
- **Confidence:** High.
- **Status:** High and open. This finding was deliberately not remediated in the current checkpoint.
- **Evidence:** `create_rdp_guacamole_token` serialises hostname, username and password into a Fernet token. The start route returns that token to JavaScript. `remote_rdp.js` puts it into `URLSearchParams` passed to `client.connect`; Kaya reads `websocket.query_params["token"]` and forwards it in the bridge URL. The token is also the in-memory dictionary key. Default lifetime is 10 minutes and it is not consumed on an ordinary initial connection; only a handoff path pops it.
- **Safe reproduction:** Use clearly fake credentials, call the token helper, and inspect the constructed browser/Kaya/upstream WebSocket URLs. Reconnect using the same token and active matching session before expiry; current lookup accepts it.
- **Affected files:** `app/routers/remote_manager.py:481-608, 1145-1185, 1287-1340`, `app/static/js/remote_rdp.js:410-487`, `scripts/guacamole-server.cjs`.
- **Root cause:** Guacamole's encrypted-token transport object is also used as the browser grant and URL credential. Encryption was treated as sufficient for the URL/log lifecycle.
- **Wider pattern search:** OIDC/reset/invitation tokens also use browser URLs, but do not embed remote passwords. Audit failure strings may contain upstream URL/error data and need redaction tests.
- **Remediation:** Authenticated POST creates an opaque random grant ID; encrypted credential stays server-side; WebSocket requires active session plus origin and one-time grant; grant is atomically consumed, short-lived, remote/user/connection-bound and never forwarded in a URL. Bridge connection data should use an internal non-URL channel.
- **Tests:** Add URL/log absence, wrong user/remote, expired, single-use, replay, concurrent consume, revoked session, bad Origin, handoff, disconnect cleanup and audit-redaction tests.
- **Migration impact:** Browser/bridge protocol changes must be deployed atomically. Existing in-memory grants can expire on restart; no persistent data migration is needed.
- **Residual risk:** Encrypted credential-bearing connection data remains present in WebSocket query data and is replayable within its validity and session constraints. Operators should restrict proxy/access logging, protect browser sessions, limit network exposure and treat captured RDP connection URLs as sensitive until opaque one-time grants are implemented.

## KAYA-RDP-002 — RDP certificate verification is hard-disabled

- **Affected component:** RDP connection settings in Kaya and the Guacamole bridge.
- **Severity:** Critical.
- **Confidence:** High.
- **Status:** Resolved. Fresh independent re-verification result: Verified with conditions at corrective commit `8ae6fbe`.
- **Evidence:** The original paths universally disabled certificate validation. PR #60 now enforces system-CA validation or an explicit SHA-256 pin, disables bypass/TOFU, atomically invalidates trust on every supported effective endpoint writer, and blocks downgrade across the minimum safe database boundary. See `security-review/reviews/RDP_CERTIFICATE_INDEPENDENT_REVIEW.md`.
- **Safe reproduction:** Generate a fake RDP token and decrypt it in a controlled test; the setting is true. Bridge default configuration independently has the same value. No real RDP server is required.
- **Affected files:** `app/routers/remote_manager.py`, `scripts/guacamole-server.cjs`, remote models/settings/templates/tests.
- **Root cause:** Compatibility with self-signed RDP hosts was implemented as universal certificate acceptance.
- **Wider pattern search:** SSH uses explicit host-key scan and pinning and is the safer local precedent. OIDC/provider TLS has an explicit administrator-controlled flag, though disabling it remains risky.
- **Remediation:** Implemented strict system-CA validation by default, explicit per-host SHA-256 pins for self-signed/private endpoints, disabled TOFU, administrator-only CSRF-protected trust changes, independent-verification acknowledgement, audit redaction, protocol/port invalidation, legacy inventory and rotation guidance. See ADR-0003.
- **Tests:** The 56-test focused Linux suite passes. Live synthetic checks reject unknown, mismatched, expired and changed certificates, accept the exact SHA-256 pin, and confirm bypass/TOFU remain absent. The seventh URL/log check reconfirms separate High finding `KAYA-RDP-001`. Independent re-review remains required before closure.
- **Migration impact:** Existing RDP connections may fail until trust is enrolled. Revision `20260804_02` retains invalidation evidence and blocks insecure downgrade; a pre-fix restore under secure code upgrades to strict CA validation without auto-trust.
- **Residual risk:** A trusted CA or pinned endpoint can still be compromised; document renewal and pin rotation.

## KAYA-BAK-001 — Backup-agent bearer protocol returns plaintext credentials and data keys without replay resistance

- **Affected component:** Compute/backup agent enrollment and Backup Manager agent API.
- **Severity:** Critical.
- **Confidence:** High.
- **Status:** Critical and blocked. The genuine external Docker-agent production source repository has not been identified, so coordinated protocol-v2 implementation and interoperability verification cannot proceed safely.
- **Evidence:** `require_agent_host` hashes a reusable Authorization bearer value and looks up a `docker_agent` host. It has no signature, timestamp, nonce, session grant, explicit scope, or `is_enabled` check. `agent_jobs` decrypts the selected target's `remote_password` and each job's `encrypted_backup_key` into the JSON response. Tokens are long-lived until regeneration.
- **Safe reproduction:** In an in-memory database, create a fake docker agent, target password ciphertext and queued job, call `agent_jobs` with the fake bearer, and observe plaintext fake values. Repeat or set `host.is_enabled=False`; authentication logic remains token-based. Existing tests already construct this boundary without live secrets.
- **Affected files:** `app/routers/backup_manager.py:69-87, 176-194, 610-689`, `app/routers/compute_manager.py`, `app/models/models.py:1334-1362, 1449-1471`, agent implementation outside repository if applicable.
- **Root cause:** Inventory-agent bearer authentication was reused for high-impact secret delivery. Agent lifecycle lacks first-class identity state, request freshness and least-privilege scopes.
- **Wider pattern search:** Status updates are host-bound, which is positive. HA agents already implement per-agent signed requests, replay tracking, rotation and revocation and provide an architectural precedent. Legacy `encrypted_agent_token` is intentionally not written for new agents.
- **Remediation:** New machine-auth ADR; secure enrollment; per-agent signing key or mTLS; signed method/path/body/timestamp/nonce; bounded skew and replay cache; short-lived scoped dispatch grant; explicit active/revoked/decommissioned state; rate limits; key rotation; response minimisation; envelope encryption separating authentication and data keys; auditable acknowledgements.
- **Tests:** Missing/invalid/revoked/disabled identity, wrong scope/host/job, stale/future timestamp, nonce replay, signature/body/path modification, concurrent dispatch, token/key rotation, decommission denial, least-data response, and log/traceback redaction.
- **Migration impact:** Requires a coordinated server/production-agent rollout or forced re-enrollment with a deadline. Do not silently retain bearer fallback for secret delivery. Existing queued jobs and agents need an operator-visible migration state.
- **Blocker:** Identify and obtain the production Docker-agent source repository, then record its repository, branch and release ownership. No replacement, stub or fake agent implementation may be used to claim remediation.
- **Residual risk:** A fully compromised enrolled agent can access secrets legitimately dispatched to it. Containment depends on scopes, rotation, job-level grants and minimal secret lifetime.

## KAYA-HA-001 — Keepalived hook holds an exclusive lock during hold-down and slow probes

- **Affected component:** Local HA agent Keepalived transition hook.
- **Severity:** High.
- **Confidence:** High.
- **Status:** Confirmed; no remediation applied.
- **Evidence:** `main` acquires `fcntl.LOCK_EX` at `ha_agent/kaya_ha_transition.py:184` and calls `automatic_transition` before leaving the context. MASTER processing sleeps 5–60 seconds at line 77, then runs DNS, ARP and privileged helper subprocesses with timeouts up to 60 seconds. All are inside the exclusive lock.
- **Safe reproduction:** Unit test with a temporary lock/state database, fake sleep/runner, and two hook processes/threads: block MASTER in hold-down and observe BACKUP cannot enter the critical section. Do not manipulate live Keepalived or DHCP.
- **Affected files:** `ha_agent/kaya_ha_transition.py`, Keepalived runtime/installer files, HA agent resilience and automatic-failover tests.
- **Root cause:** One lock serialises both small state updates and the entire slow transition workflow.
- **Wider pattern search:** Root failover helper has its own lock for privileged mutation; review its scope separately. Database busy retries also sleep, but the primary delay is intentional hold-down/probes under file lock.
- **Remediation:** Under lock, validate generation and record a unique transition intent; release; hold down/probe; reacquire; reject stale/superseded intent; atomically claim final application; run only the smallest necessary privileged critical section; reconcile final state and emit durable events.
- **Tests:** Simultaneous MASTER/BACKUP, duplicates, delay, quick failback, stale intent, restart during hold-down, probe/helper failure, lock contention/recovery, dual active claim, and final reconciliation.
- **Migration impact:** HA agent version/protocol and installer files change. Kaya should gate automatic failover on upgraded agents and provide rollback semantics.
- **Residual risk:** OS scheduling and external helper latency remain; state-machine correctness must be independently reviewed on real Pi-hole/Keepalived hosts.

## KAYA-BG-001 — HA watchdog and lease reconciliation can terminate permanently on outer-loop exception

- **Affected component:** In-process HA watchdog and lease reconciliation services.
- **Severity:** High.
- **Confidence:** High.
- **Status:** Confirmed; no remediation applied.
- **Evidence:** Both loops await `asyncio.to_thread(run_*_pass)` without an outer `try/except`. Exceptions from session creation, settings lookup, query setup, thread scheduling, or unexpected pass return escape the coroutine and complete its retained task. The sync monitor wraps its equivalent call, re-raises cancellation, logs, delays and continues, proving the inconsistency.
- **Safe reproduction:** Monkeypatch each pass to raise a synthetic exception once then return. Await the loop with controlled sleep: watchdog/lease tasks terminate after the first raise; sync continues. No live HA action is required.
- **Affected files:** `app/services/ha_watchdog.py:72-77`, `app/services/ha_lease_monitor.py:53-58`, `app/services/ha_sync_monitor.py:163-177`, `app/main.py:397-433`, tests.
- **Root cause:** Per-cluster exception handling was mistaken for permanent-loop supervision. There is no common supervisor/heartbeat contract.
- **Wider pattern search:** Other permanent loops have heterogeneous retry/cancellation behaviour. Notification runtime has a substantially stronger supervisor pattern; all loops require Phase 9 inventory.
- **Remediation:** Common named supervisor with retained task, cancellation preservation, exception classification, bounded exponential backoff/jitter, startup/shutdown logs, heartbeat, last success/error and restart count diagnostics. Do not catch and hide invariant corruption.
- **Tests:** One-shot and repeated pass failure recovery, cancellation, backoff bounds, session-factory failure, health freshness, restart count and graceful shutdown.
- **Migration impact:** No data migration. Diagnostic schema/settings may require migration if persisted.
- **Residual risk:** In-process supervision cannot survive process death and duplicates under multiple workers. Supported single-process deployment must remain explicit until leader election/external workers exist.

## KAYA-DB-001 — SQLite connection policy is inconsistent and lacks main-engine WAL/busy timeout

- **Affected component:** Main SQLAlchemy engine, direct SQLite utilities, legacy migration, backup and HA agent databases.
- **Severity:** High.
- **Confidence:** High for configuration inconsistency; Medium for deployment-specific corruption/availability impact.
- **Status:** Confirmed; no configuration change applied pending deployment tests.
- **Evidence:** `app/db/session.py` sets only `check_same_thread=False`, `pool_pre_ping`, and `PRAGMA foreign_keys=ON`. It does not set `busy_timeout` or WAL. Migration and backup direct connections set a busy timeout. HA agent state explicitly sets WAL and busy timeout. `scripts/migrate_sqlite.py` uses a direct connection and temporarily disables foreign keys.
- **Safe reproduction:** Create a temporary file database through `app.db.session`-equivalent engine settings and inspect `PRAGMA journal_mode` and `PRAGMA busy_timeout`; then hold a writer transaction and attempt a second write. Production bind/network mounts were not tested.
- **Affected files:** `app/db/session.py`, `app/db/migrations.py`, `app/db/backup.py`, `app/db/validation.py`, `scripts/migrate_sqlite.py`, HA agent SQLite code, deployment/database docs and tests.
- **Root cause:** Connection policy evolved separately in runtime, migration, backup, agent and legacy scripts. SQLite concurrency requirements are not a central contract.
- **Wider pattern search:** Tests create many independent in-memory engines, often with foreign-key hooks but no common helper, so runtime PRAGMA regressions are easy to miss.
- **Remediation:** First qualify WAL on supported local filesystems and Docker bind mounts; centralise SQLite engine/connect PRAGMAs and busy timeout; keep transactions short; add narrowly bounded lock retries at idempotent boundaries; define checkpoint/backup/shutdown/integrity policy; document unsupported network filesystems and PostgreSQL threshold.
- **Tests:** Runtime PRAGMAs for every connection, two realistic background writers plus request writer, lock retry/rollback, reader during writer, abrupt termination, checkpoint growth, backup/restore with WAL, migration upgrade/rollback, Docker bind mount, and network-mount warning behaviour.
- **Migration impact:** Enabling WAL creates `-wal`/`-shm` files and changes backup/restore and downgrade operations. Rollout requires docs, clean checkpoint, backup verification and a rollback plan.
- **Residual risk:** WAL improves concurrency but does not make high-write/multi-replica SQLite safe. Owner must define the deployment point requiring PostgreSQL or another server database.

## Cross-finding release position

`KAYA-DEM-001`, `KAYA-DEM-002`, `KAYA-OIDC-001` and `KAYA-RDP-002` are resolved. `KAYA-BAK-001` remains Critical and blocked pending identification of the genuine production agent source. `KAYA-RDP-001` and the other deferred High findings remain open. No release-readiness claim is made by this checkpoint.
