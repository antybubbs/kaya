# Kaya Threat Model

**Method:** STRIDE with explicit abuse cases
**State:** Initial Phase 2 model, 2026-08-04
**Scope:** Repository implementation and documented single-process Docker deployment. This is not a penetration test or a claim of complete security.

## Assets and trust boundaries

Primary assets are administrator control, user sessions, OIDC identity bindings, Vault and Secure Send plaintext, remote credentials and sessions, backup credentials/data keys/artifacts, HA control authority, notification subscriptions, uploaded files, the application encryption key, audit history, and database integrity.

Trust boundaries:

1. Public browser to reverse proxy and Kaya.
2. Authenticated browser session to role, module, and object permissions.
3. Kaya to OIDC, SMTP, DNS, compute, remote, push, and version services.
4. Browser to WebSocket endpoints and local SSH/RDP bridges.
5. Kaya to backup and HA agents.
6. Kaya process to SQLite and persistent files.
7. Keepalived/root helpers to the unprivileged HA agent state database.
8. Public Secure Send recipient to the isolated gateway.
9. Public demo user to shared synthetic application state.

## STRIDE legend

- **S — Spoofing:** pretending to be another user, agent, provider, or node.
- **T — Tampering:** unauthorised modification of data, requests, files, or state.
- **R — Repudiation:** actions cannot be reliably attributed or reconstructed.
- **I — Information disclosure:** secret or personal data escapes its intended boundary.
- **D — Denial of service:** availability or recovery is impaired.
- **E — Elevation of privilege:** an actor gains stronger authority.

## Authentication, sessions, and account recovery

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| Attacker brute-forces local or reset credentials, rotates source IP, or exploits process restart to reset counters | S, E | Argon2, optional TOTP, generic errors, in-memory client/email throttles, audit | Distributed/persistent limiting and bypass tests are absent. Trusted client-IP configuration is security-critical. |
| Stolen signed cookie remains usable after logout, disablement, password reset, or role change | S, E | Server `AppSession` must be active; logout/reset revoke rows; user active state checked every request | Verify all security changes revoke appropriate sessions; test concurrent sessions and role/module removal. |
| Session fixation through preserving identifiers across login | S | Login paths clear session before setting identity; new random server session ID | Add explicit fixation regression tests across local, OIDC, and 2FA completion. |
| Reset token leaks through mail, history, Referer, proxy logs, or screenshots | I, E | Random token, hash at rest, one-hour expiry, single use, no audit token | Add `Referrer-Policy`/no-store verification on reset pages and concurrent single-use tests. |
| Cross-site request changes password, TOTP, or profile | T, E | CSRF token on browser POSTs; strict/signed cookie settings | Whole-route CSRF enumeration is not present. |

## OIDC account linking and administrator invitations

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| Attacker steals an administrator-link URL, authenticates an attacker-controlled IdP identity, links it to the target administrator, then receives a Kaya session | S, E | 30-minute random invitation, hash at rest, IdP token validation, explicit confirmation | No proof that redeemer is target recipient; no reauthentication; confirmed `KAYA-OIDC-001`. Bind invitation to recipient and fresh target authentication before link. |
| Invitation is replayed, modified, revoked, or redeemed concurrently | S, T | Hash lookup, expiry, `used_at`; modified tokens fail | Used before OIDC completes, no explicit revocation field, no atomic redemption guarantee, and no test matrix. Add revocation and transactional single-use. |
| OIDC state/nonce/PKCE is bypassed or stale transaction reused | S, E | Hashed state/transaction, encrypted nonce/verifier, expiry and consumption | Existing tests are material; add concurrency and provider-configuration-change invalidation. |
| Automatic email match links attacker identity after email-claim confusion | S, E | Verified-email policy and configurable matching mode | Treat issuer/subject as authority; test claim mapping changes, duplicate/case variants, and provider compromise assumptions. |
| Role-mapped OIDC login removes last administrator or escalates viewer | T, E | Role mapping and last-admin protections in identity service | Expand negative tests for changed groups, stale claims, and concurrent admin changes. |

## Secret Vault

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| User guesses item/attachment/collection IDs to read another user's secrets | I, E | Owner/member lookup and 404 concealment; unlocked-session checks | Build a full owner/member/permission matrix for every route, including attachment and restore references. |
| Shared collection member upgrades permission or moves an item to escape scope | T, E | Enumerated member levels and route checks | Test contributor/manager/viewer boundaries and concurrent membership removal. |
| Vault plaintext leaks to logs, audit, export, exception, or temporary file | I | Encrypted payloads/files, safe audit helper, source tests | Add runtime log-capture tests and failure-injection cleanup tests. Portable export remains highly sensitive. |
| Stolen session unlocks or reveals secrets without fresh assurance | S, I | Separate Vault sessions, PIN plus TOTP/OIDC assurance, TOTP replay rejection | Validate reauthentication for every reveal/export/recovery action and disabled-user revocation. |
| Public demo user creates, restores, exports, shares, or changes Vault state | T, I | Emergency central prefix containment now blocks non-safe methods | GET secret retrieval remains allowed for seeded user-owned material; Phase 4 must decide explicit safe demo views. |

## Secure Send

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| Stolen URL token alone downloads content | S, I | Token plus sender PIN plus generated passphrase and recipient session | Confirm proxy logs never retain token and passphrase/PIN rate limits cannot be bypassed across replicas. |
| Recipient replays download after one-download completion, expiry, revocation, or deletion | S, I | Server-side state revokes access; cleanup destroys ciphertext | Continue negative/replay/clock tests and crash-between-download-and-state-update analysis. |
| Malicious upload exhausts storage or abuses archive/download names | T, D | Size limits, encrypted storage, constrained gateway | Validate aggregate limits, decompression behaviour, filenames, content sniffing, and cleanup under failure. |

## Remote Manager and RDP WebSockets

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| Proxy, browser tooling, access log, monitoring, or error system records RDP WebSocket URL containing encrypted credentials | I | Fernet confidentiality; session/user/remote binding in memory; origin check | Encryption does not remove URL lifecycle exposure; confirmed `KAYA-RDP-001`. Use opaque, one-use, server-side grants. |
| Stolen RDP URL is replayed during its 5–60 minute lifetime | S, E | Requires victim's active Kaya session and matching user/remote | Token is reusable except one handoff path and itself contains credentials. Consume atomically on first connection and bind connection intent. |
| Man-in-the-middle presents any RDP certificate | S, I, T | Strict system-CA validation or explicit per-host SHA-256 pin; bypass and TOFU disabled; admin-only enrollment | `KAYA-RDP-002` remediation implemented; live synthetic RDP-server and independent review pending. |
| Cross-origin site drives an authenticated WebSocket | S, T | Origin required and matched to host/base/allowlist; active server session and module dependency | Preserve tests for malformed hosts, wildcards, forwarded hosts, disabled users, and revoked sessions. |
| SSH/RDP errors disclose credentials, paths, or upstream internals | I | Audit messages intend to omit password | Some exceptions are returned/audited verbatim. Add structured safe error mapping and log capture tests. |
| User accesses another user's recording or remote object | I, E | Role/object checks exist per route | Complete anonymous/viewer/editor/admin/owner tests for every stream, download, deletion, and WebSocket. |

## Backup agents

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| Stolen long-lived bearer token polls jobs and receives remote password plus backup key | S, I, E | Token hash at rest and host job scoping | No signing, timestamp, nonce, short session, or second factor; confirmed `KAYA-BAK-001`. |
| Captured GET response/request is replayed to obtain secrets again | S, I | Job status moves from queued to dispatched on first response | Request has no replay proof; response loss/retry semantics are undefined; bearer remains valid. Use signed one-time dispatch grants and acknowledged secret envelopes. |
| Disabled/decommissioned agent continues to authenticate | S, E | Token regeneration exists | `require_agent_host` does not check `is_enabled` or explicit revocation state. Fail closed after decommissioning. |
| Compromised agent accesses another host's job or reports status for it | T, E | Job `host_id` binding on status and dispatch | Preserve object-binding tests and add signed request identity binding. |
| Agent log/diagnostic captures plaintext target password or key | I, R | Server audit excludes values | Agent-side lifecycle and log redaction are not represented in this repository review. Minimise response and zeroise where practical. |

## HA and Keepalived

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| MASTER hook holds exclusive lock during 5–60 second sleep and probes; BACKUP/FAULT notification waits, delaying demotion or leaving stale ownership | D, T | Exclusive file lock serialises hooks; generation check and safety probes | Lock scope is excessive; confirmed `KAYA-HA-001`. Record intent, release lock, wait, reacquire and revalidate generation/state. |
| Duplicate/out-of-order notifications apply stale DHCP/VIP transition | T, D | Generation value and fixed-purpose root helper; events and observed state | Add intent IDs, idempotency, stale-intent cancellation, restart reconciliation, and concurrency tests. |
| Process crashes mid-transition | T, D | Local state database and conservative helper checks | Explicit recoverable transition state and startup reconciliation are incomplete. |
| Compromised agent forges heartbeats/actions | S, T, E | Per-agent signed protocol, replay/request tracking, rotation/revocation | Maintain test coverage and protect bootstrap/recovery paths. |
| Multiple nodes claim active state | T, D | VIP/DHCP safety observations, duplicate-address probe, reconciliation | Exercise simultaneous MASTER, partition, stale telemetry, and dual-active recovery tests. |

## Background services and notifications

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| HA watchdog or lease pass raises before per-cluster handler and task dies silently forever | D, R | Task handle retained; per-cluster exceptions caught | Outer loop lacks exception isolation/restart; confirmed `KAYA-BG-001`. Add common supervision, health, last success/error, backoff. |
| Broad exception handler hides programming corruption and endlessly retries | T, R, D | Traceback logging in several loops | Classify operational vs invariant failures; quarantine unsafe work and surface diagnostics. |
| Duplicate notification is sent after retry/restart | R, D | Durable outbox, deduplication keys, recipient history, supervisor | Test crash at claim/send/ack boundaries and multi-process limitation. |
| Provider outage prevents source action or drops notification | D | Source action separated from durable delivery for notification pipeline | Verify every producer commits source/outbox atomically where supported. |
| Push endpoint/key leaks in logs or diagnostics | I | Redaction-focused notification design | Keep runtime log-capture tests; never include subscription endpoint in audit/history. |

## File handling

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| Filename traverses out of storage root or overwrites another object | T, I, E | Generated storage IDs and path checks in stronger modules | General attachment/import implementations differ; test every upload/download path with traversal and collision cases. |
| Oversized upload fills memory/disk; partial file remains after cancellation | D | Per-feature size limits and partial-file pattern for recordings | Add aggregate quota, free-space, cancellation, cleanup and concurrent-upload tests. |
| Stored HTML/SVG/Markdown causes XSS | I, E | Jinja autoescaping and content-type handling | Review runbook rendering, uploaded active content, filename headers, and inline media CSP. |
| Archive/import contains formulas, malicious paths, or excessive records | T, D | CSV/import validation exists per module | Add row/column/size bounds and formula/archive traversal tests consistently. |

## Demo mode

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| Malicious shared admin invokes a new mutation absent from prefix allowlist | T, E, D | Central middleware plus hand-maintained prefixes/suffixes | Policy is allowlist-by-omission, not deny-by-default; confirmed `KAYA-DEM-002`. Generate policy from declarative route metadata and fail tests on unclassified routes. |
| Demo user stores real credentials/secrets that another visitor retrieves | I | Reset schedule, some module locks, new Vault mutation containment | Licence, compute-agent, notification, upload/import and other paths require classification. UI hiding is insufficient. |
| Shared demo exposes visitor IP/user-agent to the next visitor | I | Demo audit/session code removes these values | Existing client-IP tests should remain release gates. |

## SQLite concurrency and encryption-key management

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| Background writer and request writer contend; one gets immediate `database is locked`, rolls back partial work, or kills its loop | D, T | Transactions and selective retry; migration/backup busy timeouts | Main engine lacks consistent busy timeout/WAL; confirmed `KAYA-DB-001`. Centralise policy and test realistic writers. |
| WAL is enabled blindly on unsuitable network/bind storage; checkpoint grows or backup misses WAL state | D, T | WAL not currently enabled for main DB; SQLite backup API used for migrations | Deployment qualification must precede enablement; document unsupported network filesystems and checkpoint/backup behaviour. |
| `ENCRYPTION_KEY` is lost, replaced, logged, or passed to an unsafe child | I, D | Production validation; persistent runtime secret; Fernet encryption | No central rotation model. Bridge receives key in environment. Preserve key in backup separately and minimise child-process scope. |
| Database backup exposes encrypted credentials and attacker also obtains key | I | Separation of DB and runtime key is documented | Add filesystem permissions, restore ceremony, and incident response guidance. |

## Reverse proxy and deployment

| Threat / abuse case | STRIDE | Current controls | Gap / required treatment |
|---|---|---|---|
| Direct client spoofs forwarding headers to evade rate limits/audit | S, R | Only trusted immediate peer may supply headers; production wildcard forbidden | Configuration error remains possible; preserve deployment and regression tests. |
| Proxy logs bearer/query tokens | I | Secure Send guidance and gateway suppression | RDP and OIDC/reset/invitation URLs still cross proxy logs. Remove RDP secrets; document redaction for unavoidable short-lived browser tokens. |
| Multiple web workers duplicate schedulers/jobs | T, D | Documentation says in-process single-worker model | Enforce supported worker count or add leader election before multi-replica support. |
| Container compromise reaches writable state/secrets | I, T, E | Read-only container, scoped volumes, no-new-privileges, limited capability | Review runtime user, volume modes, child processes, Docker socket exposure, and dependency provenance in later phases. |

## Priority abuse cases

1. A stolen OIDC admin-link URL binds an attacker-controlled IdP subject to an administrator and creates an administrator session.
2. A stolen backup-agent bearer token retrieves a remote-system password and backup encryption key, including after host decommissioning if the token remains present.
3. An active network attacker presents an arbitrary RDP certificate while Kaya silently accepts it.
4. Proxy/access tooling captures and replays an RDP credential-bearing WebSocket URL.
5. A quick MASTER-to-BACKUP change blocks behind the transition hook's lock-held hold-down and delays safe DHCP demotion.
6. A database/session-factory exception permanently kills HA watchdog or lease reconciliation without a health signal.
7. A newly added demo mutation is public because no developer remembered to add its path prefix.
8. Concurrent SQLite writers cause lock errors, partial operational workflows, or silent background-service death.

## Assumptions requiring owner validation

- Supported production deployment is one Kaya application process using a local SQLite file on a filesystem with reliable POSIX/SQLite locking semantics.
- TLS terminates at a trusted proxy or Kaya is accessed on a trusted local network; forwarded headers are accepted only from configured proxies.
- The public demo contains synthetic data only, but must still prevent storage/retrieval of visitor-supplied secrets and external side effects.
- Backup-agent code and its local secret handling may live outside this repository and were not reviewed here.
- IdP administrators and OIDC signing keys are trusted; provider compromise is outside Kaya's preventable boundary but must be containable and auditable.
