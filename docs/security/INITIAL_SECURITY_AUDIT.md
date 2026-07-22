# Initial Kaya security audit

**Audit date:** 21 July 2026

**Branch reviewed:** `dev0.25.0`

**Review type:** Phase A source, configuration, test and deployment review

**Status:** Owner review required before broad remediation

## Executive summary

Kaya has a better security foundation than many early self-hosted applications: Argon2 password hashing, constant-time comparisons in important token paths, CSRF checks on the state-changing browser routes sampled, server-side role dependencies, signed session cookies, a central trusted-client-IP resolver, restrictive browser headers, encrypted secret fields, object checks in Secret Vault and Secure Send, hashed single-use password-reset tokens, signed/replay-resistant HA agent requests, audit context, non-root container execution and read-only Compose filesystems are already present.

The current posture is nevertheless **not suitable for direct public internet exposure**. Three confirmed High findings require attention: first-run administration can be claimed by any network client that reaches an unconfigured instance; application session rows are not authoritative, so password/MFA/account changes do not revoke other signed cookies and Remote Manager WebSockets trust the cookie's user ID without rechecking an active user; and the SSH bridge does not verify host keys, allowing a network man-in-the-middle to impersonate a managed host and receive submitted SSH credentials.

Important Medium risks include missing fresh authentication for TOTP enrolment, incomplete outbound request/SSRF controls for LAN integrations, unbounded remote-recording reads, weak resource/replay controls on legacy Docker/backup agent APIs, an intentionally broad global-role access model for infrastructure objects, co-location of the application encryption key and encrypted data, and incomplete supply-chain scanning/locking.

No Critical issue was confirmed in this source review. That is not evidence that none exists: the assessment did not perform destructive testing, live multi-user penetration testing, a complete data-flow review of every background task, or a dedicated full-history secret scan.

### Deployment suitability

| Deployment | Assessment | Conditions |
|---|---|---|
| Trusted private LAN | **Conditionally suitable** | Keep the instance unreachable from untrusted LAN clients during first-run setup; treat all authenticated users as broadly trusted; do not rely on SSH against active MITM threats. Address High findings promptly. |
| Access through a VPN | **Conditionally suitable and preferred over public exposure** | The VPN must authenticate trusted users/devices, HTTPS should still be used where practical, the first-run window must be controlled, and proxy/client-IP settings must be narrow. A VPN does not correct application session or SSH host-key weaknesses. |
| Access through a reverse proxy | **Conditionally suitable** | Use HTTPS, secure cookies, an allow-list of hosts, and the exact immediate proxy IP/CIDR. Do not use `*`. The proxy must not expose an unconfigured Kaya instance. |
| Direct public internet | **Not suitable** | Do not expose the main Kaya application directly. The deliberately minimal Secure Send gateway has a stronger public-facing boundary, but it still needs deployment verification and scan coverage. |

## Current security architecture

- FastAPI application routes use `require_user`, `require_editor` and `require_admin`; module-specific dependencies extend these checks for Backup and High Availability.
- Starlette `SessionMiddleware` stores signed client-side session state. `AppSession` rows record session metadata, while Vault and Secure Send use additional server-side session records.
- Local passwords use Argon2 through Passlib. TOTP seeds and integration credentials use Fernet with the application encryption key. Vault and Secure Send content uses authenticated encryption and purpose-bound associated data.
- Browser mutations generally use synchroniser CSRF tokens stored in the signed session. The Secure Send recipient gateway adds strict origin, request-shape and session-bound CSRF checks.
- `TrustedProxyMiddleware` removes forwarding headers from untrusted direct connections and centralises effective client-IP calculation.
- Main application middleware adds CSP, frame controls, no-sniff, referrer, permissions, no-store and conditional HSTS headers. Production API docs are disabled.
- SQLAlchemy ORM and parameterised SQL are used. Dynamic migration identifiers observed in `app/main.py` come from static code dictionaries, not request input.
- Upload implementations normally generate storage names and apply size limits. Secret Vault and Secure Send encrypt stored attachments and verify integrity.
- HA agents use short-lived bootstrap tokens followed by Ed25519 request signatures, timestamps and replay records. Legacy Docker/backup agent APIs use long-lived bearer token hashes.
- Docker starts as root only for volume preparation/migration and executes Kaya as the `kaya` user; Compose uses `read_only`, `no-new-privileges` and narrow tmpfs mounts. `NET_RAW` is added for ping.

## Finding counts

| Severity | Open | Mitigated | Total |
|---|---:|---:|---:|
| Critical | 0 | 0 | 0 |
| High | 3 | 0 | 3 |
| Medium | 7 | 0 | 7 |
| Low | 4 | 0 | 4 |
| Informational | 1 | 1 | 2 |
| **Total** | **15** | **1** | **16** |

## Findings table

| ID | Title | Severity | Confidence | Component | Status |
|---|---|---|---|---|---|
| KAYA-SEC-001 | Application sessions are not authoritatively revoked, including Remote WebSockets | High | Confirmed | Authentication, sessions, Remote Manager | Open |
| KAYA-SEC-002 | SSH host keys are not verified | High | Confirmed | Remote Manager SSH bridge | Open |
| KAYA-SEC-003 | Any reachable client can claim first-run administrator setup | High | Confirmed | Bootstrap/setup and Compose exposure | Open |
| KAYA-SEC-004 | TOTP enrolment does not require fresh authentication | Medium | Confirmed | Profile MFA | Open |
| KAYA-SEC-005 | LAN integration requests lack one consistent outbound/SSRF policy | Medium | Confirmed | DNS, HA and integration clients | Open |
| KAYA-SEC-006 | Remote recording upload is read into memory before its size decision | Medium | Confirmed | Remote Manager recordings | Open |
| KAYA-SEC-007 | Legacy Docker and backup agent APIs have incomplete request and replay controls | Medium | Confirmed | Compute/Backup agent APIs | Open |
| KAYA-SEC-008 | General infrastructure objects use broad global-role access without object ACLs | Medium | Confirmed | Infrastructure and Remote modules | Open |
| KAYA-SEC-009 | Application encryption key is stored beside encrypted data | Medium | Confirmed | Entrypoint, data volume, vault/integrations | Open |
| KAYA-SEC-010 | Supply-chain checks and JavaScript locking are incomplete | Medium | Confirmed | Dependencies, Docker, GitHub Actions | Open |
| KAYA-SEC-011 | Trusted-proxy wildcard is accepted as valid configuration | Low | Confirmed | Client-IP configuration | Open |
| KAYA-SEC-012 | Security documentation differs from runtime session-cookie behaviour | Low | Confirmed | Documentation/session configuration | Open |
| KAYA-SEC-013 | CSP still permits inline styles globally | Low | Confirmed | Browser security policy | Open |
| KAYA-SEC-014 | Some remote/upstream exception details reach users or stored status | Low | Confirmed | Remote, DNS and compute integrations | Open |
| KAYA-SEC-015 | Multiple strong controls are already implemented | Informational | Confirmed | Cross-cutting | Mitigated |
| KAYA-SEC-016 | Full secret-history assurance requires a dedicated scanner | Informational | Requires Verification | Git history and CI | Open |

## Detailed findings

### KAYA-SEC-001 — Application sessions are not authoritatively revoked, including Remote WebSockets

| Field | Description |
|---|---|
| Severity | **High** |
| Confidence | **Confirmed** |
| Component | `app/routers/auth.py`, `app/services/sessions.py`, `app/routers/admin.py`, `app/routers/remote_manager.py` |
| Risk | A stolen or previously issued signed session cookie remains usable after password change, MFA change or administrator account edits. A disabled user is rejected by normal HTTP dependencies, but Remote Manager WebSockets read `user_id` directly from the signed cookie and do not load an active user. |
| Attack scenario | An attacker steals a user's cookie. The owner changes the password or an administrator disables the account. The attacker continues authenticated HTTP access with the old cookie until its eight-hour expiry; for SSH/RDP WebSockets, the disabled identity can still pass the handshake and reach an enabled remote object. |
| Evidence | `current_user()` in `app/routers/auth.py:150-160` checks active `User` state but never requires the `AppSession` row. `touch_user_session()` in `app/services/sessions.py:37-59` recreates missing rows and resets `ended_at`, so rows are observational rather than authoritative. Password/MFA and admin edits at `app/routers/auth.py:712-765` and `app/routers/admin.py:1045-1188` revoke Vault sessions only. WebSocket handshakes at `app/routers/remote_manager.py:911-928` and `998-1023` trust `websocket.session['user_id']` without checking the user, role or `AppSession`. |
| Recommendation | Make a random server-side session identifier mandatory and authoritative; reject missing, expired or ended rows; add idle and absolute expiries; rotate on login/privilege changes; revoke all relevant application and vault sessions on password/MFA/account changes; use the same active-session dependency in WebSocket handshakes. |
| Breaking-change risk | **Medium** — existing cookies will need a controlled one-time invalidation and session schema/expiry policy. |
| Status | **Open** |

### KAYA-SEC-002 — SSH host keys are not verified

| Field | Description |
|---|---|
| Severity | **High** |
| Confidence | **Confirmed** |
| Component | `scripts/kaya-remote-manager.cjs`, Remote Manager SSH flow |
| Risk | Kaya cannot authenticate the SSH server. A machine able to intercept LAN traffic can impersonate a managed host, capture the password submitted through Kaya and present a malicious terminal. |
| Attack scenario | An attacker uses ARP/DNS/routing manipulation between Kaya and a managed SSH host. Because the Node `ssh2` connection supplies no `hostVerifier`, the attacker presents any host key and receives the user's SSH password. |
| Evidence | The connection options in `scripts/kaya-remote-manager.cjs:124-135` provide host, port, username and password but no pinned fingerprint, known-hosts store or `hostVerifier`. The password is passed from `app/routers/remote_manager.py:929-960` to this local bridge. |
| Recommendation | Implement trust-on-first-use with explicit fingerprint display and audit, or administrator-managed pinned fingerprints/known-hosts. Reject changed keys by default. Add migration/UI states for existing hosts and tests for first use, match, mismatch and rotation. |
| Breaking-change risk | **Medium** — existing hosts need an enrolment/migration experience. |
| Status | **Open** |

### KAYA-SEC-003 — Any reachable client can claim first-run administrator setup

| Field | Description |
|---|---|
| Severity | **High** |
| Confidence | **Confirmed** |
| Component | First-run setup, Docker deployment |
| Risk | Before the owner completes setup, any client that can reach the published port can create Kaya's first administrator. |
| Attack scenario | Kaya is started on a shared LAN or cloud host. A scanner reaches `/setup` before the owner and submits its own administrator email/password. Subsequent setup attempts are redirected to login. |
| Evidence | `setup_page()` and `setup_submit()` at `app/routers/auth.py:222-239` and `438-510` are public and gate only on whether an admin already exists. No local-network, bootstrap-token or console proof is required. `docker-compose.yml:16-17` publishes port 8080 on all interfaces by default. The check-then-insert sequence is also not transactionally exclusive. |
| Recommendation | Generate a one-time bootstrap secret at startup and require it for first admin creation, or restrict setup to an explicitly local/console channel. Bind default Compose to loopback where compatible, document the first-run boundary, and make creation transactional/single-use. |
| Breaking-change risk | **Medium** — changes installation workflow and documentation but not existing configured instances. |
| Status | **Open** |

### KAYA-SEC-004 — TOTP enrolment does not require fresh authentication

| Field | Description |
|---|---|
| Severity | **Medium** |
| Confidence | **Confirmed** |
| Component | Profile MFA |
| Risk | Anyone with an unlocked application session can replace the pending TOTP seed and enable a seed they control without knowing the user's password. |
| Attack scenario | A user leaves a logged-in browser unattended. An attacker starts MFA enrolment, records the new seed and confirms its code, adding attacker-controlled second-factor state or locking the owner out. |
| Evidence | `start_profile_2fa()` and `enable_profile_2fa()` at `app/routers/auth.py:728-755` require authentication and CSRF but do not verify the current password or another fresh identity proof. Disabling MFA does require the password at `757-765`. |
| Recommendation | Require fresh password or recent OIDC MFA before generating/replacing a seed, bind the pending seed to a short-lived server-side transaction, invalidate other sessions after enablement, and add recovery codes or a documented recovery path. |
| Breaking-change risk | **Low** |
| Status | **Open** |

### KAYA-SEC-005 — LAN integration requests lack one consistent outbound/SSRF policy

| Field | Description |
|---|---|
| Severity | **Medium** |
| Confidence | **Confirmed** |
| Component | DNS Provider, HA validation, compute and test-connection integrations |
| Risk | A privileged configuration can make Kaya contact unintended services, follow redirects, consume oversized responses or silently disable TLS verification. Because LAN access is a feature, ad hoc URL validation is insufficient. |
| Attack scenario | A malicious or compromised administrator/editor configures a Pi-hole/HA endpoint that redirects to a sensitive local service or returns an unbounded body. A scheduled collector repeats the request from Kaya's trusted network position. |
| Evidence | `PiHoleProvider._request_json()` at `app/services/dns_providers.py:119-170` builds requests from configured base URLs, uses `urlopen` (redirects enabled), reads the full response and supports an unverified SSL context. HA reuses this client through `app/services/ha_validation.py:72-106`. OIDC has materially stronger checks in `app/services/oidc_discovery.py:25-141`, demonstrating inconsistent policy. |
| Recommendation | Centralise feature-aware outbound validation: allowed schemes/ports, no embedded credentials, DNS/address checks, redirect revalidation, connect/read deadlines, streamed response caps and explicit/audited TLS exceptions. Permit authorised LAN ranges per feature rather than globally blocking private IPs. |
| Breaking-change risk | **Medium** — some existing integration URLs or TLS-disabled connections may need explicit migration. |
| Status | **Open** |

### KAYA-SEC-006 — Remote recording upload is read into memory before its size decision

| Field | Description |
|---|---|
| Severity | **Medium** |
| Confidence | **Confirmed** |
| Component | Remote Manager recording upload |
| Risk | An authenticated user can force a worker to buffer a very large request, causing memory exhaustion or service interruption. The configured default maximum is itself 1 GiB. |
| Attack scenario | A viewer with Remote Manager access uploads a multi-gigabyte or chunked recording. The worker reads it before enforcing storage/size policy and is killed by the host or stalls other users. |
| Evidence | `upload_recording()` calls `data = await file.read()` at `app/routers/remote_manager.py:750-825`; `ensure_recording_storage_available(len(data))` is called only after the full read. `max_recording_upload_mb` defaults to 1024 in `app/core/config.py:29`. |
| Recommendation | Enforce request/body limits before parsing where possible, stream to a restricted temporary file in bounded chunks, stop at the configured maximum, reserve/check space before accepting, and clean partial files safely. |
| Breaking-change risk | **Low** |
| Status | **Open** |

### KAYA-SEC-007 — Legacy Docker and backup agent APIs have incomplete request and replay controls

| Field | Description |
|---|---|
| Severity | **Medium** |
| Confidence | **Confirmed** |
| Component | `/infrastructure/vm-docker-manager/api/agent/checkin`, Backup agent APIs |
| Risk | A leaked long-lived bearer token can be replayed indefinitely. Authenticated agent requests can submit unbounded arrays/metadata and status/log payload structures, consuming memory/database space or falsifying inventory and backup state. |
| Attack scenario | A token copied from an agent is reused to flood check-ins with large workload/item arrays or repeatedly fetch/alter jobs for that host. There is no request timestamp, nonce, body cap or per-agent throttle comparable to the HA agent protocol. |
| Evidence | `agent_checkin()` at `app/routers/compute_manager.py:225-366` authenticates a static token then calls `request.json()` and iterates caller-controlled arrays without record/body limits. `require_agent_host()` and agent routes at `app/routers/backup_manager.py:61-75` and `562-677` use the same static-token model. The stronger signed design and 256 KiB cap exist at `app/services/ha_agents.py:84-139`. |
| Recommendation | Converge on signed, timestamped, replay-resistant agent requests; cap bodies, arrays, strings and metadata depth; add per-agent rate limits and token expiry/rotation; validate state transitions server-side. |
| Breaking-change risk | **High** — requires agent protocol compatibility and staged rotation. |
| Status | **Open** |

### KAYA-SEC-008 — General infrastructure objects use broad global-role access without object ACLs

| Field | Description |
|---|---|
| Severity | **Medium** |
| Confidence | **Confirmed** |
| Component | Infrastructure, Runbook, Licence and Remote Manager modules |
| Risk | Any viewer can read most infrastructure records and use enabled remote sessions; any editor can mutate most records. Owner fields are generally descriptive, not access-control attributes. This is unsafe if Kaya's team roles are expected to isolate customers, teams or sensitive systems. |
| Attack scenario | A viewer changes an object ID to enumerate assets, recordings or remote hosts and opens an SSH/RDP session to any enabled target. The action passes because access is global for that role. |
| Evidence | Global dependencies in `app/routers/auth.py:163-181` check only `User.role`. Examples include remote panels and RDP/SSH start paths at `app/routers/remote_manager.py:684-911`, hardware downloads at `app/routers/hardware_assets.py:238-258`, and licence detail/reveal at `app/routers/licences.py:131-154`. Secret Vault and Secure Send do implement object-specific checks, showing the contrast. |
| Recommendation | Owner decision required: explicitly document Kaya as a fully shared workspace, or introduce reusable module/object grants. At minimum separate permission to view connection metadata, initiate remote sessions, reveal licences and download files; deny object access by default and test ID manipulation. |
| Breaking-change risk | **High** — authorisation semantics, UI and data model may change. |
| Status | **Open** |

### KAYA-SEC-009 — Application encryption key is stored beside encrypted data

| Field | Description |
|---|---|
| Severity | **Medium** |
| Confidence | **Confirmed** |
| Component | Runtime secrets, SQLite data volume, encrypted integrations/Vault |
| Risk | Copying or backing up the whole data volume captures both encrypted database values and the key used to unwrap/decrypt them. Encryption protects against casual database-only disclosure, not volume theft or host compromise. |
| Attack scenario | An attacker obtains a snapshot of `./data` or a broadly scoped backup. It contains `kaya.db` and `.runtime.env`, enabling offline decryption of Fernet-protected credentials and application-wrapped vault content. |
| Evidence | `docker-entrypoint.sh:11-48` creates `/app/data/.runtime.env` containing `SECRET_KEY` and `ENCRYPTION_KEY`. Compose mounts `./data:/app/data`. `app/core/security.py:18-31` uses `ENCRYPTION_KEY`; vault application wrapping depends on the same application secret boundary. |
| Recommendation | Document the threat model immediately. Support external Docker/Kubernetes secrets or a separately mounted root-only secret file; exclude the key from ordinary data backups; provide an explicit encrypted recovery procedure and future key rotation/versioning. Do not remove the current key or make existing data unreadable. |
| Breaking-change risk | **High** — migration must preserve access to all existing encrypted data. |
| Status | **Open** |

### KAYA-SEC-010 — Supply-chain checks and JavaScript locking are incomplete

| Field | Description |
|---|---|
| Severity | **Medium** |
| Confidence | **Confirmed** |
| Component | `package.json`, Dockerfile, GitHub Actions, dependency automation |
| Risk | JavaScript dependencies and transitive versions are not reproducibly locked or audited in CI; container and committed-secret risks are not scanned; floating base/OS packages reduce build reproducibility. |
| Attack scenario | A compromised or newly vulnerable transitive npm/base-image dependency is selected during a rebuild and published because no lockfile, npm audit, container scan or secret scan blocks it. |
| Evidence | `package.json` uses caret ranges and no `package-lock.json` is tracked. `Dockerfile:15-16` runs `npm install --omit=dev --no-audit`; the base is `python:3.12-slim` without a digest. `.github/workflows/security.yml` runs pip-audit and CodeQL only. Dependabot covers pip and Actions but not npm or Docker. |
| Recommendation | Commit a lockfile and use `npm ci`; add npm audit, Gitleaks, Trivy and an appropriate static scanner; enable npm and Docker update automation; pin scanner actions/tools and record narrow suppressions. Consider digest-pinning release builds with an update process. |
| Breaking-change risk | **Low** |
| Status | **Open** |

### KAYA-SEC-011 — Trusted-proxy wildcard is accepted as valid configuration

| Field | Description |
|---|---|
| Severity | **Low** |
| Confidence | **Confirmed** |
| Component | Trusted proxy configuration |
| Risk | An operator can set `FORWARDED_ALLOW_IPS=*`, after which direct clients can spoof forwarding identity where Kaya is directly reachable. This weakens throttling, audit attribution and IP policy. |
| Attack scenario | An inexperienced operator copies a trust-all setting from another deployment guide. Attackers rotate `X-Forwarded-For` to misattribute events or dilute IP-based abuse controls. |
| Evidence | `validate_trusted_proxies()` and `ip_is_trusted()` at `app/services/client_ip.py:31-58` explicitly accept `*`. Repository documentation warns against it, but startup does not reject it. |
| Recommendation | Reject `*` in production by default; require a conspicuous unsafe override if compatibility is essential; emit a startup/security-page warning and test the unsafe state. |
| Breaking-change risk | **Low** |
| Status | **Open** |

### KAYA-SEC-012 — Security documentation differs from runtime session-cookie behaviour

| Field | Description |
|---|---|
| Severity | **Low** |
| Confidence | **Confirmed** |
| Component | Session documentation and middleware |
| Risk | Operators and reviewers may make incorrect assumptions about cross-site cookie behaviour and deployment hardening. |
| Attack scenario | A reviewer accepts a design on the belief that cookies are Strict while the main application intentionally uses Lax for OIDC compatibility. |
| Evidence | `docs/security.md:35` states `same_site=strict`. `app/main.py:62-74` configures the main session cookie with `same_site='lax'`. The Secure Send gateway separately uses Strict. |
| Recommendation | Correct the documentation and explicitly distinguish the main application, OIDC transaction needs and recipient gateway. Add a test for cookie attributes in HTTP and trusted HTTPS-proxy cases. |
| Breaking-change risk | **None** |
| Status | **Open** |

### KAYA-SEC-013 — CSP still permits inline styles globally

| Field | Description |
|---|---|
| Severity | **Low** |
| Confidence | **Confirmed** |
| Component | Main application browser policy |
| Risk | A markup injection flaw has more styling capability and the policy cannot fully constrain style injection. This does not currently permit inline scripts or `unsafe-eval`. |
| Attack scenario | A future HTML injection can use style attributes to obscure warnings or construct misleading UI even though script execution remains blocked. |
| Evidence | CSP construction at `app/main.py:139-157` includes `style-src 'self' 'unsafe-inline'` and `style-src-attr 'unsafe-inline'`; `script-src` remains `'self'`. |
| Recommendation | Inventory inline style attributes, move them to classes or nonce/hash-compatible blocks, and remove the allowances in phases. Do not weaken script policy to make migration easier. |
| Breaking-change risk | **Medium** — visual regressions are possible. |
| Status | **Open** |

### KAYA-SEC-014 — Some remote/upstream exception details reach users or stored status

| Field | Description |
|---|---|
| Severity | **Low** |
| Confidence | **Confirmed** |
| Component | Remote Manager, DNS Provider and compute monitoring |
| Risk | Library/upstream exceptions can disclose internal hostnames, addresses, protocol details or paths to authenticated users and persistent records. |
| Attack scenario | A remote connection failure embeds sensitive network detail in an exception; the WebSocket sends it directly to a viewer or a collector stores it for later display. |
| Evidence | `app/routers/remote_manager.py:961-964` returns `SSH connection failed: {exc}`. `app/services/compute_monitor.py` stores truncated `str(exc)` in `host.last_error` and events. `app/services/dns_providers.py:145-163` may include short upstream error text. |
| Recommendation | Map exceptions to stable user-facing codes/messages; retain redacted details only in protected logs with request IDs; create a shared redaction helper for URLs, credentials and internal paths. |
| Breaking-change risk | **Low** |
| Status | **Open** |

### KAYA-SEC-015 — Multiple strong controls are already implemented

| Field | Description |
|---|---|
| Severity | **Informational** |
| Confidence | **Confirmed** |
| Component | Cross-cutting |
| Risk | None; this records controls that should be preserved during remediation. |
| Attack scenario | Not applicable. Regression or broad refactoring could remove these protections. |
| Evidence | Argon2 in `app/core/security.py`; CSRF in `app/core/csrf.py`; trusted proxy stripping in `app/services/client_ip.py`; OIDC endpoint validation in `app/services/oidc_discovery.py`; vault/send authenticated encryption in `app/services/secret_vault.py` and `app/services/secure_send.py`; HA signatures/replay protection in `app/services/ha_agents.py`; headers in `app/main.py` and `app/security_gateway.py`; non-root/read-only deployment in `Dockerfile`, `docker-entrypoint.sh` and `docker-compose.yml`. |
| Recommendation | Add regression coverage around these controls and preserve them through small changes. |
| Breaking-change risk | **None** |
| Status | **Mitigated** |

### KAYA-SEC-016 — Full secret-history assurance requires a dedicated scanner

| Field | Description |
|---|---|
| Severity | **Informational** |
| Confidence | **Requires Verification** |
| Component | Git history and CI |
| Risk | A credential pattern outside the limited manual heuristics may exist in current or historical blobs. |
| Attack scenario | A previously committed integration credential remains recoverable from Git history even after its file was removed. |
| Evidence | Current tracked filenames and history were reviewed using non-value-printing Git/regex heuristics. No private-key/GitHub/AWS signature path was reported, while expected generic secret-variable names appeared in source/tests. Historical example environment files exist. Gitleaks was not installed and CI does not run it. No secret value was printed or recorded during this audit. |
| Recommendation | Run Gitleaks against the full history in an approved environment, review findings without exposing values, rotate any confirmed live credential with owner approval, and add CI/pre-commit scanning. |
| Breaking-change risk | **None** for scanning; credential rotation requires a separate approved plan. |
| Status | **Open** |

## Five highest-priority risks

1. **KAYA-SEC-001:** make application sessions authoritative and apply the same checks to Remote Manager WebSockets.
2. **KAYA-SEC-002:** introduce SSH host-key verification before treating Remote Manager as safe against LAN interception.
3. **KAYA-SEC-003:** protect first-run administrator creation from network races/claiming.
4. **KAYA-SEC-004:** require fresh identity proof for MFA enrolment and invalidate other sessions on MFA changes.
5. **KAYA-SEC-005:** centralise feature-aware outbound request controls before expanding integrations.

## Prioritised remediation plan

### Immediate release blockers

- For any internet-facing release, block direct public exposure of the main application in documentation and examples until KAYA-SEC-001, 002 and 003 are resolved.
- Add failing regression tests for revoked/disabled sessions, WebSocket active-user checks, first-run bootstrap proof and SSH key mismatch before implementing each fix.

### High-priority fixes

1. Implement authoritative server-side sessions, expiries, rotation and bulk revocation; integrate HTTP and WebSocket authentication.
2. Add SSH known-host/fingerprint lifecycle with a safe migration for existing Remote records.
3. Add a one-time first-run bootstrap proof and transactional single-admin creation.
4. Add fresh authentication for MFA enrolment and session invalidation for all security-sensitive account changes.
5. Stream and cap Remote recording uploads.

### Medium-term hardening

- Create a central, feature-aware outbound request policy and migrate Pi-hole/HA first.
- Design and version a signed Docker/backup agent protocol with body/record limits and staged legacy deprecation.
- Decide and document whether Kaya is a fully shared workspace or needs object/module grants; implement the decision centrally.
- Separate deployed encryption keys from ordinary data volumes/backups without risking existing ciphertext.

### Defence-in-depth improvements

- Reject or strongly gate trust-all proxy configuration.
- Phase out inline styles and tighten CSP.
- Standardise safe upstream error mapping and redaction.
- Reconcile security documentation with tested runtime behaviour.

### Longer-term security improvements

- Add Gitleaks, Trivy, npm audit, npm/Docker update automation and an appropriate static scanner.
- Commit reproducible JavaScript dependency locks and consider digest-pinned release images.
- Add a documented key-rotation and encrypted-backup recovery design.
- Conduct an authenticated multi-role dynamic assessment after High fixes land.

## Owner design decisions required

1. **Authorisation model:** Is Kaya intentionally a fully shared workspace for all viewers/editors, or must access be segmented by module, team, owner, site or object?
2. **SSH trust model:** Administrator-pinned fingerprints, managed known-hosts, or trust-on-first-use with explicit confirmation?
3. **First-run experience:** One-time token in container logs, local-only setup, CLI-created admin, or another ownership proof?
4. **Session policy:** Desired idle timeout, absolute lifetime, concurrent-session visibility/limits and administrator forced-logout UX.
5. **Key custody:** Which external secret mechanisms must be supported, and what data should normal backups contain?
6. **Legacy agent compatibility:** Supported migration window and minimum version for signed Docker/backup agent requests.

## Areas not fully assessed

- No live browser or destructive penetration testing was performed against a running Kaya instance or real infrastructure.
- The local environment uses Python 3.14 on Windows, while Kaya targets Python 3.12/Linux. Full test collection could not be validated: after adding the repository to `PYTHONPATH` and using clearly fake test secrets, SQLAlchemy 2.0.36 failed on Python 3.14 typing behaviour; Linux-only `fcntl` and the local FastAPI/Starlette `httpx2` expectation also prevented collection.
- No container image was built or scanned and no live reverse proxy, OIDC provider, Pi-hole, SSH, RDP, SMTP, backup target or HA node was contacted.
- Gitleaks, Trivy and Semgrep were not installed. Git-history secret review used limited filename/regex heuristics only and deliberately did not print candidate values.
- JavaScript vendored files were not provenance-verified against upstream release hashes.
- SQLite migrations were source-reviewed but not exercised against every historical database version or interrupted-restore scenario.
- Side-channel, cryptographic implementation and browser-extension threat analysis were limited to source-level design review.

## Exact tests to add first

Add these in separate, focused batches using fake users, hosts and credentials:

1. `test_password_change_revokes_other_application_sessions`
2. `test_admin_disable_revokes_http_and_websocket_sessions`
3. `test_ended_or_missing_app_session_is_rejected_not_recreated`
4. `test_remote_websocket_rejects_inactive_user_and_wrong_role`
5. `test_remote_websocket_rejects_untrusted_origin_and_cross_user_rdp_token`
6. `test_ssh_known_host_first_use_match_mismatch_and_rotation`
7. `test_setup_requires_one_time_bootstrap_proof`
8. `test_concurrent_setup_creates_exactly_one_initial_admin`
9. `test_totp_enrolment_requires_fresh_authentication_and_expires`
10. `test_password_and_mfa_change_rotate_current_session_and_revoke_others`
11. `test_recording_upload_rejects_oversize_without_buffering_entire_body`
12. `test_agent_checkin_rejects_oversize_body_too_many_records_and_replay`
13. `test_outbound_policy_rejects_credentials_bad_schemes_and_disallowed_ports`
14. `test_outbound_policy_revalidates_redirect_and_dns_resolution`
15. `test_outbound_policy_caps_response_and_preserves_tls_verification`
16. `test_viewer_editor_admin_route_matrix_for_every_router`
17. `test_object_id_manipulation_for_remote_recording_attachment_licence_and_vault`
18. `test_csrf_rejection_for_every_state_changing_browser_route`
19. `test_stored_and_reflected_xss_payloads_are_encoded_in_runbooks_notes_names_and_audit_views`
20. `test_upload_path_traversal_content_type_size_and_safe_disposition`
21. `test_sql_injection_style_filter_and_sort_values_are_data_not_syntax`
22. `test_secret_values_are_absent_from_api_errors_logs_audit_and_exports_by_default`
23. `test_direct_forwarding_headers_are_ignored_and_trusted_chain_is_consistent`
24. `test_security_headers_and_cookie_flags_for_http_https_and_trusted_proxy`
25. `test_login_mfa_reset_and_gateway_throttles_use_trusted_client_identity`

## Phase A files changed

- `docs/security/INITIAL_SECURITY_AUDIT.md` — this evidence-based initial audit and remediation sequence.
- `SECURITY_ENGINEERING.md` — permanent security commandments and completion requirements.
- `docs/security/SECURITY_REVIEW_CHECKLIST.md` — pre-merge checklist.
- `AGENTS.md` — permanent instruction to read and follow the standard.

No application code, account, credential, database, deployment behaviour or user data was changed during Phase A.
