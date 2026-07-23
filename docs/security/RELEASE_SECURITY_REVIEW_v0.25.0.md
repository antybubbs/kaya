# Kaya v0.25.0 Release Security Review

Date: 23 July 2026  
Baseline: `v0.24.5`  
Candidate branch: `dev0.25.0`

## Release decision

| Deployment target | Decision | Conditions |
|---|---|---|
| Trusted private LAN or VPN Beta | **Go after required CI gates pass** | Use HTTPS, restrict trusted proxies, retain backups, and review the release notes. |
| Shared public demo | **Go after required CI gates pass** | Use `DEMO_MODE=true`, the deterministic reset, no Secure Send gateway, and no HA background workers. |
| Direct public-internet exposure of the main Kaya interface | **No-go** | The remaining Medium security findings require further hardening and operational review. |

This is a scoped review, not a claim that Kaya is completely secure.

## Remediated release blockers

The confirmed High findings from the initial audit have been remediated in this candidate:

1. **KAYA-SEC-001 — authoritative application sessions**
   - HTTP and Remote Manager WebSocket access now require an active user and matching, unended, unexpired server-side `AppSession`.
   - Missing, revoked, mismatched, and expired session rows fail closed.
   - Password, MFA, and administrator account-security changes revoke other active sessions.
2. **KAYA-SEC-002 — SSH server identity**
   - SSH connections are blocked until an operator scans and independently verifies a server fingerprint.
   - Enrolment re-scans before trust and rejects a key that changed between scan and confirmation.
   - The internal SSH bridge restricts the negotiated host-key algorithm and verifies the raw server key using a constant-time SHA-256 fingerprint comparison before authentication.
3. **KAYA-SEC-003 — first-run administrator ownership**
   - The container generates and persists a high-entropy setup token with mode `600`.
   - Initial setup requires that token and uses an immediate SQLite write transaction so concurrent submissions have one winner.
   - Once an administrator exists, the setup endpoint remains unavailable.
4. **Inherited plaintext FTP backup path**
   - FTP connection testing and dispatch are disabled.
   - Existing target metadata remains stored for data-preserving migration.
   - Operators are directed to SFTP, SMB, or a securely mounted local path.
5. **MFA enrolment freshness**
   - Starting local TOTP enrolment now requires the account's current password.
6. **Remote recording upload bounds**
   - Recordings are streamed to a restricted partial file in 1 MiB chunks.
   - Size and remaining-space limits are enforced while streaming, and rejected partial files are removed.
7. **Trusted proxy wildcard**
   - Production startup now rejects `FORWARDED_ALLOW_IPS=*`; operators must configure an explicit proxy IP or CIDR.

## High Availability trust paths

- Browser mutations use server-side role checks, CSRF validation, bounded inputs, explicit confirmations, and redacted audit events.
- Agent bootstrap tokens are high-entropy, hashed, single-use, node-bound, cluster-bound, and expire after 15 minutes.
- Registered agents use Ed25519 request signatures covering method, path, request ID, timestamp, and body digest.
- Replay persistence, timestamp windows, body-size limits, rate limits, protocol versions, generation checks, and checksums fail closed.
- Agent actions are fixed; the protocol does not expose arbitrary shell execution.
- Keepalived writes are validated, backed up, and rolled back after failure.
- Ambiguous VIP ownership and split-brain evidence block DHCP activation.
- Configuration sync has one explicit authority, backs up before writes, reads back after writes, and restores after failed verification.
- Kaya remains a management plane. DNS, DHCP, Keepalived, and staged lease data remain local when Kaya is offline.

## Data preservation

- Schema changes are additive and startup migration paths preserve existing records.
- DNS Manager continues to own provider observations, client identities, linked IPs, leases, traffic, investigations, and history.
- An HA Pi-hole cluster is presented to DNS Manager as one logical provider at the virtual IP.
- Moving an existing provider to an HA cluster preserves the provider identity.
- Removing an HA cluster is a soft deletion and does not delete DNS Manager history or linked records.
- Legacy FTP target metadata is retained even though insecure use is blocked.

## Public demo

The public-demo boundary now:

- blocks every `/api/ha/agent` request;
- blocks every non-read-only `/high-availability` request;
- keeps Remote Manager sessions, backup agents, Secure Send, and background infrastructure workers disabled;
- retains deterministic resets and read-only module presentation;
- includes regression coverage for representative HA creation, deployment, synchronisation, failover, agent registration, and heartbeat paths.

No demo visitor can register an HA agent, contact a Pi-hole, deploy Keepalived, copy configuration, stage leases, or initiate failover.

## Verification evidence

- Full Linux suite in an isolated container: **310 passed**.
- Focused release-security and demo boundary tests: **15 passed**.
- JavaScript syntax checks for the SSH bridge and settings UI: passed.
- Python compilation and shell entrypoint syntax: passed.
- `git diff --check`: passed.
- Bandit High-severity/High-confidence scan: passed with no findings.
- Exact hardened Docker image build: passed.
- Exact image `/healthz`: `{"status":"ok"}`.
- Exact image contains `/usr/bin/ssh-keyscan`.
- Generated runtime secret file verified as mode `600` without reading its contents.

The external dependency-advisory lookup was not authorised in this local environment. The candidate must not merge until the repository `pip-audit` and CodeQL jobs pass on the exact commit.

## Residual risk and required gates

Five Medium findings in `INITIAL_SECURITY_AUDIT.md` still require tracked follow-up. MFA freshness and recording-upload bounds are addressed by this candidate; central outbound-request policy, legacy agent surfaces, broad workspace roles, encryption-key placement, and supply-chain completeness remain relevant to the direct-public-exposure no-go decision. The trusted-proxy wildcard Low finding is also addressed.

Required before merge:

1. Review the final diff for secrets, generated databases, private addresses, tokens, and local artefacts.
2. Require the full test suite, dependency audit, and CodeQL jobs on the exact candidate commit.
3. Publish v0.25.0 as a Beta intended for trusted private LAN/VPN use.
4. Do not describe the main Kaya interface as safe for direct public-internet exposure.

## Security Impact

- **Trust boundaries changed:** yes; HA agents, Remote Manager WebSockets, SSH server identity, initial setup, and backup dispatch were hardened.
- **Sensitive data touched:** encrypted infrastructure credentials, application sessions, setup/bootstrap tokens, SSH fingerprints, Pi-hole credentials, DHCP snapshots, and audit events.
- **Validation added:** authoritative session lookup, absolute session lifetime, transactional setup ownership, constant-time token/fingerprint comparisons, SSH key-algorithm restriction, password freshness for TOTP enrolment, bounded recording streaming, explicit trusted-proxy ranges, demo-mode denial, and plaintext-FTP denial.
- **Audit changes:** rejected setup claims, host-key scans/enrolment changes, session-invalidating account changes, and blocked FTP dispatches are auditable.
- **Residual risk:** remaining Medium application-wide findings and the externally executed dependency/CodeQL gates prevent an unqualified public-internet security claim.
