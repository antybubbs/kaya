# RDP Certificate Independent Review

**Finding:** `KAYA-RDP-002`

**Pull request:** [#60](https://github.com/antybubbs/kaya/pull/60)

**Implementation commit reviewed:** `789e09ae2cf85cdedbf4b17fcaf94c151a54ac82`

**Review date:** 2026-08-04

**Final result:** **Changes required**

## Scope reviewed

The review treated strict-default, per-host pinning, administrator control, migration, logging and guacd/FreeRDP enforcement claims as untrusted. It inspected the RDP change relative to `security/oidc-admin-link-hardening` and separately preserved `KAYA-RDP-001` as an open High finding.

Affected files reviewed were ADR-0003; `app/models/models.py`; `app/routers/remote_manager.py`; both RDP settings/status templates; `scripts/guacamole-server.cjs`; deployment/module documentation; migration `20260804_02`; findings/threat-model records; and release-boundary/migration tests.

## Trust boundary and threat model

The boundary runs from authenticated Kaya users and administrator-managed trust, through the credential-bearing browser/Kaya WebSocket flow and local Node bridge, to guacd/FreeRDP and the configured RDP endpoint.

Adversaries considered:

- an active network attacker presenting unknown, expired, mismatched or changed certificates;
- an editor changing an IP address, protocol or port after an administrator pins trust;
- cross-host reuse of a pin/certificate;
- an attacker or compatibility setting enabling bypass/TOFU;
- unsafe legacy configuration surviving migration/rollback;
- certificate errors leaking credentials, tokens, URLs or certificate material.

## Code paths inspected

- Fingerprint parser and `rdp_certificate_settings()`.
- Kaya RDP token construction and start failure handling.
- Node bridge default/override settings and unencrypted-setting allowlist.
- Administrator-only CSRF-protected trust update and redacted audits.
- Remote Manager protocol/port mutation and pin clearing.
- Primary VLAN/IP Manager `update_ip_address()` and `save_remote_settings()` mutation path.
- DNS-managed IP update paths that mutate `IPAddress.address`.
- Migration, upgrade documentation and rollback warning.
- Browser token/WebSocket construction relevant to required secret-exposure check.

## Security claims tested

| Claim | Evidence/result |
|---|---|
| Strict default | Kaya emits `security=nla`, `ignore-cert=false`, `cert-tofu=false`; bridge defaults match. No RDP bypass/TOFU environment setting was found. Static/focused pass. |
| New/existing hosts do not inherit bypass | Nullable migration creates no pins and old universal bypass is removed from both RDP setting producers. Pass by code/migration inspection. |
| SHA-256-only normalization | Exact 32-byte hex parser, case/colon normalization, deduplication and maximum of three. Pass. |
| Per-record pin transport | Stored on `RemoteAccess` and passed only into that row's token. Pass for immutable endpoint records. |
| Pin follows endpoint identity safely | Separate Remote Manager route clears pins on protocol/port changes, but primary IP editor and DNS address updates do not. **Fail.** |
| Administrator-only trust changes | Route dependency is `require_admin`, CSRF is validated and fingerprint values are excluded from audit. Pass. |
| Rotation/change fails closed | Multiple explicit pins supported; malformed stored pins reject session creation. Live changed-certificate behavior unavailable. Condition. |
| No hidden RDP bypass/TOFU | Repository search found false-only RDP settings. `security:any` remains only under VNC defaults. Pass statically; live confirmation unavailable. |
| Secure migration | Adds nullable field, creates no first-seen pin and documents inventory/failure path. Pass statically. |
| Security-equivalent rollback | ADR states restoring old code reintroduces universal bypass. Operational warning exists, but rollback is not fail-safe. Condition requiring release control. |
| Certificate-error secret minimization | Focused audit tests pass. Live application/guacd/proxy error capture unavailable. `KAYA-RDP-001` still places a credential-bearing Fernet token in browser-visible WebSocket query data. Required check therefore fails independently of certificate trust. |

## Tests inspected and executed

Inspected:

- RDP sections of `tests/test_release_security_boundaries.py`;
- migration coverage in `tests/test_database_migrations.py`;
- Node bridge source assertions;
- relevant RDP token/browser code.

Focused supported-Linux command:

```text
python -m pytest -p no:cacheprovider tests/test_release_security_boundaries.py tests/test_database_migrations.py -q
```

Environment matched the OIDC report: Linux WSL2 kernel, Python 3.12.13, Dockerfile/`requirements.txt` production dependencies, `pytest 9.1.1`, SQLite temporary/in-memory databases and clearly synthetic data.

Result: **45 passed**, 0 failed, 0 skipped, 87 warnings, 75.89 seconds.

Static source checks confirmed:

- RDP `ignore-cert:true` is absent;
- RDP `cert-tofu:true` is absent;
- bridge and token use `security:nla`;
- only width/height are allowed as unencrypted RDP connection overrides;
- fingerprint values are excluded from tested audit details.

`node --check scripts/guacamole-server.cjs` and repository `git diff --check` passed. A fresh Ruff run was unavailable after Docker execution was refused, so no Python static-analysis pass is claimed.

Required gaps include live certificate behavior, primary/DNS endpoint mutation pin invalidation, hostname/IP binding, private/public CA behavior, not-yet-valid certificate handling, rollback enforcement and end-to-end proxy/application/guacd log inspection.

The previous 713-test/31-subtest result is historical only. A fresh full Linux suite could not be run after Docker-engine approvals were exhausted and is not proof for this review.

## Bypass attempts and findings

### RDP-IR-001 - Alternate endpoint mutation paths retain administrator pins

`app/routers/ip_addresses.py` changes `IPAddress.address` and calls `save_remote_settings()`. That helper can change protocol and port but never clears `RemoteAccess.rdp_cert_fingerprints`. Automatic and explicit DNS-managed address update paths also mutate `IPAddress.address` without invalidating pins. Only `save_remote_host_settings()` in `remote_manager.py` clears them.

This violates the claim that a pin is bound to the independently verified host/port and that endpoint changes require administrator action. An editor can move the endpoint while retaining administrator-established trust.

Required correction: centralize endpoint identity mutation and atomically clear RDP pins whenever address, protocol or port changes through any UI, import, automation or DNS path; emit a redacted audit/notification; add tests for every mutation path and concurrent update.

### RDP-IR-002 - Required URL/log secrecy check is known to fail under KAYA-RDP-001

The RDP start response still returns the credential-bearing Fernet token and browser JavaScript places it in Guacamole WebSocket connection query data. This is the existing `KAYA-RDP-001`, not a claim that certificate validation caused the issue. It remains open and prevents the required live check from passing.

### RDP-IR-003 - Rollback is not security-equivalent

ADR-0003 correctly warns that restoring old code re-enables universal certificate acceptance. Release procedures must therefore define pause/roll-forward behavior rather than a binary rollback that restores the vulnerable setting. This remains an operational condition.

## Live synthetic validation result

**Not performed; evidence unavailable.** Disposable synthetic XRDP and CA-trusting guacd 1.6.0 images were successfully built with fake credentials and self-signed, changed, CA-signed, mismatched, expired and not-yet-valid certificates. Before containers could be launched, the execution environment refused further Docker-engine approvals because its quota was exhausted until 2026-08-08. The control was not bypassed.

No lab container or network was launched. Temporary lab source files were removed; the two disposable local image artifacts remain for later operator cleanup because Docker execution was unavailable.

Consequently, these required checks were not performed:

1. reject unknown self-signed certificate;
2. reject hostname mismatch;
3. reject expired certificate;
4. accept an explicitly configured SHA-256 pin;
5. reject changed pinned certificate;
6. confirm no bypass/TOFU path at runtime;
7. inspect browser WebSocket URLs, reverse-proxy/application/guacd logs, exception output and audits for credentials/tokens.

Not-yet-valid, private-CA, public-CA, hostname and IP-address behavior were also not exercised live.

## Reproducible operator procedure

Use an isolated Docker network, Apache `guacamole/guacd:1.6.0`, a disposable XRDP/Windows test endpoint and conspicuously fake credentials. Never target production.

1. Create a synthetic CA and server certificates for: valid hostname, different hostname, expired, not-yet-valid, self-signed A and replacement self-signed B. Include separate DNS-SAN and IP-SAN cases.
2. Install only the synthetic CA in the guacd container trust store. Record SHA-256 leaf fingerprints independently with OpenSSL/OS tooling; do not copy them from Kaya discovery because Kaya must not TOFU.
3. Configure isolated DNS aliases and run the reviewed RDP token settings exactly: `security=nla`, `ignore-cert=false`, `cert-tofu=false`, optional `cert-fingerprints=sha256:<64 lowercase hex>`.
4. With no pin, assert self-signed, hostname mismatch, expired and not-yet-valid certificates fail before authentication. Assert valid DNS-SAN/private-CA and valid IP-SAN/private-CA endpoints proceed. Use a dedicated publicly trusted synthetic endpoint, if available, for public-CA behavior.
5. With self-signed A, assert no-pin failure, correct-pin success and wrong-pin failure. Replace A with B at the same host/port and assert the old pin fails. Add B only through the administrator/CSRF/acknowledgement path, verify overlap, then remove A.
6. Change address, protocol and port through every Remote Manager, VLAN/IP, DNS automation and import path. Assert pins are cleared atomically and a safe audit/notification is emitted.
7. Inspect browser developer-tools WebSocket URLs, reverse-proxy access/error logs, Kaya logs, guacd logs, exception responses and audit rows. Search for the fake username/password, Fernet token marker, WebSocket grant, query URL and certificate PEM. Any occurrence is a failure; current `KAYA-RDP-001` predicts a WebSocket-query failure.
8. Restart guacd/Kaya and repeat unknown/changed tests to rule out hidden TOFU persistence. Search runtime configuration/environment for bypass equivalents.
9. Preserve only sanitized status/error categories and test timestamps. Destroy test keys, containers, volumes and networks afterward.

## Unresolved uncertainties

- All runtime certificate outcomes listed above.
- Exact guacd/FreeRDP error minimization and system-CA behavior in the supported deployment image.
- Public/private CA and DNS/IP identity behavior.
- Full supported-Linux regression result after this review.
- Corrective design for cross-module endpoint mutation and safe release rollback.

## Final review result

**Changes required.** Strict false defaults and SHA-256 parsing are materially improved, but pin-to-endpoint invalidation is incomplete, the required live evidence is unavailable, and known `KAYA-RDP-001` fails the URL/token secrecy check. `KAYA-RDP-002` is not ready for merge or closure.
