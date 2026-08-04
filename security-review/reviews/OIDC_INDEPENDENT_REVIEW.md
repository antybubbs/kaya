# OIDC Administrator-Link Independent Review

**Finding:** `KAYA-OIDC-001`

**Pull request:** [#61](https://github.com/antybubbs/kaya/pull/61)

**Original implementation commit reviewed:** `42299a99a72e0a21461e225e2c32daa235aa8604`

**Corrective implementation commit:** `b5f53ceba109a9d7be30931b76932719d9a1ddcc`

**Independent result:** **Changes required**

**Current corrective status:** **Ready for independent re-review; not verified**

## Scope reviewed

The independent pass treated administrator-invitation recipient binding, OIDC protocol validation, state consumption, invitation revocation, recovery and redaction claims as untrusted. The corrective checkpoint is limited to the three confirmed blockers and does not constitute the required new independent review.

## Affected files

The corrective commit changes the OIDC model, router, client and identity service; Account Links template; migration `20260804_01`; ADR-0002; OpenID Connect documentation; and focused OIDC/migration tests.

## Trust boundary

The boundary runs from an administrator-created invitation, through the exact authenticated recipient's local password/TOTP step-up and browser session, to a signed IdP response and the durable Kaya external-identity mutation.

## Threat model used

The review considered a token thief, a normal user, an attacker with their own IdP identity, a stale IdP session, missing or attacker-influenced claims, concurrent callback consumers, multiple Kaya workers, process failure/restart, and a revoke-versus-complete race. Logs and audits were treated as potential secret sinks.

## Security claims tested

- Signed `auth_time`, rather than `iat`, `prompt` or `max_age`, proves recent IdP authentication for administrator linking.
- Only a state row matching the hashed browser transaction, state, unused marker and unexpired lifecycle can be consumed, with exactly one database winner.
- Pending or claimed invitations remain revocable; completion rechecks all bindings and commits the terminal completion marker with identity creation.
- Revocation and completion are mutually exclusive terminal states; revocation does not unlink an already completed identity.
- Failures remain generic and audit/log data excludes tokens, passwords, TOTP and sensitive claims.

## Code paths inspected

- `create_transaction()`, `consume_transaction()`, `exchange_and_validate()` and `validate_id_token()`.
- OIDC callback, invitation creation/open/local-proof/revoke routes and final confirmation.
- Invitation validation, claim, revoke, identity creation and final completion services.
- Invitation model/migration lifecycle and Account Links status rendering.
- ADR, provider compatibility, migration and recovery guidance.

## Tests inspected

The focused suites cover issuer, audience, signature, expiry, nonce, redirect safety, recipient/email/provider binding, password/TOTP proof, identity conflicts, access-log redaction and legacy invitation migration. The correction adds direct coverage for every confirmed blocker.

## Tests executed

Environment: Linux `6.6.87.2-microsoft-standard-WSL2`, x86_64; Python 3.12.13; production dependencies installed from `requirements.txt` in the existing review image; pytest 9.1.1; temporary/in-memory SQLite; synthetic values only.

```text
python -m pytest -p no:cacheprovider tests/test_oidc_identity.py tests/test_oidc_routes.py tests/test_oidc_security.py tests/test_database_migrations.py -q
```

Result: **124 passed**, 0 failed, 0 skipped, 715 warnings, 21.57 seconds.

Changed-file Ruff result: **All checks passed**.

The full supported-Linux suite is scheduled after the corrected RDP branch is updated and is not claimed here.

## Bypass attempts

- Missing, string, Boolean, negative, stale and excessively future `auth_time` values were rejected; a future value inside the documented 60-second skew was accepted.
- A fresh `iat` and requested login prompt did not override stale `auth_time` rejection.
- Modifying the signed claim invalidated the token signature.
- Two file-backed SQLite sessions racing the same state produced exactly one winner; sequential reuse and restart reuse failed.
- A synthetic failure after committed consumption did not restore state. A failed database commit rolled back before privileged effects and allowed a later legitimate retry.
- Claimed invitation revocation blocked callback completion. A file-backed revoke-versus-complete race produced one terminal winner and never two identities.

## Findings

The corrective implementation addresses OIDC-IR-001 (fresh authentication), OIDC-IR-002 (atomic state consumption) and OIDC-IR-003 (claimed invitation revocation) in focused testing. This is implementer evidence, not independent verification.

## Unresolved uncertainties

- A fresh independent reviewer must attempt to disprove the corrective claims.
- A real supported provider must confirm signed `auth_time` interoperability; providers omitting it intentionally fail closed.
- The complete supported-Linux suite has not yet run on the final corrected stack.
- End-to-end reverse-proxy and real-provider log behavior remains operational evidence rather than focused-unit evidence.

## Final review result

The previous result remains **Changes required** until re-review. Corrective commit `b5f53ce` is **ready for independent re-review**, but `KAYA-OIDC-001` is not verified, closed, approved or ready to merge.
