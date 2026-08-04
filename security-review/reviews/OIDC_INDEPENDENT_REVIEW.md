# OIDC Administrator-Link Independent Review

**Finding:** `KAYA-OIDC-001`

**Pull request:** [#61](https://github.com/antybubbs/kaya/pull/61)

**Implementation commit reviewed:** `42299a99a72e0a21461e225e2c32daa235aa8604`

**Review date:** 2026-08-04

**Final result:** **Changes required**

## Scope reviewed

The review treated the implementation as untrusted and attempted to disprove recipient binding, fresh authentication, single-use/revocation, OIDC protocol validation, recovery and redaction claims. It did not review or implement backup-agent protocol v2 or any remaining High finding.

Affected files reviewed were ADR-0002; `app/core/logging.py`; OIDC models, router, client and identity service; invitation templates; authentication documentation; migration `20260804_01`; and OIDC/migration tests changed between `security/hardening-baseline` and the implementation commit.

## Trust boundary and threat model

The boundary runs from an administrator-created invitation locator, through an authenticated recipient browser/session and local password/TOTP step-up, to an external IdP authorization response and Kaya external-identity mutation.

Adversaries considered:

- a bearer-token thief with no target account session;
- a normal authenticated Kaya user;
- an attacker with their own IdP identity;
- an attacker replaying or racing state/callback requests;
- a stale IdP session when fresh authentication is claimed;
- a recipient continuing after an administrator attempts revocation;
- a malicious or misconfigured IdP returning wrong/unverified identity claims;
- logs, errors or audits capturing authentication material.

## Code paths inspected

- Invitation creation, GET locator, CSRF-protected open, local proof, claim and revoke routes in `app/routers/oidc.py`.
- `_session_invitation`, `_begin`, callback, pending transaction and final link confirmation.
- Invitation recipient/provider binding, atomic invitation claim, identity conflict handling and final identity creation in `app/services/oidc_identity.py`.
- Transaction/state/nonce/PKCE generation, state consumption, token exchange and ID-token validation in `app/services/oidc_client.py`.
- Access-log redaction in `app/core/logging.py`.
- Invitation/transaction constraints and migration invalidation of legacy invitations.
- Session creation/clearing and local break-glass/recovery paths referenced by the flow.

## Security claims tested

| Claim | Evidence/result |
|---|---|
| Random token, state, nonce and verifier | Uses `secrets.token_urlsafe()` at adequate lengths. Pass. |
| Raw invitation token not stored | Database stores SHA-256 hash; raw token appears only in one-time no-store response/form. Pass for application storage. Reverse-proxy query logging remains an operational condition. |
| Short-lived, intended-user/provider bound | 30-minute expiry plus user/provider security-state hashes and exact active user checks. Pass. |
| Single-use invitation claim | Conditional SQL update with `used_at IS NULL`; two-session test passes. Pass. |
| Revocable invitation authorization | Unused invitation revocation passes, but claimed/incomplete invitations cannot be revoked. **Fail.** |
| Password and configured TOTP step-up | Enforced before claim; TOTP-negative test exists. Wrong-password negative coverage is absent. Code inspection passes, test evidence incomplete. |
| Genuinely fresh IdP authentication | Sends `prompt=login` and `max_age=0`, but does not require or validate `auth_time`/maximum age. A stale `auth_time=1` token was accepted by an adversarial probe. **Fail.** |
| Verified exact-email binding | Admin link requires truthy normalized verified claim and exact target email even when provider-wide verification is relaxed. Pass. |
| Issuer, audience, nonce, signature and PKCE | Authlib ID-token validation binds exact issuer/audience/nonce and approved asymmetric algorithms; wrong cases pass existing negative tests. Pass. |
| State is once-only | Sequential reuse fails, but consumption is read-then-update without a conditional atomic winner. Two sessions can both observe unused state and commit `used_at`. **Fail.** |
| No account redirection/replacement/elevation | Exact current target session and provider/user/subject uniqueness checks block tested wrong-owner and replacement paths. A dedicated normal-user privilege-escalation route test is absent. Condition. |
| Strict redirect handling | Callback URI is server-derived; return paths reject schemes, network paths and backslashes. Pass. |
| Recovery preserves safe behavior | Migration revokes legacy bearer invitations and local break-glass coverage exists. No end-to-end failed-IdP recovery test was found. Condition. |
| Audit/log redaction | App audit metadata excludes tokens/claims and Uvicorn access filter redacts callback/invitation query values. Reverse-proxy behavior was not exercised. Condition. |

## Tests inspected

- `tests/test_oidc_identity.py`
- `tests/test_oidc_routes.py`
- `tests/test_oidc_security.py`
- OIDC portions of `tests/test_database_migrations.py`

Existing coverage includes intended/wrong recipient, wrong/unverified email, issuer, audience, nonce, expiry, revocation, sequential reuse, modified token, invitation-claim concurrency, identity replacement, redirect safety, migration invalidation, audit minimization and Uvicorn access-log redaction.

Required gaps:

- stale/missing/future `auth_time` for admin-link freshness;
- concurrent state consumption using separate database sessions;
- revocation after claim but before callback/final link;
- explicit wrong-password invitation test;
- explicit missing-state callback test;
- changed-subject between callback/confirmation test;
- dedicated normal-user privilege-escalation test;
- session rotation/fixation test after sensitive step-up;
- end-to-end recovery after IdP failure;
- reverse-proxy log-redaction test.

## Tests executed

Environment:

- Linux `6.6.87.2-microsoft-standard-WSL2`, x86_64;
- Python `3.12.13`;
- production dependencies installed from `requirements.txt` in a Dockerfile-based image;
- review tools added in a derived local image: `pytest 9.1.1`, `ruff 0.12.9`;
- SQLite in-memory and temporary-file databases;
- clearly synthetic container-only configuration values.

Focused command:

```text
python -m pytest -p no:cacheprovider tests/test_oidc_identity.py tests/test_oidc_routes.py tests/test_oidc_security.py tests/test_database_migrations.py -q
```

Result: **105 passed**, 0 failed, 0 skipped, 588 warnings, 85.09 seconds.

Independent synthetic probes then reproduced:

1. an ID token with `auth_time=1` is accepted by the admin-link token validator;
2. revocation leaves `revoked_at` unset after an invitation is claimed but incomplete;
3. two database sessions can both read unused state and commit `used_at`, demonstrating the absence of an atomic consume predicate.

The previous 713-test/31-subtest Linux result is historical context only. A fresh full suite could not run after the environment exhausted Docker-engine approval quota; it is not used as verification evidence.

No OIDC production code changed during this review. Repository `git diff --check` passed. A fresh Ruff run was unavailable after Docker execution was refused, so no static-analysis pass is claimed.

## Bypass attempts and findings

### OIDC-IR-001 - Fresh IdP authentication is requested but not verified

`prompt=login` and `max_age=0` are authorization request hints. `validate_id_token()` neither requires `auth_time` nor compares it with the request time/max age. A provider ignoring the hint or returning a stale session is accepted. This disproves the fresh-IdP security claim.

Required correction: bind an explicit maximum age/request time into the server transaction, require a valid integer `auth_time` for admin-link callbacks, reject future/stale values using a small documented clock tolerance, and add missing/stale/future tests.

### OIDC-IR-002 - OIDC state consumption is not atomic

`consume_transaction()` queries an unused row, mutates `used_at`, then commits. There is no conditional `UPDATE ... WHERE used_at IS NULL` or equivalent winner check. Sequential replay tests pass but do not cover concurrent callback reuse.

Required correction: atomically consume state with a one-winner predicate and add separate-session concurrency/restart coverage.

### OIDC-IR-003 - Claimed invitations cannot be administratively revoked

The revocation route changes only rows where `used_at is None`. A claimed invitation may remain pending through IdP authorization/final confirmation; the validation path would honor `revoked_at`, but the administrator cannot set it during this interval.

Required correction: allow explicit revocation of any not-yet-completed invitation authorization, invalidate associated pending transactions/session binders safely, and test revocation between every transition.

## Unresolved uncertainties

- Reverse-proxy logging of invitation query tokens was not exercised.
- Session identifier rotation after recipient step-up was not demonstrated.
- No real IdP was used to confirm `auth_time`/`max_age` interoperability and failure behavior.
- The full supported-Linux suite was blocked by the environment after focused execution.

## Final review result

**Changes required.** Recipient/email/provider binding and invitation-claim atomicity materially improve the original design, but fresh IdP assurance, atomic OIDC state consumption and in-flight administrative revocation are not verified and have reproducible defects. `KAYA-OIDC-001` is not ready for merge or closure.
