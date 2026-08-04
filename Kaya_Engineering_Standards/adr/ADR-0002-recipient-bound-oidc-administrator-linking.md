# ADR-0002: Recipient-bound OIDC administrator linking

**Status:** Proposed  
**Date:** 2026-08-04  
**Decision owners:** Kaya maintainers

## Context

An administrator-created OIDC link URL previously acted as bearer authority to bind any valid, unlinked provider subject to the selected Kaya account. The provider proved control of the new external identity, but Kaya did not prove that the redeemer controlled the intended local account. Theft of an invitation for an administrator could therefore become account takeover (`KAYA-OIDC-001`).

The flow crosses four trust boundaries: the administrator session that creates the invitation, the recipient browser session, the Kaya-to-provider authorization-code exchange, and the durable local identity binding. Existing issuer, audience, signature, expiry, state, nonce and PKCE controls remain necessary but do not provide recipient authorisation.

## Decision

Kaya treats an administrator invitation as a short-lived locator, not as proof of authority.

- Creation requires an active administrator session and CSRF validation. The URL contains 256 bits of randomness, while only its SHA-256 hash is retained. The raw URL is shown once in a `no-store` response and is excluded from application and access logs.
- The intended recipient must already have an active Kaya session for the exact active target account. They must freshly prove the current local password and, when enabled, Kaya TOTP. Accounts without a local password cannot use this flow.
- Opening the URL replaces it with a clean URL and binds a random redemption value to both the browser session and a server-side hash. The invitation is atomically consumed before the provider redirect; replay and concurrent claims fail closed.
- The provider authorization request uses a new state, nonce and PKCE verifier plus `prompt=login` and `max_age=0`. For this privileged flow, Kaya additionally requires the signed ID token to contain a valid NumericDate `auth_time` no earlier than the server-recorded transaction start, allowing at most 60 seconds of clock skew. Missing, malformed, negative, stale or excessively future values fail closed; `iat` and provider UI hints are not substitutes.
- The validated provider email must be explicitly verified and exactly match the target's normalized current Kaya email, even when the provider's general login policy permits unverified email.
- Invitation records are bound to security-relevant target state and provider configuration. Target email, role, active state or update timestamp changes, and provider issuer, client ID, claim mapping, enabled state or update timestamp changes invalidate the invitation.
- Final confirmation again requires the same active target session. Kaya never starts a target session from an administrator-link flow. The permanent identity key remains provider ID, issuer and subject; email is only initial recipient-binding evidence.
- State consumption is one conditional database update over the hashed transaction/state pair, unused marker and expiry. Exactly one worker can transition the row to consumed; the transition commits before token exchange or identity effects, so replay, process restart and post-consumption failure cannot restore the callback.
- Invitations have explicit pending, claimed, completed, revoked and expired states. Any administrator may atomically revoke a pending or claimed invitation. Final identity creation and the claimed-to-completed transition commit together and recheck revocation, expiry, recipient and provider bindings; whichever of revocation or completion wins first is terminal. Revocation never unlinks an already completed identity.
- Creation, opening, rejection, redemption, revocation, link success and link failure remain auditable without raw tokens, passwords, TOTP values or full claims.

## Consequences

- A stolen invitation alone cannot link an attacker identity or create a target session.
- An intended recipient needs a working local authentication method before linking. This deliberately excludes OIDC-only accounts because they cannot independently prove control of the unlinked Kaya account.
- A provider or recipient change may require the administrator to issue a replacement invitation.
- Consuming the OIDC callback state before token exchange prevents concurrent callback reuse. A claimed invitation remains revocable while the provider or final-confirmation step is incomplete; an abandoned flow can be revoked and replaced.
- Providers that omit signed `auth_time` are incompatible with administrator-link invitations. Kaya fails closed rather than silently reducing authentication assurance; ordinary OIDC login remains unaffected.
- Kaya relies on the provider's signed verified-email claim for the initial match. Provider administration, signing-key compromise and upstream account recovery remain outside Kaya's direct control.

## Security and privacy impact

Positive. The decision removes bearer-only account-link authority, adds object-level recipient authorisation and local step-up authentication, and minimizes retained invitation data. Email remains displayed to the authorised administrator and recipient, while tokens and full provider claims are excluded from audit metadata.

## Compatibility and migration

Upgrade revokes every unused legacy invitation because those rows have no trustworthy recipient/provider binding and adds a nullable completion timestamp for the explicit lifecycle. Existing `ExternalIdentity` links and local accounts are preserved. Outstanding legacy/incomplete rows cannot silently become completed. Rollback restores the old schema but cannot safely restore revoked legacy invitation secrets; issue new invitations only after returning to a secure release.

Before upgrade, verify a local break-glass administrator with a strong password and TOTP. If the intended account has no local password, do not bypass recipient proof: use the approved local account-recovery process, validate the account owner out of band, establish and test a local method, and then issue a new invitation. Do not unlink a working last administrator identity during recovery.

## References

- `SECURITY_ENGINEERING.md`
- `security-review/FINDINGS_REGISTER.md` (`KAYA-OIDC-001`)
- `docs/authentication/openid-connect.md`
