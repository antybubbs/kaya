# Authentication and Session Architecture

## Supported authentication

Kaya supports local authentication and may support OpenID Connect (OIDC) when configured.

Authentication proves identity. It does not by itself grant module or action access.

## Local passwords

Local passwords must be hashed using the repository-approved Argon2 configuration.

Passwords must never be:

- encrypted reversibly;
- logged;
- included in audit metadata;
- returned through an API;
- retained in plaintext after validation.

Password changes and resets must invalidate or rotate relevant authentication state where supported.

## Sessions

Kaya uses signed session cookies.

Session configuration must:

- use a high-entropy secret;
- use `HttpOnly`;
- use `SameSite=Lax` unless a reviewed flow requires otherwise;
- use `Secure` whenever accessed over HTTPS;
- define a finite lifetime;
- avoid storing sensitive records or secrets in the cookie payload.

Do not trust `X-Forwarded-Proto` from arbitrary clients. Scheme correction must be tied to trusted proxy configuration.

## Login behaviour

Login endpoints must have:

- CSRF protection where applicable;
- rate limiting or equivalent brute-force protection;
- generic failure messages that do not disclose whether a username exists;
- audit records for meaningful success and failure events;
- safe redirect handling.

## OIDC

OIDC implementation must validate:

- state;
- nonce where used;
- issuer;
- audience/client identifier;
- token signature and expiry;
- approved callback URL;
- user mapping rules.

OIDC provider configuration and client secrets must not be exposed in logs or the UI after storage.

Disabling OIDC must not strand the last administrator without a viable local authentication path.

## Reauthentication

Sensitive functions such as vault access, recovery operations, changing authentication configuration or exporting protected material may require reauthentication or an additional factor.

The required assurance must be documented per feature.

## Session revocation

Security-relevant events should revoke active sessions where practical, including:

- account disablement;
- password reset;
- role reduction;
- suspected compromise;
- major authentication configuration change.

## Testing

Authentication tests must include:

- valid and invalid local login;
- disabled user;
- expired or invalid session;
- secure cookie attributes;
- open redirect attempts;
- OIDC state failure;
- access after role or module access removal.
