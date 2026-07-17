# Security

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Authentication

Kaya uses email/password authentication with optional TOTP two-factor authentication.

Login flow:

1. If no users exist, `/login` redirects to `/setup`.
2. `/setup` creates the initial admin user.
3. `/login` validates CSRF, rate limits attempts, verifies the password hash, and checks whether TOTP is enabled.
4. If TOTP is enabled, a pending 2FA session state is set before final login.
5. On successful login, `user_id` and a generated `session_id` are stored in the signed session cookie.
6. An `AppSession` row is created for audit/activity tracking.

## Roles

- Admin: full administrative access, settings, users, audit logs, sensitive remote recordings
- Editor: can create and modify operational records
- Viewer: read-only access to most authenticated pages

Authorisation is implemented with FastAPI dependencies:

- `require_user`
- `require_editor`
- `require_admin`

## Sessions

Session handling uses Starlette `SessionMiddleware`, so session data is stored client-side in a signed cookie. The `AppSession` table is an activity ledger, not the source of session validity.

Session cookies use `same_site=strict`. The secure flag can be configured and is reinforced for HTTPS requests.

## Passwords And Secrets

- Passwords are hashed with Argon2.
- Initial setup and user creation require passwords of at least 12 characters.
- Password reset tokens are stored as SHA-256 hashes.
- Password reset links expire after one hour.
- Login and password reset flows have in-memory rate limiting.
- TOTP secrets are Fernet-encrypted.
- Stored secrets such as licence keys, SMTP passwords, DNS provider secrets, backup passwords, and API tokens are Fernet-encrypted.

## CSRF

Browser form flows include CSRF tokens. Several JSON/form endpoints explicitly validate CSRF. Bearer-token agent APIs do not use CSRF because they are non-browser API clients; their safety depends on token secrecy.

## Secure Send

Secure Send uses per-package AES-256-GCM content keys, Argon2 credential verification and opaque recipient sessions. Recipient access requires the high-entropy URL token, a sender-selected PIN and a generated passphrase. The gateway fail-closes unknown routes and hosts with an unbranded `403`, restricts methods, origins, body sizes and static assets, protects its health endpoint, suppresses bearer-path access logs, and applies a restrictive content security policy, HSTS over HTTPS, no-store responses, throttling and session-bound CSRF protection. Expiry, revocation, deletion and one-download completion revoke access; a background cleanup worker destroys expired file and note ciphertext. See [Secure Send](modules/secure-send.md) for deployment, reverse-proxy logging and recovery details.

## Security Headers

Security headers are applied by middleware and include content security policy, frame controls, referrer policy, permissions policy, content type protection, cache control, and optional HSTS.

Trusted host behaviour is configurable through site settings and environment settings.

## Demo Mode

Demo mode:

- Creates synthetic admin/editor/viewer accounts.
- Can reset the demo database on a schedule.
- Blocks remote access paths, backup agent APIs, and many mutating admin/network/security routes.
- Invalidates demo sessions when the demo generation marker changes.

Any new route that mutates data, reaches into the network, performs remote access, or exposes secrets must be reviewed against demo-mode restrictions.

Demo mode also redacts client IP addresses and user agents from request audit
records and does not store client IP addresses in login sessions. The public
demo uses shared accounts, so visitor network identifiers must not be persisted
where another demo user could view them.

## Current Risks

- Rate limits are in-memory and not distributed.
- RBAC is coarse-grained.
- Permissions are manually applied per route.
- No object-level access control.
- Hardware photos are validated more strongly than general attachments.
- No antivirus/content scanning.
- Remote recordings may contain sensitive data.
- Licence exports can expose decrypted product keys.
- Losing `ENCRYPTION_KEY` breaks decryption of stored secrets.
- Agents receive decrypted backup credentials and backup keys when jobs are dispatched.
- Background jobs run in the web process.
- Multi-replica deployments could duplicate polling and job processing.
