# Kaya v0.24.0 — Identity, Vault and Secure Delivery

Kaya v0.24.0 is a major security and identity release. It adds enterprise-ready OpenID Connect authentication, an encrypted Secret Vault for operational recovery material, and Secure Send for temporary encrypted delivery of files and notes. It also expands DNS and network visibility, improves mobile and navigation behavior, and adds deeper operational diagnostics.

## Highlights

- OpenID Connect authentication with discovery, PKCE, secure account linking, role mapping, JIT provisioning controls, and emergency local access.
- Secret Vault with per-user encryption, MFA-gated access, encrypted attachments, recovery kits, portable backups, and offline recovery tooling.
- Secure Send with encrypted temporary packages, a dedicated recipient gateway, lifecycle controls, email notifications, and complete or individual file downloads.
- Expanded DNS client intelligence, recognised-device tracking, collector health, investigations, and client detail views.
- Improved IP address and network monitoring workflows, including WAN monitoring and richer status detail.
- A refreshed sidebar, authentication experience, tables, headings, mobile layouts, and general interface consistency.

## OpenID Connect authentication

Kaya can now authenticate users through standards-compliant OpenID Connect providers while retaining local accounts and Kaya's own authorisation model.

- Added Authorization Code flow with mandatory PKCE `S256`, state and nonce validation, discovery, JWKS validation, and asymmetric ID-token verification.
- Added configurable claim mappings, nested claim paths, allowed email domains, group-to-role mapping, and optional role synchronisation.
- Added controlled just-in-time provisioning and verified-email requirements.
- Added self-service identity linking, administrator-generated one-time linking invitations, and configurable first-login matching.
- Added **Local only**, **Local and OIDC**, **OIDC preferred**, and guarded **OIDC required** modes.
- Added a designated emergency local administrator and `/auth/local` break-glass path so provider failures do not lock administrators out.
- Added provider configuration tests, real test-login validation, sanitised error handling, and dedicated authentik deployment guidance.
- Added fresh OIDC MFA step-up support for Secret Vault operations when the provider supplies acceptable `acr`, `amr`, and `auth_time` assurance.

Existing local sign-in, password reset, TOTP, roles, sessions, and module permissions continue to work. OIDC remains disabled until configured by an administrator.

## Secret Vault

Secret Vault provides encrypted storage for recovery keys, sensitive operational notes, certificates, documents, and break-glass information.

- Added private per-user vaults protected by a separate PIN or passphrase and fresh MFA.
- Added AES-256-GCM encryption for sensitive fields and attachments with record-specific associated data.
- Added item types, collections, protected and highly sensitive fields, tags, classifications, review dates, and encrypted attachments.
- Added automatic session locking, absolute session limits, manual locking, and session revocation on logout or recovery.
- Added masked-field reveal and fresh-authentication controls for highly sensitive data.
- Added one-time recovery kits and recovery-key-based PIN reset without weakening account-wide MFA.
- Added portable `.kayavault` export and restore with authenticated encryption and a separate export passphrase.
- Added `scripts/kayavault_recovery.py` for offline package inspection and safe extraction when Kaya is unavailable.
- Added security audit events for setup, unlock, reveal, download, backup, restore, recovery, and failed authentication without recording vault content.
- Added an optional Secure Send handoff that creates an independent temporary encrypted copy.

Administrators cannot open another user's private vault through the Kaya interface. Successful disaster recovery requires the database, encrypted attachment storage, and the original application `ENCRYPTION_KEY`, or a separately protected portable `.kayavault` export.

## Secure Send

Secure Send adds temporary encrypted delivery for files and secure notes without exposing the main Kaya application to recipients.

- Added sender workflows for external and internal recipients, configurable expiry, optional one-download packages, notes, and multiple files.
- Added per-package AES-256-GCM content encryption and credentials derived from a high-entropy URL token, sender PIN, and generated passphrase.
- Added a dedicated minimal recipient gateway with no Kaya login, administration routes, API documentation, or access to the main application.
- Added opaque recipient sessions, session-bound CSRF protection, throttling, lockouts, strict route and host validation, bounded form submissions, and hardened response headers.
- Added sender lifecycle controls for access revocation, expiry extension, package deletion, download tracking, and activity history.
- Added recipient email templates and notification controls. PINs and passphrases are never included in recipient email.
- Added live gateway health reporting in the authenticated Kaya interface.
- Added clearer recipient download choices: a complete ZIP containing every file and the secure note, or compact per-file download actions.
- Fixed Edge form unlocks by retaining an origin-only referrer policy, allowing the gateway's same-origin validation to receive a usable `Origin` value without disclosing the bearer-token path.
- Added safe categorical rejection diagnostics that never log access tokens, credentials, form values, request paths, or client addresses.

The gateway is included in `docker-compose.yml` and listens on port `8999` by default. Keep the main Kaya interface private, expose only the gateway to intended recipients, and use HTTPS for every public deployment.

## DNS and network operations

- Added DNS client collection, client detail pages, recognised-device tracking, and known-hostname management.
- Expanded DNS insights, provider health, query activity, blocked-query reporting, investigations, and collector state handling.
- Improved stale, degraded, disconnected, unavailable, and failed-provider behavior while preserving the most recent successful data.
- Added richer IP address records, network monitoring detail, WAN monitoring documentation, and improved address-management workflows.
- Improved DNS and network background processing, failure isolation, retention, and performance diagnostics.

## Interface and accessibility

- Refreshed the sidebar hierarchy, collapse behavior, module imagery, version panel, and navigation spacing.
- Improved the login and authentication settings experiences, including clearer OIDC status and error presentation.
- Improved tables, headings, action buttons, forms, responsive layouts, and smaller-screen behavior across modules.
- Added dedicated styling and responsive behavior for Secret Vault and Secure Send.
- Improved dashboard, DNS, IP address, network monitor, user, and profile presentation.

## Security and reliability

- Added sanitised OIDC transaction and callback logging with authorization codes and sensitive query values redacted.
- Added outbound OIDC endpoint protections for unsafe schemes, metadata services, link-local destinations, and invalid issuer configurations.
- Added encrypted client-secret storage and prevented configured secrets from being redisplayed.
- Added gateway host, origin, method, content-type, body-size, rate-limit, and route-shape enforcement.
- Added portable-vault integrity verification, safe extraction paths, and overwrite protection.
- Expanded database performance diagnostics, connection handling, startup migrations, and reproducible performance tooling.
- Expanded automated coverage for OIDC, Secret Vault, Secure Send, DNS clients, collectors, mail, networking, migrations, UI behavior, and security controls.

## Upgrade notes

1. Back up the Kaya database, uploads, and persistent `data` directory before upgrading.
2. Preserve and separately back up the existing `ENCRYPTION_KEY`. Secret Vault and Secure Send data cannot be recovered from the database alone.
3. Rebuild or pull the new image and recreate both the main Kaya service and `secure-send-gateway` service.
4. Kaya applies the required SQLite schema additions during startup; no normal manual migration step is required.
5. If Secure Send will be public, configure its external HTTPS origin under **Site Administration > Module Settings > Secure Send** before sharing packages.
6. Configure reverse proxies to preserve the original host and HTTPS scheme, trust only the proxy's actual IP or network through `FORWARDED_ALLOW_IPS`, and redact Secure Send bearer paths from upstream access logs.
7. Before requiring OIDC, designate and test an emergency local administrator, validate discovery, complete a real test login, and confirm `/auth/local` works.
8. Before relying on Secret Vault, verify MFA, persistent encrypted storage, the application-key backup, and a tested portable export.

## Compatibility

- Existing local users and permissions remain supported.
- OIDC, Secret Vault, and Secure Send are disabled or unconfigured until deliberately enabled by an administrator.
- Secure Send is visible but non-functional in the public demo.
- Standard SQLite installations are migrated automatically and existing records are retained.

**Full comparison:** [v0.22.0...v0.24.0](https://github.com/antybubbs/kaya/compare/v0.22.0...v0.24.0)
