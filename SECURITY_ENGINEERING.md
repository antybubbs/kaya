# Kaya Security Engineering Standard

This document is mandatory for every change to Kaya. Kaya is a security-sensitive infrastructure-management product. A self-hosted or internal deployment is not assumed to be harmless, and secure operation must not depend on every installer being a security specialist.

## Scope and use

Before changing application code, an engineer or coding agent must:

1. Read this document.
2. Identify the trust boundaries and security-sensitive data affected.
3. Decide whether authentication, role-based authorisation, and object-level authorisation are required.
4. Review relevant input, output, browser, network, file, secret, audit, and deployment risks.
5. Add or update tests for the security properties affected.
6. Include a Security Impact section in the completion summary.

If a proposed design creates a high-risk trust boundary, exposes a service, weakens a control, or changes how secrets are protected, stop and explain the design and alternatives before implementation.

## The Kaya Security Commandments

### 1. Deny by default

Every route, API endpoint, WebSocket, file and action is private unless it has been intentionally declared public. Public endpoints must be documented, narrowly scoped and tested.

### 2. Authentication is not authorisation

Every protected operation must verify both identity and permission.

### 3. Authorise the specific object

Permission to use a module does not automatically grant permission to every record within it. Verify ownership, membership or an explicit object-level grant on every object read or mutation.

### 4. Enforce security server-side

Buttons, menus, disabled fields, client-side checks and hidden routes are not security controls.

### 5. Treat all input as hostile

Validate browser, API, file, integration, header, cookie, environment and WebSocket input for type, length, format, range, expected values, ownership and permission.

### 6. Return the minimum necessary data

Do not expose full models, internal fields or secrets merely because they are available. Response schemas must explicitly select allowed fields.

### 7. Never expose or log secrets

Passwords, tokens, session cookies, encryption keys, TOTP seeds, recovery values and credentials must be redacted. Audit that a secret changed, never the secret itself.

### 8. Use safe primitives

Use parameterised database queries, reviewed cryptographic libraries, secure random generation and structured process execution. Never invent custom cryptography. Never construct a shell command from untrusted strings.

### 9. Protect every state-changing browser action from CSRF

Every browser-initiated POST, PUT, PATCH and DELETE requires a server-generated, server-validated CSRF token. SameSite cookies are defence in depth, not a replacement.

### 10. Assume object identifiers can be guessed

UUIDs and long random identifiers reduce guessing but do not replace authorisation.

### 11. Treat outbound network access as dangerous

Every user-influenced outbound request must be reviewed for SSRF, DNS rebinding, redirects, schemes, embedded credentials, ports, timeouts, response sizes and TLS verification. LAN access must be constrained to the feature's authorised purpose.

### 12. Treat file handling as dangerous

Never trust filenames, paths, extensions or browser-provided content types. Generate storage names, constrain paths, limit sizes, validate content where practical, prevent archive traversal, and authorise every download.

### 13. Use secure defaults

An inexperienced user following the default installation path must not accidentally deploy Kaya in an obviously unsafe state. Dangerous compatibility options must be explicit and clearly labelled.

### 14. Fail closed

When a permission check, identity check, configuration validation or security dependency fails, deny the operation safely.

### 15. Preserve auditability

Security-sensitive actions must produce useful, redacted and tamper-resistant audit records containing actor, action, target, outcome, trusted client IP and request/correlation ID where available.

### 16. Do not weaken a security control to fix functionality

Do not solve CSP, TLS, permission, validation or authentication errors by broadly disabling the control. Find the underlying cause.

### 17. Avoid broad refactors during security fixes

Use small, reviewable changes with regression tests. Keep unrelated cosmetic and architectural work out of security patches.

### 18. Security changes require tests

Every corrected vulnerability must have a test that would fail if the vulnerability returned. Tests use only clearly fake credentials and synthetic infrastructure data.

### 19. Protect backwards compatibility carefully

Compatibility matters, but it does not override a Critical or High risk. Provide a migration path and release note when a security correction changes behaviour. Never silently alter or delete user data.

### 20. Never claim complete security

Security reviews and release notes must state their scope, assumptions and limitations. Automated scans are evidence, not proof of security.

## Required engineering checks

For every feature or fix, determine and document as applicable:

- The public, authenticated, administrator, agent, gateway, integration and local-process trust boundaries involved.
- Authentication requirements for HTTP and WebSocket paths, including disabled-user and revoked-session behaviour.
- Permitted roles and object-level rules for reads, writes, downloads, bulk actions and indirect identifiers.
- Input limits and allow-list validation for form, JSON, query, path, header, cookie, WebSocket, import and upload data.
- Output encoding, safe HTML handling, explicit response fields and cache policy.
- CSRF, XSS, SQL injection, SSRF, command injection and path traversal exposure.
- Secret storage, transport, display, masking, logging, audit, export and backup behaviour.
- Rate limits and resource limits, using the trusted client identity where relevant.
- Safe errors: no stack traces, SQL errors, paths, secrets or raw credential-bearing upstream responses.
- Audit events for successful and failed security-sensitive actions.
- Docker, proxy, dependency, migration and backwards-compatibility impact.

## Security Impact completion format

Every feature or bug-fix completion summary must include:

### Security Impact

- **Security-sensitive components touched:** List them, or state none.
- **Authentication and authorisation:** Describe requirements and object-level enforcement.
- **Input validation:** Describe limits and validation added or changed.
- **Secrets or personal data:** Describe what is involved and how it is protected.
- **Tests:** List security and regression tests added or updated.
- **Remaining risks or assumptions:** State them explicitly.

For a genuinely security-neutral change, state why it does not alter trust boundaries, permissions, untrusted input, sensitive output, secrets, audit behaviour or deployment security.

## Review and exceptions

Any exception to this standard requires an explicit, documented owner decision recording the affected commandment, threat model, compensating controls, expiry/review date and tests. A scanner suppression must be narrow and explain why the result is a false positive or accepted risk.
