# Kaya pull-request security review checklist

Use this checklist before merging. Mark non-applicable items and briefly explain why.

## Identity and access

- [ ] **Authentication:** Every non-public HTTP, API and WebSocket path verifies a current active identity server-side.
- [ ] **Session lifecycle:** Login rotates session state; logout, password/MFA changes, account disablement and forced logout invalidate applicable sessions.
- [ ] **Role authorisation:** Each operation allows only the documented roles, including direct API calls.
- [ ] **Object authorisation:** Every record, file and bulk identifier is checked for ownership, membership or an explicit grant.
- [ ] **Deny by default:** New routes and actions are private unless their public status is intentional, documented and tested.

## Requests and responses

- [ ] **Input validation:** Path, query, form, JSON, header, cookie, WebSocket and integration data have type, length, format, range and allow-list checks.
- [ ] **Output encoding:** Templates escape untrusted values; any safe-HTML use has a reviewed allow-list or safe renderer.
- [ ] **Data minimisation:** APIs and templates return only necessary fields and never generic full-model serialisation.
- [ ] **CSRF:** Every browser state change validates a server-generated token.
- [ ] **XSS:** Stored and reflected values, URLs, Markdown and filenames cannot create executable markup or script.
- [ ] **SQL injection:** Values are parameterised and dynamic columns/sort keys are allow-listed.
- [ ] **Safe errors:** Responses do not reveal traces, SQL, paths, internal hosts, secrets or raw upstream content.

## Network and process boundaries

- [ ] **SSRF:** User-influenced destinations have scheme/host/port policy, DNS/address checks, redirect revalidation, TLS verification, timeouts and response-size limits.
- [ ] **Command injection:** Processes use argument arrays and validated values; no untrusted value reaches a shell command string.
- [ ] **WebSockets:** Handshakes validate active sessions, roles, object access and allowed origins; sessions cannot be guessed or attached across users.
- [ ] **Rate limits:** Authentication, remote, integration and expensive operations have bounded, trusted-identity abuse controls and a recovery path.

## Files and secrets

- [ ] **Path traversal:** User values cannot select absolute paths, parent paths, symlinks or files outside the intended storage root.
- [ ] **Uploads:** Generated storage names, streaming size limits, content validation and non-executable storage are used.
- [ ] **Downloads:** Per-object permission is checked and `Content-Disposition`, content type and cache headers are safe.
- [ ] **Archives/imports:** Entry paths, record counts, nesting, decompressed size, field lengths and overwrite behaviour are bounded.
- [ ] **Secrets:** Passwords, tokens, cookies, keys, TOTP seeds and credentials are encrypted/hashed as appropriate and never logged or returned.
- [ ] **Masked values:** Placeholder or masked form values cannot overwrite a stored secret accidentally.
- [ ] **Backups/exports:** Inclusion of secrets is deliberate, documented and protected; restore integrity and confirmation are enforced.

## Observability and operations

- [ ] **Logging/redaction:** Request and upstream errors are redacted; sensitive bodies, headers and identifiers are excluded.
- [ ] **Audit logging:** Actor, action, target, outcome, trusted IP and request ID are recorded for security-sensitive success and failure.
- [ ] **Audit integrity:** Ordinary users cannot modify or delete audit records through application paths.
- [ ] **Proxy handling:** Client identity comes from the central trusted-proxy resolver and direct spoofed headers are ignored.
- [ ] **Security headers:** CSP, frame policy, content-type, referrer, permissions, HSTS (when appropriate) and no-store behaviour remain effective.

## Supply chain and deployment

- [ ] **Dependency impact:** New or changed packages are necessary, pinned/locked appropriately, licensed acceptably and covered by vulnerability scanning.
- [ ] **Docker impact:** The service remains non-root after setup, least-privileged, no-new-privileges, minimally capable and narrowly exposed.
- [ ] **Secrets deployment:** Secrets are injected with safe permissions and are not baked into images, committed or printed.
- [ ] **CI security:** Applicable dependency, static, secret and container scans run and failures are not broadly suppressed.

## Delivery quality

- [ ] **Tests:** Anonymous, role, object-ID, malformed-input and security-control regression cases are included where applicable.
- [ ] **Fake fixtures:** Tests contain only synthetic credentials, addresses and infrastructure details.
- [ ] **Documentation:** Deployment, configuration, threat-model and operator guidance reflects the change.
- [ ] **Migration:** Data and configuration changes are non-destructive, recoverable and documented.
- [ ] **Backwards compatibility:** Behaviour changes have a safe migration path and release note; compatibility does not preserve a Critical or High risk.
- [ ] **Security Impact:** The completion summary contains the required Security Impact section.
