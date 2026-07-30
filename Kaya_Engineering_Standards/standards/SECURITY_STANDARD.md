# Security Standard

## 1. General rule

Security controls must be designed into the feature and enforced by the server.

This standard should be read alongside OWASP guidance, but Kaya's implementation rules in this document are authoritative for the repository.

## 2. Input validation

Validate type, length, range and format at the boundary.

Do not rely only on HTML constraints.

Normalise identifiers before comparison where the domain requires it, such as MAC addresses, hostnames and IP addresses.

Reject unexpected file types and paths.

## 3. Output encoding and XSS

Jinja auto-escaping must remain enabled for HTML templates.

Use `|safe` only for content that is generated or sanitised by Kaya and reviewed for that exact use.

Do not insert user-provided strings through `innerHTML`. Prefer text nodes or safe DOM construction.

## 4. CSRF

All browser-authenticated state-changing requests must be protected against CSRF.

GET and HEAD routes must not mutate state.

JSON endpoints used by the browser require equivalent CSRF protection unless they use a reviewed authentication mechanism not automatically sent cross-site.

## 5. SQL injection

Use SQLAlchemy expressions or parameterised SQL.

Never interpolate user values into SQL strings, identifiers or order clauses without strict allow-listing.

## 6. Authentication and passwords

Use Argon2 through the shared security helper.

Do not implement custom password hashing.

Apply rate limiting or progressive delay to authentication and recovery endpoints.

Authentication errors should not reveal whether an account exists.

## 7. Authorisation

Check global role, module access and record-level restrictions on the server.

Every alternate endpoint, export, import, bulk action and background-trigger endpoint must enforce equivalent permissions.

## 8. Sessions and cookies

Session cookies must be signed, HttpOnly, SameSite and Secure over HTTPS.

Session secrets require sufficient entropy and must not use documented defaults in production.

Session identifiers or signed session payloads must not be logged.

## 9. Reverse proxy trust

Client-controlled forwarding headers are untrusted.

Only configured proxy addresses may influence effective client IP or scheme.

Audit logs must use the trusted client-IP service, not direct parsing copied into individual modules.

## 10. Security headers

Production responses should maintain:

- Content Security Policy;
- `X-Content-Type-Options: nosniff`;
- appropriate frame protection;
- restrictive referrer policy;
- permissions policy;
- HSTS when safely configured.

CSP exceptions require review. Do not add `'unsafe-inline'` to script policy.

Inline style allowances should be reduced over time rather than expanded.

## 11. Secrets and encryption

Do not commit or log secrets.

Encryption keys must be separate from encrypted data backups where practical, but recovery documentation must ensure both can be restored by an authorised owner.

Use the shared cryptography implementation. Do not invent ciphers, key derivation or token formats.

Encrypted fields must have a migration and key-rotation strategy.

## 12. Secure Vault

Vault content requires encryption at rest and additional access controls proportionate to its sensitivity.

Vault plaintext must:

- exist in memory only as long as required;
- never appear in logs, traces or audit metadata;
- not be placed in URLs;
- not be cached by the browser;
- be excluded from broad exports unless explicitly authorised.

Vault backups must be encrypted and recoverable.

## 13. Secure Send

Secure Send tokens must be high entropy, revocable and redacted from logs.

Downloads should support expiry, download limits and clear consumed/expired state.

Files must be stored outside directly served static directories.

## 14. File uploads

Uploads require:

- size limits;
- extension and content-type checks;
- generated storage names;
- path traversal protection;
- storage outside the static root;
- malware scanning integration where available and proportionate;
- authorised download handlers;
- content-disposition safety.

Never trust the original filename as a filesystem path.

## 15. SSRF and external requests

URLs and host targets supplied by users can create SSRF risk.

Restrict schemes and destination classes according to feature requirements.

Do not allow arbitrary requests to cloud metadata endpoints, local Unix sockets or unsupported schemes.

Set timeouts and limit redirects.

## 16. Command execution

Avoid shell execution.

When required, pass argument arrays without `shell=True`, validate every argument and document the trust boundary.

Credentials must not appear in process arguments where they can be observed.

## 17. WebSockets and remote access

Remote Manager and Guacamole-related channels must authenticate the session and validate target access before connection.

Connection identifiers must be unguessable or bound to the session.

Frame and CSP exceptions must be limited to the specific remote panel routes that require them.

## 18. Shared wallboards

Shared wallboards must use unguessable tokens, revocation and configurable access protection.

Sensitive bearer identifiers must be redacted from audit paths and application logs.

Wallboards must expose only the minimum required monitoring data.

## 19. Logging and privacy

Do not log passwords, TOTP seeds, vault content, API keys, session cookies, OIDC tokens, shared-link tokens, private keys or full protected payloads.

User agents and IP addresses are personal data in many jurisdictions and should be retained only as required.

## 20. Dependencies

Run dependency vulnerability checks in CI.

A critical vulnerability in an internet-facing or security-critical dependency must be assessed promptly.

Do not upgrade blindly. Review breaking changes and test the affected security flows.

## 21. Security review triggers

Use the security review template for changes involving:

- authentication;
- roles or module access;
- cryptography;
- files;
- shared public links;
- remote access;
- reverse proxies;
- external URL fetching;
- backups of sensitive data;
- command execution;
- new network listeners.
