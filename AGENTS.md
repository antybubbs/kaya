# Kaya agent instructions

These instructions apply to the entire repository.

## Mandatory security standard

Before changing application code, read and follow [SECURITY_ENGINEERING.md](SECURITY_ENGINEERING.md). Do not proceed on assumptions based only on function or middleware names; trace the actual HTTP, API, WebSocket, agent, file or background-job path.

For every code change:

1. Identify affected trust boundaries.
2. Identify whether authentication is required.
3. Identify the roles permitted to perform the action.
4. Check object-level authorisation for every referenced record or file.
5. Validate all new input by type, length, format, range, expected value, ownership and permission.
6. Confirm output encoding and data minimisation.
7. Consider CSRF, XSS, SQL injection, SSRF, command injection and path traversal as applicable.
8. Confirm secrets are not logged, audited, returned or placed in URLs or process arguments.
9. Add or update relevant tests, using clearly fake data only.
10. Preserve redacted audit logging for security-relevant actions.
11. Avoid weakening existing controls or making broad security refactors.
12. Report security concerns discovered during unrelated work.
13. Stop and explain before introducing a high-risk design or materially expanding a trust boundary.

Every feature or bug-fix completion summary must contain the **Security Impact** section defined in `SECURITY_ENGINEERING.md`, including security-sensitive components, authentication and authorisation, input validation, secrets or personal data, tests, and remaining risks or assumptions. For a security-neutral change, explain why it is neutral.

## Change discipline

- Preserve Kaya's module structure, visual branding and working behaviour unless a documented security requirement demands a change.
- Prefer small, reviewable patches and focused regression tests.
- Do not reset databases, destructively migrate data, rotate/delete credentials, alter accounts, or test destructively against live services without explicit owner approval.
- Never put discovered secret values in terminal output, reports, fixtures or commits.
- Follow existing repository conventions where they remain safe.
