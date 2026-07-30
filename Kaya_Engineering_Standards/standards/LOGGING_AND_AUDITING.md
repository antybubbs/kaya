# Logging and Auditing Standard

## Separation

Application logging supports diagnosis and operation.

Audit logging records who performed a meaningful action, what changed and when.

They overlap but are not interchangeable.

## Application logs

Use the standard logging framework. Do not use `print()`.

Logs should include:

- severity;
- component or service;
- concise event;
- request or task identifier where available;
- exception traceback for unexpected failures.

Avoid dumping full objects or payloads.

## Severity

- `DEBUG`: detailed diagnostic information disabled in normal production.
- `INFO`: lifecycle and meaningful operational events.
- `WARNING`: recoverable abnormal condition requiring awareness.
- `ERROR`: operation failed or subsystem degraded.
- `CRITICAL`: Kaya cannot safely continue or a severe integrity/security condition exists.

## Audit events

Audit meaningful actions such as:

- authentication success and security-relevant failure;
- user, role and module-access changes;
- settings changes;
- creation, update and deletion of protected records;
- exports and restores;
- shared-link creation and revocation;
- vault access and protected document actions;
- failover and high-availability control actions.

## Audit content

An audit event should include, where appropriate:

- actor;
- action;
- entity type and stable identifier;
- timestamp;
- trusted client address;
- request identifier;
- outcome/status;
- concise safe metadata.

## Redaction

Never record:

- passwords;
- session cookies;
- OIDC tokens;
- TOTP seeds;
- vault plaintext;
- API keys;
- encryption keys;
- shared bearer tokens;
- private file contents.

Sensitive URL segments must be redacted before persistence.

## Failure behaviour

Audit failure must be handled deliberately.

For high-risk actions, inability to write a required audit record may justify failing the action. For lower-risk requests, the application may proceed while logging the audit subsystem failure.

The chosen behaviour must be consistent and tested.

## Retention and access

Audit records should have a documented retention policy.

Only authorised users may view or export audit data.

Audit export itself must be audited.
