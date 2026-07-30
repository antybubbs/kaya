# Testing Standard

## Goals

Tests protect security boundaries, user-visible behaviour, data integrity and difficult failure modes.

## Test layers

### Unit tests

Use for focused services, parsers, validators, token logic, retention rules and status calculations.

### Integration tests

Use for routes, database operations, permissions, templates and multi-step workflows.

### Regression tests

Every confirmed defect should receive a test that fails before the fix and passes after it, where practical.

## Required coverage by change type

### New route

Test:

- anonymous access;
- insufficient module access;
- insufficient role;
- valid request;
- invalid input;
- expected failure;
- relevant audit behaviour.

### Database change

Test:

- fresh schema;
- migration or compatibility path;
- existing data preservation;
- constraints;
- rollback.

### Background service

Test:

- successful cycle;
- recoverable failure;
- repeated failure without task death;
- cancellation;
- stale-state reporting;
- duplicate-run protection where required.

### Shared link

Test:

- valid token;
- invalid token;
- revoked token;
- expired token;
- PIN or passcode handling;
- token redaction from audit output.

### UI change

At minimum, validate rendered structure and critical accessibility properties. High-risk flows should receive browser-level tests when the project test stack supports them.

## Test independence

Tests must not depend on execution order, external internet access or a developer's local environment.

External systems should be represented through fixtures, fakes or controlled test services.

## Time

Use controllable clocks or injected time where expiry and intervals are important.

Avoid sleeps in unit tests.

## Security tests

Maintain tests for:

- CSRF;
- open redirect prevention;
- host validation;
- trusted proxy handling;
- session cookie flags;
- role and module access;
- secret redaction;
- file traversal;
- XSS-sensitive rendering.

## Assertions

Assert behaviour, not incidental implementation detail.

A test should produce a useful failure message and avoid overly broad assertions such as “status is not 500” when a specific result is expected.

## CI

The pull-request test workflow must run the supported test suite and fail on test errors.

Security and lint checks should be added as the tooling is formalised.

## Reporting

Do not claim tests passed unless they were actually run. Record the exact command and result in the pull request.
