# Contributing to Kaya

## Before starting

Read:

- `KAYA_ENGINEERING_STANDARDS.md`
- the relevant architecture documents;
- the relevant specialist standards;
- existing tests for the affected behaviour.

Search the repository before adding a new helper, component, service or convention.

## Scope

Keep pull requests focused. Separate unrelated refactors, dependency upgrades and formatting changes from functional work unless they are necessary to deliver it safely.

## Branches

Use short, descriptive branch names, for example:

- `feature/module-access`
- `fix/network-monitor-stall`
- `security/trusted-proxy-validation`
- `docs/engineering-standards`

## Implementation expectations

- Validate external input.
- Enforce authorisation server-side.
- Use transactions for logical multi-write operations.
- Set timeouts for external calls.
- Avoid blocking work in async request handlers.
- Reuse the Kaya design system.
- Add or update tests.
- Update documentation in the same change.

## Commit expectations

Commits should describe the change, not the activity.

Good:

- `Fix stalled IP monitor task recovery`
- `Add module access checks to secure vault routes`
- `Document trusted proxy requirements`

Avoid:

- `changes`
- `fix stuff`
- `Codex update`
- `final`

## Pull request description

A pull request should state:

- what changed;
- why it changed;
- security and compatibility implications;
- database or deployment changes;
- tests performed;
- documentation updated;
- known limitations.

## Review

Reviewers should assess correctness, security, maintainability, compatibility, test coverage and documentation. Passing tests alone do not prove a change is suitable.

## AI-assisted contributions

AI-generated code is reviewed to the same standard as any other code. The contributor remains responsible for understanding and validating it.

Do not submit code solely because an AI assistant reported that it was correct.
