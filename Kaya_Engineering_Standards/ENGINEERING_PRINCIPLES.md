# Kaya Engineering Principles

These principles guide decisions where a specialist rule does not provide a complete answer.

## 1. Prefer predictable code

A developer should be able to understand a Kaya module by recognising familiar route, service, model, template and test patterns.

Predictable code is easier to review, diagnose and secure than clever code.

## 2. Improve deliberately

Leave affected code cleaner when doing so is safe and relevant, but do not turn every feature into a broad refactor.

A small, reviewable correction is usually preferable to an ambitious rewrite.

## 3. Keep security decisions on the server

The interface may hide actions a user cannot perform, but the server must independently deny them.

The same rule applies to API routes, background actions and imported data.

## 4. Share genuine behaviour

Code should be shared when the underlying rule is genuinely the same. Superficially similar behaviour should not be forced into an abstraction that makes both cases harder to understand.

## 5. Make state visible

Kaya manages infrastructure and operational information. Users should be able to tell whether data is current, stale, failed, disabled, degraded or still loading.

Do not display an old success as though it were a current success.

## 6. Protect user-managed installations

Users own their Kaya installation and data. Upgrades must respect existing configuration and provide safe migration paths.

Avoid assumptions that only work in the maintainer's environment.

## 7. Treat documentation as implementation

Documentation that no longer matches the application is a defect.

A new shared pattern is incomplete until future contributors can discover and follow it.

## 8. Test important behaviour, not implementation trivia

Tests should protect user-visible behaviour, security boundaries, data integrity and difficult edge cases.

Do not overfit tests to harmless internal arrangement.

## 9. Fail safely

When something goes wrong, preserve data, deny unsafe actions, record useful diagnostic information and present a clear user-facing state.

## 10. Keep operational complexity proportionate

Kaya should remain practical for self-hosted environments. Do not require new infrastructure unless the feature genuinely needs it and the operational impact is documented.
