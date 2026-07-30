# ADR-0001: Engineering standards as the source of truth

**Status:** Accepted  
**Date:** 2026-07-30  
**Decision owners:** Kaya maintainers

## Context

Kaya has grown across many modules and has received contributions produced through both human and AI-assisted development. Without an authoritative engineering reference, equivalent problems can be solved in inconsistent ways and documentation can lag behind implementation.

## Decision

`docs/engineering/KAYA_ENGINEERING_STANDARDS.md` is the highest-authority engineering document in the repository.

Specialist standards, architecture documents, ADRs and module documentation sit beneath it in the hierarchy described by `docs/engineering/README.md`.

Contributors must review and update the engineering documentation in the same change whenever their implementation changes a documented architecture, security control, convention or development requirement.

## Consequences

- Future work has a discoverable and reviewable baseline.
- Existing code may require incremental alignment.
- Pull requests include documentation work where relevant.
- AI coding assistants must inspect the standards before editing.
- Maintainers must review standards changes carefully because they affect future development.

## Security and privacy impact

Positive. Security expectations become explicit and consistently reviewable.

## Compatibility and migration

No runtime change. Existing implementation is not required to be rewritten immediately.

## References

- `docs/engineering/KAYA_ENGINEERING_STANDARDS.md`
- `docs/engineering/README.md`
