# Kaya Engineering Documentation

This directory contains the authoritative engineering documentation for Kaya.

## Start here

Every contributor, including maintainers, external developers and AI coding assistants, must begin with:

1. [Kaya Engineering Standards](KAYA_ENGINEERING_STANDARDS.md)
2. [Engineering Principles](ENGINEERING_PRINCIPLES.md)
3. [Contributing to Kaya](CONTRIBUTING.md)
4. The architecture and specialist standards relevant to the proposed change

## Authority and document hierarchy

The documentation is ordered by authority:

1. `KAYA_ENGINEERING_STANDARDS.md`
2. Specialist standards under `standards/`
3. Architecture documents under `architecture/`
4. Accepted Architecture Decision Records under `adr/`
5. Module-level documentation
6. Historical implementation and comments

Where two documents conflict, the higher document in this list takes precedence. A conflict must be corrected or recorded as an approved exception. Existing code does not automatically define the preferred standard simply because it predates this documentation.

## Normative language

The words **must**, **must not**, **required**, **should**, **should not** and **may** are intentional:

- **Must / must not**: mandatory unless an approved exception is recorded.
- **Should / should not**: expected unless there is a documented reason to differ.
- **May**: optional.

## Keeping the documentation current

These documents are part of the product. A change is incomplete when it changes an architectural rule, shared implementation pattern, security control, database convention, user-interface convention, deployment requirement or development workflow without updating the affected document.

Documentation changes must be made in the same pull request or commit series as the code they describe.

## Documents

### Governing documents

- [Kaya Engineering Standards](KAYA_ENGINEERING_STANDARDS.md)
- [Engineering Principles](ENGINEERING_PRINCIPLES.md)
- [Contributing](CONTRIBUTING.md)
- [Glossary](GLOSSARY.md)

### Architecture

- [Architecture Overview](architecture/OVERVIEW.md)
- [Request Lifecycle](architecture/REQUEST_LIFECYCLE.md)
- [Module Architecture](architecture/MODULE_ARCHITECTURE.md)
- [Authentication and Sessions](architecture/AUTHENTICATION.md)
- [Authorisation and Module Access](architecture/AUTHORIZATION.md)
- [Background Services](architecture/BACKGROUND_TASKS.md)
- [Deployment Architecture](architecture/DEPLOYMENT_ARCHITECTURE.md)

### Standards

- [Coding Standards](standards/CODING_STANDARDS.md)
- [Security Standard](standards/SECURITY_STANDARD.md)
- [Database Standard](standards/DATABASE_STANDARD.md)
- [UI Design Standard](standards/UI_DESIGN_STANDARD.md)
- [Testing Standard](standards/TESTING_STANDARD.md)
- [Performance Standard](standards/PERFORMANCE_STANDARD.md)
- [Logging and Auditing](standards/LOGGING_AND_AUDITING.md)
- [Documentation Standard](standards/DOCUMENTATION_STANDARD.md)
- [Git and Release Standard](standards/GIT_AND_RELEASE_STANDARD.md)
- [Accessibility Standard](standards/ACCESSIBILITY_STANDARD.md)

### Templates

- [ADR Template](templates/ADR_TEMPLATE.md)
- [Module Review Template](templates/MODULE_REVIEW_TEMPLATE.md)
- [Security Review Template](templates/SECURITY_REVIEW_TEMPLATE.md)
- [Pull Request Checklist](templates/PULL_REQUEST_CHECKLIST.md)
