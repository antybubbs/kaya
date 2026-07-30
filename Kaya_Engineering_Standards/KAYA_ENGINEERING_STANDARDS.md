# Kaya Engineering Standards

**Status:** Active  
**Version:** 1.0  
**Owner:** Kaya maintainers  
**Applies to:** All code, tests, migrations, templates, static assets, documentation, deployment files and automation in the Kaya repository

## 1. Purpose

This document is the authoritative engineering standard for Kaya. It defines the minimum expectations for architecture, implementation, security, testing, documentation, user experience and operational reliability.

The objective is not to make Kaya unnecessarily complex. The objective is to keep the product understandable, dependable and safe as it grows.

These standards apply equally to code written manually and code produced with AI assistance.

## 2. Source of truth

This document is the primary source of truth for engineering decisions in Kaya.

Where current implementation differs from this standard:

1. Do not assume the current implementation is correct merely because it exists.
2. Do not rewrite working code solely to make it look different.
3. Follow the documented standard for new work.
4. Improve legacy code incrementally when the affected area is already being changed.
5. Record a deliberate exception when immediate alignment would create disproportionate risk.

An exception must identify:

- the requirement being excepted;
- the affected files or subsystem;
- why compliance is not currently practical;
- the risk introduced;
- the intended remediation or review condition.

## 3. Living document

The standards must evolve with Kaya.

A contributor must review this documentation whenever a change:

- introduces or changes an architectural pattern;
- adds a shared service, middleware component or infrastructure dependency;
- changes authentication, authorisation, encryption or session behaviour;
- changes database structure, migration practice or data retention;
- creates a new UI component or interaction pattern;
- changes background processing, monitoring or scheduling;
- alters Docker, reverse-proxy or deployment requirements;
- changes testing, release or contribution expectations.

When any of these conditions apply, the relevant document must be updated in the same change. “Documentation to follow” is not an acceptable completion state for merged work.

## 4. Kaya's current technical foundation

Kaya is a server-rendered Python web application built around:

- FastAPI and Starlette for HTTP routing and middleware;
- Jinja2 for server-rendered interfaces;
- SQLAlchemy for persistence;
- Pydantic settings for configuration;
- signed cookie-backed sessions;
- Argon2 password hashing;
- optional OIDC authentication;
- application-level services for domain behaviour;
- background monitoring loops for operational modules;
- Docker as the primary deployment model.

These choices are not immutable, but replacements require a clear benefit, migration plan, compatibility assessment and Architecture Decision Record.

## 5. Core engineering requirements

### 5.1 Consistency

New work must follow the established, documented Kaya pattern for the same kind of problem.

A contributor must search for an existing implementation before creating a new helper, service, component, permission check, status indicator or data-access pattern.

Similar features should behave similarly. Differences must be intentional and explainable.

### 5.2 Simplicity

Use the simplest design that safely meets the requirement.

Avoid:

- speculative abstractions;
- unnecessary framework layers;
- generic systems built for hypothetical future requirements;
- complex inheritance where composition or a function is clearer;
- hidden behaviour triggered through unrelated side effects.

Simple does not mean careless. Validation, permissions, transactions, logging and tests are part of the simplest complete solution.

### 5.3 Separation of responsibilities

HTTP routes should coordinate requests and responses. They should not become the main location for reusable business rules.

Business logic should live in a service or clearly named domain helper when it:

- is reused;
- performs multi-step operations;
- owns security-sensitive decisions;
- coordinates transactions;
- calls external systems;
- requires focused tests independent of HTTP.

Templates display data. They must not implement permissions or business rules.

JavaScript enhances interaction. It must not be the only enforcement point for a rule.

### 5.4 Security by default

All external input is untrusted, including form fields, JSON, query parameters, cookies, headers, file names, uploaded files and responses from integrated systems.

Security-sensitive decisions must be enforced server-side.

No feature may:

- rely on a hidden button as authorisation;
- trust forwarded client headers without trusted-proxy controls;
- store plaintext passwords, access tokens, recovery secrets or encryption keys;
- expose stack traces or internal exception details to users;
- write secrets or sensitive payloads into logs or audit metadata;
- weaken an existing security control solely to make a feature easier to implement.

See [Security Standard](standards/SECURITY_STANDARD.md).

### 5.5 Backwards compatibility

Kaya is deployed into user-managed environments. Changes must account for existing databases, configuration, mounted volumes, reverse proxies and bookmarked routes.

Breaking changes require:

- explicit approval;
- a documented reason;
- an upgrade path;
- release notes;
- migration or compatibility handling where technically possible.

A database model change is not complete without migration handling.

### 5.6 Reliability

Long-running tasks, polling loops and external integration calls must fail predictably.

They must define:

- timeout behaviour;
- retry behaviour;
- cancellation and shutdown behaviour;
- logging;
- state after partial failure;
- protection against duplicate concurrent execution where relevant.

An external service being unavailable must not cause unrelated Kaya pages to fail.

### 5.7 Observable behaviour

Important state changes must be observable through appropriate logs, audit records, status indicators or health information.

Application logs and audit logs serve different purposes:

- application logs help operate and diagnose Kaya;
- audit logs record security and user-relevant actions.

Do not use one as an incomplete substitute for the other.

### 5.8 Data integrity

Database writes that form one logical operation must be transactional.

A partially completed action must not leave records in a misleading or insecure state.

Destructive actions require explicit validation and appropriate confirmation in the UI.

### 5.9 User experience

New screens must feel like part of Kaya.

They must:

- use existing layout and component conventions;
- work in light and dark themes;
- remain usable on supported mobile widths;
- clearly communicate loading, empty, warning, error and success states;
- avoid exposing implementation language to ordinary users;
- meet the accessibility standard.

### 5.10 Performance

Performance must be considered before a change is merged.

Routes must avoid obvious query multiplication, unbounded result sets and blocking external calls without timeouts.

Monitoring pages must not increase polling frequency merely to appear more responsive without measuring server and browser cost.

See [Performance Standard](standards/PERFORMANCE_STANDARD.md).

## 6. Repository and dependency rules

Dependencies must be pinned or managed through the repository's approved dependency mechanism.

A new dependency must have:

- a clear need;
- an acceptable licence;
- active maintenance;
- a security review proportionate to its role;
- no simpler existing equivalent already present in Kaya.

Do not add a package to avoid writing a small, well-tested standard-library function.

Generated files, credentials, local databases, uploaded content and runtime secrets must not be committed.

## 7. Change discipline

Before editing, a contributor must:

1. Identify the affected routes, services, models, templates, scripts and tests.
2. Read the relevant engineering documents.
3. Inspect existing patterns for equivalent behaviour.
4. identify security, data and compatibility implications.
5. Keep the change scoped to the requirement.

While editing:

- avoid unrelated formatting churn;
- avoid opportunistic rewrites that obscure the functional change;
- preserve public behaviour unless change is intended;
- update tests alongside implementation;
- update documentation where required.

After editing:

- run the relevant test suite;
- inspect the change for secret exposure;
- check permission boundaries;
- check both themes for UI changes;
- check responsive behaviour for UI changes;
- confirm migrations and startup behaviour for data changes;
- review logs and audit output for sensitive data.

## 8. Architecture decisions

A new Architecture Decision Record is required when a change:

- adds or replaces a major framework or datastore;
- changes authentication or session architecture;
- changes the meaning of global roles or module access;
- adds a new form of encryption or key management;
- introduces a new process, agent or network trust boundary;
- changes the supported deployment architecture;
- establishes a pattern expected to be reused across modules;
- deliberately deviates from these standards.

ADRs record context, decision and consequences. They are not used for routine implementation detail.

## 9. AI-assisted development

AI coding assistants, including Codex, must be treated as contributors, not authorities.

Before making a change, an AI assistant must:

- read this document and relevant specialist standards;
- inspect the existing implementation;
- identify reusable components and services;
- inspect tests that describe current behaviour;
- state material assumptions in its implementation notes.

An AI assistant must not:

- invent repository structures without checking the repository;
- claim tests passed unless they were run;
- silently replace established patterns;
- weaken validation, authorisation or security controls;
- delete or regenerate large files to make a small change;
- create migrations that discard user data without explicit instruction;
- mark placeholder documentation as complete;
- leave TODO-only implementations where completed work was requested.

When a requested change conflicts with these standards, the assistant must identify the conflict and choose the safest standards-compliant implementation unless explicitly directed otherwise.

## 10. Definition of done

A change is complete only when all applicable items are true:

- The requirement is implemented fully.
- Failure and edge cases are handled.
- Server-side validation and permissions are enforced.
- Data changes include safe migration handling.
- Relevant automated tests exist and pass.
- Existing relevant tests still pass.
- Logging and auditing are appropriate and redact sensitive data.
- UI behaviour works in light mode, dark mode and supported responsive layouts.
- Accessibility has been considered and tested proportionately.
- Performance and external-call timeouts have been considered.
- Documentation is updated.
- An ADR is included when required.
- No credentials, tokens, personal data or local runtime artefacts are committed.
- The implementation notes describe significant risks, limitations and verification performed.

## 11. Governance

Maintainers approve changes to normative standards.

Standards changes should make requirements clearer or safer. They must not be used to retroactively justify an isolated implementation without considering the wider project.

The version at the top of this document should change when its meaning changes:

- patch: clarification without changing requirements;
- minor: new or materially expanded requirement;
- major: incompatible change to the governing engineering model.
