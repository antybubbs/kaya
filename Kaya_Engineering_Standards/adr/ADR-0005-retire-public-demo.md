# ADR-0005: Retire the shared public demo

- **Status:** Accepted
- **Date:** 2026-08-04
- **Decision owners:** Kaya maintainers
- **Security findings:** KAYA-DEM-001, KAYA-DEM-002

## Context

Kaya previously carried a cross-cutting public-demo mode with shared accounts, synthetic seed/reset behavior, route-string restrictions, redacted audit/session context, disabled integrations, and separate interface and deployment paths. The policy duplicated production control decisions and depended on every new HTTP and WebSocket path being classified correctly. That security and maintenance burden no longer served the core self-hosted product.

## Decision

Retire the hosted public demo and permanently remove demo mode from the product. Kaya will have one application behavior: the ordinary production path protected by authentication, module permissions, role and object authorisation, CSRF validation, input validation and redacted security audit logging.

Remove the mode's configuration and environment variables, middleware and route policy, shared accounts and seed/reset lifecycle, interface behavior, deployment assets, documentation and hosted links. Evaluation should take place in an isolated operator-controlled deployment using synthetic data.

## Security consequences

- KAYA-DEM-001 is resolved because no shared demo trust boundary or demo Vault exception remains.
- KAYA-DEM-002 is resolved as no longer applicable because the parallel path-string policy no longer exists.
- Existing production RBAC, object authorisation, CSRF, Secret Vault assurance and audit controls remain unchanged in authority and scope.
- This decision does not claim that unrelated production routes are free of security defects.

## Operational consequences

Deployments that set former demo environment variables must remove them. Demo seed databases are not migrated into production. No automatic deletion of existing external demo data or infrastructure is performed by the application change; operators must retire hosted infrastructure through their normal controlled process.
