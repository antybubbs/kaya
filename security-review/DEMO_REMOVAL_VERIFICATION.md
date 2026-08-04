# Public Demo Removal Verification

**Date:** 2026-08-04  
**Branch:** `security/remove-public-demo`  
**Base:** `dev0.27.0` at `58a750ec129cbcb2aba1cd15ce9e25f9f5662f3f`

## Decision and scope

The shared hosted evaluation environment is retired. The change removes its application mode rather than attempting to redesign its cross-cutting path policy. ADR-0005 records the product decision.

Removed surfaces include:

- configuration and environment switches;
- global middleware and route allowlist/denylist logic;
- shared-account authentication and generation-bound sessions;
- seed/reset scripts, deployment composition and persistent demo paths;
- interface banners, notices, login shortcuts, disabled-module showcases and CSS;
- alternate audit, dashboard, DNS, OIDC, Remote Manager, Secure Send, Vault and background-worker branches;
- hosted links and deployment instructions.

The normal production paths remain. Authentication policy, active server sessions, module permissions, role and object authorisation, CSRF validation, input validation, RDP endpoint trust, Secret Vault assurance and redacted audit logging were not weakened.

## Repository search

A repository-wide search covered `demo`, `DEMO_MODE`, `is_demo`, `demo_request_is_blocked`, shared account identifiers, hosted URLs and demo-only route exceptions. Remaining occurrences are limited to this decision/evidence, the findings register, release notes and removal regression assertions. Matches inside words such as DHCP “demotion” are unrelated.

## Verification evidence

Supported Linux image: `kaya-independent-security-review:local`  
Python runtime: 3.12

Focused removal and affected production-path regression command:

```text
python -m pytest -p no:cacheprovider +  tests/test_retired_public_demo.py tests/test_dashboard.py +  tests/test_client_ip.py tests/test_dns_dashboard_summary.py +  tests/test_docker_publish_workflow.py +  tests/test_release_security_boundaries.py +  tests/test_starlette_badhost_regression.py -q
```

Result: **72 passed**, 0 failed, 1,176 warnings.

Expanded affected security-boundary command:

```text
python -m pytest -p no:cacheprovider +  tests/test_authentication_policy.py tests/test_oidc_identity.py +  tests/test_oidc_routes.py tests/test_oidc_security.py tests/test_oidc_ui.py +  tests/test_secure_send.py tests/test_secret_vault.py +  tests/test_module_access.py tests/test_module_navigation.py +  tests/test_module_tabs.py tests/test_release_security_boundaries.py +  tests/test_rdp_endpoint_trust.py tests/test_database_migrations.py -q
```

Result: **227 passed**, 0 failed, 1,116 warnings.

Ruff passed all changed Python application and test files. A full-codebase Ruff invocation also identified one unrelated pre-existing unused `csv_safe` import in `app/routers/network_monitor.py`; it was not changed in this focused checkpoint. `git diff --check` passed.

Warnings are the existing deprecation classes for naive UTC datetimes, FastAPI startup/shutdown events, Passlib/Argon2 metadata and one Starlette status alias. No new security-relevant warning was observed from the removal assertions.

## Findings

- `KAYA-DEM-001`: resolved through permanent removal.
- `KAYA-DEM-002`: resolved as no longer applicable.
- `KAYA-RDP-001`: remains High and open; not remediated here.
- `KAYA-BAK-001`: remains Critical and blocked pending identification of the genuine external production Docker-agent source repository. No replacement, stub or fake agent was created.

This report does not declare v0.27 release-ready.
