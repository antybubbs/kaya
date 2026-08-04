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

Exact post-merge focused reruns on this branch:

- OIDC: `tests/test_oidc_identity.py tests/test_oidc_routes.py tests/test_oidc_security.py tests/test_database_migrations.py` — **125 passed**, 0 failed, 715 warnings.
- RDP: `tests/test_release_security_boundaries.py tests/test_rdp_endpoint_trust.py tests/test_database_migrations.py` — **56 passed**, 0 failed, 164 warnings.

Fresh PR #62 merge-gate review:

- Application import/startup without any demo configuration: passed.
- Legacy `DEMO_MODE=true` upgrade residue: ignored safely; no demo application state is created.
- Focused retirement suite: **5 passed**, 0 failed.
- Final full supported-Linux suite: **738 passed**, 0 failed, 11,252 warnings.
- Exact database migration suite: **30 passed**, 0 failed, 12 warnings.
- Full repository Ruff: passed after making the tested `network_monitor.csv_safe` compatibility export explicit.
- `git diff --check`: passed.

Remaining uses of “demo” were classified as:

- **Documentation history/evidence:** ADR-0005, this report, release notes and resolved finding identifiers.
- **Removal regression assertions:** paths, configuration names and interface strings that must remain absent.
- **Unrelated harmless words:** DHCP demotion symbols and tests.
- **Unintended remaining demo functionality:** none found.

An intermediate full-suite run exposed that `network_monitor.csv_safe` is a tested compatibility export used by the spreadsheet-formula neutralisation regression. It was restored as an explicit re-export; the focused regression, full Ruff and final full suite then passed.

Ruff passed all changed Python application and test files. A full-codebase Ruff invocation also identified one unrelated pre-existing unused `csv_safe` import in `app/routers/network_monitor.py`; it was not changed in this focused checkpoint. `git diff --check` passed.

Warnings are the existing deprecation classes for naive UTC datetimes, FastAPI startup/shutdown events, Passlib/Argon2 metadata and one Starlette status alias. No new security-relevant warning was observed from the removal assertions.

## Findings

- `KAYA-DEM-001`: resolved through permanent removal.
- `KAYA-DEM-002`: resolved as no longer applicable.
- `KAYA-RDP-001`: remains High and open; not remediated here.
- `KAYA-BAK-001`: remains Critical and blocked pending identification of the genuine external production Docker-agent source repository. No replacement, stub or fake agent was created.

This report does not declare v0.27 release-ready.
