# Contributing to Kaya

Thanks for taking the time to contribute to Kaya. If you are reading this, i would assume you want to contribute - thank you!

Kaya is an actively developed, self-hosted infrastructure operations platform. Contributions are welcome, including bug fixes, documentation, UI improvements, integrations and new features.

Because Kaya manages infrastructure data, authentication, remote access, DNS/DHCP, backups and encrypted sensitive information, changes must be made carefully. The aim is simple:

> **Make Kaya more capable without making existing installations less reliable or less secure.**

Before contributing, please read this document in full.

---

## 1. Before You Start

Before changing code:

1. Read the current `README.md`.
2. Inspect the current implementation of the feature you want to change.
3. Review recent commits and pull requests affecting that area.
4. Check whether an issue already exists.
5. Understand database, security, permissions and upgrade implications.
6. Reuse existing Kaya patterns and helpers before creating new ones.

Do not make assumptions from old screenshots, old discussions, old specifications or previous releases if the current code says something different.

**The current repository is the source of truth.**

Code must also be understandable to experienced public reviewers without private discussion history or undocumented assumptions. Prefer established tools and patterns—Alembic, Jinja, pathlib, pytest, the agreed lint/format tools, and ADRs—before custom infrastructure. A custom mechanism requires written justification.

Use clear responsibility boundaries: do not accumulate unrelated work in `main.py`, generic service files, giant functions, or broad utility modules. Prefer descriptive names and readable control flow over compressed statements. Comments explain rationale, risk, or unusual constraints.

Temporary compatibility code must document why it exists, supported versions, its removal condition and target review release, and must have regression tests. Broad `except Exception` is acceptable only at a genuine boundary that logs safely, handles failure explicitly, and preserves the original exception context.

Existing installations and user data are preserved by default. Breaking changes require owner approval, upgrade and recovery guidance, release-note warnings, and upgrade tests. Every schema change is versioned with Alembic; `create_all()` is not an upgrade mechanism and normal startup must not perform ad hoc `ALTER TABLE` changes.

---

## 2. Core Contribution Rules

### Preserve existing behaviour

Kaya has existing users and existing installations.

Do not remove or change working behaviour unless the contribution specifically intends to replace it.

Prefer a focused fix over a broad rewrite.

### Keep Kaya cohesive

Kaya should feel like one application, not a collection of unrelated tools.

New modules and features should:

- follow existing navigation patterns;
- use existing UI components and styles;
- reuse shared services and helpers;
- integrate with existing records where appropriate;
- avoid creating duplicate sources of truth.

### Avoid parallel implementations

Before adding new:

- authentication helpers;
- permission checks;
- audit logic;
- encryption helpers;
- client IP parsing;
- module registries;
- polling mechanisms;
- database abstractions;
- UI patterns;

check whether Kaya already has a shared implementation.

If it does, extend or reuse it rather than building another version beside it.

---

## 3. Architecture Overview

Kaya is primarily built with:

- Python 3.12;
- FastAPI;
- Uvicorn;
- Jinja2;
- SQLAlchemy;
- SQLite;
- JavaScript and CSS;
- Docker / Docker Compose.

Remote Manager also uses Node-based helper services and Apache Guacamole `guacd`.

The main FastAPI application is assembled in `app/main.py`.

Major areas include:

- Authentication and OIDC
- Dashboard
- Site Administration
- VLAN / IP Manager
- DNS Manager
- High Availability
- IP / WAN Monitor
- VM and Docker Manager
- Hardware Asset Manager
- Rack Manager
- Backup Manager
- Remote Manager
- Runbook Manager
- Domain Manager
- Licence Manager
- Secret Vault
- Secure Send

When changing a feature, trace the full implementation. This may include:

- router;
- service;
- SQLAlchemy models;
- migration/bootstrap logic;
- templates;
- JavaScript;
- CSS;
- background workers;
- APIs;
- tests.

Do not change only the visible page if the real behaviour is implemented elsewhere.

---

## 4. Branches and Pull Requests

Do not assume the current development branch name. Check the repository first.

Development has historically used versioned branches such as:

```text
dev0.25.0
dev0.26.0
```

The release branch is:

```text
main
```

### Keep pull requests focused

A PR should ideally address one logical change.

Avoid combining unrelated:

- UI work;
- refactors;
- bug fixes;
- dependency upgrades;
- schema changes;
- new features.

A useful PR description should explain:

- the problem being solved;
- what changed;
- why the approach fits Kaya;
- whether the database changes;
- whether existing installs are affected;
- whether permissions or security are affected;
- what was tested;
- known limitations.

Screenshots are encouraged for visible UI changes.

---

## 5. Database and Upgrade Rules

Kaya currently uses SQLAlchemy with SQLite as its standard database.

**Existing installations must continue to work after an update.**

If you change persistent data:

- inspect the existing models;
- inspect startup migration logic;
- support upgrades from existing databases;
- test a clean installation;
- test an upgraded installation where practical;
- preserve existing data;
- consider indexes and foreign keys;
- consider delete and cleanup behaviour.

Do not assume every user starts with a clean database.

Do not rename, remove or repurpose persisted fields without a migration plan.

Do not introduce changes that require users to delete their Kaya database to update.

---

## 6. Security Rules

Security-sensitive contributions receive additional scrutiny.

Kaya includes:

- local authentication;
- Argon2 password hashing;
- TOTP MFA;
- OpenID Connect;
- role-based permissions;
- per-user module access;
- CSRF protection;
- encrypted secrets;
- audit logging;
- trusted reverse-proxy handling;
- security headers;
- Secret Vault;
- Secure Send.

### Never weaken security to make implementation easier

Do not:

- disable CSRF protection;
- bypass server-side permissions;
- trust arbitrary forwarded headers;
- log plaintext secrets;
- store passwords unnecessarily;
- expose decrypted data before it is needed;
- weaken Vault MFA/PIN requirements;
- remove audit events from sensitive actions;
- weaken Secure Send recipient isolation;
- hard-code credentials or secrets.

**Hiding a button or navigation item is not access control.**

---

## 7. Roles and Module Access

Kaya uses these core roles:

- Administrator
- Editor
- Viewer

Kaya also supports per-user module access.

These are separate concepts.

When adding or changing a module:

- register it correctly with the module access system;
- ensure navigation respects access;
- enforce access in routes and APIs;
- ensure dashboard widgets do not leak inaccessible data;
- preserve sensible administrator behaviour;
- consider access for existing and new users.

Never rely only on frontend visibility.

---

## 8. Audit Logging

Important actions should be auditable, including:

- authentication changes;
- user and permission changes;
- administrative settings;
- secret or product-key reveals;
- Vault activity;
- Secure Send lifecycle events;
- destructive operations;
- HA failover/failback actions.

Audit logs must be useful without containing sensitive content.

Never log:

- passwords;
- PINs;
- passphrases;
- TOTP secrets;
- encryption keys;
- decrypted Vault content;
- secure package contents.

---

## 9. Reverse Proxies and Client IPs

Kaya supports direct access and deployments behind proxies such as:

- Nginx;
- Nginx Proxy Manager;
- Caddy;
- Traefik;
- NetBird;
- Cloudflare Tunnel.

Use Kaya's trusted proxy/client-IP handling.

Do not independently trust or parse `X-Forwarded-For`.

`FORWARDED_ALLOW_IPS` controls which upstream systems may supply forwarding information.

`ALLOWED_HOSTS` controls which browser hostnames Kaya accepts.

They are not interchangeable.

---

## 10. UI and UX Rules

Kaya has an established visual identity.

New UI should match the existing application rather than introducing a separate design language.

### Themes

Changes must work in:

- Command dark mode;
- Light Ops light mode.

### Responsive behaviour

Interfaces should be usable on:

- desktop;
- tablet;
- mobile/PWA.

The shared `responsive.css` stylesheet is loaded after core and module styles and owns narrow-screen safeguards. New interfaces must remain usable at 320 CSS pixels, use touch targets of at least 44px on phones, allow headings and action groups to wrap, and avoid fixed widths that create page-level horizontal scrolling. Wide operational tables keep their columns inside keyboard-focusable horizontal scroll regions; do not hide data merely to make a table fit. Module navigation may scroll horizontally while its authorised Settings action remains reachable.

### Navigation

Do not add every module subpage to the main sidebar.

Subpages should normally remain inside their parent module.

Site Administration should use its existing structured navigation patterns.

### Standard Module Page Layout

Every user-facing module page follows this hierarchy:

1. Module Hero
2. Module Navigation Bar
3. Page Toolbar or Page Controls
4. Module Content

The Module Navigation Bar is required even when a module currently has only one page. Module page links appear on the left and the shared **Settings** action appears at the far right only when a real central destination exists under **Site Administration → Module Settings** and the user is authorised to manage it. Both the operational module route and the settings route must enforce authentication, role and module allocation on the server; navigation visibility is not an authorisation control.

Hero blocks hold module identity, context, status and operational summaries. Current-page actions such as search, filters, refresh, add/create and bulk actions remain in the hero toolbar or page toolbar. Table settings remain separate from module administration.

New modules must use `components/module_navigation.html` from their initial implementation. Do not create module-specific copies of the component or duplicate central settings forms inside an operational module.

Module administration and module configuration are separate concepts. Categories, custom fields and other controls that define how a module's records are organised belong to that module and are reached from its Module Navigation Bar. Central **Site Administration → Module Settings** is reserved for system-level configuration such as provider connections, infrastructure definitions, collection behaviour, retention and security controls. Do not add contextual record-administration links to the global sidebar or duplicate them in central settings. Render these links only for modules with a working implementation and only for roles authorised by the destination route; direct routes must still enforce role, module allocation and object-level access.

Remote Manager is the deliberate exception because its terminal/RDP workspace prioritises vertical screen space. It omits the Module Navigation Bar, keeps recordings in the existing application sidebar, and renders the same RBAC-controlled central **Settings** shortcut at the far right of its module hero.

### Use existing patterns for

- buttons;
- forms;
- cards;
- tables;
- status badges;
- alerts;
- confirmations;
- empty states;
- search/filter controls;
- headings.

Destructive actions should be clearly identified and confirmed.

---

## 11. Performance and Background Collection

Do not perform expensive infrastructure polling simply because a user opens a page.

Prefer:

```text
External service
      ↓
Background collector
      ↓
Kaya database/state
      ↓
UI/API
```

rather than:

```text
Browser request
      ↓
External service
      ↓
Wait
      ↓
Render page
```

Avoid:

- unnecessary provider calls;
- N+1 database queries;
- full-page refresh loops;
- duplicate background workers;
- rapid polling of external services when a lightweight Kaya API refresh would suffice.

One failed integration should not take down unrelated pages or widgets.

---

## 12. DNS Manager Rules

DNS Manager currently has strong Pi-hole support.

### A client is not just an IP address

DHCP addresses can change and can later be reused by another device.

Kaya therefore retains identity/history such as:

- observed clients;
- MAC identity where available;
- hostname history;
- IP history;
- DHCP lease history;
- historical DNS attribution.

Do not recreate client duplication by treating every historical IP or lease as a new permanent client.

### VLAN / IP Manager integration

VLAN / IP Manager represents managed network records.

DNS Manager represents observed DNS/DHCP intelligence.

Do not silently overwrite a manually managed static IP record because an external DNS/DHCP provider reports something different.

---

## 13. High Availability Rules

High Availability is currently **BETA** and should be treated as a high-risk area.

The initial HA implementation focuses on paired Pi-hole nodes.

Before changing HA code:

- inspect recent HA commits;
- inspect current orchestration services;
- understand active/standby state;
- understand VIP ownership;
- understand DNS and DHCP behaviour;
- understand synchronisation and reconciliation;
- test real service behaviour, not only database state.

### Critical DHCP invariant

> **DHCP must never be deliberately active on both HA nodes at the same time.**

Do not use dual DHCP activity as a shortcut to fixing a degraded state.

### Failover and failback should validate

- node reachability;
- peer reachability;
- DNS health;
- DHCP health;
- sync readiness;
- VIP ownership;
- final convergence.

Expected temporary service transitions during controlled failover should be distinguished from genuine failure.

Never hard-code:

- Pi-hole addresses;
- VIPs;
- DHCP ranges;
- interface names;
- credentials;
- local network assumptions.

---

## 14. Secret Vault Rules

Secret Vault is deliberately security-sensitive.

It is intended for:

- sensitive documents;
- secure notes;
- recovery records;
- certificates;
- break-glass information;
- protected data.

It is not intended to become a general password-manager replacement.

Existing security concepts include:

- separate per-user vaults;
- vault PIN/passphrase;
- fresh MFA;
- per-vault keys;
- AES-256-GCM;
- encrypted metadata;
- automatic locking;
- encrypted exports;
- recovery kits;
- offline recovery.

Do not introduce an administrator bypass that allows one user to decrypt another user's private Vault.

Changes involving encryption, key derivation, recovery, sharing, session handling or backup/restore must preserve compatibility or include an explicit safe migration path.

---

## 15. Secure Send Rules

Secure Send uses a separate, minimal recipient-facing gateway.

Do not expose normal Kaya authenticated/admin routes through the recipient gateway.

Security includes:

- encrypted packages;
- high-entropy access links;
- PIN;
- generated passphrase;
- expiry;
- throttling;
- session controls;
- optional one-download destruction;
- revoke/delete behaviour.

Do not send the URL, PIN and passphrase together in the same email.

Do not weaken expiry or revocation semantics.

---

## 16. Remote Manager Rules

Remote Manager supports browser-based SSH and RDP.

RDP uses Guacamole/`guacd`.

Kaya is not intended to become a permanent store of remote login passwords.

Credentials should continue to be supplied when a connection is initiated unless the architecture is deliberately changed and security-reviewed.

Take care when changing:

- WebSockets;
- session tokens;
- recordings;
- Guacamole integration;
- remote connection parameters;
- browser framing/CSP behaviour.

---

## 17. Testing Expectations

Test the real workflow you changed.

Depending on the contribution, consider:

- clean installation;
- existing database upgrade;
- login/logout;
- unauthenticated access;
- Administrator;
- Editor;
- Viewer;
- module permissions;
- dark mode;
- light mode;
- desktop;
- mobile;
- empty state;
- provider offline;
- provider recovery;
- destructive confirmation;
- audit events.

### Code quality checks

Run these repository-wide checks before opening a pull request:

```text
ruff check .
black --check .
pytest
git diff --check
```

Keep imports conventional and let Ruff report unused or misplaced imports. Do
not compress suites onto the header line or join statements with semicolons.
Use the shared binary byte formatter rather than introducing another KB/MB
formatter with ambiguous units.

Resolve packaged resources through `app.core.paths` (or a path derived from
the owning module's `__file__`), never from the process working directory.
Keep runtime data locations configurable and preserve the documented container
volume defaults.

Application pages belong in Jinja templates. Python may generate deliberately
limited formats such as escaped email bodies or sanitised Markdown fragments
when the reason is documented and covered by injection tests. A broad
`except Exception` is reserved for genuine process, request, integration or
background-task boundaries; it must log safe context and either fail clearly
or implement an explicit best-effort contract.

Run any configured type checker and security scanner when the repository adds
one; do not imply type or security-tool coverage that is not configured.

### Integration changes

Test both:

```text
service available
```

and:

```text
service unavailable
```

Kaya should fail gracefully.

### HA changes

Where relevant, test:

- both nodes healthy;
- controlled failover;
- controlled failback;
- primary lost;
- secondary lost;
- peer communication lost;
- DNS failure;
- DHCP failure;
- VIP mismatch;
- stale sync state;
- recovery;
- restart after degraded state;
- DHCP-enabled mode;
- DNS-only mode.

Verify actual DNS/DHCP/VIP behaviour, not only the status badge in Kaya.

### Vault / Secure Send changes

Consider:

- correct authentication;
- wrong authentication;
- MFA;
- session expiry;
- revocation;
- encryption/decryption;
- tampered data;
- expiry;
- deletion;
- backup;
- restore;
- file extraction/path safety.

---

## 18. Definition of Done

A contribution should normally not be considered complete until:

- the requirement works;
- existing behaviour is preserved;
- access control is enforced server-side;
- database upgrades are safe;
- failure states are handled;
- UI matches Kaya;
- dark and light mode work;
- responsive behaviour is reasonable;
- sensitive actions are audited;
- secrets are not logged;
- tests pass;
- repository lint, formatting and diff checks pass;
- debug code has been removed;
- documentation is updated where setup or behaviour changed.

---

## 19. AI-Assisted Contributions

AI-assisted development is welcome.

The same standards apply whether code is written manually or with Codex, ChatGPT or another coding assistant.

If you use AI:

- give it the current repository context;
- make it inspect the existing implementation first;
- do not accept generated code blindly;
- review every change;
- test the result;
- ensure it has not duplicated existing helpers or architecture;
- ensure it has not weakened permissions/security;
- ensure migrations preserve existing installations.

The contributor remains responsible for submitted code.

---

## 20. What Not to Do

Please avoid contributions that:

- rewrite large working areas without a clear reason;
- introduce a second framework for something Kaya already handles;
- require users to delete their database;
- silently break existing configuration;
- add hard-coded infrastructure details;
- bypass role/module permissions;
- weaken security controls;
- introduce plaintext secret storage;
- duplicate data already owned by another module;
- poll external services on every page request;
- substantially change Kaya's design language without discussion;
- include unrelated changes in the same PR.

---

## 21. Bug Reports

A useful bug report should include:

- Kaya version;
- deployment method;
- relevant environment/configuration;
- expected behaviour;
- actual behaviour;
- reproduction steps;
- relevant logs;
- screenshots where useful.

Before posting publicly, remove:

- passwords;
- tokens;
- API keys;
- private URLs;
- Vault data;
- personal information.

---

## 22. Feature Suggestions

For larger features, please open an issue before implementing them.

Explain:

- the problem being solved;
- who benefits;
- how it fits Kaya;
- affected modules;
- security implications;
- database implications;
- whether new external services are required.

Large architectural changes are easier to review before significant code has already been written.

---

## 23. Contributor Checklist

Before opening a PR:

- [ ] I inspected the current implementation before changing it.
- [ ] I kept the change focused.
- [ ] I reused existing Kaya patterns/helpers.
- [ ] I considered existing installations and database upgrades.
- [ ] I checked server-side permissions.
- [ ] I checked security implications.
- [ ] I checked audit requirements.
- [ ] I tested relevant failure states.
- [ ] I tested dark and light mode if the UI changed.
- [ ] I considered mobile/responsive behaviour.
- [ ] I did not hard-code environment-specific values.
- [ ] I did not log or expose secrets.
- [ ] I updated documentation if setup or behaviour changed.
- [ ] I can explain what the PR changes and why.

---

## 24. Final Principle

> **Kaya should become more useful without becoming more fragile.**

Understand what already exists before changing it. Protect user data. Preserve security. Keep modules integrated. Prefer truthful operational state over a cosmetically healthy UI.

Thanks for helping improve Kaya.
