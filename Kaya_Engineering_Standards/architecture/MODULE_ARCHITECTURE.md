# Module Architecture

## Purpose

This document defines how Kaya modules should be organised and how they participate in shared application behaviour.

## Required characteristics

Every module must have:

- a stable module key;
- a human-readable name;
- a registered route prefix;
- explicit module-access behaviour;
- appropriate global-role checks;
- navigation registration;
- tests for inaccessible and disabled states;
- user-facing empty and error states;
- documentation describing its purpose and dependencies.

## Recommended layout

Existing modules may remain in the current shared directory layout. New or substantially refactored modules should keep their files grouped logically:

```text
app/
  routers/<module>.py
  services/<module>.py
  templates/<module>/
  static/js/<module>.js
tests/test_<module>*.py
```

A package layout may be adopted through an ADR when a module becomes large enough to justify it.

## Route responsibilities

A module router owns:

- URL and HTTP method definitions;
- request parsing;
- authentication and access dependencies;
- response types;
- template selection;
- translation of domain errors.

It should not own:

- external polling loops;
- encryption implementation;
- reusable data reconciliation;
- complex report construction;
- duplicated permission logic.

## Service responsibilities

A module service owns multi-step behaviour and integration work. Service names should describe actions or domain concepts rather than HTTP details.

Good:

- `create_shared_wallboard`
- `record_monitor_result`
- `reconcile_dns_client_identity`

Avoid:

- `handle_post`
- `process_data`
- `do_action`

## Module settings

A module may expose settings only when the settings change behaviour for that module.

Settings must:

- have defaults;
- be validated server-side;
- be documented;
- be safe when missing during upgrade;
- appear within Site Administration using the established settings hierarchy;
- be hidden or disabled when the module itself is unavailable, where appropriate.

## Categories and custom fields

Categories and custom fields must only be shown in modules that support them.

A module must explicitly register support. The shared navigation and settings interface must not infer support from incidental database tables.

## Module access

Module access controls whether a user can enter or invoke a module. Global role controls what the user can do inside accessible modules.

Both must be enforced server-side.

A disabled module must not remain callable through direct URLs or JSON endpoints.

## Cross-module relationships

Cross-module links may enrich data, but one module must not corrupt or take ownership of another module's records.

Where DNS Manager and VLAN/IP Manager share identity information, the integration should use a stable shared service or explicit mapping rather than direct, undocumented table manipulation.

## Module completion checklist

A module change is not complete until:

- route and service responsibilities are clear;
- permissions are tested;
- disabled-module behaviour is tested;
- database migration is safe;
- audit behaviour is appropriate;
- navigation and Site Administration are consistent;
- light, dark and responsive interfaces are checked;
- relevant engineering documentation is updated.
