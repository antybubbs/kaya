# Documentation Standard

## Documentation is part of the change

A feature is incomplete when users or future developers cannot understand how to configure, operate, maintain or extend it.

## Engineering documentation

Update engineering documents when a change affects standards or architecture.

Do not create a new document when an existing authoritative document is the correct location.

## Module documentation

A substantial module should document:

- purpose;
- major data concepts;
- route and service ownership;
- permissions;
- settings;
- background services;
- external integrations;
- security considerations;
- backup and recovery;
- known limitations.

## User documentation

User-facing documentation should explain outcomes and procedures, not internal code structure.

Include prerequisites, safe examples, expected result and recovery steps.

## Code documentation

Use comments for non-obvious intent, constraints and risk.

Do not duplicate the code in prose.

## Accuracy

Documentation examples must match supported routes, settings and behaviour.

When renaming a configuration option or path, search and update all documentation references.

## Diagrams

Use Mermaid in Markdown where practical so diagrams remain reviewable as text.

Diagrams must have a short explanation and must be updated with the architecture they represent.

## Changelog and release notes

User-visible changes, migrations, security changes and compatibility requirements belong in release notes.

Do not expose sensitive vulnerability exploitation detail before users have a reasonable upgrade path.
