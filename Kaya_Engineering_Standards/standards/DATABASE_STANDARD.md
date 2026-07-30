# Database Standard

## Models

Models should represent persisted facts and relationships.

Keep HTTP and template concerns out of models.

Use explicit column types, nullability, defaults and foreign keys.

## Naming

Use stable, descriptive table and column names. Do not rename public data structures casually.

Boolean fields should read clearly, such as `is_enabled`, `is_known` or `requires_pin`.

Timestamp names should identify meaning, such as `created_at`, `last_checked_at` and `expires_at`.

## Constraints

Use database constraints for invariants that must hold regardless of application path.

Examples:

- uniqueness of stable identifiers;
- non-null required ownership fields;
- valid foreign-key relationships.

Application validation should provide a friendly error, but it does not replace database integrity.

## Indexes

Add indexes for frequent filtering, joins, ordering and uniqueness.

Do not index every field. Consider write cost and selectivity.

Monitoring history tables should be reviewed for compound indexes matching actual queries.

## Transactions

One logical operation should commit atomically.

Services performing multiple writes must roll back on failure.

Do not commit repeatedly inside a loop unless partial persistence is an intentional and documented design.

## Sessions

Session ownership must be clear.

Request-scoped work should use a request-scoped or dependency-provided session where available.

Background services may create sessions per cycle or unit of work and must close them reliably.

## Migrations

Every schema change requires an explicit migration strategy.

A migration must be:

- safe for existing installations;
- repeatable or guarded against duplicate application;
- tested with representative existing data;
- documented in release notes when operationally relevant.

Do not rely solely on `create_all` to evolve existing schemas.

## Destructive changes

Dropping or rewriting user data requires explicit approval and a recovery plan.

Prefer staged migrations:

1. add new structure;
2. populate or dual-read;
3. switch application behaviour;
4. remove old structure in a later release.

## Sensitive data

Mark and document encrypted fields.

Do not store recoverable secrets unencrypted.

Do not copy sensitive values into history tables or audit records without a clear requirement.

## Retention

High-volume history data must have a retention policy or archiving approach.

Retention jobs must not remove records still required for audit, recovery or user-configured history.

## SQLite and concurrency

Where SQLite is supported, designs must account for its locking and concurrency characteristics.

Do not assume behaviour only available in a different database engine unless Kaya formally adds support for that engine.

## Tests

Database tests should cover:

- fresh database creation;
- upgrade from a representative older schema;
- constraints;
- rollback after failure;
- cascade behaviour;
- retention logic;
- encrypted-field round trip without exposing plaintext.
