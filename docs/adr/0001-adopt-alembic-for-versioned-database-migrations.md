# ADR-0001: Adopt Alembic for Versioned Database Migrations

- **Status:** Accepted
- **Date:** 2026-07-30

## Context

Kaya historically combined `Base.metadata.create_all()`, a large runtime migration function, and a substantially duplicated standalone SQLite script. This was additive and useful early in development, but could drift, could not state a database revision, and used a raw overwriteable backup in Docker.

## Decision

Kaya uses Alembic with a manually reviewed static baseline (`20260730_01`). Fresh databases run `upgrade head`. A database without `alembic_version` is treated as legacy: Kaya validates it, creates and verifies a SQLite API backup, runs the retained compatibility bridge, validates the resulting schema against model metadata, and only then stamps the baseline. Recognised versioned databases use ordinary Alembic upgrades. Unknown or inconsistent states abort startup.

Schema migration and application defaults are separate. `app/db/migrations.py` owns orchestration, `backup.py` owns recoverability, `validation.py` owns the schema contract, `compatibility.py` owns the temporary pre-Alembic bridge, and `seeds.py` owns idempotent defaults.

## Options considered

- Continue manual startup DDL: rejected because it retains duplication and has no revision graph.
- Recreate databases from current models: rejected because it risks data, constraints, and historical compatibility.
- External migration only: rejected because ordinary self-hosted container upgrades must remain automatic.
- Alembic: selected because it is the established SQLAlchemy migration framework and supports explicit revision history, reviewed scripts, and programmatic startup use.

## Backup and rollback

Every write to an existing SQLite database is preceded by a timestamped, non-overwriting backup made with SQLite's online backup API. The backup is opened read-only and checked with bounded `quick_check` and `foreign_key_check` operations; metadata records source and target revisions. Migration failure stops startup. Restore is an explicit administrator operation. The baseline downgrade drops the fresh schema and is therefore for disposable new-install testing only; it must never be used as a recovery substitute for a populated database.

## Compatibility lifecycle

The bridge supports the historical additive path represented by v0.18.x through v0.25.x and the final pre-Alembic development schema. It remains through at least v0.27 and is reviewed no earlier than v0.28, after Kaya has a published minimum upgrade version and adequate recovery evidence.

## Consequences

All future schema changes require an Alembic revision and upgrade tests. Autogeneration is only a draft. SQLite batch behaviour, duration, locking, downgrade safety, backup and recovery must be reviewed in each database pull request. Model changes without a revision are invalid.
