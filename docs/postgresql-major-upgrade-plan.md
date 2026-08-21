# Future PostgreSQL 16 to 17 assessment

This is a design-only assessment. Phase 11 does not migrate production data,
change Kaya to PostgreSQL 17, run `pg_upgrade`, or support mounting a
PostgreSQL 16 data directory into PostgreSQL 17.

A future phase must first create and verify a backup, rehearse restore, audit
extensions and locale/collation settings, choose between `pg_upgrade` and a
logical dump/restore, test the selected image and data-volume strategy, define
downtime and rollback, and run a complete CI matrix. The production runbook
must require explicit operator approval and preserve the original data and
backup until the replacement is accepted.

Kaya currently uses PostgreSQL default `plpgsql` only; no application-specific
extension was identified by the Phase 11 disposable audit. The current
deployment must still re-audit extensions, encoding, collation, ctype, locale
provider and timezone immediately before a future major upgrade.

Based on Kaya's self-hosted deployment and existing custom-format backup and
restore tooling, logical dump/restore is the safer initial candidate than an
in-place `pg_upgrade`: it provides an explicit portable boundary, allows the
new cluster to be validated beside the old one, and makes rollback a preserved
old cluster or verified restore. The recommendation is provisional and must be
revalidated against actual database size, downtime tolerance, extensions and
restore duration before implementation.

The future acceptance plan must cover image change, extension compatibility,
locale/collation portability, sequence and identity correctness, encrypted
data/key recovery, application and worker reconnection, no SQLite fallback,
backup/restore, and an operator-visible rollback procedure.
