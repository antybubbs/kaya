# Migrating Kaya from SQLite to PostgreSQL

Kaya **v0.28.0** moves the production database platform from SQLite to PostgreSQL.

Existing installations running Kaya v0.27.4 or an earlier SQLite-backed release must migrate their existing database before starting the normal v0.28.0 production stack.

This guide explains the supported migration process.

<Callout type="warning">
Do not delete your existing SQLite database after migration.

Keep the original database and migration backups until you have fully verified the PostgreSQL installation and are satisfied that all expected Kaya data is present.
</Callout>

---

## Overview

The supported upgrade path is:

```text
Existing Kaya installation
        │
        ▼
Back up existing deployment
        │
        ▼
Stop Kaya
        │
        ▼
Pull v0.28.0
        │
        ▼
Run PostgreSQL migration workflow
        │
        ▼
Validate migration
        │
        ▼
Start normal v0.28.0 stack
        │
        ▼
Verify Kaya
        │
        ▼
Retain SQLite backup
```

The migration process is designed to move the existing Kaya application database into a new PostgreSQL database while preserving application relationships and data integrity.

The migration tooling performs additional safety checks before and after conversion and will fail rather than silently continue when the resulting database cannot be trusted.

---

# Before you begin

## Requirements

Before starting the migration, make sure that:

- You have shell access to the Kaya Docker host.
- Docker and Docker Compose are working normally.
- Your existing Kaya installation is currently functioning.
- You know where your current Kaya data directory is stored.
- You have enough free disk space for:
  - The existing SQLite database
  - Migration backups
  - PostgreSQL storage
  - Temporary migration data
- You have a verified backup of the existing installation.
- No other administrator is upgrading or changing Kaya at the same time.

You should also ensure that there is no active maintenance being performed against the existing database.

---

## Supported migration direction

This process supports:

```text
SQLite → PostgreSQL
```

It is not a PostgreSQL to SQLite conversion mechanism.

Once the new installation has been verified, PostgreSQL should be treated as the production database.

---

# 1. Identify your existing installation

Go to the directory containing your existing Kaya Compose deployment.

For example:

```bash
cd ~/kaya
```

Confirm the current installation:

```bash
docker compose ps
```

You should see the services associated with your existing Kaya deployment.

It is also worth recording the currently running image:

```bash
docker compose images
```

If your installation is currently running v0.27.4, you should see an image corresponding to that release.

---

# 2. Record the current version

Before making any changes, record the version you are upgrading from.

If available from the Kaya interface, note the displayed version.

You can also inspect the running container image:

```bash
docker compose images
```

For this migration guide, the expected starting point is generally:

```text
v0.27.4
```

although the migration tooling performs its own compatibility and database checks.

---

# 3. Back up Kaya

<Callout type="danger">
Do not continue without a backup.
</Callout>

At minimum, preserve:

- The existing SQLite database
- Kaya configuration
- Secrets
- Uploaded files
- Any persistent application data
- The current Compose configuration

If your deployment stores its persistent data beneath a local `data` directory, you may create a backup such as:

```bash
cp -a data "data-backup-$(date +%Y%m%d-%H%M%S)"
```

Alternatively, create an archive:

```bash
tar -czf "kaya-pre-v0280-backup-$(date +%Y%m%d-%H%M%S).tar.gz" data
```

If your Compose files or environment configuration are stored separately, back those up as well.

For example:

```bash
cp docker-compose.yml docker-compose.yml.pre-v0.28.0
```

and, where applicable:

```bash
cp .env .env.pre-v0.28.0
```

Protect these backups appropriately because they may contain sensitive configuration or application data.

---

# 4. Verify the backup

A backup that has never been checked should not be assumed to be usable.

Confirm that the backup exists:

```bash
ls -lah
```

If you created a compressed archive, inspect its contents:

```bash
tar -tzf kaya-pre-v0280-backup-*.tar.gz | head
```

You should be able to see your existing Kaya data within the archive.

---

# 5. Stop the existing Kaya installation

Stop Kaya before performing the database migration.

```bash
docker compose down
```

Confirm that the containers are no longer running:

```bash
docker compose ps
```

There should be no active Kaya application container writing to the SQLite database.

<Callout type="warning">
Do not run the old Kaya application against the SQLite database while the migration is taking place.
</Callout>

---

# 6. Update the Kaya repository or deployment files

If your Kaya deployment is based on a Git checkout, update it to the v0.28.0 release.

For example:

```bash
git fetch --tags
git checkout v0.28.0
```

Confirm:

```bash
git status
```

If you deploy Kaya using downloaded Compose files instead, replace the deployment files with those supplied for v0.28.0 while retaining your backed-up copy of the previous configuration.

---

# 7. Review the new Compose layout

v0.28.0 separates normal production operation from database conversion.

The normal production stack is defined in:

```text
docker-compose.yml
```

The SQLite to PostgreSQL conversion workflow is defined separately in:

```text
docker-compose.upgrade.yml
```

The upgrade Compose file exists specifically to perform the database migration.

Do not treat it as the normal long-running Kaya deployment.

---

# 8. Pull the v0.28.0 image

Pull the release image before starting the migration:

```bash
docker pull ghcr.io/antybubbs/kaya:v0.28.0
```

If your Compose configuration uses the normal release tag, you can also pull through Compose:

```bash
docker compose pull
```

Confirm the expected image is available:

```bash
docker images ghcr.io/antybubbs/kaya
```

---

# 9. Confirm the SQLite source database

Before running the migration, make sure the existing SQLite database is still present.

The exact location depends on your existing Kaya installation and configured data path.

Inspect your persistent data directory:

```bash
find ./data -maxdepth 3 -type f
```

You should be able to identify the existing Kaya SQLite database.

Do not rename, modify or manually open the database in a way that might write to it.

---

# 10. Start the migration workflow

Run the dedicated upgrade Compose configuration.

From the Kaya deployment directory:

```bash
docker compose -f docker-compose.upgrade.yml up
```

Depending on the release configuration, you may instead run the upgrade service explicitly:

```bash
docker compose -f docker-compose.upgrade.yml run --rm migrate
```

Use the command documented by the Compose file included with the release if the service name differs.

The migration container will initialise the PostgreSQL target and begin the conversion process.

---

# 11. What the migration process does

The converter is intentionally more cautious than a simple database copy.

During migration Kaya performs a number of checks and conversion stages.

These include:

- Identifying the source SQLite database
- Recording the source database fingerprint
- Checking migration preconditions
- Initialising the PostgreSQL target
- Reflecting the PostgreSQL schema
- Building table dependency relationships
- Determining a safe migration order
- Handling cyclic foreign-key relationships
- Deferring supported nullable relationships where necessary
- Copying application records
- Restoring deferred foreign keys
- Repairing PostgreSQL sequences
- Validating migrated relationships
- Comparing source and target state
- Recording migration status
- Producing migration metadata and reports

---

# 12. Source database fingerprinting

Kaya records a cryptographic fingerprint of the SQLite source used for conversion.

This prevents an ambiguous situation where migration state from one database is accidentally associated with another.

Migration metadata may include fields similar to:

```json
{
  "database_engine": "sqlite",
  "original_source_fingerprint": "...",
  "conversion_source_fingerprint": "..."
}
```

The original and conversion source fingerprints should correspond to the database being migrated.

If the migration tooling reports a source fingerprint mismatch, stop and investigate rather than bypassing the check.

---

# 13. Foreign-key migration handling

Kaya contains a large relational schema.

Some tables contain relationships that form dependency cycles, meaning the data cannot safely be copied using simple alphabetical table ordering.

v0.28.0 therefore constructs a foreign-key dependency graph from the PostgreSQL target schema.

The converter:

1. Reflects the target schema.
2. Identifies table dependencies.
3. Performs deterministic dependency ordering.
4. Detects strongly connected components.
5. Identifies supported nullable relationships within cycles.
6. Temporarily defers those values during initial insertion.
7. Inserts the required records.
8. Restores the deferred relationships.
9. Re-validates foreign-key integrity.

This allows valid cyclic relationships to be migrated without disabling relational integrity across the whole database.

---

# 14. Migration failures are fail-closed

<Callout type="info">
The converter is deliberately designed to stop when it cannot guarantee a trustworthy result.
</Callout>

Earlier migration strategies could retry inserts when a foreign-key operation failed.

The v0.28.0 migration engine does not silently retry rejected inserts into an uncertain state.

If an insert that should be valid is rejected, the migration fails.

This is intentional.

A failed migration is preferable to a production database containing silently missing or incorrectly related records.

---

# 15. Monitor migration output

Watch the console while migration is running.

Successful stages should progress through source validation, schema preparation, data conversion and post-migration verification.

If you started the migration in detached mode, inspect the logs using:

```bash
docker compose -f docker-compose.upgrade.yml logs -f
```

If a dedicated migration service is defined, specify it:

```bash
docker compose -f docker-compose.upgrade.yml logs -f migrate
```

Do not interrupt a migration simply because a large table takes longer than smaller tables.

---

# 16. Migration report

Kaya records migration state in a migration report.

Depending on your configured data directory, this may appear as:

```text
kaya-database-upgrade.json
```

For example:

```bash
cat ~/data/kaya-database-upgrade.json
```

or:

```bash
cat ./data/kaya-database-upgrade.json
```

The report provides information about the attempted conversion and is especially important if the migration fails.

Possible information includes:

- Source fingerprint
- Conversion fingerprint
- Source database engine
- Migration identifier
- Migration status
- Failure type
- Validation information

---

# 17. Successful migration

Do not consider the migration complete simply because the converter container exited.

Confirm that the migration report indicates successful completion and that the migration logs contain no unresolved validation errors.

Check the exit status:

```bash
docker compose -f docker-compose.upgrade.yml ps -a
```

If you ran the migration using:

```bash
docker compose -f docker-compose.upgrade.yml run --rm migrate
```

the command should return exit code `0`.

You can confirm the previous shell command with:

```bash
echo $?
```

Expected:

```text
0
```

---

# 18. If the migration fails

If the migration exits with an error:

**Do not start the normal v0.28.0 application stack.**

First inspect:

```bash
cat ./data/kaya-database-upgrade.json
```

and the migration logs:

```bash
docker compose -f docker-compose.upgrade.yml logs
```

If the containers still exist:

```bash
docker compose -f docker-compose.upgrade.yml ps -a
```

Look for the first migration error rather than only the final container exit message.

---

# 19. Preserve failure evidence

If you need to report a failed migration, preserve:

- `kaya-database-upgrade.json`
- Migration container logs
- Kaya version being upgraded from
- v0.28.0 image digest
- Docker version
- Docker Compose version
- Operating system
- Relevant Compose configuration

Do **not** publicly upload the SQLite database itself unless you have intentionally removed or anonymised sensitive application data.

---

# 20. Do not repeatedly retry an unexplained failure

A failed migration may leave PostgreSQL containing a partially populated target database.

Do not repeatedly run the converter against the same failed target without understanding whether the migration workflow has reset or recreated that target.

The migration process is designed to detect and handle known conversion state, but an unexplained failure should be investigated before attempting manual changes.

Avoid manually inserting, deleting or editing records in PostgreSQL in an attempt to "help" the converter finish.

---

# 21. Recovery after a failed migration

If migration fails, the original SQLite database should remain your authoritative source.

Because Kaya was stopped before migration, you can return to the previous release if necessary.

A normal recovery process is:

```text
Migration fails
      │
      ▼
Preserve logs/report
      │
      ▼
Stop upgrade services
      │
      ▼
Restore previous Compose configuration if required
      │
      ▼
Ensure original SQLite data is present
      │
      ▼
Start previous Kaya release
```

Stop the upgrade stack:

```bash
docker compose -f docker-compose.upgrade.yml down
```

If necessary, restore your previous deployment configuration and start the previous version again.

For example:

```bash
docker compose up -d
```

Verify the old installation before allowing users back onto the system.

---

# 22. Do not overwrite the original SQLite database

The migration process should treat the SQLite source as the source of truth during conversion.

Do not:

- Replace the SQLite file with an empty database
- Rename another SQLite database into its location
- Edit rows manually before retrying
- Run schema migrations against it using unrelated tooling
- Delete it once PostgreSQL first starts

Keep it intact until the upgrade has been fully accepted.

---

# 23. Start the normal PostgreSQL-backed Kaya stack

Once migration has completed successfully, stop any temporary upgrade services:

```bash
docker compose -f docker-compose.upgrade.yml down
```

Then start the normal v0.28.0 production environment:

```bash
docker compose up -d
```

This normal stack uses PostgreSQL.

---

# 24. Check container health

Confirm all expected containers are running:

```bash
docker compose ps
```

You should see the core v0.28.0 services, including the PostgreSQL database.

Wait until services which expose health checks report healthy.

Inspect startup logs:

```bash
docker compose logs --tail=200
```

For ongoing monitoring:

```bash
docker compose logs -f
```

Look for unexpected:

```text
ERROR
CRITICAL
Traceback
migration
database
connection refused
authentication failed
foreign key
```

Some informational messages containing terms such as `migration` are normal, so assess them in context.

---

# 25. Verify the application

Open Kaya and sign in using an existing administrator account.

Do not begin making large configuration changes yet.

First verify that existing information has migrated correctly.

---

# 26. Recommended post-migration checks

Check the parts of Kaya that contain important relational data.

At minimum, verify:

### Authentication

- Existing administrator login works.
- Existing users can authenticate.
- Roles and permissions appear correct.

### Users

- User accounts exist.
- User information is present.
- Expected administrator accounts remain administrators.

### Asset Manager

- Assets are present.
- Asset metadata is correct.
- Existing attachments can be opened.
- Existing uploaded files are accessible.

### DNS

Where you use Kaya's DNS functionality:

- DNS servers are present.
- Configuration is correct.
- Existing relationships between DNS objects remain intact.

### High Availability

Where HA is configured:

- HA clusters are present.
- Nodes are correctly associated with their clusters.
- Preferred-node configuration remains correct.
- Current node state is sensible.
- VIP state is correct.
- DHCP state matches the expected active node.

### Remote Manager

- Existing managed systems are present.
- Saved connection metadata is present.
- Remote sessions can still be initiated.

### Settings

Review:

- General application settings
- Integrations
- Notification settings
- Agent settings
- Security settings
- Any organisation-specific configuration

---

# 27. Record counts

For important installations it can be useful to compare key record counts before and after migration.

Examples include:

- Users
- Assets
- Managed systems
- DNS records
- HA clusters
- HA nodes
- Audit records

The built-in migration validation already checks database state, but operational verification provides an additional level of confidence.

---

# 28. Verify PostgreSQL is actually being used

After starting v0.28.0, confirm PostgreSQL is running:

```bash
docker compose ps
```

You should see the PostgreSQL service.

You can also inspect Kaya's startup logs:

```bash
docker compose logs --tail=200
```

The application should not be opening the old SQLite database for normal production operation.

---

# 29. Verify restart behaviour

Once the initial application checks have passed, restart the stack:

```bash
docker compose restart
```

Then verify:

```bash
docker compose ps
```

and sign back into Kaya.

This confirms that the new PostgreSQL environment survives a normal application restart.

---

# 30. Verify a full stop/start

A stronger final check is a full Compose stop and start:

```bash
docker compose down
docker compose up -d
```

Then verify:

```bash
docker compose ps
```

and test Kaya again.

Persistent application and PostgreSQL data should survive the cycle.

---

# 31. PostgreSQL data is now production data

After successful migration and validation:

```text
PostgreSQL = production database
SQLite     = retained migration backup
```

Do not continue running some Kaya services against SQLite and others against PostgreSQL.

There should be one authoritative production database.

---

# 32. Retain the SQLite backup

Even after a successful migration, retain the old SQLite database for an appropriate backup period.

A sensible approach is to store it alongside your migration records with a clear name such as:

```text
kaya-v0.27.4-pre-postgresql.sqlite
```

Keep the file somewhere that is:

- Backed up
- Access controlled
- Not mounted as Kaya's active database
- Clearly marked as historical

The database may contain sensitive Kaya data and should be protected accordingly.

---

# 33. Back up PostgreSQL

Your backup strategy must change after upgrading.

Backing up only an old SQLite file is no longer sufficient.

Your regular backup process must include the PostgreSQL database.

The exact backup strategy depends on your environment, but PostgreSQL provides standard tools such as:

```bash
pg_dump
```

and:

```bash
pg_dumpall
```

For production installations, use a tested backup and restore process appropriate to your deployment.

<Callout type="warning">
A Docker volume is persistent storage, not a backup.
</Callout>

Keep database backups outside the Docker host where possible.

---

# 34. Example PostgreSQL logical backup

Where your Compose configuration permits it, a logical backup may resemble:

```bash
docker compose exec postgres pg_dump \
  -U kaya \
  -d kaya \
  -Fc \
  > kaya-postgresql-backup.dump
```

The exact database name and username depend on your deployment configuration.

Confirm them from your Compose environment rather than assuming the example values above.

Protect the resulting backup because it contains application data.

---

# 35. Test your PostgreSQL backups

Creating a backup file is only half of a backup strategy.

Periodically verify that the backup can be read and restored into a non-production PostgreSQL instance.

For a custom-format `pg_dump` archive, you can inspect its contents with:

```bash
pg_restore --list kaya-postgresql-backup.dump
```

Your recovery procedure should be documented and tested before you need it.

---

# 36. High Availability installations

Operators using Kaya's HA functionality should perform additional checks after migration.

v0.28.0 contains important DHCP fencing improvements.

A node is not considered safe to provide DHCP service merely because it observes transient ownership of the VIP.

Promotion repair now requires continuous eligible VIP ownership before DHCP is enabled.

Current behaviour also protects against stale promotion and demotion commands.

After migration, verify:

- The intended active node owns the VIP.
- The expected node is providing DHCP.
- The standby node is not providing DHCP.
- Cluster generation/state appears consistent.
- Preferred-node configuration is correct.
- Agent communication is healthy.
- No repeated promotion/demotion cycle is occurring.

Do not intentionally induce a production failover until the normal post-migration checks have passed.

---

# 37. HA failover test

If you routinely test HA and have an approved maintenance window, perform a controlled failover after the basic upgrade has been accepted.

During the test, verify:

```text
Old ACTIVE
   │
   ▼
VIP handover
   │
   ▼
New ACTIVE
   │
   ▼
Stable VIP ownership
   │
   ▼
DHCP promotion
```

Confirm there is never a period where two nodes are simultaneously serving DHCP.

Afterwards, either leave the new active node in service or perform an authorised handback according to your normal HA procedure.

---

# 38. Upgrade troubleshooting

## Kaya cannot connect to PostgreSQL

Check:

```bash
docker compose ps
```

Then inspect PostgreSQL logs:

```bash
docker compose logs postgres
```

and Kaya logs:

```bash
docker compose logs kaya
```

Common causes include:

- PostgreSQL has not finished initialising.
- Incorrect credentials.
- Incorrect secret file.
- Database hostname mismatch.
- PostgreSQL container is unhealthy.
- Old deployment configuration is being used.

---

## Migration reports `SQLiteToPostgresError`

This is a migration failure class rather than a reason to manually edit the database.

Inspect the migration report:

```bash
cat ./data/kaya-database-upgrade.json
```

Then inspect the complete migration log.

Look for the first specific database or validation error preceding `SQLiteToPostgresError`.

Preserve the report before attempting another migration.

---

## Source fingerprint mismatch

A fingerprint mismatch means the database presented for conversion does not match the database associated with existing migration state.

Check that:

- You are using the intended SQLite file.
- The source database has not been replaced.
- A restored backup is the correct backup.
- Migration state from another Kaya installation has not been copied into this deployment.

Do not bypass this check by manually changing the recorded hash.

---

## Foreign-key error

The migration engine already understands Kaya's expected relational dependencies and known nullable cyclic relationships.

An unexpected foreign-key rejection therefore causes the migration to fail.

Do not fix this by disabling PostgreSQL foreign keys or constraints.

Preserve the logs and migration report and investigate the underlying source or migration issue.

---

## PostgreSQL starts but Kaya data appears missing

Stop making changes immediately.

Check:

1. The migration report indicates success.
2. The expected PostgreSQL volume is mounted.
3. Kaya is connected to the same database populated by the converter.
4. The production Compose file has not created a second empty PostgreSQL volume.
5. Environment or secret values match between migration and normal runtime.

Do not initialise a fresh database over the migration target.

---

# 39. Rollback considerations

Before users begin making changes in the PostgreSQL-backed version, rollback is relatively straightforward because the original SQLite database remains unchanged.

After users begin making production changes in v0.28.0, the PostgreSQL database contains new data that does not exist in the old SQLite database.

At that point, simply starting v0.27.4 against the old SQLite file would result in data loss from everything created or changed after migration.

Therefore:

<Callout type="danger">
Do not treat the old SQLite database as an indefinitely interchangeable production fallback once users have resumed work on v0.28.0.
</Callout>

If a serious problem is discovered after production use has resumed, preserve the PostgreSQL database before considering any rollback.

---

# 40. Migration acceptance checklist

Use the following checklist before considering the migration complete.

## Before migration

- [ ] Existing Kaya installation works.
- [ ] Current Kaya version recorded.
- [ ] Full data backup created.
- [ ] Backup checked.
- [ ] Existing SQLite database identified.
- [ ] Existing Kaya containers stopped.
- [ ] v0.28.0 deployment files obtained.
- [ ] v0.28.0 image pulled.

## Migration

- [ ] `docker-compose.upgrade.yml` used.
- [ ] Migration completed without unresolved errors.
- [ ] Migration command exited successfully.
- [ ] Migration report reviewed.
- [ ] Source fingerprint is correct.
- [ ] No failed validation remains.
- [ ] Original SQLite database retained.

## Production startup

- [ ] Upgrade stack stopped.
- [ ] Normal `docker-compose.yml` started.
- [ ] PostgreSQL container healthy.
- [ ] Kaya container healthy.
- [ ] Kaya connects to PostgreSQL.
- [ ] Existing administrator login works.

## Application validation

- [ ] Users are present.
- [ ] Roles and permissions are correct.
- [ ] Assets are present.
- [ ] Asset files/attachments work.
- [ ] Managed systems are present.
- [ ] DNS configuration is present.
- [ ] HA configuration is present, where applicable.
- [ ] Application settings are correct.
- [ ] Integrations are correct.

## Operational validation

- [ ] Application restart tested.
- [ ] Full Compose stop/start tested.
- [ ] PostgreSQL persistence confirmed.
- [ ] PostgreSQL backup strategy updated.
- [ ] First PostgreSQL backup created.
- [ ] Historical SQLite backup stored safely.

## HA installations

- [ ] Expected node owns VIP.
- [ ] Exactly one node provides DHCP.
- [ ] Agent communication healthy.
- [ ] Cluster state stable.
- [ ] Controlled failover tested, where appropriate.

---

# 41. After migration

Once the migration has been accepted:

- Continue using PostgreSQL for production.
- Update monitoring to include PostgreSQL.
- Update backup procedures.
- Remove any old automation that backs up only the SQLite database.
- Retain the historical SQLite database securely.
- Keep the migration report with your upgrade records.
- Monitor Kaya logs more closely during the first period after upgrade.

---

# 42. Getting help

If migration fails and you need to raise an issue, include:

- Kaya source version
- Kaya target version
- Docker version
- Docker Compose version
- Host operating system
- Migration report
- Relevant migration logs
- Whether the installation uses HA
- Whether the migration has previously been attempted

Where possible, include the exact first error produced by the converter.

Do not publish:

- Passwords
- Secret files
- Database credentials
- Authentication tokens
- Private keys
- Full production databases containing sensitive information

---

# Summary

Kaya v0.28.0 changes the production database architecture from SQLite to PostgreSQL.

The safe upgrade sequence is:

```bash
# 1. Back up the existing installation

# 2. Stop Kaya
docker compose down

# 3. Obtain/pull v0.28.0
docker pull ghcr.io/antybubbs/kaya:v0.28.0

# 4. Run the dedicated migration
docker compose -f docker-compose.upgrade.yml up

# 5. Review migration status and logs

# 6. Stop migration services
docker compose -f docker-compose.upgrade.yml down

# 7. Start normal v0.28.0
docker compose up -d

# 8. Verify
docker compose ps
docker compose logs --tail=200
```

Do not delete the original SQLite database after conversion.

Once production activity resumes on PostgreSQL, PostgreSQL becomes the authoritative Kaya database and must be included in your normal backup and recovery strategy.
