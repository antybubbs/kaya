#!/usr/bin/env python3
"""Converge Kaya's PostgreSQL bootstrap/runtime role topology safely."""

from __future__ import annotations

import json
import hashlib
import logging
import os
import stat
from pathlib import Path

import psycopg

LOG = logging.getLogger("kaya.postgres.role_topology")
APP_ROLE = "kaya"
BOOTSTRAP_ROLE = "kaya_bootstrap"
MIGRATION_ADMIN_ROLE = "kaya_phase12_migration_admin"
DATABASE = "kaya"
SCHEMA = "public"


def secret(path_value: str) -> str:
    path = Path(path_value)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError(f"secret file permissions are unsafe: {path.name}")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"secret file is empty: {path.name}")
    return value


def connect(user: str, password: str, database: str = "postgres"):
    return psycopg.connect(
        host=os.environ.get("POSTGRES_HOST", "postgres"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        dbname=database,
        user=user,
        password=password,
        connect_timeout=8,
    )


def role(conn, name: str) -> dict[str, object] | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT oid, rolname, rolsuper, rolcreatedb, rolcreaterole, rolcanlogin
            FROM pg_authid WHERE rolname = %s
            """,
            (name,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return dict(zip(("oid", "rolname", "rolsuper", "rolcreatedb", "rolcreaterole", "rolcanlogin"), row))


def ownership(conn) -> tuple[str | None, str | None]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT pg_get_userbyid(d.datdba), pg_get_userbyid(n.nspowner)
            FROM pg_database d CROSS JOIN pg_namespace n
            WHERE d.datname = %s AND n.nspname = %s
            """,
            (DATABASE, SCHEMA),
        )
        row = cur.fetchone()
    return (row[0], row[1]) if row else (None, None)


def has_kaya_schema(password: str) -> bool:
    with connect(BOOTSTRAP_ROLE, password, DATABASE) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.alembic_version') IS NOT NULL")
            return bool(cur.fetchone()[0])


def verify_backup_marker(marker: Path) -> None:
    info = marker.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("verified backup marker permissions are unsafe")
    try:
        evidence = json.loads(marker.read_text(encoding="utf-8"))
        archive_name = evidence["archive"]
        expected_sha = evidence["sha256"]
        expected_bytes = int(evidence["archive_bytes"])
        expected_run = os.environ.get("KAYA_ROLE_MIGRATION_RUN_ID", "production")
        if evidence["source_database"] != DATABASE or evidence["source_role"] != APP_ROLE:
            raise ValueError
        if evidence["backup_purpose"] != "pre_role_topology_migration" or evidence["run_id"] != expected_run:
            raise ValueError
        if not isinstance(archive_name, str) or Path(archive_name).name != archive_name:
            raise ValueError
        if not isinstance(expected_sha, str) or len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
            raise ValueError
        archive = marker.parent / archive_name
        metadata = archive.with_name(f"{archive.name}.json")
        checksum = archive.with_name(f"{archive.name}.sha256")
        if not archive.is_file() or not metadata.is_file() or not checksum.is_file():
            raise ValueError
        if archive.stat().st_size != expected_bytes:
            raise ValueError
        digest = hashlib.sha256()
        with archive.open("rb") as archive_stream:
            for chunk in iter(lambda: archive_stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_sha:
            raise ValueError
        metadata_value = json.loads(metadata.read_text(encoding="utf-8"))
        if metadata_value.get("verification_state") != "verified" or metadata_value.get("sha256") != expected_sha:
            raise ValueError
        if metadata_value.get("alembic_revision") != evidence["alembic_revision"]:
            raise ValueError
        if not checksum.read_text(encoding="utf-8").startswith(f"{expected_sha}  {archive}"):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("verified backup marker is missing or not bound to a verified archive") from exc


def create_runtime_role(conn, password: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT format('CREATE ROLE %%I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %%L', %s::text, %s::text)",
            (APP_ROLE, password),
        )
        cur.execute(cur.fetchone()[0])
        cur.execute("ALTER DATABASE kaya OWNER TO kaya")
    conn.commit()
    with connect(BOOTSTRAP_ROLE, secret(os.environ["KAYA_BOOTSTRAP_PASSWORD_FILE"]), DATABASE) as database_conn:
        with database_conn.cursor() as cur:
            cur.execute("ALTER SCHEMA public OWNER TO kaya")
        database_conn.commit()


def create_named_bootstrap_role(conn, name: str, password: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT format('CREATE ROLE %%I LOGIN SUPERUSER CREATEDB CREATEROLE PASSWORD %%L', %s::text, %s::text)",
            (name, password),
        )
        cur.execute(cur.fetchone()[0])
    conn.commit()


def create_bootstrap_role(conn, password: str) -> None:
    create_named_bootstrap_role(conn, BOOTSTRAP_ROLE, password)


def migrate_cluster_bootstrap_role(conn, app_password: str, bootstrap_password: str) -> None:
    create_named_bootstrap_role(conn, MIGRATION_ADMIN_ROLE, bootstrap_password)
    with connect(MIGRATION_ADMIN_ROLE, bootstrap_password) as migration_conn:
        with migration_conn.cursor() as cur:
            cur.execute("ALTER ROLE kaya RENAME TO kaya_bootstrap")
            cur.execute(
                "SELECT format('ALTER ROLE %%I PASSWORD %%L', %s::text, %s::text)",
                (BOOTSTRAP_ROLE, bootstrap_password),
            )
            cur.execute(cur.fetchone()[0])
            cur.execute(
                "SELECT format('CREATE ROLE %%I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %%L', %s::text, %s::text)",
                (APP_ROLE, app_password),
            )
            cur.execute(cur.fetchone()[0])
        migration_conn.commit()
    with connect(MIGRATION_ADMIN_ROLE, bootstrap_password, DATABASE) as database_conn:
        with database_conn.cursor() as cur:
            cur.execute(
                """
                DO $phase12$
                DECLARE
                    item record;
                BEGIN
                    FOR item IN
                        SELECT c.oid AS relid, c.relkind, n.nspname, c.relname
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE c.relowner = 'kaya_bootstrap'::regrole
                          AND n.nspname = 'public'
                    LOOP
                        IF item.relkind IN ('r', 'p', 'f') THEN
                            EXECUTE format('ALTER TABLE %I.%I OWNER TO kaya', item.nspname, item.relname);
                        ELSIF item.relkind = 'S' THEN
                            IF NOT EXISTS (
                                SELECT 1
                                FROM pg_depend
                                WHERE classid = 'pg_class'::regclass
                                  AND objid = item.relid
                                  AND deptype = 'a'
                            ) THEN
                                EXECUTE format('ALTER SEQUENCE %I.%I OWNER TO kaya', item.nspname, item.relname);
                            END IF;
                        ELSIF item.relkind IN ('v', 'm') THEN
                            EXECUTE format('ALTER %s %I.%I OWNER TO kaya',
                                           CASE WHEN item.relkind = 'v' THEN 'VIEW' ELSE 'MATERIALIZED VIEW' END,
                                           item.nspname, item.relname);
                        END IF;
                    END LOOP;
                    FOR item IN
                        SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) AS args
                        FROM pg_proc p
                        JOIN pg_namespace n ON n.oid = p.pronamespace
                        WHERE p.proowner = 'kaya_bootstrap'::regrole
                          AND n.nspname = 'public'
                    LOOP
                        EXECUTE format('ALTER FUNCTION %I.%I(%s) OWNER TO kaya',
                                       item.nspname, item.proname, item.args);
                    END LOOP;
                END
                $phase12$
                """
            )
            cur.execute("ALTER SCHEMA public OWNER TO kaya")
        database_conn.commit()
    with connect(MIGRATION_ADMIN_ROLE, bootstrap_password) as admin_conn:
        with admin_conn.cursor() as cur:
            cur.execute("ALTER DATABASE kaya OWNER TO kaya")
        admin_conn.commit()
    with connect(BOOTSTRAP_ROLE, bootstrap_password, DATABASE) as database_conn:
        with database_conn.cursor() as cur:
            cur.execute("ALTER SCHEMA public OWNER TO kaya")
        database_conn.commit()
    with connect(BOOTSTRAP_ROLE, bootstrap_password) as cleanup_conn:
        with cleanup_conn.cursor() as cur:
            cur.execute("DROP ROLE IF EXISTS kaya_phase12_migration_admin")
        cleanup_conn.commit()
    return


def repair_role_sql(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("ALTER DATABASE kaya OWNER TO kaya")
        cur.execute("ALTER ROLE kaya LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
    conn.commit()
    with connect(BOOTSTRAP_ROLE, secret(os.environ["KAYA_BOOTSTRAP_PASSWORD_FILE"]), DATABASE) as database_conn:
        with database_conn.cursor() as cur:
            cur.execute("ALTER SCHEMA public OWNER TO kaya")
        database_conn.commit()


def verify(conn) -> dict[str, object]:
    app = role(conn, APP_ROLE)
    bootstrap = role(conn, BOOTSTRAP_ROLE)
    db_owner, schema_owner = ownership(conn)
    if app is None or not app["rolcanlogin"] or app["rolsuper"] or app["rolcreatedb"] or app["rolcreaterole"]:
        raise RuntimeError("runtime PostgreSQL role does not satisfy the constrained-role policy")
    # PostgreSQL 15+ reports the special public-schema owner as
    # pg_database_owner.  With the database owned by kaya, that role is the
    # effective schema owner and is safe for the constrained runtime role.
    if db_owner != APP_ROLE or schema_owner not in {APP_ROLE, "pg_database_owner"}:
        raise RuntimeError(
            f"Kaya database/schema ownership is not safely established: database={db_owner!r} schema={schema_owner!r}"
        )
    if bootstrap is None or not bootstrap["rolcanlogin"] or not bootstrap["rolsuper"]:
        raise RuntimeError("bootstrap PostgreSQL role is missing or lacks required setup capability")
    return {
        "legacy_role_superuser_before": None,
        "runtime_role_superuser_after": bool(app["rolsuper"]),
        "runtime_role_createdb_after": bool(app["rolcreatedb"]),
        "runtime_role_createrole_after": bool(app["rolcreaterole"]),
        "runtime_role_login_after": bool(app["rolcanlogin"]),
        "database_owner_after": db_owner,
        "schema_owner_after": schema_owner,
        "bootstrap_role_present": True,
    }


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    app_password = secret(os.environ.get("KAYA_APP_PASSWORD_FILE", "/run/kaya-secrets/postgres_password"))
    bootstrap_password = secret(os.environ.get("KAYA_BOOTSTRAP_PASSWORD_FILE", "/run/kaya-secrets/postgres_bootstrap_password"))
    admin = None
    admin_user = None
    admin_password = None
    bootstrap_authenticated_with_app_secret = False
    try:
        try:
            admin = connect(BOOTSTRAP_ROLE, bootstrap_password)
            admin_user = BOOTSTRAP_ROLE
            admin_password = bootstrap_password
        except psycopg.Error:
            try:
                admin = connect(BOOTSTRAP_ROLE, app_password)
                admin_user = BOOTSTRAP_ROLE
                admin_password = app_password
                bootstrap_authenticated_with_app_secret = True
            except psycopg.Error:
                admin = connect(APP_ROLE, app_password)
                admin_user = APP_ROLE
                admin_password = app_password
        with connect(admin_user, admin_password, DATABASE) as ownership_conn:
            db_owner_before, schema_owner_before = ownership(ownership_conn)
        app_before = role(admin, APP_ROLE)
        bootstrap_before = role(admin, BOOTSTRAP_ROLE)
        if app_before is None:
            LOG.info("postgres.role_topology.detected state=fresh")
            if bootstrap_before is None:
                raise RuntimeError("bootstrap role is missing from a fresh cluster")
            if has_kaya_schema(bootstrap_password):
                raise RuntimeError("Kaya schema exists but the runtime role is missing")
            create_runtime_role(admin, app_password)
            with connect(BOOTSTRAP_ROLE, bootstrap_password, DATABASE) as final_conn:
                result = verify(final_conn)
            result["database_owner_before"] = db_owner_before
            result["schema_owner_before"] = schema_owner_before
            result["legacy_role_superuser_before"] = None
            LOG.info("postgres.role_topology.migration_completed")
            print(json.dumps(result, sort_keys=True))
            return 0
        elif not app_before["rolsuper"] and not app_before["rolcreatedb"] and not app_before["rolcreaterole"] and app_before["rolcanlogin"] and db_owner_before == APP_ROLE and schema_owner_before in {APP_ROLE, "pg_database_owner"}:
            LOG.info("postgres.role_topology.detected state=current")
            if bootstrap_authenticated_with_app_secret:
                with admin.cursor() as cur:
                    cur.execute(
                        "SELECT format('ALTER ROLE %%I PASSWORD %%L', %s::text, %s::text)",
                        (BOOTSTRAP_ROLE, bootstrap_password),
                    )
                    cur.execute(cur.fetchone()[0])
                admin.commit()
            with connect(BOOTSTRAP_ROLE, bootstrap_password, DATABASE) as final_conn:
                result = verify(final_conn)
            result["database_owner_before"] = db_owner_before
            result["schema_owner_before"] = schema_owner_before
            result["legacy_role_superuser_before"] = False
            LOG.info("postgres.role_topology.already_current")
            print(json.dumps(result, sort_keys=True))
            return 0
        elif app_before["rolsuper"] and db_owner_before == APP_ROLE and schema_owner_before in {APP_ROLE, "pg_database_owner"}:
            if bootstrap_before is not None and admin_password != bootstrap_password:
                raise RuntimeError("bootstrap role exists but cannot be authenticated with its configured secret")
            marker = Path(os.environ.get("KAYA_ROLE_MIGRATION_MARKER", "/var/backups/kaya-postgres/.role-migration-backup-verified"))
            if not marker.is_file():
                raise RuntimeError("verified backup is required before legacy role mutation")
            verify_backup_marker(marker)
            LOG.info("postgres.role_topology.migration_started")
            if int(app_before["oid"]) == 10:
                if bootstrap_before is not None:
                    raise RuntimeError("cluster bootstrap role has a conflicting partial bootstrap identity")
                migrate_cluster_bootstrap_role(admin, app_password, bootstrap_password)
            elif bootstrap_before is None:
                create_bootstrap_role(admin, bootstrap_password)
                with connect(BOOTSTRAP_ROLE, bootstrap_password) as bootstrap_conn:
                    repair_role_sql(bootstrap_conn)
            else:
                with admin.cursor() as cur:
                    cur.execute("ALTER ROLE kaya_bootstrap LOGIN SUPERUSER CREATEDB CREATEROLE PASSWORD %s", (bootstrap_password,))
                admin.commit()
                with connect(BOOTSTRAP_ROLE, bootstrap_password) as bootstrap_conn:
                    repair_role_sql(bootstrap_conn)
            with connect(BOOTSTRAP_ROLE, bootstrap_password) as final_conn:
                result = verify(final_conn)
            result["database_owner_before"] = db_owner_before
            result["schema_owner_before"] = schema_owner_before
            result["legacy_role_superuser_before"] = True
            LOG.info("postgres.role_topology.migration_completed")
            print(json.dumps(result, sort_keys=True))
            return 0
        else:
            raise RuntimeError("ambiguous or unsafe Kaya PostgreSQL role topology")
    except (OSError, ValueError, psycopg.Error, RuntimeError) as exc:
        LOG.error("postgres.role_topology.failed reason=%s", str(exc)[:240])
        return 1
    finally:
        if admin is not None:
            admin.close()


if __name__ == "__main__":
    raise SystemExit(main())
