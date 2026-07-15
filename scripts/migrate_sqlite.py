#!/usr/bin/env python3

import sqlite3
import sys
import re
from pathlib import Path

DB_PATH = Path("/app/data/kaya.db")


def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    return column in [row[1] for row in cursor.fetchall()]


def table_exists(cursor, table):
    cursor.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    )
    return cursor.fetchone() is not None


def main():
    if not DB_PATH.exists():
        print("Database does not exist yet. Skipping migrations.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = OFF")

    migrations_applied = []

    if table_exists(cur, "users"):
        for column, definition in {
            "authentication_type": "VARCHAR(30) DEFAULT 'local' NOT NULL",
            "is_break_glass": "BOOLEAN DEFAULT 0 NOT NULL",
            "role_source": "VARCHAR(30) DEFAULT 'local' NOT NULL",
            "updated_at": "DATETIME",
        }.items():
            if not column_exists(cur, "users", column):
                cur.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
                migrations_applied.append(f"users.{column}")
        cur.execute("UPDATE users SET authentication_type = 'local' WHERE authentication_type IS NULL OR authentication_type = ''")
        cur.execute("UPDATE users SET role_source = 'local' WHERE role_source IS NULL OR role_source = ''")
        cur.execute("UPDATE users SET is_break_glass = 0 WHERE is_break_glass IS NULL")
        cur.execute("UPDATE users SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)")

        password_info = next((row for row in cur.execute("PRAGMA table_info(users)").fetchall() if row[1] == "password_hash"), None)
        if password_info and password_info[3]:
            create_sql = cur.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").fetchone()[0]
            nullable_sql = re.sub(
                r"password_hash\s+VARCHAR\(255\)\s+NOT\s+NULL",
                "password_hash VARCHAR(255)",
                create_sql,
                count=1,
                flags=re.IGNORECASE,
            )
            if nullable_sql == create_sql:
                raise sqlite3.OperationalError("Could not safely make users.password_hash nullable")
            nullable_sql = re.sub(r"CREATE\s+TABLE\s+users", "CREATE TABLE users_oidc_new", nullable_sql, count=1, flags=re.IGNORECASE)
            columns = [row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()]
            column_list = ", ".join(f'"{name}"' for name in columns)
            cur.execute(nullable_sql)
            cur.execute(f"INSERT INTO users_oidc_new ({column_list}) SELECT {column_list} FROM users")
            cur.execute("DROP TABLE users")
            cur.execute("ALTER TABLE users_oidc_new RENAME TO users")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)")
            cur.execute("CREATE INDEX IF NOT EXISTS ix_users_authentication_type ON users (authentication_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS ix_users_is_break_glass ON users (is_break_glass)")
            cur.execute("CREATE INDEX IF NOT EXISTS ix_users_role_source ON users (role_source)")
            migrations_applied.append("users.password_hash nullable")

    if table_exists(cur, "app_sessions") and not column_exists(cur, "app_sessions", "encrypted_oidc_id_token"):
        cur.execute("ALTER TABLE app_sessions ADD COLUMN encrypted_oidc_id_token TEXT")
        migrations_applied.append("app_sessions.encrypted_oidc_id_token")

    # Public releases before v0.18 do not have compute_hosts yet. In that case,
    # application startup creates the complete current table via SQLAlchemy.
    # May the migration God bless us all.
    if table_exists(cur, "compute_hosts"):
        if not column_exists(cur, "compute_hosts", "agent_last_seen_at"):
            cur.execute(
                "ALTER TABLE compute_hosts ADD COLUMN agent_last_seen_at DATETIME"
            )
            migrations_applied.append("compute_hosts.agent_last_seen_at")

        if not column_exists(cur, "compute_hosts", "encrypted_agent_token"):
            cur.execute(
                "ALTER TABLE compute_hosts ADD COLUMN encrypted_agent_token TEXT"
            )
            migrations_applied.append("compute_hosts.encrypted_agent_token")

    if not table_exists(cur, "backup_records"):
        cur.execute(
            "CREATE TABLE backup_records (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, source_type VARCHAR(40) DEFAULT 'manual' NOT NULL, source_ref VARCHAR(500), target VARCHAR(500), schedule VARCHAR(255), owner VARCHAR(255), last_status VARCHAR(40), last_run_at DATETIME, notes TEXT, is_enabled BOOLEAN DEFAULT 1 NOT NULL, created_at DATETIME, updated_at DATETIME)"
        )
        for column in ["name", "source_type", "source_ref", "owner", "last_status", "last_run_at", "is_enabled"]:
            cur.execute(f"CREATE INDEX ix_backup_records_{column} ON backup_records ({column})")
        migrations_applied.append("backup_records")

    if not table_exists(cur, "backup_jobs"):
        cur.execute(
            "CREATE TABLE backup_jobs (id INTEGER NOT NULL PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES compute_hosts(id), workload_id INTEGER REFERENCES compute_workloads(id), operation VARCHAR(30) NOT NULL, status VARCHAR(40) DEFAULT 'queued' NOT NULL, encryption_enabled BOOLEAN DEFAULT 1 NOT NULL, encrypted_backup_key TEXT, artifact_path VARCHAR(1000), size_bytes INTEGER, error TEXT, log TEXT, metadata_json TEXT, requested_by_id INTEGER REFERENCES users(id), created_at DATETIME, dispatched_at DATETIME, started_at DATETIME, finished_at DATETIME, updated_at DATETIME)"
        )
        for column in ["host_id", "workload_id", "operation", "status", "encryption_enabled", "requested_by_id", "created_at", "dispatched_at", "started_at", "finished_at"]:
            cur.execute(f"CREATE INDEX ix_backup_jobs_{column} ON backup_jobs ({column})")
        migrations_applied.append("backup_jobs")

    if not table_exists(cur, "dns_providers"):
        cur.execute(
            "CREATE TABLE dns_providers (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, provider_type VARCHAR(40) DEFAULT 'pihole' NOT NULL, base_url VARCHAR(500) NOT NULL, auth_method VARCHAR(40) DEFAULT 'password' NOT NULL, encrypted_secret TEXT, ssl_verify BOOLEAN DEFAULT 1 NOT NULL, timeout_seconds INTEGER DEFAULT 10 NOT NULL, is_enabled BOOLEAN DEFAULT 1 NOT NULL, description TEXT, last_status VARCHAR(40), last_error TEXT, last_checked_at DATETIME, created_at DATETIME, updated_at DATETIME)"
        )
        for column in ["name", "provider_type", "is_enabled", "last_status", "last_checked_at"]:
            cur.execute(f"CREATE INDEX ix_dns_providers_{column} ON dns_providers ({column})")
        migrations_applied.append("dns_providers")

    if not table_exists(cur, "dns_investigations"):
        cur.execute(
            "CREATE TABLE dns_investigations (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER REFERENCES dns_providers(id) ON DELETE SET NULL, domain VARCHAR(500) NOT NULL, client_name VARCHAR(255), client_ip VARCHAR(80), query_type VARCHAR(40), status VARCHAR(40) DEFAULT 'open' NOT NULL, reply_type VARCHAR(120), reply_time VARCHAR(80), upstream VARCHAR(255), observed_at VARCHAR(80), notes TEXT, created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME, updated_at DATETIME)"
        )
        for column in ["provider_id", "domain", "client_name", "client_ip", "query_type", "status", "reply_type", "created_by_id", "created_at"]:
            cur.execute(f"CREATE INDEX ix_dns_investigations_{column} ON dns_investigations ({column})")
        migrations_applied.append("dns_investigations")

    if not table_exists(cur, "dns_insights"):
        cur.execute(
            "CREATE TABLE dns_insights (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE, insight_key VARCHAR(500) NOT NULL, rule_key VARCHAR(120) NOT NULL, category VARCHAR(40) NOT NULL, severity VARCHAR(20) NOT NULL, status VARCHAR(20) DEFAULT 'active' NOT NULL, title VARCHAR(255) NOT NULL, summary VARCHAR(1000) NOT NULL, detail TEXT, entity_type VARCHAR(40), entity_identifier VARCHAR(500), current_value VARCHAR(255), comparison_value VARCHAR(255), percentage_change FLOAT, action_type VARCHAR(60), metadata_json TEXT, first_detected_at DATETIME, last_detected_at DATETIME, resolved_at DATETIME, acknowledged_at DATETIME, acknowledged_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, dismissed_at DATETIME, created_at DATETIME, updated_at DATETIME)"
        )
        cur.execute("CREATE UNIQUE INDEX uq_dns_insights_provider_key ON dns_insights (provider_id, insight_key)")
        for column in ["provider_id", "insight_key", "rule_key", "category", "severity", "status", "entity_type", "entity_identifier", "first_detected_at", "last_detected_at", "resolved_at", "acknowledged_at", "acknowledged_by_id", "dismissed_at", "created_at"]:
            cur.execute(f"CREATE INDEX ix_dns_insights_{column} ON dns_insights ({column})")
        migrations_applied.append("dns_insights")

    if not table_exists(cur, "dns_statistics_snapshots"):
        cur.execute(
            "CREATE TABLE dns_statistics_snapshots (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE, period_start DATETIME NOT NULL, period_end DATETIME NOT NULL, total_queries INTEGER, blocked_queries INTEGER, failed_queries INTEGER, cached_queries INTEGER, forwarded_queries INTEGER, active_clients INTEGER, blocking_enabled BOOLEAN, provider_connected BOOLEAN DEFAULT 1 NOT NULL, client_aggregates_json TEXT, domain_aggregates_json TEXT, response_aggregates_json TEXT, capabilities_json TEXT, analysis_summary_json TEXT, created_at DATETIME)"
        )
        cur.execute("CREATE UNIQUE INDEX uq_dns_snapshots_provider_period ON dns_statistics_snapshots (provider_id, period_start)")
        for column in ["provider_id", "period_start", "period_end", "created_at"]:
            cur.execute(f"CREATE INDEX ix_dns_statistics_snapshots_{column} ON dns_statistics_snapshots ({column})")
        migrations_applied.append("dns_statistics_snapshots")
    else:
        if not column_exists(cur, "dns_statistics_snapshots", "capabilities_json"):
            cur.execute("ALTER TABLE dns_statistics_snapshots ADD COLUMN capabilities_json TEXT")
            migrations_applied.append("dns_statistics_snapshots.capabilities_json")
        if not column_exists(cur, "dns_statistics_snapshots", "analysis_summary_json"):
            cur.execute("ALTER TABLE dns_statistics_snapshots ADD COLUMN analysis_summary_json TEXT")
            migrations_applied.append("dns_statistics_snapshots.analysis_summary_json")

    if not table_exists(cur, "dns_recognised_devices"):
        cur.execute(
            "CREATE TABLE dns_recognised_devices (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE, identity_type VARCHAR(30) NOT NULL, identity_value VARCHAR(500) NOT NULL, hostname VARCHAR(255), previous_hostname VARCHAR(255), current_ip VARCHAR(80), previous_ip VARCHAR(80), mac_address VARCHAR(120), provider_client_id VARCHAR(255), provider_type VARCHAR(40) DEFAULT 'pihole' NOT NULL, friendly_name VARCHAR(255), normalised_hostname VARCHAR(255), normalised_mac VARCHAR(17), is_known BOOLEAN DEFAULT 0 NOT NULL, is_ignored BOOLEAN DEFAULT 0 NOT NULL, last_synced_at DATETIME, linked_ip_record_id INTEGER REFERENCES ip_addresses(id) ON DELETE SET NULL, match_confidence INTEGER, match_method VARCHAR(80), observation_source VARCHAR(255), query_count INTEGER DEFAULT 0 NOT NULL, blocked_query_count INTEGER DEFAULT 0 NOT NULL, notes TEXT, hardware_asset_id INTEGER REFERENCES hardware_assets(id) ON DELETE SET NULL, first_seen_at DATETIME, last_seen_at DATETIME, is_suppressed BOOLEAN DEFAULT 0 NOT NULL, created_at DATETIME, updated_at DATETIME)"
        )
        cur.execute("CREATE UNIQUE INDEX uq_dns_devices_provider_identity ON dns_recognised_devices (provider_id, identity_type, identity_value)")
        for column in ["provider_id", "identity_type", "identity_value", "hostname", "current_ip", "mac_address", "provider_client_id", "hardware_asset_id", "first_seen_at", "last_seen_at", "is_suppressed"]:
            cur.execute(f"CREATE INDEX ix_dns_recognised_devices_{column} ON dns_recognised_devices ({column})")
        migrations_applied.append("dns_recognised_devices")
    else:
        dns_client_columns = {
            "provider_type": "VARCHAR(40) DEFAULT 'pihole' NOT NULL", "friendly_name": "VARCHAR(255)",
            "normalised_hostname": "VARCHAR(255)", "normalised_mac": "VARCHAR(17)",
            "is_known": "BOOLEAN DEFAULT 0 NOT NULL", "is_ignored": "BOOLEAN DEFAULT 0 NOT NULL",
            "last_synced_at": "DATETIME", "linked_ip_record_id": "INTEGER REFERENCES ip_addresses(id) ON DELETE SET NULL", "suggested_ip_record_id": "INTEGER REFERENCES ip_addresses(id) ON DELETE SET NULL",
            "match_confidence": "INTEGER", "match_method": "VARCHAR(80)", "observation_source": "VARCHAR(255)",
            "query_count": "INTEGER DEFAULT 0 NOT NULL", "blocked_query_count": "INTEGER DEFAULT 0 NOT NULL", "notes": "TEXT",
        }
        for column, definition in dns_client_columns.items():
            if not column_exists(cur, "dns_recognised_devices", column):
                cur.execute(f"ALTER TABLE dns_recognised_devices ADD COLUMN {column} {definition}")
                migrations_applied.append(f"dns_recognised_devices.{column}")
        cur.execute("UPDATE dns_recognised_devices SET is_known = 1, is_ignored = COALESCE(is_suppressed, 0), normalised_hostname = LOWER(RTRIM(hostname, '.')), normalised_mac = LOWER(REPLACE(mac_address, '-', ':')), last_synced_at = COALESCE(last_synced_at, last_seen_at), provider_type = COALESCE(provider_type, 'pihole')")

    if not column_exists(cur, "dns_recognised_devices", "suggested_ip_record_id"):
        cur.execute("ALTER TABLE dns_recognised_devices ADD COLUMN suggested_ip_record_id INTEGER REFERENCES ip_addresses(id) ON DELETE SET NULL")
        migrations_applied.append("dns_recognised_devices.suggested_ip_record_id")

    for table_sql, indexes in [
        ("CREATE TABLE IF NOT EXISTS dns_client_ip_history (id INTEGER NOT NULL PRIMARY KEY, dns_client_id INTEGER NOT NULL REFERENCES dns_recognised_devices(id) ON DELETE CASCADE, ip_address VARCHAR(80) NOT NULL, first_seen_at DATETIME, last_seen_at DATETIME, observation_count INTEGER DEFAULT 1 NOT NULL, provider_id INTEGER REFERENCES dns_providers(id) ON DELETE SET NULL, source VARCHAR(255), created_at DATETIME, updated_at DATETIME, UNIQUE (dns_client_id, ip_address))", ["dns_client_id", "ip_address", "last_seen_at", "provider_id"]),
        ("CREATE TABLE IF NOT EXISTS dns_client_hostname_history (id INTEGER NOT NULL PRIMARY KEY, dns_client_id INTEGER NOT NULL REFERENCES dns_recognised_devices(id) ON DELETE CASCADE, hostname VARCHAR(255) NOT NULL, normalised_hostname VARCHAR(255) NOT NULL, first_seen_at DATETIME, last_seen_at DATETIME, observation_count INTEGER DEFAULT 1 NOT NULL, provider_id INTEGER REFERENCES dns_providers(id) ON DELETE SET NULL, source VARCHAR(255), created_at DATETIME, updated_at DATETIME, UNIQUE (dns_client_id, normalised_hostname))", ["dns_client_id", "hostname", "normalised_hostname", "last_seen_at", "provider_id"]),
        ("CREATE TABLE IF NOT EXISTS dns_client_events (id INTEGER NOT NULL PRIMARY KEY, dns_client_id INTEGER NOT NULL REFERENCES dns_recognised_devices(id) ON DELETE CASCADE, event_type VARCHAR(60) NOT NULL, event_summary VARCHAR(500) NOT NULL, old_value VARCHAR(500), new_value VARCHAR(500), source VARCHAR(255), provider_id INTEGER REFERENCES dns_providers(id) ON DELETE SET NULL, created_at DATETIME)", ["dns_client_id", "event_type", "provider_id", "created_at"]),
        ("CREATE TABLE IF NOT EXISTS dns_client_traffic_events (id INTEGER NOT NULL PRIMARY KEY, dns_client_id INTEGER NOT NULL REFERENCES dns_recognised_devices(id) ON DELETE CASCADE, provider_id INTEGER NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE, dhcp_lease_id INTEGER REFERENCES dhcp_lease_history(id) ON DELETE SET NULL, event_key VARCHAR(64) NOT NULL, client_ip VARCHAR(80), domain VARCHAR(500) NOT NULL, query_type VARCHAR(40), status VARCHAR(80), reply_type VARCHAR(120), reply_time_ms FLOAT, upstream VARCHAR(255), is_blocked BOOLEAN DEFAULT 0 NOT NULL, observed_at DATETIME NOT NULL, created_at DATETIME NOT NULL, UNIQUE (provider_id, event_key))", ["dns_client_id", "provider_id", "event_key", "domain", "query_type", "status", "reply_type", "is_blocked", "observed_at", "created_at"]),
    ]:
        cur.execute(table_sql)
        table = table_sql.split("dns_client_", 1)[1].split(" ", 1)[0]
        table = f"dns_client_{table}"
        for column in indexes:
            cur.execute(f"CREATE INDEX IF NOT EXISTS ix_{table}_{column} ON {table} ({column})")
    cur.execute("INSERT OR IGNORE INTO dns_client_ip_history (dns_client_id, ip_address, first_seen_at, last_seen_at, observation_count, provider_id, source, created_at, updated_at) SELECT id, current_ip, first_seen_at, last_seen_at, 1, provider_id, 'migration', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM dns_recognised_devices WHERE current_ip IS NOT NULL AND current_ip != ''")
    cur.execute("INSERT OR IGNORE INTO dns_client_hostname_history (dns_client_id, hostname, normalised_hostname, first_seen_at, last_seen_at, observation_count, provider_id, source, created_at, updated_at) SELECT id, hostname, LOWER(RTRIM(hostname, '.')), first_seen_at, last_seen_at, 1, provider_id, 'migration', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP FROM dns_recognised_devices WHERE hostname IS NOT NULL AND hostname != ''")

    if table_exists(cur, "ip_addresses") and not column_exists(cur, "ip_addresses", "mac_address"):
        cur.execute("ALTER TABLE ip_addresses ADD COLUMN mac_address VARCHAR(17)")
        migrations_applied.append("ip_addresses.mac_address")
    if table_exists(cur, "vlans") and not column_exists(cur, "vlans", "subnet_cidr"):
        cur.execute("ALTER TABLE vlans ADD COLUMN subnet_cidr VARCHAR(80)")
        migrations_applied.append("vlans.subnet_cidr")
    if not table_exists(cur, "dhcp_ranges"):
        cur.execute("CREATE TABLE dhcp_ranges (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(120) NOT NULL UNIQUE, vlan_id INTEGER REFERENCES vlans(id) ON DELETE SET NULL, start_address VARCHAR(80) NOT NULL, end_address VARCHAR(80) NOT NULL, description TEXT, is_enabled BOOLEAN DEFAULT 1 NOT NULL, created_at DATETIME, updated_at DATETIME)")
        for column in ["name", "vlan_id", "start_address", "end_address", "is_enabled"]:
            cur.execute(f"CREATE INDEX ix_dhcp_ranges_{column} ON dhcp_ranges ({column})")
        migrations_applied.append("dhcp_ranges")
    if not table_exists(cur, "dhcp_lease_history"):
        cur.execute("CREATE TABLE dhcp_lease_history (id INTEGER NOT NULL PRIMARY KEY, provider_id INTEGER REFERENCES dns_providers(id) ON DELETE SET NULL, dns_client_id INTEGER REFERENCES dns_recognised_devices(id) ON DELETE SET NULL, dhcp_range_id INTEGER REFERENCES dhcp_ranges(id) ON DELETE SET NULL, ip_address VARCHAR(80) NOT NULL, mac_address VARCHAR(17), hostname VARCHAR(255), provider_lease_id VARCHAR(255), lease_started_at DATETIME NOT NULL, first_seen_at DATETIME NOT NULL, last_seen_at DATETIME NOT NULL, expires_at DATETIME, ended_at DATETIME, is_active BOOLEAN DEFAULT 1 NOT NULL, source VARCHAR(255), created_at DATETIME, updated_at DATETIME)")
        for column in ["provider_id", "dns_client_id", "dhcp_range_id", "ip_address", "mac_address", "hostname", "provider_lease_id", "lease_started_at", "first_seen_at", "last_seen_at", "expires_at", "ended_at", "is_active"]:
            cur.execute(f"CREATE INDEX ix_dhcp_lease_history_{column} ON dhcp_lease_history ({column})")
        migrations_applied.append("dhcp_lease_history")
    if not column_exists(cur, "dns_client_traffic_events", "client_ip"):
        cur.execute("ALTER TABLE dns_client_traffic_events ADD COLUMN client_ip VARCHAR(80)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_dns_client_traffic_events_client_ip ON dns_client_traffic_events (client_ip)")
        migrations_applied.append("dns_client_traffic_events.client_ip")
    if not column_exists(cur, "dns_client_traffic_events", "dhcp_lease_id"):
        cur.execute("ALTER TABLE dns_client_traffic_events ADD COLUMN dhcp_lease_id INTEGER REFERENCES dhcp_lease_history(id) ON DELETE SET NULL")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_dns_client_traffic_events_dhcp_lease_id ON dns_client_traffic_events (dhcp_lease_id)")
        migrations_applied.append("dns_client_traffic_events.dhcp_lease_id")

    runbook_image_columns = {row[1] for row in cur.execute("PRAGMA table_info(runbook_images)").fetchall()} if table_exists(cur, "runbook_images") else set()
    if not runbook_image_columns:
        cur.execute(
            "CREATE TABLE runbook_images (id INTEGER NOT NULL PRIMARY KEY, original_filename VARCHAR(255), content_type VARCHAR(120) NOT NULL, size_bytes INTEGER DEFAULT 0 NOT NULL, data BLOB, uploaded_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME)"
        )
        for column in ["uploaded_by_id", "created_at"]:
            cur.execute(f"CREATE INDEX ix_runbook_images_{column} ON runbook_images ({column})")
        migrations_applied.append("runbook_images")
    elif "stored_filename" in runbook_image_columns:
        cur.execute("ALTER TABLE runbook_images RENAME TO runbook_images_legacy")
        cur.execute(
            "CREATE TABLE runbook_images (id INTEGER NOT NULL PRIMARY KEY, original_filename VARCHAR(255), content_type VARCHAR(120) NOT NULL, size_bytes INTEGER DEFAULT 0 NOT NULL, data BLOB, uploaded_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at DATETIME)"
        )
        cur.execute(
            "INSERT INTO runbook_images (id, original_filename, content_type, size_bytes, uploaded_by_id, created_at) SELECT id, original_filename, content_type, size_bytes, uploaded_by_id, created_at FROM runbook_images_legacy"
        )
        cur.execute("DROP TABLE runbook_images_legacy")
        for column in ["uploaded_by_id", "created_at"]:
            cur.execute(f"CREATE INDEX ix_runbook_images_{column} ON runbook_images ({column})")
        migrations_applied.append("runbook_images.blob_storage")
    elif "data" not in runbook_image_columns:
        cur.execute("ALTER TABLE runbook_images ADD COLUMN data BLOB")
        migrations_applied.append("runbook_images.data")

    conn.commit()
    cur.execute("PRAGMA foreign_keys = ON")
    conn.close()

    if migrations_applied:
        print("Applied migrations:")
        for migration in migrations_applied:
            print(f" - {migration}")
    else:
        print("Database schema already up to date.")


if __name__ == "__main__":
    try:
        main()
    except sqlite3.OperationalError as exc:
        if "database or disk is full" in str(exc).lower():
            print(
                "Database migration failed because SQLite reported that the database or disk is full.",
                file=sys.stderr,
            )
            print(
                "Free space on the host path mounted to /app/data, then start Kaya again.",
                file=sys.stderr,
            )
        raise
