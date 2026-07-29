import sqlite3

import scripts.migrate_sqlite as migration


def test_existing_user_migration_preserves_local_account_and_makes_password_nullable(tmp_path, monkeypatch):
    path = tmp_path / "kaya.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE users (id INTEGER NOT NULL PRIMARY KEY, email VARCHAR(255) NOT NULL UNIQUE, password_hash VARCHAR(255) NOT NULL, first_name VARCHAR(120), last_name VARCHAR(120), role VARCHAR(30), is_active BOOLEAN, totp_secret TEXT, totp_enabled BOOLEAN, created_at DATETIME)"
    )
    connection.execute(
        "INSERT INTO users (email, password_hash, role, is_active, totp_enabled) VALUES ('admin@example.com', 'existing-hash', 'admin', 1, 0)"
    )
    connection.execute("CREATE TABLE app_sessions (id INTEGER NOT NULL PRIMARY KEY, session_id VARCHAR(120), user_id INTEGER NOT NULL REFERENCES users(id))")
    connection.execute("INSERT INTO app_sessions (session_id, user_id) VALUES ('existing-session', 1)")
    connection.execute(
        "CREATE TABLE network_monitors (id INTEGER NOT NULL PRIMARY KEY, ip_address_id INTEGER NOT NULL, "
        "is_enabled BOOLEAN DEFAULT 1 NOT NULL, interval_seconds INTEGER DEFAULT 300 NOT NULL, "
        "timeout_ms INTEGER DEFAULT 2000 NOT NULL, last_status VARCHAR(30), last_latency_ms INTEGER)"
    )
    connection.execute(
        "INSERT INTO network_monitors (id, ip_address_id, last_status, last_latency_ms) "
        "VALUES (7, 70, 'up', 12)"
    )
    connection.execute(
        "CREATE TABLE network_monitor_checks (id INTEGER NOT NULL PRIMARY KEY, monitor_id INTEGER NOT NULL, "
        "status VARCHAR(30) NOT NULL, latency_ms INTEGER, error VARCHAR(500), checked_at DATETIME)"
    )
    connection.execute(
        "INSERT INTO network_monitor_checks (id, monitor_id, status, latency_ms, checked_at) "
        "VALUES (9, 7, 'up', 12, '2026-07-01 12:00:00')"
    )
    connection.commit(); connection.close()
    monkeypatch.setattr(migration, "DB_PATH", path)

    migration.main()

    connection = sqlite3.connect(path)
    columns = {row[1]: row for row in connection.execute("PRAGMA table_info(users)")}
    session_columns = {row[1]: row for row in connection.execute("PRAGMA table_info(app_sessions)")}
    row = connection.execute("SELECT email, password_hash, authentication_type, role_source, is_break_glass FROM users").fetchone()
    session_user = connection.execute("SELECT user_id FROM app_sessions WHERE session_id = 'existing-session'").fetchone()[0]
    foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
    ha_tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('ha_provider_connections', 'ha_clusters', 'ha_nodes', 'ha_health_checks', 'ha_agent_credentials', 'ha_agent_requests', 'ha_events', 'ha_agent_action_results', 'ha_sync_runs', 'ha_backups', 'ha_drift_items')"
        )
    }
    ha_node_columns = {row[1] for row in connection.execute("PRAGMA table_info(ha_nodes)")}
    ha_cluster_columns = {row[1] for row in connection.execute("PRAGMA table_info(ha_clusters)")}
    ha_check_columns = {row[1] for row in connection.execute("PRAGMA table_info(ha_health_checks)")}
    dns_provider_columns = {row[1] for row in connection.execute("PRAGMA table_info(dns_providers)")}
    monitor_columns = {row[1] for row in connection.execute("PRAGMA table_info(network_monitors)")}
    check_columns = {row[1] for row in connection.execute("PRAGMA table_info(network_monitor_checks)")}
    retained_check = connection.execute(
        "SELECT monitor_id, status, latency_ms, checked_at FROM network_monitor_checks WHERE id = 9"
    ).fetchone()
    migrated_monitor = connection.execute(
        "SELECT last_status, latency_warning_ms, latency_critical_ms, packet_loss_warning_percent, "
        "packet_loss_critical_percent, recovery_threshold FROM network_monitors WHERE id = 7"
    ).fetchone()
    monitor_history_tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN "
            "('network_monitor_events', 'network_monitor_outages', 'network_monitor_statistics')"
        )
    }
    connection.close()
    assert columns["password_hash"][3] == 0
    assert "encrypted_oidc_id_token" in session_columns
    assert row == ("admin@example.com", "existing-hash", "local", "local", 0)
    assert session_user == 1
    assert foreign_key_errors == []
    assert ha_tables == {"ha_provider_connections", "ha_clusters", "ha_nodes", "ha_health_checks", "ha_agent_credentials", "ha_agent_requests", "ha_events", "ha_agent_action_results", "ha_sync_runs", "ha_backups", "ha_drift_items"}
    assert "ha_cluster_id" in dns_provider_columns
    assert "ha_connection_id" in ha_node_columns
    assert {"capabilities_json", "configuration_snapshot_json", "configuration_checksum"} <= ha_node_columns
    assert {"observed_role", "observed_generation", "vip_owned", "dhcp_running", "dns_healthy", "peer_reachable", "peer_icmp_probe_status", "peer_dns_reachable", "lease_generation", "config_generation"} <= ha_node_columns
    assert {"last_peer_attempt_at", "last_peer_success_at", "last_peer_dns_attempt_at", "last_peer_dns_success_at", "recovery_state", "recovery_started_at", "recovery_stable_since"} <= ha_node_columns
    assert {"keepalived_status", "keepalived_config_checksum", "keepalived_backup_reference", "keepalived_last_error", "keepalived_reported_at", "keepalived_runtime_state"} <= ha_node_columns
    assert {"vrrp_router_id", "keepalived_generation", "keepalived_status", "keepalived_requested_at", "keepalived_deployed_at"} <= ha_cluster_columns
    assert "preferred_node_id" in ha_cluster_columns
    assert "remediation" in ha_check_columns
    assert {"use_default_thresholds", "state_reason", "is_in_maintenance"} <= monitor_columns
    assert {"packet_loss_percent", "response_time_ms", "health_state"} <= check_columns
    assert retained_check == (7, "up", 12, "2026-07-01 12:00:00")
    assert migrated_monitor == (None, 100, 250, 5, 25, 3)
    assert monitor_history_tables == {
        "network_monitor_events", "network_monitor_outages", "network_monitor_statistics",
    }
