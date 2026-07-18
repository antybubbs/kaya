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
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('ha_clusters', 'ha_nodes', 'ha_health_checks')"
        )
    }
    connection.close()
    assert columns["password_hash"][3] == 0
    assert "encrypted_oidc_id_token" in session_columns
    assert row == ("admin@example.com", "existing-hash", "local", "local", 0)
    assert session_user == 1
    assert foreign_key_errors == []
    assert ha_tables == {"ha_clusters", "ha_nodes", "ha_health_checks"}
