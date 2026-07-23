from pathlib import Path


def test_entrypoint_initialises_fresh_schema_before_migrations_and_admin_lookup():
    entrypoint = Path("docker-entrypoint.sh").read_text(encoding="utf-8")

    schema_bootstrap = entrypoint.index('echo "Initialising new Kaya database schema..."')
    migrations = entrypoint.index('echo "Running database migrations..."')
    admin_lookup = entrypoint.index("db.query(User.id)")

    assert '[ ! -s /app/data/kaya.db ]' in entrypoint
    assert '${KAYA_GATEWAY_MODE:-false}' in entrypoint
    assert "Base.metadata.create_all(bind=engine)" in entrypoint
    assert schema_bootstrap < migrations < admin_lookup
