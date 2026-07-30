from pathlib import Path


def test_entrypoint_prepares_database_before_admin_lookup():
    entrypoint = Path("docker-entrypoint.sh").read_text(encoding="utf-8")

    preparation = entrypoint.index('echo "Preparing Kaya database..."')
    admin_lookup = entrypoint.index("db.query(User.id)")

    assert "python -m app.db.cli" in entrypoint
    assert "Base.metadata.create_all" not in entrypoint
    assert "cp /app/data/kaya.db" not in entrypoint
    assert ">/dev/null" not in entrypoint
    assert "2>/dev/null" not in entrypoint
    assert "exec python" not in entrypoint
    assert "rm -f /app/data/kaya.db-wal /app/data/kaya.db-shm" not in entrypoint
    assert preparation < admin_lookup
