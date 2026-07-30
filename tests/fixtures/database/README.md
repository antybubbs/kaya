# Historical migration fixtures

The v0.18.x, v0.20.x, v0.22.x, v0.24.x, and v0.25.x cases in `test_database_migrations.py` are reconstructed fixtures, not user databases or byte-for-byte release snapshots. They use the earliest retained user/authentication shape plus the repository's historical additive migration DDL, then verify the static Alembic baseline supplies objects that historical `create_all()` previously supplied.

Fixtures contain synthetic `.invalid` email addresses and obviously fake hashes only. Genuine user databases must never be committed as test data.
