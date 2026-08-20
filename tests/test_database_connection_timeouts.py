from app.core.config import Settings, postgres_engine_options


def test_postgresql_engine_options_bound_connection_and_pool_waits():
    options = postgres_engine_options(
        Settings(
            app_env="test",
            database_connect_timeout_seconds=7,
            database_pool_timeout_seconds=11,
            encryption_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
    )
    assert options["connect_args"] == {"connect_timeout": 7}
    assert options["pool_timeout"] == 11
    assert options["pool_pre_ping"] is True
