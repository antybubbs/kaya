from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.models.models import Base

config = context.config
if config.config_file_name is not None:
    # Migration setup must not disable Kaya's security/audit loggers when
    # Alembic runs inside the application process.
    fileConfig(config.config_file_name, disable_existing_loggers=False)
target_metadata = Base.metadata


def _reject_unsafe_sqlite_downgrade() -> None:
    migration_context = context.get_context()
    environment_context = migration_context.environment_context
    command = environment_context.context_opts.get("fn") if environment_context else None
    destination = environment_context.context_opts.get("destination_rev") if environment_context else None
    if (
        migration_context.dialect.name == "sqlite"
        and getattr(command, "__name__", None) == "downgrade"
        and destination
        and destination < "20260810_02"
    ):
        raise RuntimeError(
            "Migration downgrade is blocked for SQLite databases before 20260810_02."
        )


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        _reject_unsafe_sqlite_downgrade()
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
