"""Alembic environment.

Two deliberate departures from the generated template:

1. **Migrations run on a hardened engine.** The stock template calls
   `engine_from_config` and builds its own connection, which would bypass the
   `connect` listener in `rlapi.db` -- so a data migration would execute with
   foreign key enforcement OFF, exactly the condition step 1 exists to prevent.
   Using `create_db_engine` means migrations are held to the same integrity
   rules as the application.
2. **The database URL comes from the environment**, not from `alembic.ini`.
   Harmless for a local SQLite file, but the habit matters: by step 18 this
   would be a real connection string, and committing one is how credentials
   reach a repository.

`render_as_batch=True` is required for SQLite, which cannot `ALTER COLUMN`.
Alembic emulates it by rebuilding the table. Worth knowing that the rebuild
drops and recreates constraints, so a batch migration is a moment where a
CHECK or FK can silently go missing -- verify the resulting schema, do not
assume it.
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection

from rlapi.db import create_db_engine
from rlapi.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

DEFAULT_DATABASE_URL = "sqlite:///rlapi.db"
DATABASE_URL_ENV_VAR = "RLAPI_DATABASE_URL"


def database_url() -> str:
    """Resolve the target database, environment first."""
    from_env = os.environ.get(DATABASE_URL_ENV_VAR)
    if from_env:
        return from_env
    return config.get_main_option("sqlalchemy.url") or DEFAULT_DATABASE_URL


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting."""
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # SQLite cannot ALTER COLUMN; Alembic rebuilds the table instead.
        render_as_batch=True,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and run migrations, on a hardened engine."""
    engine = create_db_engine(database_url())
    try:
        with engine.connect() as connection:
            _run(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
