"""Alembic environment configuration for VulnOS.

Reads DATABASE_URL from application settings and imports all models through
the Base metadata so Alembic autogenerate can detect drift.
"""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

# Import all models so they register with Base.metadata
import backend.app.db.models  # noqa: F401
from alembic import context
from backend.app.core.config import get_settings
from backend.app.db.base import Base

# Alembic Config object (provides alembic.ini values)
config = context.config

# Setup Python logging from the config file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set target metadata for autogenerate support
target_metadata = Base.metadata


def _get_url() -> str:
    """Resolve the database URL from application settings.

    Converts psycopg URL format for SQLAlchemy compatibility.
    """
    settings = get_settings()
    url = settings.DATABASE_URL
    # Alembic needs the sync driver; ensure postgresql+psycopg is used
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures the context with just a URL and not an Engine. Calls to
    context.execute() emit the given string to the script output.
    """
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Creates an Engine and associates a connection with the context.
    """
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
