"""Alembic environment.

Wired against the application's declarative ``Base`` (``app.db.Base``) so that
autogenerate sees every ORM model. The database URL is resolved from the
application's centralized settings (``app.config.get_settings``), which honor the
``DATABASE_URL`` environment variable, rather than the static value in
``alembic.ini`` — there are no secrets in source (task 1.2/1.3).

Model modules (task 2.2) are pulled in via the ``app.models`` aggregator import
below, which registers every ORM table on ``Base.metadata`` so autogenerate and
offline runs see the full schema.
"""

from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# The application's declarative Base and centralized settings (task 1.2).
from app.config import get_settings
from app.db import Base

# Importing the model aggregator registers every ORM table on Base.metadata so
# autogenerate sees them (task 2.2).
import app.models  # noqa: F401

# Alembic Config object providing access to values in the .ini file.
config = context.config

# Resolve the connection URL from centralized settings (which honor DATABASE_URL
# via pydantic-settings) so we never hardcode credentials in alembic.ini.
config.set_main_option("sqlalchemy.url", get_settings().database_url)

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for 'autogenerate' support. Model modules (task 2.x) inherit
# from this same Base, so importing them registers their tables here.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (URL only, no DBAPI required)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode with a live connection."""
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
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
