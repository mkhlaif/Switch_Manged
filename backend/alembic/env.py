"""Alembic environment (async). The URL is taken from DATABASE_URL via app settings."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection

from app.core.config import get_settings
from app.db.base import Base
from app.db.session import _make_engine
import app.models  # noqa: F401  (register models)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    return config.attributes.get("database_url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True,
                      render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata,
                      render_as_batch=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def _check_sqlite_integrity(connection: Connection) -> None:
    violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(f"Foreign key violations after migration: {violations[:20]}")


async def run_migrations_online() -> None:
    url = _url()
    # SQLite: enforcement off while tables are rebuilt (see _make_engine), verified afterwards.
    engine = _make_engine(url, sqlite_foreign_keys=not url.startswith("sqlite"))
    async with engine.connect() as connection:
        await connection.run_sync(_run)
        if url.startswith("sqlite"):
            await connection.run_sync(_check_sqlite_integrity)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
