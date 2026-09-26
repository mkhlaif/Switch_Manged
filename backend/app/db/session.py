from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _make_engine(url: str, *, sqlite_foreign_keys: bool = True) -> AsyncEngine:
    """``sqlite_foreign_keys=False`` is only for migrations: SQLite batch migrations rebuild a
    table by dropping it, and with enforcement on that DROP fires ON DELETE actions (SET NULL /
    CASCADE) on every referencing row. Migrations check integrity afterwards instead."""
    s = get_settings()
    kwargs: dict = {
        "pool_pre_ping": True,
        "pool_size": s.db_pool_size,
        "max_overflow": s.db_max_overflow,
        "pool_timeout": s.db_pool_timeout,
        "pool_recycle": 1800,
    }
    if url.startswith("postgresql"):
        kwargs["connect_args"] = {
            "timeout": s.db_connect_timeout,          # TCP connect + authentication
            "command_timeout": s.db_statement_timeout,  # client-side limit per statement
            "server_settings": {
                # A session that stays "idle in transaction" (e.g. a crashed request) is closed
                # by the server so it cannot hold row locks indefinitely.
                "idle_in_transaction_session_timeout": str(s.db_idle_in_transaction_ms),
                "statement_timeout": str(s.db_statement_timeout * 1000),
                "application_name": "netops-backend",
            },
        }
    if url.startswith("sqlite"):
        db_path = url.split("///", 1)[-1]
        if db_path and db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        kwargs = {"connect_args": {"timeout": 30}}
    engine = create_async_engine(url, **kwargs)
    if url.startswith("sqlite"):
        foreign_keys = "ON" if sqlite_foreign_keys else "OFF"

        @event.listens_for(engine.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - trivial
            cursor = dbapi_connection.cursor()
            cursor.execute(f"PRAGMA foreign_keys={foreign_keys}")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    return engine


def init_engine(url: str | None = None) -> AsyncEngine:
    global _engine, _sessionmaker
    _engine = _make_engine(url or get_settings().database_url)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        init_engine()
    assert _engine is not None
    return _engine


def session_factory() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        init_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


async def get_db() -> AsyncIterator[AsyncSession]:
    async with session_factory()() as session:
        yield session
