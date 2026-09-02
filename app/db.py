"""SQLAlchemy engine and session management.

PostgreSQL is the authoritative store for the Foundation slice
(08-technology-stack.md §4). This module owns the engine, the session factory,
and the declarative ``Base`` that all ORM models inherit from.

Configuration wiring is completed in task 1.2: the connection URL is now sourced
from :class:`~app.config.Settings` rather than read ad hoc from the environment.
``Settings`` still provides a safe local default so the module imports cleanly.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    """Declarative base shared by all Foundation ORM models."""


# The engine is created at import; pool_pre_ping guards against stale connections
# in managed-Postgres environments. The URL comes from centralized settings.
engine = create_engine(get_settings().database_url, pool_pre_ping=True, future=True)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session() -> Iterator[Session]:
    """Yield a scoped SQLAlchemy session (FastAPI dependency).

    Commits are the responsibility of the service layer; this dependency only
    guarantees the session is closed after the request.
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


__all__ = ["Base", "engine", "SessionLocal", "get_session"]
