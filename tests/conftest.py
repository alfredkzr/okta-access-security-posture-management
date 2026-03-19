"""Shared test fixtures and SQLite compatibility helpers."""

from __future__ import annotations

import os
import uuid

# Set required env vars before any src imports trigger Settings() validation
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-use")
os.environ.setdefault("ENCRYPTION_KEY", "dGVzdC1lbmNyeXB0aW9uLWtleS0xMjM0NTY3ODk=")  # noqa: E501

# Generate a valid Fernet key for tests if the default isn't valid
from cryptography.fernet import Fernet as _Fernet
try:
    _Fernet(os.environ["ENCRYPTION_KEY"].encode())
except Exception:
    os.environ["ENCRYPTION_KEY"] = _Fernet.generate_key().decode()

import pytest
import pytest_asyncio
from sqlalchemy import JSON, event
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.models.base import Base
from src.models.scan import Scan, ScanStatus


def _deduplicate_indexes(metadata):
    """Remove duplicate indexes from metadata tables for SQLite compatibility.

    When a column has index=True AND an explicit Index with the same target
    columns, SQLite will fail with 'index already exists'. This removes the
    auto-generated index (keeping the explicit one).
    """
    for table in metadata.sorted_tables:
        seen_columns = {}
        to_remove = []
        for idx in table.indexes:
            col_key = frozenset(c.name for c in idx.columns)
            if col_key in seen_columns:
                # Remove the auto-generated one (shorter name or no explicit name)
                to_remove.append(idx)
            else:
                seen_columns[col_key] = idx

        for idx in to_remove:
            table.indexes.discard(idx)


def _render_jsonb_as_json(ddl_compiler, type_, **kw):
    """Render PostgreSQL JSONB columns as JSON for SQLite compatibility."""
    return "JSON"


def _render_uuid_as_char(ddl_compiler, type_, **kw):
    """Render PostgreSQL UUID columns as CHAR(32) for SQLite compatibility."""
    return "CHAR(32)"


@pytest_asyncio.fixture
async def engine():
    """Create an in-memory SQLite async engine with PostgreSQL type adaptations."""
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")

    # Register type adaptations before creating tables
    from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler

    if not hasattr(SQLiteTypeCompiler, "visit_JSONB"):
        SQLiteTypeCompiler.visit_JSONB = _render_jsonb_as_json
    if not hasattr(SQLiteTypeCompiler, "_visit_UUID"):
        # UUID is already handled by SQLAlchemy for SQLite, but just in case
        pass

    # Remove duplicate indexes that conflict on SQLite.
    # Some models have both index=True on a column AND an explicit Index
    # with the same name in __table_args__. SQLAlchemy auto-generates an
    # index name like "ix_<table>_<col>" for index=True, which can clash
    # with explicitly named indexes.
    _deduplicate_indexes(Base.metadata)

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db_session(engine):
    """Provide an async session for tests."""
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
