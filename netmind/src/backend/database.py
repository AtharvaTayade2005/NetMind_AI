"""NetMind AI - Database Engine and Session Lifecycle Management.

Architectural Rationale:
------------------------
1. Connection Lifecycle & Engine Factory:
   Supports PostgreSQL in production environments (via DATABASE_URL) while gracefully
   providing SQLite local fallback for development, testing, and isolated CI runs.
2. SQLAlchemy 2.0 Standard:
   Implements modern 2.0 declarative base (`DeclarativeBase`) and scoped session makers.
   Session lifecycle is injected via FastAPI `Depends(get_db)` yielding transactions with
   guaranteed teardown and rollback on unhandled exceptions.
3. Connection Pool Management:
   Enables `pool_pre_ping=True` for resilient connection health validation across firewall
   timeouts and database service restarts.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)

# Determine database URL from environment or fallback to SQLite
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "netmind.db"
DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

RAW_DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}")

# Normalize postgres:// -> postgresql:// for SQLAlchemy 2.0 compatibility
if RAW_DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = RAW_DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    DATABASE_URL = RAW_DATABASE_URL

# Engine configuration depending on dialect
connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,
}

if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
else:
    # PostgreSQL production pool configuration
    engine_kwargs.update({
        "pool_size": int(os.getenv("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "20")),
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "1800")),
    })

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    **engine_kwargs,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=Session,
)


class Base(DeclarativeBase):
    """Base declarative class for all NetMind AI SQLAlchemy models."""
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding database sessions with managed lifecycles.

    Yields:
        Session: Active SQLAlchemy session.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Initialize database tables defined in models."""
    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized successfully.")


def close_db() -> None:
    """Dispose connection engine during application shutdown."""
    logger.info("Disposing database connection pool...")
    engine.dispose()
    logger.info("Database connection pool closed.")
