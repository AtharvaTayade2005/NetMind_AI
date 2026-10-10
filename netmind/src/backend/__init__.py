"""NetMind AI - Backend Layer (Phase 3).

Modules:
- database: SQLAlchemy connection engine and session factory.
- models: Typed SQLAlchemy 2.0 ORM models with composite indexes.
- schemas: Pydantic v2 request and response contracts.
- repository: Data access repository pattern.
- decision_engine: Composite risk scoring and automated recommendation logic.
- main: FastAPI application entrypoint.
"""

from netmind.src.backend import models, schemas
from netmind.src.backend.database import Base, SessionLocal, get_db, init_db
from netmind.src.backend.decision_engine import DecisionEngine
from netmind.src.backend.main import app

__all__ = [
    "app",
    "Base",
    "SessionLocal",
    "get_db",
    "init_db",
    "models",
    "schemas",
    "DecisionEngine",
]
