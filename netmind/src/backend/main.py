"""NetMind AI - FastAPI Application Entrypoint.

Architectural Rationale:
------------------------
1. Lifespan Connection & Cache Management:
   Uses the modern FastAPI `lifespan` context manager to initialize database schemas (`init_db()`),
   seed initial operational telemetry if the database is unpopulated, and warm up Phase 2 ML
   artifacts (Isolation Forest, XGBoost, TreeSHAP).
2. Clean Modular Routers:
   Separates operational status, threat analysis, predictions, mitigation recommendations, and
   ML scoring into independent, decoupled routers.
3. CORS & API Versioning:
   Configures CORS middleware allowing seamless integration with modern web frontends.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from netmind.src.backend import models
from netmind.src.backend.database import SessionLocal, close_db, init_db
from netmind.src.backend.routers import (
    inference,
    predictions,
    recommendations,
    status,
    threats,
)
from netmind.src.backend.routers.inference import ModelManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("netmind.api")


def seed_demo_telemetry_if_empty(db: Session) -> None:
    """Populate database with initial baseline telemetry if tables are empty."""
    host_count = db.scalar(select(func.count(models.Host.id))) or 0
    if host_count > 0:
        return

    logger.info("Seeding initial operational telemetry and security baseline...")
    now = datetime.now(timezone.utc)

    # 1. Seed Hosts
    h1 = models.Host(ip_address="192.168.1.105", hostname="workstation-alpha", risk_score=15.0, status="active", first_seen=now - timedelta(days=5), last_seen=now)
    h2 = models.Host(ip_address="192.168.1.110", hostname="finance-server", risk_score=42.0, status="active", first_seen=now - timedelta(days=10), last_seen=now)
    h3 = models.Host(ip_address="192.168.1.200", hostname="suspect-scanner", risk_score=88.5, status="quarantined", first_seen=now - timedelta(days=1), last_seen=now)
    h4 = models.Host(ip_address="10.0.0.50", hostname="gateway-proxy", risk_score=8.0, status="active", first_seen=now - timedelta(days=30), last_seen=now)
    db.add_all([h1, h2, h3, h4])
    db.commit()

    # 2. Seed Network Flows
    f1 = models.NetworkFlow(src_ip="192.168.1.105", dst_ip="10.0.0.50", src_port=54321, dst_port=80, protocol="tcp", duration=0.85, packets=25, bytes=5500, timestamp=now - timedelta(minutes=15))
    f2 = models.NetworkFlow(src_ip="192.168.1.200", dst_ip="10.0.0.50", src_port=41234, dst_port=22, protocol="tcp", duration=0.001, packets=1, bytes=60, timestamp=now - timedelta(minutes=5))
    db.add_all([f1, f2])
    db.commit()

    # 3. Seed Security Event & Recommendation
    evt1 = models.SecurityEvent(
        source_ip="192.168.1.200",
        destination_ip="10.0.0.50",
        event_type="Port Scan",
        severity="HIGH",
        confidence=0.999,
        description="Reconnaissance SYN sweep targeting internal server port range.",
        timestamp=now - timedelta(minutes=5),
    )
    evt2 = models.SecurityEvent(
        source_ip="192.168.1.110",
        destination_ip="10.0.0.60",
        event_type="Web Attack",
        severity="CRITICAL",
        confidence=0.985,
        description="SQL Injection payload detected in HTTP URI parameter.",
        timestamp=now - timedelta(minutes=2),
    )
    db.add_all([evt1, evt2])
    db.commit()

    rec1 = models.Recommendation(
        event_id=evt1.id,
        action="BLOCK_SOURCE_IP",
        reason="Reconnaissance sweep detected from host 192.168.1.200 (Risk: 88.5). Apply perimeter drop rule.",
        status="pending",
    )
    rec2 = models.Recommendation(
        event_id=evt2.id,
        action="WAF_BLOCK_URI_PATTERN",
        reason="Critical Web Attack observed against production gateway. Deploy virtual WAF patch.",
        status="approved",
        reviewed_by="analyst_lead",
        reviewed_at=now - timedelta(minutes=1),
    )
    db.add_all([rec1, rec2])

    # 4. Seed Anomaly
    anom1 = models.Anomaly(
        flow_id=f2.id,
        anomaly_score=0.842,
        model_version="iso_forest_v1",
        status="open",
        timestamp=now - timedelta(minutes=5),
    )
    db.add(anom1)

    # 5. Seed Time-Series Predictions
    pred1 = models.Prediction(
        model_name="traffic_predictor",
        target="bytes_per_second",
        prediction=1850000.0,
        confidence=0.92,
        model_version="xgb_reg_v1",
        timestamp=now,
    )
    pred2 = models.Prediction(
        model_name="traffic_predictor",
        target="packets_per_second",
        prediction=3200.0,
        confidence=0.91,
        model_version="xgb_reg_v1",
        timestamp=now,
    )
    db.add_all([pred1, pred2])
    db.commit()
    logger.info("Initial operational telemetry seeded successfully.")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle management."""
    logger.info("Starting NetMind AI Backend Service...")
    init_db()

    # Seed initial demonstration telemetry
    db = SessionLocal()
    try:
        seed_demo_telemetry_if_empty(db)
    finally:
        db.close()

    # Pre-warm ML model manager
    ModelManager.get_instance()

    yield

    logger.info("Shutting down NetMind AI Backend Service...")
    close_db()


# Initialize FastAPI application
app = FastAPI(
    title="NetMind AI - Network Monitoring & Decision Support System",
    description=(
        "Production REST API for real-time network telemetry scoring, intrusion detection, "
        "time-series traffic forecasting, and explainable AI (TreeSHAP)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Enable Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(status.router)
app.include_router(threats.router)
app.include_router(predictions.router)
app.include_router(recommendations.router)
app.include_router(inference.router)


@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Service health verification endpoint."""
    return {
        "status": "online",
        "service": "NetMind AI API",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
