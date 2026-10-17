"""NetMind AI - Network Status & Telemetry Overview API Router."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from netmind.src.backend import models
from netmind.src.backend.database import get_db
from netmind.src.backend.decision_engine import DecisionEngine
from netmind.src.backend.schemas import NetworkStatusSummary, RiskCategory

router = APIRouter(prefix="/api/network", tags=["Network Status"])


@router.get("/status", response_model=NetworkStatusSummary)
def get_network_status(db: Session = Depends(get_db)) -> NetworkStatusSummary:
    """Retrieve macro-level network health, telemetry throughput, and threat summary."""
    # 1. Host metrics
    total_hosts = db.scalar(select(func.count(models.Host.id))) or 0
    active_hosts = db.scalar(select(func.count(models.Host.id)).where(models.Host.status == "active")) or 0
    quarantined_hosts = db.scalar(select(func.count(models.Host.id)).where(models.Host.status == "quarantined")) or 0

    # 2. Average Risk calculation
    avg_risk = db.scalar(select(func.avg(models.Host.risk_score))) or 0.0
    avg_risk = round(float(avg_risk), 2)
    risk_cat = DecisionEngine.categorize_score(avg_risk)

    # 3. Active threats and anomalies
    active_threats = db.scalar(
        select(func.count(models.SecurityEvent.id)).where(
            models.SecurityEvent.severity.in_(["HIGH", "CRITICAL"])
        )
    ) or 0

    unresolved_anomalies = db.scalar(
        select(func.count(models.Anomaly.id)).where(models.Anomaly.status == "open")
    ) or 0

    pending_recs = db.scalar(
        select(func.count(models.Recommendation.id)).where(models.Recommendation.status == "pending")
    ) or 0

    # 4. Live Bandwidth / Packet Rates from hardware NIC or ML predictions
    from netmind.src.ingestion.nic_sniffer import LiveNICCapture
    nic = LiveNICCapture.get_instance()
    nic_pps = nic.current_inbound_pps + nic.current_outbound_pps
    nic_bps = (nic.current_inbound_mbps + nic.current_outbound_mbps) * 1_000_000.0 / 8.0

    if nic_pps > 0 or nic_bps > 0:
        current_bps = float(nic_bps)
        current_pps = float(nic_pps)
    else:
        latest_bytes_pred = db.scalar(
            select(models.Prediction.prediction)
            .where(models.Prediction.target == "bytes_per_second")
            .order_by(models.Prediction.timestamp.desc())
            .limit(1)
        )
        latest_pkts_pred = db.scalar(
            select(models.Prediction.prediction)
            .where(models.Prediction.target == "packets_per_second")
            .order_by(models.Prediction.timestamp.desc())
            .limit(1)
        )
        current_bps = float(latest_bytes_pred or 1450000.0)
        current_pps = float(latest_pkts_pred or 2400.0)

    # 5. System Status determination
    if active_threats > 5 or risk_cat == RiskCategory.CRITICAL:
        system_status = "UNDER_ATTACK"
    elif unresolved_anomalies > 10 or risk_cat == RiskCategory.HIGH:
        system_status = "DEGRADED"
    else:
        system_status = "HEALTHY"

    return NetworkStatusSummary(
        system_status=system_status,
        active_risk_level=risk_cat,
        average_risk_score=avg_risk,
        total_hosts=total_hosts,
        active_hosts=active_hosts,
        quarantined_hosts=quarantined_hosts,
        active_threats_count=active_threats,
        unresolved_anomalies_count=unresolved_anomalies,
        pending_recommendations_count=pending_recs,
        current_bandwidth_bps=current_bps,
        current_packet_rate_pps=current_pps,
        last_updated=datetime.now(timezone.utc),
    )
