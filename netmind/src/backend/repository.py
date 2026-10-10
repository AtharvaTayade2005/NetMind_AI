"""NetMind AI - Repository Pattern Data Access Layer.

Architectural Rationale:
------------------------
The Repository Pattern decouples persistence logic from business and API routing logic.
All database queries (filtering, sorting, pagination, and atomic aggregations) are isolated
inside dedicated repository classes, providing:
1. Testability: Handlers can be tested with mock or in-memory session providers.
2. Maintainability: Centralized query optimization, caching hooks, and schema updates.
3. DRY Principals: Common queries (e.g. host risk recalculation, pending recommendations)
   are defined in a single location.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from netmind.src.backend import models


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HostRepository:
    """Data access repository for Host entities."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, host_id: int) -> Optional[models.Host]:
        return self.db.get(models.Host, host_id)

    def get_by_ip(self, ip_address: str) -> Optional[models.Host]:
        stmt = select(models.Host).where(models.Host.ip_address == ip_address)
        return self.db.scalars(stmt).first()

    def get_or_create(self, ip_address: str, hostname: Optional[str] = None) -> models.Host:
        host = self.get_by_ip(ip_address)
        if not host:
            host = models.Host(
                ip_address=ip_address,
                hostname=hostname,
                first_seen=utc_now(),
                last_seen=utc_now(),
                risk_score=0.0,
                status="active",
            )
            self.db.add(host)
            self.db.commit()
            self.db.refresh(host)
        else:
            host.last_seen = utc_now()
            if hostname and not host.hostname:
                host.hostname = hostname
            self.db.commit()
        return host

    def list_hosts(self, skip: int = 0, limit: int = 50, status: Optional[str] = None) -> Tuple[List[models.Host], int]:
        stmt = select(models.Host)
        count_stmt = select(func.count(models.Host.id))
        if status:
            stmt = stmt.where(models.Host.status == status)
            count_stmt = count_stmt.where(models.Host.status == status)
        stmt = stmt.order_by(desc(models.Host.risk_score), desc(models.Host.last_seen)).offset(skip).limit(limit)
        total = self.db.scalar(count_stmt) or 0
        items = list(self.db.scalars(stmt).all())
        return items, total

    def update_risk(self, host_id: int, new_risk_score: float) -> Optional[models.Host]:
        host = self.get_by_id(host_id)
        if host:
            host.risk_score = round(new_risk_score, 2)
            self.db.commit()
            self.db.refresh(host)
        return host

    def update_status(self, host_id: int, new_status: str) -> Optional[models.Host]:
        host = self.get_by_id(host_id)
        if host:
            host.status = new_status
            self.db.commit()
            self.db.refresh(host)
        return host


class NetworkFlowRepository:
    """Data access repository for NetworkFlow entities."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        duration: float = 0.0,
        packets: int = 0,
        bytes_count: int = 0,
        timestamp: Optional[datetime] = None,
    ) -> models.NetworkFlow:
        flow = models.NetworkFlow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            duration=duration,
            packets=packets,
            bytes=bytes_count,
            timestamp=timestamp or utc_now(),
        )
        self.db.add(flow)
        self.db.commit()
        self.db.refresh(flow)
        return flow

    def list_flows(
        self,
        skip: int = 0,
        limit: int = 50,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
    ) -> Tuple[List[models.NetworkFlow], int]:
        stmt = select(models.NetworkFlow)
        count_stmt = select(func.count(models.NetworkFlow.id))
        if src_ip:
            stmt = stmt.where(models.NetworkFlow.src_ip == src_ip)
            count_stmt = count_stmt.where(models.NetworkFlow.src_ip == src_ip)
        if dst_ip:
            stmt = stmt.where(models.NetworkFlow.dst_ip == dst_ip)
            count_stmt = count_stmt.where(models.NetworkFlow.dst_ip == dst_ip)
        stmt = stmt.order_by(desc(models.NetworkFlow.timestamp)).offset(skip).limit(limit)
        total = self.db.scalar(count_stmt) or 0
        items = list(self.db.scalars(stmt).all())
        return items, total


class SecurityEventRepository:
    """Data access repository for SecurityEvent entities."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, event_id: int) -> Optional[models.SecurityEvent]:
        return self.db.get(models.SecurityEvent, event_id)

    def create(
        self,
        source_ip: str,
        destination_ip: str,
        event_type: str,
        severity: str,
        confidence: float,
        description: str,
        timestamp: Optional[datetime] = None,
    ) -> models.SecurityEvent:
        event = models.SecurityEvent(
            source_ip=source_ip,
            destination_ip=destination_ip,
            event_type=event_type,
            severity=severity,
            confidence=confidence,
            description=description,
            timestamp=timestamp or utc_now(),
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

    def list_events(
        self,
        skip: int = 0,
        limit: int = 50,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> Tuple[List[models.SecurityEvent], int]:
        stmt = select(models.SecurityEvent)
        count_stmt = select(func.count(models.SecurityEvent.id))
        if severity:
            stmt = stmt.where(models.SecurityEvent.severity == severity.upper())
            count_stmt = count_stmt.where(models.SecurityEvent.severity == severity.upper())
        if event_type:
            stmt = stmt.where(models.SecurityEvent.event_type == event_type)
            count_stmt = count_stmt.where(models.SecurityEvent.event_type == event_type)
        stmt = stmt.order_by(desc(models.SecurityEvent.timestamp)).offset(skip).limit(limit)
        total = self.db.scalar(count_stmt) or 0
        items = list(self.db.scalars(stmt).all())
        return items, total


class AnomalyRepository:
    """Data access repository for Anomaly entities."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, anomaly_id: int) -> Optional[models.Anomaly]:
        return self.db.get(models.Anomaly, anomaly_id)

    def create(
        self,
        anomaly_score: float,
        flow_id: Optional[int] = None,
        model_version: str = "iso_forest_v1",
        status: str = "open",
        timestamp: Optional[datetime] = None,
    ) -> models.Anomaly:
        anomaly = models.Anomaly(
            flow_id=flow_id,
            anomaly_score=anomaly_score,
            model_version=model_version,
            status=status,
            timestamp=timestamp or utc_now(),
        )
        self.db.add(anomaly)
        self.db.commit()
        self.db.refresh(anomaly)
        return anomaly

    def list_anomalies(
        self,
        skip: int = 0,
        limit: int = 50,
        status: Optional[str] = None,
    ) -> Tuple[List[models.Anomaly], int]:
        stmt = select(models.Anomaly)
        count_stmt = select(func.count(models.Anomaly.id))
        if status:
            stmt = stmt.where(models.Anomaly.status == status)
            count_stmt = count_stmt.where(models.Anomaly.status == status)
        stmt = stmt.order_by(desc(models.Anomaly.timestamp)).offset(skip).limit(limit)
        total = self.db.scalar(count_stmt) or 0
        items = list(self.db.scalars(stmt).all())
        return items, total

    def update_status(self, anomaly_id: int, new_status: str) -> Optional[models.Anomaly]:
        anom = self.get_by_id(anomaly_id)
        if anom:
            anom.status = new_status
            self.db.commit()
            self.db.refresh(anom)
        return anom


class RecommendationRepository:
    """Data access repository for Recommendation entities."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, rec_id: int) -> Optional[models.Recommendation]:
        return self.db.get(models.Recommendation, rec_id)

    def create(
        self,
        event_id: int,
        action: str,
        reason: str,
        status: str = "pending",
    ) -> models.Recommendation:
        rec = models.Recommendation(
            event_id=event_id,
            action=action,
            reason=reason,
            status=status,
        )
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

    def list_recommendations(
        self,
        skip: int = 0,
        limit: int = 50,
        status: Optional[str] = None,
    ) -> Tuple[List[models.Recommendation], int]:
        stmt = select(models.Recommendation)
        count_stmt = select(func.count(models.Recommendation.id))
        if status:
            stmt = stmt.where(models.Recommendation.status == status)
            count_stmt = count_stmt.where(models.Recommendation.status == status)
        stmt = stmt.order_by(desc(models.Recommendation.id)).offset(skip).limit(limit)
        total = self.db.scalar(count_stmt) or 0
        items = list(self.db.scalars(stmt).all())
        return items, total

    def review(
        self,
        rec_id: int,
        decision_status: str,
        reviewed_by: str,
    ) -> Optional[models.Recommendation]:
        rec = self.get_by_id(rec_id)
        if rec:
            rec.status = decision_status
            rec.reviewed_by = reviewed_by
            rec.reviewed_at = utc_now()
            self.db.commit()
            self.db.refresh(rec)
        return rec


class PredictionRepository:
    """Data access repository for Prediction forecasting records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        model_name: str,
        target: str,
        prediction: float,
        confidence: Optional[float] = None,
        model_version: str = "xgb_reg_v1",
        timestamp: Optional[datetime] = None,
    ) -> models.Prediction:
        pred = models.Prediction(
            model_name=model_name,
            target=target,
            prediction=prediction,
            confidence=confidence,
            model_version=model_version,
            timestamp=timestamp or utc_now(),
        )
        self.db.add(pred)
        self.db.commit()
        self.db.refresh(pred)
        return pred

    def list_predictions(
        self,
        skip: int = 0,
        limit: int = 50,
        target: Optional[str] = None,
    ) -> Tuple[List[models.Prediction], int]:
        stmt = select(models.Prediction)
        count_stmt = select(func.count(models.Prediction.id))
        if target:
            stmt = stmt.where(models.Prediction.target == target)
            count_stmt = count_stmt.where(models.Prediction.target == target)
        stmt = stmt.order_by(desc(models.Prediction.timestamp)).offset(skip).limit(limit)
        total = self.db.scalar(count_stmt) or 0
        items = list(self.db.scalars(stmt).all())
        return items, total


class RiskScoreRepository:
    """Data access repository for Host RiskScore historical evaluations."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        host_id: int,
        security_score: float,
        anomaly_score: float,
        performance_score: float,
        overall_score: float,
        timestamp: Optional[datetime] = None,
    ) -> models.RiskScore:
        score_record = models.RiskScore(
            host_id=host_id,
            security_score=security_score,
            anomaly_score=anomaly_score,
            performance_score=performance_score,
            overall_score=overall_score,
            timestamp=timestamp or utc_now(),
        )
        self.db.add(score_record)
        self.db.commit()
        self.db.refresh(score_record)
        return score_record

    def list_for_host(self, host_id: int, limit: int = 30) -> List[models.RiskScore]:
        stmt = select(models.RiskScore).where(models.RiskScore.host_id == host_id).order_by(desc(models.RiskScore.timestamp)).limit(limit)
        return list(self.db.scalars(stmt).all())
