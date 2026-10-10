"""NetMind AI - SQLAlchemy 2.0 PostgreSQL ORM Models.

Architectural Rationale:
------------------------
1. Modern Typed Declarations:
   Uses SQLAlchemy 2.0 `Mapped[...]` and `mapped_column(...)` for static typing,
   IDE autocompletion, and tight type safety matching Python 3.11+.
2. Explicit Indexing Strategy:
   In high-throughput network telemetry databases (TimescaleDB / PostgreSQL), sequential scans
   on multi-million row flow and event tables are catastrophic. Explicit composite and single
   indexes are established on:
   - High-cardinality IP address lookups (`src_ip`, `dst_ip`, `ip_address`).
   - Time-series range queries (`timestamp`, `last_seen`).
   - Foreign keys linking flows, anomalies, events, and recommendations.
3. Relational Integrity:
   Establishes clear parent-child relationships (e.g. Host -> RiskScore, SecurityEvent -> Recommendation)
   with cascade rules.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netmind.src.backend.database import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class Host(Base):
    """Network endpoint entity tracked across telemetry streams."""

    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False, index=True)  # active, quarantined, dormant

    # Relationships
    risk_scores: Mapped[List["RiskScore"]] = relationship(
        "RiskScore", back_populates="host", cascade="all, delete-orphan", order_by="desc(RiskScore.timestamp)"
    )

    __table_args__ = (
        Index("ix_hosts_status_risk", "status", "risk_score"),
    )

    def __repr__(self) -> str:
        return f"<Host id={self.id} ip={self.ip_address} risk={self.risk_score} status={self.status}>"


class NetworkFlow(Base):
    """Raw bidirectional network connection record ingested from Zeek or NetFlow."""

    __tablename__ = "network_flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)  # tcp, udp, icmp
    duration: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    packets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    anomalies: Mapped[List["Anomaly"]] = relationship(
        "Anomaly", back_populates="flow", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_flows_src_dst_time", "src_ip", "dst_ip", "timestamp"),
        Index("ix_flows_dst_port_time", "dst_port", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<NetworkFlow id={self.id} {self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port} {self.protocol}>"


class SecurityEvent(Base):
    """Flagged cybersecurity intrusion detection event or attack classification."""

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)  # DoS, Port Scan, Brute Force, Web Attack
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)      # LOW, MEDIUM, HIGH, CRITICAL
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships
    recommendations: Mapped[List["Recommendation"]] = relationship(
        "Recommendation", back_populates="event", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_security_events_severity_time", "severity", "timestamp"),
        Index("ix_security_events_type_time", "event_type", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<SecurityEvent id={self.id} type={self.event_type} sev={self.severity} conf={self.confidence:.2f}>"


class Anomaly(Base):
    """Unsupervised Isolation Forest zero-day anomaly detection output."""

    __tablename__ = "anomalies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    flow_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("network_flows.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)  # 0.0 to 1.0
    model_version: Mapped[str] = mapped_column(String(50), default="iso_forest_v1", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False, index=True)  # open, investigating, resolved, false_positive

    # Relationships
    flow: Mapped[Optional["NetworkFlow"]] = relationship("NetworkFlow", back_populates="anomalies")

    def __repr__(self) -> str:
        return f"<Anomaly id={self.id} score={self.anomaly_score:.3f} status={self.status}>"


class Prediction(Base):
    """Time-series telemetry regression forecast (bandwidth & packet rates)."""

    __tablename__ = "predictions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)  # traffic_predictor
    target: Mapped[str] = mapped_column(String(100), nullable=False, index=True)  # bytes_per_second, packets_per_second
    prediction: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    model_version: Mapped[str] = mapped_column(String(50), default="xgb_reg_v1", nullable=False)

    __table_args__ = (
        Index("ix_predictions_target_time", "target", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<Prediction id={self.id} target={self.target} pred={self.prediction:.2f}>"


class RiskScore(Base):
    """Historical host risk assessment entry evaluated by Decision Engine."""

    __tablename__ = "risk_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    security_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    performance_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    overall_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)

    # Relationships
    host: Mapped["Host"] = relationship("Host", back_populates="risk_scores")

    def __repr__(self) -> str:
        return f"<RiskScore id={self.id} host_id={self.host_id} overall={self.overall_score:.1f}>"


class Recommendation(Base):
    """Actionable mitigation recommendation generated by Decision Engine."""

    __tablename__ = "recommendations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(Integer, ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # QUARANTINE_HOST, RATE_LIMIT_PORT, BLOCK_IP
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False, index=True)  # pending, approved, rejected, applied
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    event: Mapped["SecurityEvent"] = relationship("SecurityEvent", back_populates="recommendations")

    def __repr__(self) -> str:
        return f"<Recommendation id={self.id} event_id={self.event_id} action={self.action} status={self.status}>"
