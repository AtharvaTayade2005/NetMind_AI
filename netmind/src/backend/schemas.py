"""NetMind AI - Pydantic v2 Validation and Serialization Schemas.

Architectural Rationale:
------------------------
1. Clear Boundary Separation:
   SQLAlchemy ORM models represent persistence state, constraints, and relational indexes.
   Pydantic v2 schemas represent input contracts, validation constraints, and public API representations.
2. High-Performance Pydantic v2:
   Leverages `model_config = ConfigDict(from_attributes=True)` for zero-copy serialization
   from SQLAlchemy ORM objects into JSON responses.
3. Domain Enums:
   Strict enum definitions for risk categories, severities, actions, and review states.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ==============================================================================
# Domain Enums
# ==============================================================================

class RiskCategory(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RecommendationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"


class RecommendationAction(str, Enum):
    QUARANTINE_HOST = "QUARANTINE_HOST"
    BLOCK_SOURCE_IP = "BLOCK_SOURCE_IP"
    RATE_LIMIT_PORT = "RATE_LIMIT_PORT"
    LOCK_USER_CREDENTIALS = "LOCK_USER_CREDENTIALS"
    WAF_BLOCK_URI_PATTERN = "WAF_BLOCK_URI_PATTERN"
    DEEP_PACKET_INSPECTION = "DEEP_PACKET_INSPECTION"
    MONITOR_BASELINE = "MONITOR_BASELINE"


# ==============================================================================
# Base & Entity Schemas
# ==============================================================================

class HostBase(BaseModel):
    ip_address: str = Field(..., description="IPv4 or IPv6 address")
    hostname: Optional[str] = Field(None, description="Resolved DNS or NetBIOS hostname")
    status: str = Field("active", description="Operational status: active, quarantined, dormant")


class HostCreate(HostBase):
    risk_score: float = Field(0.0, ge=0.0, le=100.0)


class HostRead(HostBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    risk_score: float
    model_config = ConfigDict(from_attributes=True)


class NetworkFlowBase(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str = Field("tcp", description="Transport protocol (tcp, udp, icmp)")
    duration: float = Field(0.0, ge=0.0)
    packets: int = Field(0, ge=0)
    bytes: int = Field(0, ge=0)


class NetworkFlowCreate(NetworkFlowBase):
    timestamp: Optional[datetime] = None


class NetworkFlowRead(NetworkFlowBase):
    id: int
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


class SecurityEventBase(BaseModel):
    source_ip: str
    destination_ip: str
    event_type: str = Field(..., description="Attack category: DoS, Port Scan, Brute Force, Web Attack")
    severity: EventSeverity = Field(EventSeverity.MEDIUM)
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str


class SecurityEventCreate(SecurityEventBase):
    timestamp: Optional[datetime] = None


class SecurityEventRead(SecurityEventBase):
    id: int
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


class AnomalyBase(BaseModel):
    flow_id: Optional[int] = None
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    model_version: str = "iso_forest_v1"
    status: str = Field("open", description="open, investigating, resolved, false_positive")


class AnomalyCreate(AnomalyBase):
    timestamp: Optional[datetime] = None


class AnomalyRead(AnomalyBase):
    id: int
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


class PredictionBase(BaseModel):
    model_name: str
    target: str = Field(..., description="bytes_per_second or packets_per_second")
    prediction: float = Field(..., ge=0.0)
    confidence: Optional[float] = None
    model_version: str = "xgb_reg_v1"


class PredictionCreate(PredictionBase):
    timestamp: Optional[datetime] = None


class PredictionRead(PredictionBase):
    id: int
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


class RiskScoreBase(BaseModel):
    host_id: int
    security_score: float = Field(..., ge=0.0, le=100.0)
    anomaly_score: float = Field(..., ge=0.0, le=100.0)
    performance_score: float = Field(..., ge=0.0, le=100.0)
    overall_score: float = Field(..., ge=0.0, le=100.0)


class RiskScoreCreate(RiskScoreBase):
    timestamp: Optional[datetime] = None


class RiskScoreRead(RiskScoreBase):
    id: int
    timestamp: datetime
    risk_category: Optional[RiskCategory] = None
    model_config = ConfigDict(from_attributes=True)


class RecommendationBase(BaseModel):
    event_id: int
    action: str
    reason: str
    status: str = "pending"


class RecommendationCreate(RecommendationBase):
    pass


class RecommendationRead(RecommendationBase):
    id: int
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Operational & Incident Response Schemas
# ==============================================================================

class ReviewEventRequest(BaseModel):
    status: str = Field(..., description="Action taken: acknowledge, resolve, false_positive")
    reviewed_by: str = Field(..., min_length=2, max_length=100, description="SOC Analyst identity")
    notes: Optional[str] = Field(None, description="Investigation notes or triage explanation")


class ReviewRecommendationRequest(BaseModel):
    status: RecommendationStatus = Field(..., description="Decision: approved, rejected, applied")
    reviewed_by: str = Field(..., min_length=2, max_length=100)


class PaginatedResponse(BaseModel):
    total: int
    page: int
    page_size: int
    pages: int
    items: List[Any]


# ==============================================================================
# Overview & Network Health Dashboard Schemas
# ==============================================================================

class NetworkStatusSummary(BaseModel):
    system_status: str = Field("HEALTHY", description="HEALTHY, DEGRADED, UNDER_ATTACK")
    active_risk_level: RiskCategory = Field(RiskCategory.LOW)
    average_risk_score: float = Field(..., ge=0.0, le=100.0)
    total_hosts: int
    active_hosts: int
    quarantined_hosts: int
    active_threats_count: int
    unresolved_anomalies_count: int
    pending_recommendations_count: int
    current_bandwidth_bps: float
    current_packet_rate_pps: float
    last_updated: datetime


# ==============================================================================
# Real-Time Inference Input & Output Schemas (Phase 2 Models)
# ==============================================================================

class FlowFeaturesInput(BaseModel):
    """Input vector representing flow attributes extracted by Phase 1 Feature Engineer."""
    duration: float = Field(0.0, ge=0.0)
    packet_count: float = Field(1.0, ge=0.0)
    byte_count: float = Field(60.0, ge=0.0)
    avg_packet_size: Optional[float] = None
    orig_bytes: float = Field(60.0, ge=0.0)
    resp_bytes: float = Field(0.0, ge=0.0)
    orig_pkts: float = Field(1.0, ge=0.0)
    resp_pkts: float = Field(0.0, ge=0.0)
    packets_per_second: Optional[float] = None
    bytes_per_second: Optional[float] = None
    syn_count: float = Field(1.0, ge=0.0)
    ack_count: float = Field(0.0, ge=0.0)
    rst_count: float = Field(0.0, ge=0.0)
    fin_count: float = Field(0.0, ge=0.0)
    syn_ack_ratio: Optional[float] = None
    unique_destinations: float = Field(1.0, ge=1.0)
    failed_connections: float = Field(0.0, ge=0.0)
    failed_conn_ratio: float = Field(0.0, ge=0.0, le=1.0)
    unique_dest_ports: float = Field(1.0, ge=1.0)
    src_conn_count: float = Field(1.0, ge=1.0)
    is_failed_connection: float = Field(0.0, ge=0.0, le=1.0)
    is_src_private_ip: float = Field(1.0, ge=0.0, le=1.0)
    is_dst_private_ip: float = Field(1.0, ge=0.0, le=1.0)
    is_dst_well_known_port: float = Field(1.0, ge=0.0, le=1.0)
    is_dst_registered_port: float = Field(0.0, ge=0.0, le=1.0)
    is_src_ephemeral_port: float = Field(1.0, ge=0.0, le=1.0)
    dst_port: float = Field(80.0, ge=0.0, le=65535.0)
    proto_tcp: float = Field(1.0, ge=0.0, le=1.0)
    proto_udp: float = Field(0.0, ge=0.0, le=1.0)
    proto_icmp: float = Field(0.0, ge=0.0, le=1.0)

    # Optional metadata identifiers for triage (never used as ML features)
    src_ip: Optional[str] = "192.168.1.100"
    dst_ip: Optional[str] = "10.0.0.1"


class AttackPredictionResponse(BaseModel):
    predicted_class_id: int
    predicted_class_name: str
    confidence: float
    class_probabilities: Dict[str, float]
    top_explainability_reasons: List[str]
    risk_score: float
    risk_category: RiskCategory
    recommended_action: str
    recommendation_reason: str


class AnomalyPredictionResponse(BaseModel):
    is_anomaly: bool
    anomaly_score: float
    calibrated_threshold: float
    requires_investigation: bool
    top_behavioral_indicators: List[Dict[str, Any]]
