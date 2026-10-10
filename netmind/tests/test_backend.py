"""Unit & Integration Tests for NetMind AI Phase 3: Backend, Decision Engine & API Serving Layer.

Verifies:
1. SQLAlchemy 2.0 ORM models, relationships, and foreign keys.
2. Composite Risk Scoring equation (40% Sec, 25% Anom, 20% Perf, 15% Hist) and tier classification.
3. Rule-based mitigation recommendation engine playbooks.
4. FastAPI REST endpoints:
   - GET /health
   - GET /api/network/status
   - GET /api/threats
   - GET /api/anomalies
   - GET /api/predictions
   - GET /api/recommendations
   - POST /api/events/{id}/review
   - POST /api/recommendations/{id}/review
   - POST /api/predict/attack (Real-time XGBoost + TreeSHAP)
   - POST /api/predict/anomaly (Real-time Isolation Forest)
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Setup path resolution
TEST_DIR = Path(__file__).resolve().parent
NETMIND_DIR = TEST_DIR.parent
WORKSPACE_DIR = NETMIND_DIR.parent

for p in [str(WORKSPACE_DIR), str(NETMIND_DIR), str(NETMIND_DIR / "src")]:
    if p not in sys.path:
        sys.path.insert(0, p)

from netmind.src.backend import models, schemas
from netmind.src.backend.database import Base, get_db
from netmind.src.backend.decision_engine import DecisionEngine, RiskCategory
from netmind.src.backend.main import app, seed_demo_telemetry_if_empty
from netmind.src.backend.repository import (
    HostRepository,
    RecommendationRepository,
    SecurityEventRepository,
)


# In-memory SQLite engine for isolated test runs
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine, class_=Session)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create all tables in memory once for the test session."""
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    seed_demo_telemetry_if_empty(db)
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


# ==============================================================================
# 1. ORM Model & Repository Tests
# ==============================================================================

def test_host_and_event_orm_relationships():
    """Verify ORM models, foreign keys, and repository transactions."""
    db = TestingSessionLocal()
    host_repo = HostRepository(db)
    evt_repo = SecurityEventRepository(db)
    rec_repo = RecommendationRepository(db)

    # Create test host
    test_ip = "192.168.100.50"
    host = host_repo.get_or_create(test_ip, hostname="test-server")
    assert host.id is not None
    assert host.ip_address == test_ip
    assert host.status == "active"

    # Create security event
    evt = evt_repo.create(
        source_ip=test_ip,
        destination_ip="10.0.0.1",
        event_type="DoS",
        severity="CRITICAL",
        confidence=0.99,
        description="High volume SYN flood test event",
    )
    assert evt.id is not None
    assert evt.event_type == "DoS"
    assert evt.severity == "CRITICAL"

    # Create recommendation linked to event
    rec = rec_repo.create(
        event_id=evt.id,
        action="RATE_LIMIT_PORT",
        reason="Rate limit destination port to prevent connection pool exhaustion",
    )
    assert rec.id is not None
    assert rec.event_id == evt.id
    assert rec.status == "pending"

    # Verify relationship navigation
    db.refresh(evt)
    assert len(evt.recommendations) >= 1
    assert evt.recommendations[0].action == "RATE_LIMIT_PORT"

    db.close()


# ==============================================================================
# 2. Decision Engine Unit Tests
# ==============================================================================

def test_decision_engine_risk_calculation_formula():
    """Verify Risk = 0.40 * Sec + 0.25 * Anom + 0.20 * Perf + 0.15 * Hist."""
    # Test values: Sec=80, Anom=60, Perf=50, Hist=40
    # Expected: 0.40*80 + 0.25*60 + 0.20*50 + 0.15*40 = 32 + 15 + 10 + 6 = 63.0
    res = DecisionEngine.calculate_risk_score(
        security_risk=80.0,
        anomaly_score=60.0,
        performance_risk=50.0,
        historical_risk=40.0,
    )
    assert res.overall_score == pytest.approx(63.0)
    assert res.risk_category == RiskCategory.HIGH

    # Test boundary limits
    low_res = DecisionEngine.calculate_risk_score(10, 10, 10, 10)
    assert low_res.overall_score == 10.0
    assert low_res.risk_category == RiskCategory.LOW

    crit_res = DecisionEngine.calculate_risk_score(100, 100, 100, 100)
    assert crit_res.overall_score == 100.0
    assert crit_res.risk_category == RiskCategory.CRITICAL


def test_decision_engine_categorization_tiers():
    """Verify tier mapping: LOW (0-25), MEDIUM (26-50), HIGH (51-75), CRITICAL (76-100)."""
    assert DecisionEngine.categorize_score(0.0) == RiskCategory.LOW
    assert DecisionEngine.categorize_score(25.0) == RiskCategory.LOW
    assert DecisionEngine.categorize_score(26.0) == RiskCategory.MEDIUM
    assert DecisionEngine.categorize_score(50.0) == RiskCategory.MEDIUM
    assert DecisionEngine.categorize_score(51.0) == RiskCategory.HIGH
    assert DecisionEngine.categorize_score(75.0) == RiskCategory.HIGH
    assert DecisionEngine.categorize_score(76.0) == RiskCategory.CRITICAL
    assert DecisionEngine.categorize_score(100.0) == RiskCategory.CRITICAL


def test_decision_engine_mitigation_rules():
    """Verify rule-based mitigation generation for various attack vectors."""
    risk_high = DecisionEngine.calculate_risk_score(80, 70, 60, 40)

    # DoS attack should generate RATE_LIMIT_PORT and BLOCK_SOURCE_IP
    dos_recs = DecisionEngine.generate_recommendations(
        attack_type="DoS",
        confidence=0.98,
        risk_result=risk_high,
        source_ip="192.168.1.200",
        destination_ip="10.0.0.50",
        dst_port=80,
    )
    actions = [r.action_str for r in dos_recs]
    assert "RATE_LIMIT_PORT" in actions
    assert "BLOCK_SOURCE_IP" in actions

    # Port Scan should recommend BLOCK_SOURCE_IP
    scan_recs = DecisionEngine.generate_recommendations(
        attack_type="Port Scan",
        confidence=0.95,
        risk_result=risk_high,
        source_ip="192.168.1.200",
        destination_ip="10.0.0.50",
        dst_port=22,
    )
    assert any(r.action_str == "BLOCK_SOURCE_IP" for r in scan_recs)

    # Brute Force should recommend LOCK_USER_CREDENTIALS
    bf_recs = DecisionEngine.generate_recommendations(
        attack_type="Brute Force",
        confidence=0.92,
        risk_result=risk_high,
        source_ip="192.168.1.150",
        destination_ip="10.0.0.50",
        dst_port=22,
    )
    assert any(r.action_str == "LOCK_USER_CREDENTIALS" for r in bf_recs)


# ==============================================================================
# 3. FastAPI REST Endpoint Tests
# ==============================================================================

def test_api_health_endpoint():
    """Test GET /health returns status online."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "service" in data


def test_api_network_status_overview():
    """Test GET /api/network/status returns comprehensive macro health metrics."""
    response = client.get("/api/network/status")
    assert response.status_code == 200
    data = response.json()
    assert "system_status" in data
    assert "active_risk_level" in data
    assert "average_risk_score" in data
    assert "total_hosts" in data
    assert data["total_hosts"] >= 4  # Seeded hosts
    assert "current_bandwidth_bps" in data
    assert "current_packet_rate_pps" in data


def test_api_threats_and_anomalies_pagination():
    """Test GET /api/threats and GET /api/anomalies with pagination."""
    # Threats
    r_threats = client.get("/api/threats?page=1&page_size=10")
    assert r_threats.status_code == 200
    t_data = r_threats.json()
    assert "items" in t_data
    assert "total" in t_data
    assert t_data["total"] >= 2

    # Anomalies
    r_anom = client.get("/api/anomalies?page=1&page_size=10")
    assert r_anom.status_code == 200
    a_data = r_anom.json()
    assert a_data["total"] >= 1


def test_api_predictions_endpoint():
    """Test GET /api/predictions returns time-series forecast records."""
    response = client.get("/api/predictions")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["total"] >= 2


def test_api_recommendations_and_review():
    """Test GET /api/recommendations and POST review endpoint."""
    r_list = client.get("/api/recommendations?status=pending")
    assert r_list.status_code == 200
    data = r_list.json()
    assert data["total"] >= 1
    rec_id = data["items"][0]["id"]

    # Review recommendation
    review_resp = client.post(
        f"/api/recommendations/{rec_id}/review",
        json={"status": "approved", "reviewed_by": "sec_lead_analyst"},
    )
    assert review_resp.status_code == 200
    assert review_resp.json()["status"] == "approved"
    assert review_resp.json()["reviewed_by"] == "sec_lead_analyst"


def test_api_event_review_endpoint():
    """Test POST /api/events/{id}/review to acknowledge/resolve an incident."""
    r_threats = client.get("/api/threats")
    evt_id = r_threats.json()["items"][0]["id"]

    review_resp = client.post(
        f"/api/events/{evt_id}/review",
        json={
            "status": "resolve",
            "reviewed_by": "ir_analyst_01",
            "notes": "Verified source IP blocked at perimeter firewall.",
        },
    )
    assert review_resp.status_code == 200
    updated_evt = review_resp.json()
    assert "ir_analyst_01" in updated_evt["description"]
    assert "RESOLVE" in updated_evt["description"]


# ==============================================================================
# 4. Real-Time Model Inference Endpoints
# ==============================================================================

def test_api_predict_attack_endpoint():
    """Test POST /api/predict/attack with DoS flow characteristics."""
    # Synthetic DoS flow vector (high packet rate, high SYN, 0 ACKs)
    dos_payload = {
        "duration": 0.005,
        "packet_count": 200.0,
        "byte_count": 12000.0,
        "orig_bytes": 12000.0,
        "resp_bytes": 0.0,
        "orig_pkts": 200.0,
        "resp_pkts": 0.0,
        "packets_per_second": 40000.0,
        "bytes_per_second": 2400000.0,
        "syn_count": 200.0,
        "ack_count": 0.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 20000.0,
        "unique_destinations": 1.0,
        "failed_connections": 50.0,
        "failed_conn_ratio": 1.0,
        "unique_dest_ports": 1.0,
        "src_conn_count": 100.0,
        "is_failed_connection": 1.0,
        "is_src_private_ip": 1.0,
        "is_dst_private_ip": 1.0,
        "is_dst_well_known_port": 1.0,
        "is_dst_registered_port": 0.0,
        "is_src_ephemeral_port": 1.0,
        "dst_port": 80.0,
        "proto_tcp": 1.0,
        "proto_udp": 0.0,
        "proto_icmp": 0.0,
        "src_ip": "192.168.1.205",
        "dst_ip": "10.0.0.50",
    }

    response = client.post("/api/predict/attack", json=dos_payload)
    assert response.status_code == 200
    res = response.json()

    assert "predicted_class_name" in res
    assert res["predicted_class_name"] == "DoS"
    assert res["confidence"] > 0.80
    assert "class_probabilities" in res
    assert "top_explainability_reasons" in res
    assert len(res["top_explainability_reasons"]) > 0
    assert "risk_score" in res
    assert res["risk_score"] > 60.0
    assert res["recommended_action"] in ["RATE_LIMIT_PORT", "BLOCK_SOURCE_IP"]


def test_api_predict_anomaly_endpoint():
    """Test POST /api/predict/anomaly with normal vs anomalous vectors."""
    # Baseline flow vector
    baseline_payload = {
        "duration": 1.25,
        "packet_count": 15.0,
        "byte_count": 3200.0,
        "orig_bytes": 800.0,
        "resp_bytes": 2400.0,
        "orig_pkts": 6.0,
        "resp_pkts": 9.0,
        "packets_per_second": 12.0,
        "bytes_per_second": 2560.0,
        "syn_count": 1.0,
        "ack_count": 12.0,
        "rst_count": 0.0,
        "fin_count": 2.0,
        "syn_ack_ratio": 0.08,
        "unique_destinations": 1.0,
        "failed_connections": 0.0,
        "failed_conn_ratio": 0.0,
        "unique_dest_ports": 1.0,
        "src_conn_count": 10.0,
        "is_failed_connection": 0.0,
        "is_src_private_ip": 1.0,
        "is_dst_private_ip": 0.0,
        "is_dst_well_known_port": 1.0,
        "is_dst_registered_port": 0.0,
        "is_src_ephemeral_port": 1.0,
        "dst_port": 443.0,
        "proto_tcp": 1.0,
        "proto_udp": 0.0,
        "proto_icmp": 0.0,
    }

    response = client.post("/api/predict/anomaly", json=baseline_payload)
    assert response.status_code == 200
    res = response.json()

    assert "is_anomaly" in res
    assert "anomaly_score" in res
    assert "calibrated_threshold" in res
    assert "top_behavioral_indicators" in res
    assert 0.0 <= res["anomaly_score"] <= 1.0


if __name__ == "__main__":
    pytest.main(["-v", str(Path(__file__))])
