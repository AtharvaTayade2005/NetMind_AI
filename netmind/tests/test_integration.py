"""NetMind AI - Phase 5 Systems Integration & Automated Ingestion Tests.

Verifies:
1. Traffic Generator defensive controls (safe IP checking, rate limiting).
2. Synthetic telemetry log emission (Zeek TSV & Suricata NDJSON).
3. Log Tailer checkpoint management & rotation resilience.
4. End-to-end telemetry ingestion, ML inference, decision engine scoring,
   and database persistence.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Dict, Generator

# Setup path resolution
TEST_DIR = Path(__file__).resolve().parent
NETMIND_DIR = TEST_DIR.parent
WORKSPACE_DIR = NETMIND_DIR.parent

for p in [str(WORKSPACE_DIR), str(NETMIND_DIR), str(NETMIND_DIR / "src")]:
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from netmind.src.backend.database import Base
from netmind.src.backend.models import (
    Anomaly,
    Host,
    NetworkFlow,
    Recommendation,
    RiskScore,
    SecurityEvent,
)
from scripts.traffic_generator import (
    DefensiveRateLimiter,
    SyntheticTrafficGenerator,
    TelemetryLogEmitter,
    is_safe_target_ip,
)
from netmind.src.worker.log_tailer import (
    CheckpointManager,
    ModelStore,
    NetMindLogTailer,
)


@pytest.fixture
def temp_test_env(tmp_path: Path) -> Generator[Dict[str, Path], None, None]:
    """Provide isolated directory structure for test logs, checkpoints, and sqlite db."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "test_netmind.db"

    yield {
        "log_dir": log_dir,
        "conn_log": log_dir / "conn.log",
        "eve_json": log_dir / "eve.json",
        "checkpoint": log_dir / ".tailer_checkpoint.json",
        "db_url": f"sqlite:///{db_path.as_posix()}",
    }


def test_traffic_generator_safe_ip_validation() -> None:
    """Verify traffic generator disallows scanning external non-RFC1918 IPs by default."""
    assert is_safe_target_ip("127.0.0.1") is True
    assert is_safe_target_ip("localhost") is True
    assert is_safe_target_ip("192.168.1.100") is True
    assert is_safe_target_ip("10.0.0.1") is True
    assert is_safe_target_ip("172.16.0.50") is True

    # Public Internet addresses should fail defensive check unless explicitly permitted
    assert is_safe_target_ip("8.8.8.8", allow_external=False) is False
    assert is_safe_target_ip("8.8.8.8", allow_external=True) is True
    assert is_safe_target_ip("1.1.1.1", allow_external=False) is False


def test_traffic_generator_rate_limiter() -> None:
    """Verify defensive rate limiter correctly clamps packet frequency."""
    limiter = DefensiveRateLimiter(max_rate_per_sec=20.0)  # 50ms min interval
    t0 = time.monotonic()
    for _ in range(5):
        limiter.wait()
    elapsed = time.monotonic() - t0
    # 5 iterations at 20 pps should take at least ~0.15s
    assert elapsed >= 0.15


def test_telemetry_log_emitter(temp_test_env: Dict[str, Path]) -> None:
    """Verify TelemetryLogEmitter produces valid Zeek TSV and Suricata NDJSON format."""
    emitter = TelemetryLogEmitter(temp_test_env["log_dir"])

    emitter.emit_zeek_conn(
        src_ip="192.168.1.50",
        src_port=54321,
        dst_ip="127.0.0.1",
        dst_port=8000,
        proto="tcp",
        service="http",
        duration=0.05,
        orig_bytes=200,
        resp_bytes=800,
        conn_state="SF",
        history="ShADadFf",
        orig_pkts=5,
        resp_pkts=6,
    )

    emitter.emit_suricata_alert(
        src_ip="192.168.1.50",
        src_port=54321,
        dst_ip="127.0.0.1",
        dst_port=8000,
        proto="TCP",
        signature="ET SCAN Test Probe",
        category="Reconnaissance",
        severity=2,
    )

    conn_lines = temp_test_env["conn_log"].read_text(encoding="utf-8").strip().splitlines()
    assert len(conn_lines) >= 9  # Header comments + 1 data line
    assert "192.168.1.50" in conn_lines[-1]
    assert "8000" in conn_lines[-1]

    eve_content = temp_test_env["eve_json"].read_text(encoding="utf-8").strip()
    eve_record = json.loads(eve_content)
    assert eve_record["event_type"] == "alert"
    assert eve_record["src_ip"] == "192.168.1.50"
    assert eve_record["alert"]["signature"] == "ET SCAN Test Probe"


def test_checkpoint_manager_rotation_detection(temp_test_env: Dict[str, Path]) -> None:
    """Verify CheckpointManager tracks byte offsets and resets on log truncation."""
    test_file = temp_test_env["conn_log"]
    test_file.write_text("line1\nline2\nline3\n", encoding="utf-8")
    initial_size = test_file.stat().st_size

    mgr = CheckpointManager(temp_test_env["checkpoint"])
    # First query offset
    offset = mgr.get_offset("zeek", test_file)
    assert offset == 0

    # Advance offset
    mgr.update_offset("zeek", test_file, initial_size)
    mgr.save()

    # Re-instantiate checkpoint manager
    mgr2 = CheckpointManager(temp_test_env["checkpoint"])
    assert mgr2.get_offset("zeek", test_file) == initial_size

    # Simulate log rotation / truncation (smaller size)
    test_file.write_text("new_line\n", encoding="utf-8")
    new_offset = mgr2.get_offset("zeek", test_file)
    assert new_offset == 0  # Successfully detected rotation and reset


def test_end_to_end_worker_ingestion_pipeline(temp_test_env: Dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify complete end-to-end pipeline: synthetic emission -> log tailer -> ML inference -> DB."""
    # Configure in-memory / temporary SQLite database
    test_engine = create_engine(temp_test_env["db_url"], connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    # Monkeypatch database session in worker
    monkeypatch.setattr("netmind.src.worker.log_tailer.SessionLocal", TestingSessionLocal)

    # 1. Emit synthetic logs using traffic generator
    gen = SyntheticTrafficGenerator(
        target_ip="127.0.0.1",
        target_port=8000,
        rate=100.0,
        emit_logs=True,
        log_dir=str(temp_test_env["log_dir"]),
    )
    # Run small port probe and burst to generate rich alerts
    gen.run_port_probe(start_port=8000, end_port=8005, delay_per_port=0.001)
    gen.run_high_volume_burst(burst_packets=50, rate_ceiling=200.0)

    # 2. Run Worker Ingestion in single-pass mode
    models = ModelStore()
    tailer = NetMindLogTailer(
        zeek_path=temp_test_env["conn_log"],
        suricata_path=temp_test_env["eve_json"],
        checkpoint_path=temp_test_env["checkpoint"],
        model_store=models,
        poll_interval=0.1,
    )
    tailer.run(once=True)

    # 3. Verify Database Records
    db: Session = TestingSessionLocal()
    try:
        flows_count = db.query(NetworkFlow).count()
        events_count = db.query(SecurityEvent).count()
        recs_count = db.query(Recommendation).count()
        hosts_count = db.query(Host).count()

        assert flows_count > 0, f"Expected flows to be ingested, found {flows_count}"
        assert events_count > 0, f"Expected security events to be flagged, found {events_count}"
        assert recs_count > 0, f"Expected mitigation recommendations, found {recs_count}"
        assert hosts_count > 0, f"Expected host records, found {hosts_count}"

        # Check sample recommendation structure
        sample_rec = db.query(Recommendation).first()
        assert sample_rec is not None
        assert sample_rec.action in ["BLOCK_SOURCE_IP", "RATE_LIMIT_PORT", "QUARANTINE_HOST", "LOCK_USER_CREDENTIALS", "MONITOR_BASELINE"]
        assert sample_rec.status == "pending"
    finally:
        db.close()
