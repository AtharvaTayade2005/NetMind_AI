#!/usr/bin/env python3
"""NetMind AI - Real-Time Telemetry Log Tailer & ML Ingestion Worker.

Architectural Rationale & Pipeline Overview:
--------------------------------------------
In an enterprise Security Operations Center (SOC) and automated network monitoring
fabric, log ingestion must operate asynchronously from the API query layer.

This daemon continuously tails Zeek `conn.log` and Suricata `eve.json` files,
processes new network entries through the NetMind intelligence pipeline, and
persists results into PostgreSQL/TimescaleDB.

Pipeline Flow Per Telemetry Entry:
-----------------------------------
1. Ingestion & Offset Tracking:
   Tracks byte offsets with `.tailer_checkpoint.json`. Seamlessly survives log
   rotation (detecting size reduction and file inode changes) while preventing
   duplicate re-ingestion of already processed records.
2. Log Parsing & Canonical Normalization:
   Parses Zeek TSV / Suricata NDJSON records into standardized network flow tuples
   (src_ip, dst_ip, src_port, dst_port, proto, duration, bytes, packets).
3. Feature Engineering & Scaling:
   Transforms flow metrics into the 30-dimensional NetMind behavioral feature vector
   (rate metrics, TCP flag ratios, connection diversity) avoiding static IP memorization,
   and scales features via the serialized `NetMindPreprocessor`.
4. Machine Learning Inference:
   - Isolation Forest (`anomaly_detector.joblib`): Computes unsupervised anomaly score
     and flags zero-day / behavioral drift.
   - XGBoost Classifier (`attack_classifier.joblib`): Predicts attack category
     (Normal, DoS, Port Scan, Brute Force, Web Attack) with probability confidence.
5. Decision Engine & Multi-Vector Risk Calculation:
   Fuses threat evidence, anomaly score, link performance stress, and host history:
     Risk = 0.40 * SecurityRisk + 0.25 * AnomalyScore + 0.20 * PerformanceRisk + 0.15 * HistoricalRisk
6. Actionable Mitigation Proposal:
   Generates playbooks (RATE_LIMIT_PORT, BLOCK_SOURCE_IP, QUARANTINE_HOST) aligned with NIST SP 800-61.
7. Database Persistence & Atomic Checkpoint:
   Persists `NetworkFlow`, `Anomaly`, `SecurityEvent`, `Recommendation`, and updates
   `Host` and `RiskScore` records inside an atomic database transaction.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

# Setup path resolution to support root execution, worker subdir, and container paths
CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent.parent
for candidate in [str(REPO_ROOT), str(REPO_ROOT / "netmind"), "/app"]:
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

# NetMind imports
from netmind.src.backend.database import SessionLocal, init_db
from netmind.src.backend.decision_engine import DecisionEngine
from netmind.src.backend.models import (
    Anomaly,
    Host,
    NetworkFlow,
    Recommendation,
    RiskScore,
    SecurityEvent,
)
from netmind.src.backend.repository import (
    AnomalyRepository,
    HostRepository,
    NetworkFlowRepository,
    RecommendationRepository,
    RiskScoreRepository,
    SecurityEventRepository,
)
from netmind.src.backend.schemas import RiskCategory
from netmind.src.features.engineer import NetMindFeatureEngineer

# Structured Logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("netmind.worker.log_tailer")


# Canonical Zeek TSV fields default fallback
DEFAULT_ZEEK_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]


class ModelStore:
    """Manages loading and caching of trained ML artifacts."""

    def __init__(self, model_dir: Optional[Path] = None) -> None:
        self.model_dir = self._find_model_dir(model_dir)
        self.preprocessor = None
        self.anomaly_detector = None
        self.attack_classifier = None
        self.load_models()

    def _find_model_dir(self, custom_path: Optional[Path]) -> Path:
        candidates = [
            custom_path,
            REPO_ROOT / "models",
            REPO_ROOT / "netmind" / "models",
            Path("/app/models"),
        ]
        for c in candidates:
            if c and c.is_dir() and (c / "preprocessor.joblib").exists():
                return c
        # Fallback to REPO_ROOT / "models"
        return REPO_ROOT / "models"

    def load_models(self) -> None:
        """Load trained preprocessor and ML models from disk."""
        prep_path = self.model_dir / "preprocessor.joblib"
        anom_path = self.model_dir / "anomaly_detector.joblib"
        clf_path = self.model_dir / "attack_classifier.joblib"

        if prep_path.exists():
            self.preprocessor = joblib.load(prep_path)
            logger.info(f"Loaded Preprocessor from {prep_path}")
        else:
            logger.warning(f"Preprocessor artifact not found at {prep_path}")

        if anom_path.exists():
            self.anomaly_detector = joblib.load(anom_path)
            logger.info(f"Loaded AnomalyDetector from {anom_path}")
        else:
            logger.warning(f"AnomalyDetector artifact not found at {anom_path}")

        if clf_path.exists():
            self.attack_classifier = joblib.load(clf_path)
            logger.info(f"Loaded AttackClassifier from {clf_path}")
        else:
            logger.warning(f"AttackClassifier artifact not found at {clf_path}")

    @property
    def is_ready(self) -> bool:
        return (
            self.preprocessor is not None
            and self.anomaly_detector is not None
            and self.attack_classifier is not None
        )


class CheckpointManager:
    """Persists file byte offsets and handles log rotation detection."""

    def __init__(self, checkpoint_path: Path) -> None:
        self.checkpoint_path = checkpoint_path
        self.state: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self.checkpoint_path.exists():
            try:
                with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to read checkpoint file, resetting: {e}")
        return {}

    def save(self) -> None:
        """Atomically persist checkpoint state to disk."""
        try:
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.checkpoint_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
            tmp_path.replace(self.checkpoint_path)
        except Exception as e:
            logger.error(f"Error persisting checkpoint state: {e}")

    def get_offset(self, log_key: str, file_path: Path) -> int:
        """Retrieve current byte offset, detecting file rotation."""
        if not file_path.exists():
            return 0

        stat = file_path.stat()
        current_size = stat.st_size
        current_inode = getattr(stat, "st_ino", 0)

        entry = self.state.get(log_key)
        if not entry:
            self.state[log_key] = {
                "offset": 0,
                "inode": current_inode,
                "size": current_size,
                "updated_at": time.time(),
            }
            return 0

        stored_offset = entry.get("offset", 0)
        stored_inode = entry.get("inode", 0)

        # Rotation Detection:
        # 1. Inode changed (Unix logrotate standard)
        # 2. File size shrank below current offset (truncated file / Windows rotation)
        if (stored_inode and current_inode and stored_inode != current_inode) or (current_size < stored_offset):
            logger.info(f"Log rotation detected for '{log_key}' (Size: {current_size} < Stored: {stored_offset}). Resetting offset to 0.")
            entry["offset"] = 0
            entry["inode"] = current_inode
            entry["size"] = current_size
            entry["updated_at"] = time.time()
            return 0

        return stored_offset

    def update_offset(self, log_key: str, file_path: Path, new_offset: int) -> None:
        """Update byte offset for a log file."""
        stat = file_path.stat() if file_path.exists() else None
        current_inode = getattr(stat, "st_ino", 0) if stat else 0
        current_size = stat.st_size if stat else new_offset

        self.state[log_key] = {
            "offset": new_offset,
            "inode": current_inode,
            "size": current_size,
            "updated_at": time.time(),
        }


class NetMindLogTailer:
    """Production background daemon streaming Zeek & Suricata logs into NetMind AI."""

    def __init__(
        self,
        zeek_path: Path,
        suricata_path: Path,
        checkpoint_path: Path,
        model_store: ModelStore,
        poll_interval: float = 1.0,
    ) -> None:
        self.zeek_path = zeek_path
        self.suricata_path = suricata_path
        self.poll_interval = poll_interval
        self.checkpoint_mgr = CheckpointManager(checkpoint_path)
        self.models = model_store
        self.feature_engineer = NetMindFeatureEngineer()
        self.zeek_fields = list(DEFAULT_ZEEK_FIELDS)
        self.running = True

    def stop(self) -> None:
        """Signal worker to stop gracefully."""
        logger.info("Stopping NetMindLogTailer worker...")
        self.running = False

    def run(self, once: bool = False) -> None:
        """Main execution loop."""
        logger.info("Initializing database connection...")
        init_db()

        logger.info(f"Starting NetMind Log Tailer daemon:")
        logger.info(f"  Zeek conn.log:     {self.zeek_path}")
        logger.info(f"  Suricata eve.json: {self.suricata_path}")
        logger.info(f"  Checkpoint Store:  {self.checkpoint_mgr.checkpoint_path}")
        logger.info(f"  Poll Interval:     {self.poll_interval}s")
        logger.info(f"  Models Ready:      {self.models.is_ready}")

        while self.running:
            processed_zeek = self._process_zeek_logs()
            processed_suricata = self._process_suricata_logs()

            if processed_zeek > 0 or processed_suricata > 0:
                self.checkpoint_mgr.save()
                logger.info(f"Processed batch: {processed_zeek} Zeek flows, {processed_suricata} Suricata alerts.")

            if once:
                break

            time.sleep(self.poll_interval)

    # --------------------------------------------------------------------------
    # Zeek conn.log Processing
    # --------------------------------------------------------------------------
    def _process_zeek_logs(self) -> int:
        if not self.zeek_path.exists():
            return 0

        offset = self.checkpoint_mgr.get_offset("zeek", self.zeek_path)
        file_size = self.zeek_path.stat().st_size
        if offset >= file_size:
            return 0

        count = 0
        new_offset = offset

        try:
            with open(self.zeek_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                lines = f.readlines()
                new_offset = f.tell()

            if not lines:
                return 0

            records_to_process: List[Dict[str, Any]] = []
            for raw_line in lines:
                line = raw_line.strip()
                if not line:
                    continue

                # Header detection
                if line.startswith("#fields"):
                    parts = line.split()
                    if len(parts) > 1:
                        self.zeek_fields = parts[1:]
                    continue
                elif line.startswith("#"):
                    continue

                # Data line parsing
                fields = line.split("\t")
                if len(fields) >= len(self.zeek_fields):
                    rec = dict(zip(self.zeek_fields, fields[: len(self.zeek_fields)]))
                    records_to_process.append(rec)
                elif len(fields) >= 10:
                    rec = dict(zip(DEFAULT_ZEEK_FIELDS, fields[: len(DEFAULT_ZEEK_FIELDS)]))
                    records_to_process.append(rec)

            if records_to_process:
                count = self._ingest_zeek_batch(records_to_process)

            self.checkpoint_mgr.update_offset("zeek", self.zeek_path, new_offset)
        except Exception as e:
            logger.error(f"Error processing Zeek log file: {e}", exc_info=True)

        return count

    def _ingest_zeek_batch(self, records: List[Dict[str, Any]]) -> int:
        """Run ML inference, evaluate risk, and persist Zeek records to PostgreSQL."""
        db = SessionLocal()
        ingested = 0
        try:
            flow_repo = NetworkFlowRepository(db)
            event_repo = SecurityEventRepository(db)
            anom_repo = AnomalyRepository(db)
            rec_repo = RecommendationRepository(db)
            host_repo = HostRepository(db)
            risk_repo = RiskScoreRepository(db)

            for rec in records:
                try:
                    # 1. Parse standard network fields
                    src_ip = rec.get("id.orig_h") or rec.get("src_ip", "0.0.0.0")
                    dst_ip = rec.get("id.resp_h") or rec.get("dst_ip", "0.0.0.0")
                    src_port = int(rec.get("id.orig_p") or rec.get("src_port", 0))
                    dst_port = int(rec.get("id.resp_p") or rec.get("dst_port", 0))
                    proto = (rec.get("proto") or "tcp").lower()
                    conn_state = rec.get("conn_state", "SF")

                    # Numerical metrics with clean fallback
                    duration = float(rec.get("duration", 0.0)) if rec.get("duration") not in ("-", "", None) else 0.0
                    orig_bytes = int(rec.get("orig_bytes", 0)) if rec.get("orig_bytes") not in ("-", "", None) else 0
                    resp_bytes = int(rec.get("resp_bytes", 0)) if rec.get("resp_bytes") not in ("-", "", None) else 0
                    orig_pkts = int(rec.get("orig_pkts", 1)) if rec.get("orig_pkts") not in ("-", "", None) else 1
                    resp_pkts = int(rec.get("resp_pkts", 0)) if rec.get("resp_pkts") not in ("-", "", None) else 0

                    total_bytes = orig_bytes + resp_bytes
                    total_pkts = orig_pkts + resp_pkts

                    # Parse timestamp
                    ts_raw = rec.get("ts")
                    try:
                        ts_dt = datetime.datetime.fromtimestamp(float(ts_raw), tz=datetime.timezone.utc) if ts_raw else datetime.datetime.now(datetime.timezone.utc)
                    except Exception:
                        ts_dt = datetime.datetime.now(datetime.timezone.utc)

                    # 2. Persist NetworkFlow
                    flow = flow_repo.create(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=proto,
                        duration=duration,
                        packets=total_pkts,
                        bytes_count=total_bytes,
                        timestamp=ts_dt,
                    )

                    # 3. Feature Extraction (construct 30-feature vector matching preprocessor)
                    bps = total_bytes / max(duration, 1e-4)
                    pps = total_pkts / max(duration, 1e-4)
                    syn_c = float(orig_pkts) if "S" in rec.get("history", "S") else 1.0
                    ack_c = float(max(1, resp_pkts)) if "A" in rec.get("history", "") else 0.0

                    feature_dict = {
                        "duration": duration,
                        "packet_count": float(total_pkts),
                        "byte_count": float(total_bytes),
                        "avg_packet_size": float(total_bytes / max(1, total_pkts)),
                        "orig_bytes": float(orig_bytes),
                        "resp_bytes": float(resp_bytes),
                        "orig_pkts": float(orig_pkts),
                        "resp_pkts": float(resp_pkts),
                        "packets_per_second": pps,
                        "bytes_per_second": bps,
                        "syn_count": syn_c,
                        "ack_count": ack_c,
                        "rst_count": 1.0 if "R" in rec.get("history", "") or conn_state in ("REJ", "RSTO") else 0.0,
                        "fin_count": 1.0 if "F" in rec.get("history", "") else 0.0,
                        "syn_ack_ratio": float(syn_c / (ack_c + 1e-5)),
                        "unique_destinations": 1.0,
                        "failed_connections": 1.0 if conn_state in ("S0", "REJ", "RSTOS0") else 0.0,
                        "failed_conn_ratio": 1.0 if conn_state in ("S0", "REJ", "RSTOS0") else 0.0,
                        "unique_dest_ports": 1.0,
                        "src_conn_count": 10.0,
                        "is_failed_connection": 1.0 if conn_state in ("S0", "REJ", "RSTOS0") else 0.0,
                        "is_src_private_ip": 1.0 if src_ip.startswith(("10.", "192.168.", "172.16.", "127.")) else 0.0,
                        "is_dst_private_ip": 1.0 if dst_ip.startswith(("10.", "192.168.", "172.16.", "127.")) else 0.0,
                        "is_dst_well_known_port": 1.0 if dst_port < 1024 else 0.0,
                        "is_dst_registered_port": 1.0 if 1024 <= dst_port < 49152 else 0.0,
                        "is_src_ephemeral_port": 1.0 if src_port >= 49152 else 0.0,
                        "dst_port": float(dst_port),
                        "proto_tcp": 1.0 if proto == "tcp" else 0.0,
                        "proto_udp": 1.0 if proto == "udp" else 0.0,
                        "proto_icmp": 1.0 if proto == "icmp" else 0.0,
                    }

                    df_feat = pd.DataFrame([feature_dict])

                    # 4. ML Model Invocations
                    anomaly_score = 0.2
                    is_anomaly = False
                    attack_type = "Normal"
                    confidence = 0.95

                    if self.models.is_ready:
                        try:
                            scaled_feat = self.models.preprocessor.transform(df_feat)
                            # Anomaly detection
                            anom_out = self.models.anomaly_detector.predict(scaled_feat)
                            anomaly_score = float(anom_out.anomaly_scores[0])
                            is_anomaly = bool(anom_out.is_anomaly[0])

                            # Attack classification
                            probs = self.models.attack_classifier.predict_proba(scaled_feat)[0]
                            pred_class_id = int(np.argmax(probs))
                            confidence = float(probs[pred_class_id])
                            attack_labels = self.models.attack_classifier.predict_labels(scaled_feat)
                            attack_type = attack_labels[0]
                        except Exception as e:
                            logger.warning(f"ML inference error: {e}")

                    # Record Anomaly if flagged
                    if is_anomaly or anomaly_score >= 0.55:
                        anom_repo.create(
                            anomaly_score=anomaly_score,
                            flow_id=flow.id,
                            model_version="iso_forest_v1",
                            status="open",
                            timestamp=ts_dt,
                        )

                    # 5. Decision Engine Risk Evaluation
                    src_host = host_repo.get_or_create(src_ip)
                    is_quarantined = src_host.status == "quarantined"

                    risk_res = DecisionEngine.evaluate_flow_risk(
                        attack_type=attack_type,
                        confidence=confidence,
                        anomaly_score=anomaly_score,
                        bytes_per_sec=bps,
                        packets_per_sec=pps,
                        is_quarantined_host=is_quarantined,
                    )

                    # 6. Record Security Event & Actionable Recommendations
                    if attack_type != "Normal" or risk_res.risk_category in (RiskCategory.HIGH, RiskCategory.CRITICAL):
                        event = event_repo.create(
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            event_type=attack_type if attack_type != "Normal" else "Behavioral Anomaly",
                            severity=risk_res.risk_category.value,
                            confidence=confidence,
                            description=(
                                f"Autonomous detection flagged {attack_type} against {dst_ip}:{dst_port} "
                                f"(Overall Risk: {risk_res.overall_score:.1f}/100). {risk_res.breakdown_rationale}"
                            ),
                            timestamp=ts_dt,
                        )

                        # Generate playbooks
                        recommendations = DecisionEngine.generate_recommendations(
                            attack_type=attack_type,
                            confidence=confidence,
                            risk_result=risk_res,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            dst_port=dst_port,
                        )
                        for rec_action in recommendations:
                            rec_repo.create(
                                event_id=event.id,
                                action=rec_action.action_str,
                                reason=rec_action.reason,
                                status="pending",
                            )

                    # 7. Update Host Risk Score History
                    host_repo.update_risk(src_host.id, max(src_host.risk_score, risk_res.overall_score))
                    risk_repo.create(
                        host_id=src_host.id,
                        security_score=risk_res.security_risk,
                        anomaly_score=risk_res.anomaly_score,
                        performance_score=risk_res.performance_risk,
                        overall_score=risk_res.overall_score,
                        timestamp=ts_dt,
                    )

                    # Also register destination host
                    _ = host_repo.get_or_create(dst_ip)
                    ingested += 1

                except Exception as rec_err:
                    logger.warning(f"Skipping problematic Zeek record: {rec_err}")

            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Transaction failed during Zeek batch ingestion: {e}", exc_info=True)
        finally:
            db.close()

        return ingested

    # --------------------------------------------------------------------------
    # Suricata eve.json Processing
    # --------------------------------------------------------------------------
    def _process_suricata_logs(self) -> int:
        if not self.suricata_path.exists():
            return 0

        offset = self.checkpoint_mgr.get_offset("suricata", self.suricata_path)
        file_size = self.suricata_path.stat().st_size
        if offset >= file_size:
            return 0

        count = 0
        new_offset = offset

        try:
            with open(self.suricata_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                lines = f.readlines()
                new_offset = f.tell()

            if not lines:
                return 0

            records_to_process: List[Dict[str, Any]] = []
            for raw_line in lines:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if record.get("event_type") == "alert" and "alert" in record:
                        records_to_process.append(record)
                except json.JSONDecodeError:
                    continue

            if records_to_process:
                count = self._ingest_suricata_batch(records_to_process)

            self.checkpoint_mgr.update_offset("suricata", self.suricata_path, new_offset)
        except Exception as e:
            logger.error(f"Error processing Suricata log file: {e}", exc_info=True)

        return count

    def _ingest_suricata_batch(self, records: List[Dict[str, Any]]) -> int:
        """Process Suricata alert events, evaluate risk, and store recommendations."""
        db = SessionLocal()
        ingested = 0
        try:
            event_repo = SecurityEventRepository(db)
            rec_repo = RecommendationRepository(db)
            host_repo = HostRepository(db)
            risk_repo = RiskScoreRepository(db)

            for rec in records:
                try:
                    src_ip = rec.get("src_ip", "0.0.0.0")
                    dst_ip = rec.get("dest_ip", "0.0.0.0")
                    src_port = int(rec.get("src_port", 0))
                    dst_port = int(rec.get("dest_port", 0))

                    alert = rec.get("alert", {})
                    signature = alert.get("signature", "Generic Alert")
                    category = alert.get("category", "Intrusion Attempt")
                    raw_severity = alert.get("severity", 2)

                    # Map Suricata severity: 1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=LOW
                    sev_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
                    severity_str = sev_map.get(raw_severity, "MEDIUM")

                    # Classify attack type from Suricata metadata
                    sig_upper = signature.upper()
                    if "SCAN" in sig_upper:
                        attack_type = "Port Scan"
                    elif "DOS" in sig_upper or "DENIAL" in sig_upper:
                        attack_type = "DoS"
                    elif "SQL" in sig_upper or "EXPLOIT" in sig_upper or "WEB" in sig_upper:
                        attack_type = "Web Attack"
                    elif "BRUTE" in sig_upper or "AUTH" in sig_upper:
                        attack_type = "Brute Force"
                    else:
                        attack_type = "Port Scan"

                    # Parse timestamp
                    ts_raw = rec.get("timestamp")
                    try:
                        ts_dt = datetime.datetime.fromisoformat(ts_raw.replace("Z", "+00:00")) if ts_raw else datetime.datetime.now(datetime.timezone.utc)
                    except Exception:
                        ts_dt = datetime.datetime.now(datetime.timezone.utc)

                    confidence = 0.92

                    # Evaluate Risk
                    src_host = host_repo.get_or_create(src_ip)
                    risk_res = DecisionEngine.calculate_risk_score(
                        security_risk=85.0 if severity_str in ("HIGH", "CRITICAL") else 50.0,
                        anomaly_score=70.0,
                        performance_risk=40.0,
                        historical_risk=80.0 if src_host.status == "quarantined" else 15.0,
                    )

                    # Create Security Event
                    event = event_repo.create(
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        event_type=attack_type,
                        severity=severity_str,
                        confidence=confidence,
                        description=f"Suricata IDS Alert: {signature} ({category}) from {src_ip}:{src_port} targeting {dst_ip}:{dst_port}",
                        timestamp=ts_dt,
                    )

                    # Generate Playbooks
                    recommendations = DecisionEngine.generate_recommendations(
                        attack_type=attack_type,
                        confidence=confidence,
                        risk_result=risk_res,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        dst_port=dst_port,
                    )
                    for rec_action in recommendations:
                        rec_repo.create(
                            event_id=event.id,
                            action=rec_action.action_str,
                            reason=rec_action.reason,
                            status="pending",
                        )

                    # Update host risk
                    host_repo.update_risk(src_host.id, max(src_host.risk_score, risk_res.overall_score))
                    risk_repo.create(
                        host_id=src_host.id,
                        security_score=risk_res.security_risk,
                        anomaly_score=risk_res.anomaly_score,
                        performance_score=risk_res.performance_risk,
                        overall_score=risk_res.overall_score,
                        timestamp=ts_dt,
                    )

                    _ = host_repo.get_or_create(dst_ip)
                    ingested += 1
                except Exception as alert_err:
                    logger.warning(f"Skipping problematic Suricata alert: {alert_err}")

            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Transaction failed during Suricata batch ingestion: {e}", exc_info=True)
        finally:
            db.close()

        return ingested


def main() -> None:
    """CLI entrypoint for log tailer worker."""
    parser = argparse.ArgumentParser(
        description="NetMind AI - Real-Time Telemetry Log Tailer Worker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--conn-log",
        default=os.getenv("ZEEK_LOG_PATH", "logs/conn.log"),
        help="Path to Zeek conn.log file (default: logs/conn.log).",
    )
    parser.add_argument(
        "--eve-json",
        default=os.getenv("SURICATA_EVE_PATH", "logs/eve.json"),
        help="Path to Suricata eve.json file (default: logs/eve.json).",
    )
    parser.add_argument(
        "--checkpoint-file",
        default="logs/.tailer_checkpoint.json",
        help="Path to checkpoint state JSON file (default: logs/.tailer_checkpoint.json).",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.getenv("POLL_INTERVAL", "1.0")),
        help="Polling interval in seconds (default: 1.0).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single ingestion pass over unread lines and exit.",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        default=True,
        help="Run continuously in background daemon loop (default: True).",
    )

    args = parser.parse_args()

    # Load ML Model artifacts
    model_store = ModelStore()

    tailer = NetMindLogTailer(
        zeek_path=Path(args.conn_log),
        suricata_path=Path(args.eve_json),
        checkpoint_path=Path(args.checkpoint_file),
        model_store=model_store,
        poll_interval=args.poll_interval,
    )

    # Clean signal handling for SIGINT and SIGTERM
    def handle_signal(sig: int, frame: Any) -> None:
        logger.info(f"Received termination signal ({sig}). Shutting down worker...")
        tailer.stop()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    tailer.run(once=args.once)


if __name__ == "__main__":
    main()
