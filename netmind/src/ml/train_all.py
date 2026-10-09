"""NetMind AI - Phase 2 End-to-End ML & Explainability Training Pipeline.

Orchestrates the entire Phase 2 training workflow:
1. Generates statistically grounded synthetic network flows covering Normal, DoS, Port Scan,
   Brute Force, and Web Attack profiles according to the Phase 1 NetMind schema.
2. Preprocesses and deterministically partitions data into Train, Validation, and Test sets.
3. Fits and calibrates the Unsupervised Isolation Forest Anomaly Detector.
4. Trains and evaluates the Multiclass XGBoost Attack Classifier.
5. Trains and validates the Time-Series Traffic Predictor for rate forecasting.
6. Initializes TreeSHAP and generates human-readable alert reason strings for detected attacks.
7. Serializes all trained models and preprocessor artifacts to the `models/` directory.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("netmind.train_all")

# Path discovery
CURRENT_DIR = Path(__file__).resolve().parent
NETMIND_DIR = CURRENT_DIR.parent.parent
REPO_ROOT = NETMIND_DIR.parent

for p in [str(REPO_ROOT), str(NETMIND_DIR), str(NETMIND_DIR / "src")]:
    if p not in sys.path:
        sys.path.insert(0, p)

from netmind.src.ml.anomaly_detector import NetworkAnomalyDetector
from netmind.src.ml.attack_classifier import (
    ATTACK_CLASS_MAP,
    AttackClassifier,
)
from netmind.src.ml.dataset import NetMindPreprocessor, prepare_train_val_test_splits
from netmind.src.ml.explainer import NetMindExplainer
from netmind.src.ml.traffic_predictor import NetworkTrafficPredictor


def generate_synthetic_flow_dataset(
    n_normal: int = 3500,
    n_dos: int = 600,
    n_portscan: int = 600,
    n_bruteforce: int = 350,
    n_webattack: int = 250,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.Series]:
    """Generate statistically grounded synthetic telemetry representing 5 traffic categories.

    Returns:
        Tuple[pd.DataFrame, pd.Series]: Features DataFrame X and class labels Series y.
    """
    rng = np.random.RandomState(random_state)
    records: List[Dict[str, float]] = []
    labels: List[int] = []

    # --------------------------------------------------------------------------
    # 1. Normal Baseline Traffic (Class 0)
    # --------------------------------------------------------------------------
    for _ in range(n_normal):
        dur = float(rng.exponential(scale=1.5) + 0.05)
        orig_p = int(rng.geometric(p=0.1) + 3)
        resp_p = int(orig_p * rng.uniform(1.2, 3.0))
        orig_b = int(orig_p * rng.uniform(60, 250))
        resp_b = int(resp_p * rng.uniform(200, 1200))
        pkts = orig_p + resp_p
        bytes_total = orig_b + resp_b

        syn_c = 1.0
        ack_c = float(max(1, pkts - 2))
        rst_c = 0.0 if rng.rand() > 0.05 else 1.0
        dst_p = int(rng.choice([80, 443, 53, 8080, 3306]))

        records.append({
            "duration": dur,
            "packet_count": float(pkts),
            "byte_count": float(bytes_total),
            "avg_packet_size": float(bytes_total / pkts),
            "orig_bytes": float(orig_b),
            "resp_bytes": float(resp_b),
            "orig_pkts": float(orig_p),
            "resp_pkts": float(resp_p),
            "packets_per_second": float(pkts / max(dur, 1e-4)),
            "bytes_per_second": float(bytes_total / max(dur, 1e-4)),
            "syn_count": syn_c,
            "ack_count": ack_c,
            "rst_count": rst_c,
            "fin_count": 2.0,
            "syn_ack_ratio": float(syn_c / (ack_c + 1e-5)),
            "unique_destinations": float(rng.randint(1, 4)),
            "failed_connections": 0.0,
            "failed_conn_ratio": 0.0,
            "unique_dest_ports": float(rng.randint(1, 3)),
            "src_conn_count": float(rng.randint(5, 50)),
            "is_failed_connection": 0.0,
            "is_src_private_ip": 1.0,
            "is_dst_private_ip": float(1.0 if dst_p not in (80, 443, 53) else 0.0),
            "is_dst_well_known_port": float(1.0 if dst_p < 1024 else 0.0),
            "is_dst_registered_port": float(1.0 if 1024 <= dst_p < 49152 else 0.0),
            "is_src_ephemeral_port": 1.0,
            "dst_port": float(dst_p),
            "proto_tcp": 1.0 if dst_p != 53 else 0.0,
            "proto_udp": 1.0 if dst_p == 53 else 0.0,
            "proto_icmp": 0.0,
        })
        labels.append(0)

    # --------------------------------------------------------------------------
    # 2. Denial of Service / SYN Flood (Class 1)
    # --------------------------------------------------------------------------
    for _ in range(n_dos):
        dur = float(rng.uniform(0.0005, 0.03))
        orig_p = int(rng.randint(50, 400))
        resp_p = int(rng.choice([0, 1]))
        orig_b = orig_p * 60
        resp_b = resp_p * 40
        pkts = orig_p + resp_p
        bytes_total = orig_b + resp_b

        syn_c = float(orig_p)
        ack_c = float(resp_p)
        dst_p = int(rng.choice([80, 443]))

        records.append({
            "duration": dur,
            "packet_count": float(pkts),
            "byte_count": float(bytes_total),
            "avg_packet_size": float(bytes_total / pkts),
            "orig_bytes": float(orig_b),
            "resp_bytes": float(resp_b),
            "orig_pkts": float(orig_p),
            "resp_pkts": float(resp_p),
            "packets_per_second": float(pkts / dur),
            "bytes_per_second": float(bytes_total / dur),
            "syn_count": syn_c,
            "ack_count": ack_c,
            "rst_count": float(resp_p),
            "fin_count": 0.0,
            "syn_ack_ratio": float(syn_c / (ack_c + 1e-5)),
            "unique_destinations": 1.0,
            "failed_connections": float(rng.randint(20, 100)),
            "failed_conn_ratio": 1.0,
            "unique_dest_ports": 1.0,
            "src_conn_count": float(rng.randint(100, 500)),
            "is_failed_connection": 1.0,
            "is_src_private_ip": float(rng.choice([0.0, 1.0])),
            "is_dst_private_ip": 1.0,
            "is_dst_well_known_port": 1.0,
            "is_dst_registered_port": 0.0,
            "is_src_ephemeral_port": 1.0,
            "dst_port": float(dst_p),
            "proto_tcp": 1.0,
            "proto_udp": 0.0,
            "proto_icmp": 0.0,
        })
        labels.append(1)

    # --------------------------------------------------------------------------
    # 3. Port Scan (Class 2)
    # --------------------------------------------------------------------------
    for _ in range(n_portscan):
        dur = float(rng.uniform(0.0001, 0.002))
        orig_p = 1
        resp_p = int(rng.choice([0, 1]))
        orig_b = 60
        resp_b = resp_p * 40
        pkts = orig_p + resp_p
        bytes_total = orig_b + resp_b

        dst_p = int(rng.randint(1, 65535))

        records.append({
            "duration": dur,
            "packet_count": float(pkts),
            "byte_count": float(bytes_total),
            "avg_packet_size": float(bytes_total / pkts),
            "orig_bytes": float(orig_b),
            "resp_bytes": float(resp_b),
            "orig_pkts": float(orig_p),
            "resp_pkts": float(resp_p),
            "packets_per_second": float(pkts / dur),
            "bytes_per_second": float(bytes_total / dur),
            "syn_count": 1.0,
            "ack_count": 0.0,
            "rst_count": float(resp_p),
            "fin_count": 0.0,
            "syn_ack_ratio": 1000.0,
            "unique_destinations": float(rng.randint(1, 10)),
            "failed_connections": float(rng.randint(15, 80)),
            "failed_conn_ratio": 0.95,
            "unique_dest_ports": float(rng.randint(25, 200)),
            "src_conn_count": float(rng.randint(50, 300)),
            "is_failed_connection": 1.0,
            "is_src_private_ip": float(rng.choice([0.0, 1.0])),
            "is_dst_private_ip": 1.0,
            "is_dst_well_known_port": float(1.0 if dst_p < 1024 else 0.0),
            "is_dst_registered_port": float(1.0 if 1024 <= dst_p < 49152 else 0.0),
            "is_src_ephemeral_port": 1.0,
            "dst_port": float(dst_p),
            "proto_tcp": 1.0,
            "proto_udp": 0.0,
            "proto_icmp": 0.0,
        })
        labels.append(2)

    # --------------------------------------------------------------------------
    # 4. Brute Force (Class 3)
    # --------------------------------------------------------------------------
    for _ in range(n_bruteforce):
        dur = float(rng.uniform(0.15, 1.2))
        orig_p = int(rng.randint(8, 22))
        resp_p = int(rng.randint(6, 18))
        orig_b = int(orig_p * rng.uniform(80, 140))
        resp_b = int(resp_p * rng.uniform(60, 120))
        pkts = orig_p + resp_p
        bytes_total = orig_b + resp_b

        dst_p = int(rng.choice([22, 3389, 21]))

        records.append({
            "duration": dur,
            "packet_count": float(pkts),
            "byte_count": float(bytes_total),
            "avg_packet_size": float(bytes_total / pkts),
            "orig_bytes": float(orig_b),
            "resp_bytes": float(resp_b),
            "orig_pkts": float(orig_p),
            "resp_pkts": float(resp_p),
            "packets_per_second": float(pkts / dur),
            "bytes_per_second": float(bytes_total / dur),
            "syn_count": 1.0,
            "ack_count": float(pkts - 3),
            "rst_count": float(rng.choice([0.0, 1.0])),
            "fin_count": 1.0,
            "syn_ack_ratio": float(1.0 / max(pkts - 3, 1)),
            "unique_destinations": 1.0,
            "failed_connections": float(rng.randint(8, 35)),
            "failed_conn_ratio": 0.85,
            "unique_dest_ports": 1.0,
            "src_conn_count": float(rng.randint(20, 100)),
            "is_failed_connection": float(rng.choice([0.0, 1.0])),
            "is_src_private_ip": float(rng.choice([0.0, 1.0])),
            "is_dst_private_ip": 1.0,
            "is_dst_well_known_port": float(1.0 if dst_p < 1024 else 0.0),
            "is_dst_registered_port": float(1.0 if 1024 <= dst_p < 49152 else 0.0),
            "is_src_ephemeral_port": 1.0,
            "dst_port": float(dst_p),
            "proto_tcp": 1.0,
            "proto_udp": 0.0,
            "proto_icmp": 0.0,
        })
        labels.append(3)

    # --------------------------------------------------------------------------
    # 5. Web Attack / SQLi / XSS (Class 4)
    # --------------------------------------------------------------------------
    for _ in range(n_webattack):
        dur = float(rng.uniform(0.3, 2.5))
        orig_p = int(rng.randint(10, 30))
        resp_p = int(rng.randint(8, 25))
        # Malicious payload injections inflate orig_bytes
        orig_b = int(orig_p * rng.uniform(250, 600))
        resp_b = int(resp_p * rng.uniform(150, 400))
        pkts = orig_p + resp_p
        bytes_total = orig_b + resp_b

        dst_p = int(rng.choice([80, 443, 8080]))

        records.append({
            "duration": dur,
            "packet_count": float(pkts),
            "byte_count": float(bytes_total),
            "avg_packet_size": float(bytes_total / pkts),
            "orig_bytes": float(orig_b),
            "resp_bytes": float(resp_b),
            "orig_pkts": float(orig_p),
            "resp_pkts": float(resp_p),
            "packets_per_second": float(pkts / dur),
            "bytes_per_second": float(bytes_total / dur),
            "syn_count": 1.0,
            "ack_count": float(pkts - 2),
            "rst_count": 0.0,
            "fin_count": 2.0,
            "syn_ack_ratio": float(1.0 / max(pkts - 2, 1)),
            "unique_destinations": 1.0,
            "failed_connections": float(rng.choice([0.0, 1.0, 2.0])),
            "failed_conn_ratio": 0.1,
            "unique_dest_ports": 1.0,
            "src_conn_count": float(rng.randint(5, 40)),
            "is_failed_connection": 0.0,
            "is_src_private_ip": float(rng.choice([0.0, 1.0])),
            "is_dst_private_ip": 1.0,
            "is_dst_well_known_port": float(1.0 if dst_p < 1024 else 0.0),
            "is_dst_registered_port": float(1.0 if 1024 <= dst_p < 49152 else 0.0),
            "is_src_ephemeral_port": 1.0,
            "dst_port": float(dst_p),
            "proto_tcp": 1.0,
            "proto_udp": 0.0,
            "proto_icmp": 0.0,
        })
        labels.append(4)

    df_X = pd.DataFrame(records)
    s_y = pd.Series(labels, name="attack_category")
    return df_X, s_y


def run_training_pipeline() -> None:
    """Execute end-to-end training and artifact serialization for Phase 2."""
    models_dir = NETMIND_DIR / "models"
    root_models_dir = REPO_ROOT / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    root_models_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("NetMind AI - Phase 2 Machine Learning & Explainability Training Pipeline")
    print("=" * 80)

    # 1. Synthesize Flow Dataset
    print("\n[Step 1/6] Synthesizing Telemetry Dataset (Normal, DoS, PortScan, BruteForce, WebAttack)...")
    X_raw, y_raw = generate_synthetic_flow_dataset()
    print(f"  Dataset Shape: {X_raw.shape[0]:,} flows across {X_raw.shape[1]} behavioral features.")
    print("  Class Distribution:")
    for cls_id, cls_name in ATTACK_CLASS_MAP.items():
        count = int((y_raw == cls_id).sum())
        print(f"    - {cls_name} (Class {cls_id}): {count:,} flows ({count / len(y_raw):.1%})")

    # 2. Partition & Preprocess Data
    print("\n[Step 2/6] Partitioning Dataset & Fitting Robust Preprocessor...")
    splits = prepare_train_val_test_splits(X_raw, y_raw, val_size=0.15, test_size=0.15, random_state=42)
    print(f"  Splits: Train={splits.X_train.shape[0]:,}, Val={splits.X_val.shape[0]:,}, Test={splits.X_test.shape[0]:,}")

    preprocessor = NetMindPreprocessor(scaler_type="robust")
    X_train_scaled = preprocessor.fit_transform(splits.X_train)
    X_val_scaled = preprocessor.transform(splits.X_val)
    X_test_scaled = preprocessor.transform(splits.X_test)

    # Save preprocessor
    preprocessor.save(models_dir / "preprocessor.joblib")
    preprocessor.save(root_models_dir / "preprocessor.joblib")

    # 3. Train Unsupervised Isolation Forest Anomaly Detector
    print("\n[Step 3/6] Training Unsupervised Isolation Forest on Benign Baseline Telemetry...")
    # Baseline traffic = Class 0 in training partition
    normal_mask_train = splits.y_train == 0
    X_train_normal = X_train_scaled[normal_mask_train]

    anomaly_detector = NetworkAnomalyDetector(
        n_estimators=150,
        contamination=0.05,
        random_state=42,
    )
    anomaly_detector.fit(X_train_normal, calibrate_percentile=95.0)

    # Evaluate anomaly detector on test split
    anom_results = anomaly_detector.predict(X_test_scaled, extract_indicators=True, top_k=2)
    anom_flagged = int(np.sum(anom_results.is_anomaly))
    print(f"  Calibrated Dynamic Threshold: {anomaly_detector.calibrated_threshold_:.4f}")
    print(f"  Test Anomaly Detections: {anom_flagged} / {len(splits.X_test)} ({anom_flagged / len(splits.X_test):.1%})")

    anomaly_detector.save(models_dir / "anomaly_detector.joblib")
    anomaly_detector.save(root_models_dir / "anomaly_detector.joblib")

    # 4. Train Multiclass XGBoost Attack Classifier
    print("\n[Step 4/6] Training Supervised Multiclass XGBoost Attack Classifier...")
    attack_classifier = AttackClassifier(
        n_estimators=180,
        max_depth=5,
        learning_rate=0.08,
        random_state=42,
    )
    attack_classifier.fit(
        X_train_scaled,
        splits.y_train,
        eval_set=[(X_val_scaled, splits.y_val)],
        early_stopping_rounds=15,
        verbose=False,
    )

    eval_report = attack_classifier.evaluate(X_test_scaled, splits.y_test)
    print("\n  Classification Performance Evaluation (Test Set):")
    print(eval_report.summary_table())

    print("  Confusion Matrix:")
    print(eval_report.confusion_matrix.to_string())

    attack_classifier.save(models_dir / "attack_classifier.joblib")
    attack_classifier.save(root_models_dir / "attack_classifier.joblib")

    # 5. Train Time-Series Traffic Predictor
    print("\n[Step 5/6] Training Time-Series Traffic Rate Predictor (bytes/s, packets/s)...")
    traffic_predictor = NetworkTrafficPredictor(
        target_cols=["bytes_per_second", "packets_per_second"],
        lags=(1, 2, 5),
        rolling_windows=(3, 5),
        n_estimators=100,
        max_depth=4,
        random_state=42,
    )

    # Create chronologically ordered synthetic stream
    X_lagged, y_targets = traffic_predictor.create_lagged_features(splits.X_train)
    # Split chronologically (75% train, 25% test)
    split_idx = int(len(X_lagged) * 0.75)
    X_ts_train, X_ts_test = X_lagged.iloc[:split_idx], X_lagged.iloc[split_idx:]
    y_ts_train, y_ts_test = y_targets.iloc[:split_idx], y_targets.iloc[split_idx:]

    traffic_predictor.fit(X_ts_train, y_ts_train)
    ts_report = traffic_predictor.evaluate(X_ts_test, y_ts_test)
    print("  " + ts_report.summary().replace("\n", "\n  "))

    traffic_predictor.save(models_dir / "traffic_predictor.joblib")
    traffic_predictor.save(root_models_dir / "traffic_predictor.joblib")

    # 6. Initialize TreeSHAP and Generate Human-Readable Explanations
    print("\n[Step 6/6] Initializing TreeSHAP Explainer & Generating SOC Incident Narratives...")
    explainer = NetMindExplainer(attack_classifier)

    # Sample each attack class from the test set to display clear human explanations
    print("\n  --- Sample Alert Explanations for Incident Responders ---")
    for cls_id in [1, 2, 3, 4]:
        cls_name = ATTACK_CLASS_MAP[cls_id]
        matches = splits.X_test[splits.y_test == cls_id]
        if not matches.empty:
            sample_scaled = X_test_scaled.loc[matches.index[0:1]]
            exp = explainer.explain_instance(sample_scaled, target_class=cls_id, top_k=3)
            print(f"\n  [ALERT] Predicted: {exp.predicted_class_name} (Confidence: {exp.class_probability:.1%})")
            print(f"  Base Value (Prior): {exp.base_value:+.2f}")
            print("  Top Explainability Reasons:")
            for reason in exp.human_readable_reasons:
                print(f"    * {reason}")

    print("\n" + "=" * 80)
    print("Phase 2 Model Training Complete. Serialized Artifacts Available in:")
    print(f"  - {models_dir}")
    print(f"  - {root_models_dir}")
    print("=" * 80)


if __name__ == "__main__":
    run_training_pipeline()
