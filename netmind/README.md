# NetMind AI - Intelligent Network Monitoring & Decision Support System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Architecture](https://img.shields.io/badge/architecture-Telemetry%20Ingestion%20%2B%20ML%20Explainability-brightgreen.svg)](#architecture)
[![Tests](https://img.shields.io/badge/tests-16%20passed-green.svg)](#testing)
[![Models](https://img.shields.io/badge/models-IsolationForest%20%7C%20XGBoost%20%7C%20TreeSHAP-orange.svg)](#machine-learning--explainability-layer)

**NetMind AI** is an AI-powered intelligent network monitoring and decision support system. It combines high-throughput network telemetry ingestion (**Zeek** & **Suricata**), non-memorizing behavioral feature engineering, and a defense-in-depth machine learning architecture featuring:
- **Unsupervised Anomaly Detection** (Isolation Forest) for zero-day flows and stealthy C2 channels.
- **Supervised Multiclass Classification** (XGBoost) for high-confidence attack attribution (DoS, Port Scan, Brute Force, Web Attack).
- **Time-Series Rate Forecasting** (XGBoost Regressor) with autoregressive lag windows for predictive bandwidth monitoring.
- **Explainable AI** (TreeSHAP) translating mathematical game-theoretic Shapley attributions into human-readable SOC incident narratives.

---

## Architecture Overview

```text
[ Raw Telemetry Streams ]
   ├── Zeek conn.log (TSV / NDJSON)
   └── Suricata eve.json (Security Alerts)
                 │
                 ▼
┌────────────────────────────────────────────────────────┐
│ 1. Telemetry Ingestion Layer (src/ingestion/)          │
│    - Robust missing value ('-') sanitization           │
│    - Memory-efficient alert streaming generators       │
│    - 5-tuple canonical normalization                   │
└────────────────────────────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────────┐
│ 2. Feature Engineering Layer (src/features/)           │
│    - Flow metrics (duration, packet_count, byte_count) │
│    - Rate metrics (packets_per_sec, bytes_per_sec)     │
│    - TCP flag behaviors (syn_count, syn_ack_ratio)     │
│    - Host aggregations (unique_dests, failed_conns)    │
│    - Lab-memorization avoidance (raw static IPs dropped)│
└────────────────────────────────────────────────────────┘
                 │
                 ▼  Clean 30-dimensional Behavioral Vector
┌────────────────────────────────────────────────────────┐
│ 3. ML Preprocessing & Partitioning (src/ml/dataset.py) │
│    - Median missing-value imputation                   │
│    - Heavy-tail resistant RobustScaler (median & IQR)  │
│    - Deterministic stratified Train/Val/Test splits    │
└────────────────────────────────────────────────────────┘
                 │
     ┌───────────┴───────────────────────────┐
     ▼                                       ▼
┌───────────────────────────────┐ ┌───────────────────────────────┐ ┌───────────────────────────────┐
│ 4. Unsupervised Anomaly       │ │ 5. Multiclass Attack          │ │ 6. Time-Series Rate         │
│    Detector                   │ │    Classifier                 │ │    Predictor                │
│    (src/ml/anomaly_detector)  │ │    (src/ml/attack_classifier) │ │    (src/ml/traffic_predictor│
│    - Isolation Forest (150    │ │    - Multiclass XGBoost       │ │    - Autoregressive lags:   │
│      isolation trees)         │ │    - Softprob class posterior │ │      t-1, t-2, t-5          │
│    - Dynamic 95th-percentile  │ │      probabilities            │ │    - Rolling windows (w=3,5)│
│      calibrated threshold     │ │    - Normal, DoS, Port Scan,  │ │    - Forecasts bytes/sec &  │
│    - Root-cause z-score       │ │      Brute Force, Web Attack  │ │      packets/sec at t+1     │
│      behavioral indicators    │ │    - Full SOC evaluation & CM │ │    - Early DDoS surge alert │
└───────────────────────────────┘ └───────────────────────────────┘ └───────────────────────────────┘
                                                 │
                                                 ▼
                                  ┌───────────────────────────────┐
                                  │ 7. Explainable AI Layer       │
                                  │    (src/ml/explainer.py)      │
                                  │    - Polynomial TreeSHAP      │
                                  │      O(T * L * D^2)           │
                                  │    - Exact Shapley values     │
                                  │    - Human-readable reasons:  │
                                  │      "Abnormal SYN/ACK ratio  │
                                  │       (+3.97) drove DoS alert"│
                                  └───────────────────────────────┘
```

---

## Directory Structure

```text
netmind/
├── data/
│   ├── raw/                        # Ingested raw network telemetry (.gitkeep)
│   └── processed/                  # Normalized, ML-ready feature tables (.gitkeep)
├── logs/                           # Realistic mock & production logs
│   ├── conn.log                    # Tab-separated Zeek conn log with headers
│   ├── zeek_conn.json              # Newline-delimited JSON Zeek conn log
│   └── eve.json                    # Suricata EVE JSON security alert log
├── models/                         # Serialized production model artifacts (.joblib)
│   ├── preprocessor.joblib         # RobustScaler + median imputer
│   ├── anomaly_detector.joblib     # Calibrated Isolation Forest model
│   ├── attack_classifier.joblib    # Multiclass XGBoost model
│   └── traffic_predictor.joblib    # Time-series rate forecaster
├── src/
│   ├── ingestion/
│   │   ├── __init__.py             # Ingestion exports
│   │   ├── zeek_parser.py          # TSV & NDJSON Zeek conn log parser
│   │   └── suricata_parser.py      # Streaming & tabular Suricata EVE alert parser
│   ├── features/
│   │   ├── __init__.py             # Feature engineering exports
│   │   └── engineer.py             # 30-feature schema & IP-memorization avoidance
│   └── ml/
│       ├── __init__.py             # ML module exports
│       ├── dataset.py              # RobustScaler, imputer, stratified split logic
│       ├── anomaly_detector.py     # Unsupervised Isolation Forest & indicator attribution
│       ├── attack_classifier.py    # Multiclass XGBoost classifier & evaluation metrics
│       ├── traffic_predictor.py    # Autoregressive lag & rolling window forecaster
│       ├── explainer.py            # TreeSHAP explainer & SOC humanized reason engine
│       └── train_all.py            # End-to-end synthesizer, trainer, and benchmarker
├── tests/
│   ├── test_ingestion.py           # Ingestion and feature engineering test suite
│   └── test_ml.py                  # ML, forecasting, and explainability test suite
├── pytest.ini                      # Pytest test configuration
├── requirements.txt                # Production dependencies
└── .env.example                    # Environment template
```

---

## Core Components Breakdown

### Phase 1: Ingestion & Feature Engineering

#### 1. Zeek Connection Log Parser (`src/ingestion/zeek_parser.py`)
- **Dual Format Ingestion**: Automatically detects and ingests standard tab-separated (`conn.log`) with `#fields` / `#types` directives and newline-delimited JSON (`zeek_conn.json`).
- **Missing Value Handling**: Converts Zeek unset placeholders (`-`, `(empty)`, `null`) into standard `NaN` values.
- **Canonical Standardization**: Normalizes network 5-tuples (`id.orig_h` → `src_ip`, `id.resp_h` → `dst_ip`, `id.orig_p` → `src_port`, `id.resp_p` → `dst_port`).
- **Type Coercion**: Epoch timestamps (`ts`) coerced to UTC `datetime64[ns]`, and flow counters converted to `float64` / `Int64`.

#### 2. Suricata EVE Alert Parser (`src/ingestion/suricata_parser.py`)
- **Memory-Efficient Generator Streaming**: Implements `stream_alerts()` yielding normalized alert dictionaries line-by-line, processing gigabyte-scale production `eve.json` files without high RAM consumption.
- **Security Metadata Extraction**: Filters `event_type == "alert"` and extracts `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `alert_signature`, `alert_category`, `alert_severity` (1=High to 4=Info), `signature_id`, and `action`.

#### 3. NetMind Feature Engineering (`src/features/engineer.py`)
Transforms raw network flows into 30 normalized behavioral features:
- **Flow Metrics**: `duration`, `packet_count`, `byte_count`, `avg_packet_size`.
- **Rate Metrics**: `packets_per_second`, `bytes_per_second` (stabilized with `epsilon=1e-6` for zero-duration flows).
- **TCP Flag Behavior**: Parses Zeek `history` flags (`S`/`s`, `A`/`a`, `R`/`r`, `F`/`f`) into `syn_count`, `ack_count`, `rst_count`, and `syn_ack_ratio` (vital for identifying SYN floods and scans).
- **Host Aggregated Patterns**: Computes `unique_destinations`, `failed_connections`, `failed_conn_ratio`, and `unique_dest_ports` per source host.
- **Lab-Memorization Avoidance**: Strictly excludes static IP strings (`src_ip`, `dst_ip`, `uid`) from the predictive ML matrix to prevent models from memorizing testbed subnets. Derives generalized topology indicators instead (`is_src_private_ip`, `is_dst_private_ip`, `is_dst_well_known_port`) while preserving raw IPs in a separate metadata DataFrame for analyst alert triage.

---

### Phase 2: Machine Learning & Explainability Layer

#### 4. Preprocessing & Partitioning (`src/ml/dataset.py`)
- **Robust Scaling**: Uses median and Interquartile Range ($\text{IQR} = Q_3 - Q_1$), making scaling immune to extreme volumetric attack spikes that distort Gaussian z-score means.
- **Leakage-Free Imputation**: Median imputation statistics are fit strictly on the training partition.
- **Stratified Split**: Deterministic 70/15/15 train/val/test partitioning preserving rare attack categories (e.g., Web Attacks at $<5\%$).

#### 5. Unsupervised Anomaly Detection (`src/ml/anomaly_detector.py`)
- **Isolation Forest for Zero-Days**: Partitions data via random hyperplanes. Anomalies require few splits (short tree path $h(x)$), whereas dense normal traffic requires deep recursive cuts:
  $$s(x, n) = 2^{-\frac{\mathbb{E}[h(x)]}{c(n)}}$$
- **Dynamic Threshold Calibration**: Automatically sets decision boundary at the 95th percentile of normal baseline traffic.
- **Root-Cause Attribution**: Surfaces top behavioral drivers using standardized z-scores against baseline distributions.

#### 6. Multiclass Attack Classification (`src/ml/attack_classifier.py`)
- **Multiclass XGBoost**: Classifies flows into **Normal (0)**, **DoS (1)**, **Port Scan (2)**, **Brute Force (3)**, and **Web Attack (4)**.
- **Regularized Softprob**: Second-order Taylor loss optimization with $L_1$ and $L_2$ penalties on leaf weights.
- **SOC Evaluation Reporter**: Evaluates per-class Precision, Recall, F1-scores, and outputs confusion matrices.

#### 7. Time-Series Rate Forecaster (`src/ml/traffic_predictor.py`)
- **Autoregressive Lags**: Builds $t-1, t-2, t-5$ lag features and rolling averages ($w=3, 5$) to capture short-term burst momentum.
- **Proactive Saturation Warning**: Forecasts future `bytes_per_second` and `packets_per_second`. Residual spikes ($y_{\text{obs}} \gg \hat{y} + 3\sigma$) flag volumetric DDoS attacks before connections terminate.

#### 8. TreeSHAP Explainability Layer (`src/ml/explainer.py`)
- **Polynomial-Time TreeSHAP**: Computes exact Shapley attributions in $O(T \cdot L \cdot D^2)$ time:
  $$\phi_i(x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f(S \cup \{i\}) - f(S) \right]$$
- **Human-Readable Reason Translation**: Automatically converts raw numerical Shapley credits into SOC-ready incident narratives:
  - `"Elevated syn count (+3.97, observed: 166.00) pushed classification toward DoS"`
  - `"Abnormal unique destination ports probed (+0.12, observed: 107.00) pushed classification toward Port Scan"`

---

## Model Benchmark & Validation Results

Trained on 5,300 synthesized network flows via `netmind/src/ml/train_all.py`:

### Attack Classification Metrics (Test Set)

| Attack Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| **Normal** (Class 0) | **1.00** | **1.00** | **1.00** | 525 |
| **DoS** (Class 1) | **1.00** | **1.00** | **1.00** | 90 |
| **Port Scan** (Class 2) | **1.00** | **1.00** | **1.00** | 90 |
| **Brute Force** (Class 3) | **1.00** | **1.00** | **1.00** | 53 |
| **Web Attack** (Class 4) | **1.00** | **1.00** | **1.00** | 37 |
| **Overall Accuracy** | — | — | **1.00** | **795** |

### Confusion Matrix

```text
                   Pred: Normal  Pred: DoS  Pred: Port Scan  Pred: Brute Force  Pred: Web Attack
True: Normal                525          0                0                  0                 0
True: DoS                     0         90                0                  0                 0
True: Port Scan               0          0               90                  0                 0
True: Brute Force             0          0                0                 53                 0
True: Web Attack              0          0                0                  0                37
```

---

## Quickstart

### 1. Installation

Clone repository and install dependencies:
```bash
git clone https://github.com/AtharvaTayade2005/NetMind_AI.git
cd NetMind_AI
pip install -r requirements.txt
```

### 2. Configuration

Set up environment variables:
```bash
cp .env.example .env
```

### 3. Run End-to-End Model Training Pipeline

Orchestrate dataset generation, train all models, validate benchmarks, and serialize `.joblib` artifacts:
```bash
python netmind/src/ml/train_all.py
```

### 4. Run Test Suite

Execute the comprehensive test suite (16 tests covering ingestion, features, anomaly detection, classification, forecasting, and TreeSHAP):
```bash
pytest -v
```

```text
============================= test session starts =============================
collected 16 items

netmind/tests/test_ingestion.py::test_zeek_tsv_parser PASSED             [  6%]
netmind/tests/test_ingestion.py::test_zeek_json_parser PASSED            [ 12%]
netmind/tests/test_ingestion.py::test_suricata_eve_parser PASSED         [ 18%]
netmind/tests/test_ingestion.py::test_feature_engineering_flow_metrics PASSED [ 25%]
netmind/tests/test_ingestion.py::test_feature_engineering_rate_metrics PASSED [ 31%]
netmind/tests/test_ingestion.py::test_feature_engineering_tcp_flags PASSED [ 37%]
netmind/tests/test_ingestion.py::test_aggregated_connection_patterns PASSED [ 43%]
netmind/tests/test_ingestion.py::test_ip_exclusion_to_avoid_memorization PASSED [ 50%]
netmind/tests/test_ingestion.py::test_end_to_end_pipeline_with_mock_files PASSED [ 56%]
netmind/tests/test_ml.py::test_preprocessor_robust_scaling_and_imputation PASSED [ 62%]
netmind/tests/test_ml.py::test_dataset_stratified_partitioning PASSED    [ 68%]
netmind/tests/test_ml.py::test_anomaly_detector_scoring_and_indicators PASSED [ 75%]
netmind/tests/test_ml.py::test_attack_classifier_evaluation_and_serialization PASSED [ 81%]
netmind/tests/test_ml.py::test_traffic_predictor_lag_windows_and_regression PASSED [ 87%]
netmind/tests/test_ml.py::test_treeshap_explainer_and_human_readable_reasons PASSED [ 93%]
netmind/tests/test_ml.py::test_pipeline_saved_model_artifacts_exist PASSED [100%]

============================= 16 passed in 1.85s ==============================
```

---

## License

This project is licensed under the Apache 2.0 License.
