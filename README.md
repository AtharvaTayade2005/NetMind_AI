# NetMind AI - Intelligent Network Monitoring & Decision Support System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![SQLAlchemy 2.0](https://img.shields.io/badge/SQLAlchemy-2.0+-red.svg)](https://www.sqlalchemy.org/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2+-e92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/tests-33%20passed-green.svg)](#testing)
[![Models](https://img.shields.io/badge/models-IsolationForest%20%7C%20XGBoost%20%7C%20TreeSHAP-orange.svg)](#machine-learning--explainability-layer)

**NetMind AI** is an AI-powered intelligent network monitoring and decision support system. It combines high-throughput network telemetry ingestion (**Zeek** & **Suricata**), non-memorizing behavioral feature engineering, and a defense-in-depth machine learning architecture featuring:
- **Unsupervised Anomaly Detection** (Isolation Forest) for zero-day flows and stealthy C2 channels.
- **Supervised Multiclass Classification** (XGBoost) for high-confidence attack attribution (DoS, Port Scan, Brute Force, Web Attack).
- **Time-Series Rate Forecasting** (XGBoost Regressor) with autoregressive lag windows for predictive bandwidth monitoring.
- **Explainable AI** (TreeSHAP) translating mathematical game-theoretic Shapley attributions into human-readable SOC incident narratives.
- **Persistence, Scoring & API Serving Layer** (FastAPI, SQLAlchemy 2.0, PostgreSQL/TimescaleDB) featuring a multi-vector Decision Engine and incident triage workflows.

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
                                                 │
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 8. Persistence, Scoring & API Serving Layer (src/backend/)                                      │
│    - PostgreSQL / SQLAlchemy 2.0 Typed ORM Models with composite time & IP indexes             │
│    - Pydantic v2 Data Contracts (ConfigDict from_attributes)                                    │
│    - Repository Pattern isolating database queries and mutations                                │
│    - Decision Engine: Composite Risk = 0.40*Sec + 0.25*Anom + 0.20*Perf + 0.15*Hist             │
│    - Containment Playbooks: QUARANTINE_HOST, RATE_LIMIT_PORT, BLOCK_SOURCE_IP                   │
│    - FastAPI REST Service: /api/network/status, /api/threats, /api/predict/attack, etc.         │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
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
│   ├── ingestion/                  # Phase 1: Ingestion Parsers
│   │   ├── __init__.py
│   │   ├── zeek_parser.py          # TSV & NDJSON Zeek conn log parser
│   │   └── suricata_parser.py      # Streaming & tabular Suricata EVE alert parser
│   ├── features/                   # Phase 1: Feature Engineering
│   │   ├── __init__.py
│   │   └── engineer.py             # 30-feature schema & IP-memorization avoidance
│   ├── ml/                         # Phase 2: Machine Learning & Explainability
│   │   ├── __init__.py
│   │   ├── dataset.py              # RobustScaler, imputer, stratified split logic
│   │   ├── anomaly_detector.py     # Unsupervised Isolation Forest & indicator attribution
│   │   ├── attack_classifier.py    # Multiclass XGBoost classifier & evaluation metrics
│   │   ├── traffic_predictor.py    # Autoregressive lag & rolling window forecaster
│   │   ├── explainer.py            # TreeSHAP explainer & SOC humanized reason engine
│   │   └── train_all.py            # End-to-end synthesizer, trainer, and benchmarker
│   ├── backend/                    # Phase 3: Persistence, Scoring & API Serving
│   │   ├── __init__.py
│   │   ├── database.py             # Connection lifecycle & SQLAlchemy 2.0 session factory
│   │   ├── models.py               # Typed PostgreSQL ORM models with composite indexes
│   │   ├── schemas.py              # Pydantic v2 validation & response contracts
│   │   ├── repository.py           # Clean Repository pattern data access layer
│   │   ├── decision_engine.py      # Composite risk scoring algorithm & mitigation rules
│   │   ├── main.py                 # FastAPI application entrypoint with lifespan
│   │   └── routers/
│   │       ├── __init__.py
│   │       ├── status.py           # GET /api/network/status overview
│   │       ├── threats.py          # GET /api/threats, /api/anomalies, review endpoint
│   │       ├── predictions.py      # GET /api/predictions rate forecasts
│   │       ├── recommendations.py  # GET /api/recommendations & mitigation approvals
│   │       └── inference.py        # POST /api/predict/attack & /api/predict/anomaly
│   └── worker/                     # Phase 5: Background Telemetry Streaming
│       ├── __init__.py
│       └── log_tailer.py           # Zeek & Suricata offset tracking, rotation-resilient daemon
├── frontend/                       # Phase 4: Clean Neutral SOC Web Portal
│   ├── src/                        # React 18 + TypeScript + Recharts + FontAwesome components
│   ├── Dockerfile                  # Multi-stage production container build (Node.js -> Nginx)
│   ├── nginx.conf                  # Production reverse proxy and static asset server
│   └── package.json
├── scripts/                        # Phase 5: Testing & Automation Tooling
│   └── traffic_generator.py        # Safe loopback generator (Baseline, Port Probe, Burst)
├── tests/                          # 33 Comprehensive Unit & Integration Tests
│   ├── test_ingestion.py           # Phase 1 tests (9 passed)
│   ├── test_ml.py                  # Phase 2 tests (7 passed)
│   ├── test_backend.py             # Phase 3 tests (12 passed)
│   └── test_integration.py         # Phase 5 tests (5 passed)
├── Dockerfile                      # Root container for Backend API and Worker daemon
├── docker-compose.yml              # Multi-container orchestration (Postgres, Backend, Worker, Frontend)
├── pytest.ini                      # Pytest test configuration
├── requirements.txt                # Production dependencies
└── .env.example                    # Environment template with Phase 5 parameters
```

---

## Architectural Separation of Concerns

NetMind AI strictly enforces a tri-layer separation of concerns between storage, public contracts, and automated reasoning:

```
┌────────────────────────┐       ┌────────────────────────┐       ┌────────────────────────┐
│  SQLAlchemy 2.0 ORM    │       │   Pydantic v2 Schemas  │       │    Decision Engine     │
│       (models.py)      │       │      (schemas.py)      │       │  (decision_engine.py)  │
├────────────────────────┤       ├────────────────────────┤       ├────────────────────────┤
│ • Persistence & Tables │       │ • Public API Contracts │       │ • Multi-vector Risk    │
│ • Database Constraints │       │ • Input Validation     │ │   Scoring Formula      │
│ • Foreign Keys         │◄─────►│ • Type Coercion        │◄─────►│ • Rule-based Mitigation│
│ • Composite Indexes    │       │ • JSON Serialization   │       │   Playbook Mapping     │
│ • Relational Cascades  │       │ • Zero-copy attributes │       │ • SOC Containment      │
└────────────────────────┘       └────────────────────────┘       └────────────────────────┘
```

1. **SQLAlchemy 2.0 ORM Models (`models.py`)**:
   - Solely responsible for relational schema definitions, foreign key integrity, and database query efficiency.
   - Declares explicit composite indexes (`src_ip, dst_ip, timestamp`) to prevent sequential scans in multi-million row telemetry tables.
   - Completely decoupled from incoming HTTP payloads or serialization logic.

2. **Pydantic v2 Schemas (`schemas.py`)**:
   - Enforces strict input validation, range bounds, and canonical representations for incoming REST payloads.
   - Uses `ConfigDict(from_attributes=True)` to convert SQLAlchemy ORM instances into outgoing JSON responses.
   - Prevents sensitive internal columns from leaking into public APIs.

3. **Decision Engine (`decision_engine.py`)**:
   - Pure domain business logic and automated risk reasoning.
   - Contains no database session dependencies or FastAPI route decorators.
   - Evaluates multi-vector telemetry metrics and outputs structured incident mitigation proposals.

4. **Repository Pattern (`repository.py`)**:
   - Isolates all database operations (CRUD, filtering, pagination, and aggregates) into testable classes (`HostRepository`, `SecurityEventRepository`, etc.).
   - Routers remain thin, focusing purely on HTTP status codes and serialization.

---

## Phase 3: Decision Engine & Risk Scoring Algorithm

### Composite Risk Formulation

Single-indicator alerting (e.g. firing purely on packet rate spikes) triggers severe SOC false-positive alert fatigue. NetMind AI computes a composite risk score fusing four orthogonal dimensions:

$$\text{Risk} = 0.40 \times \text{SecurityRisk} + 0.25 \times \text{AnomalyScore} + 0.20 \times \text{PerformanceRisk} + 0.15 \times \text{HistoricalRisk}$$

| Component | Weight | Source | Domain Justification |
| :--- | :---: | :--- | :--- |
| **SecurityRisk** | **40%** | Multiclass XGBoost & IDS alerts | Direct attack evidence scaled by model probability confidence ($[0, 100]$). |
| **AnomalyScore** | **25%** | Isolation Forest detector | Unsupervised zero-day score capturing novel behavioral drift ($[0, 1] \times 100$). |
| **PerformanceRisk** | **20%** | Interface throughput telemetry | Bandwidth or packet rate saturation relative to interface capacity ($[0, 100]$). |
| **HistoricalRisk** | **15%** | Host incident history | Recurrence penalty for repeat offender hosts or past quarantine actions ($[0, 100]$). |

### Risk Categorization Tiers

- **LOW (0 – 25)**: Nominal enterprise baseline; standard observability.
- **MEDIUM (26 – 50)**: Elevated telemetry variance; passive sampling and analyst awareness.
- **HIGH (51 – 75)**: Confirmed adversarial technique; automated rate limiting and credential isolation.
- **CRITICAL (76 – 100)**: Active severe breach; perimeter drop and host quarantine.

### Automated Mitigation Playbooks

| Detected Threat | Risk Tier | Containment Action | Playbook Rationale |
| :--- | :---: | :--- | :--- |
| **DoS** | **CRITICAL** | `RATE_LIMIT_PORT` & `BLOCK_SOURCE_IP` | Throttle destination port connection pool; apply edge ACL drop on attacking IP. |
| **Port Scan** | **HIGH** | `BLOCK_SOURCE_IP` | Temporarily drop source connection attempts to suppress target mapping. |
| **Brute Force** | **HIGH** | `LOCK_USER_CREDENTIALS` & `QUARANTINE_HOST` | Invalidate active auth tokens, enforce MFA step-up, isolate offending host. |
| **Web Attack** | **CRITICAL** | `WAF_BLOCK_URI_PATTERN` | Deploy virtual patch rule to Web Application Firewall chain. |
| **Novel Anomaly** | **HIGH** | `DEEP_PACKET_INSPECTION` | High anomaly score without signature match; triggers full session PCAP capture. |
| **Normal Flow** | **LOW** | `MONITOR_BASELINE` | Conforms to enterprise baseline; continue passive telemetry collection. |

---

## REST API Reference & Sample `curl` Commands

### 1. Health Verification

Verify backend service availability:
```bash
curl -X GET http://localhost:8000/health
```
```json
{
  "status": "online",
  "service": "NetMind AI API",
  "timestamp": "2026-10-10T14:00:00.000000Z"
}
```

### 2. Network Status Overview

Get macro-level network health, telemetry rates, and threat counts:
```bash
curl -X GET http://localhost:8000/api/network/status
```
```json
{
  "system_status": "HEALTHY",
  "active_risk_level": "LOW",
  "average_risk_score": 18.5,
  "total_hosts": 4,
  "active_hosts": 3,
  "quarantined_hosts": 1,
  "active_threats_count": 2,
  "unresolved_anomalies_count": 1,
  "pending_recommendations_count": 1,
  "current_bandwidth_bps": 1850000.0,
  "current_packet_rate_pps": 3200.0,
  "last_updated": "2026-10-10T14:00:00.000000Z"
}
```

### 3. Threat Detections (Paginated)

Retrieve active security events with optional severity filter:
```bash
curl -X GET "http://localhost:8000/api/threats?page=1&page_size=10&severity=HIGH"
```

### 4. Zero-Day Anomalies

List unsupervised Isolation Forest anomaly detections:
```bash
curl -X GET "http://localhost:8000/api/anomalies?page=1&page_size=10&status=open"
```

### 5. Telemetry Rate Predictions

Retrieve time-series bandwidth forecasts:
```bash
curl -X GET "http://localhost:8000/api/predictions?target=bytes_per_second"
```

### 6. Mitigation Recommendations

List pending containment recommendations:
```bash
curl -X GET "http://localhost:8000/api/recommendations?status=pending"
```

Approve or apply a recommendation:
```bash
curl -X POST http://localhost:8000/api/recommendations/1/review \
  -H "Content-Type: application/json" \
  -d '{
    "status": "approved",
    "reviewed_by": "sec_analyst_lead"
  }'
```

### 7. Incident Review & Resolution

Acknowledge or resolve an active security event:
```bash
curl -X POST http://localhost:8000/api/events/1/review \
  -H "Content-Type: application/json" \
  -d '{
    "status": "resolve",
    "reviewed_by": "ir_lead_01",
    "notes": "Verified malicious source IP blocked at perimeter firewall."
  }'
```

### 8. Real-Time Attack Scoring (XGBoost + TreeSHAP)

Submit a live flow feature vector for real-time attack attribution, TreeSHAP explanation, and Decision Engine mitigation:
```bash
curl -X POST http://localhost:8000/api/predict/attack \
  -H "Content-Type: application/json" \
  -d '{
    "duration": 0.005,
    "packet_count": 200.0,
    "byte_count": 12000.0,
    "orig_bytes": 12000.0,
    "resp_bytes": 0.0,
    "orig_pkts": 200.0,
    "resp_pkts": 0.0,
    "syn_count": 200.0,
    "ack_count": 0.0,
    "rst_count": 0.0,
    "fin_count": 0.0,
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
    "dst_ip": "10.0.0.50"
  }'
```
```json
{
  "predicted_class_id": 1,
  "predicted_class_name": "DoS",
  "confidence": 0.9991,
  "class_probabilities": {
    "Normal": 0.0001,
    "DoS": 0.9991,
    "Port Scan": 0.0004,
    "Brute Force": 0.0002,
    "Web Attack": 0.0002
  },
  "top_explainability_reasons": [
    "Elevated syn count (+3.97, observed: 200.00) pushed classification toward DoS",
    "Abnormal ratio of failed connections (+0.80, observed: 1.00) pushed classification toward DoS"
  ],
  "risk_score": 90.0,
  "risk_category": "CRITICAL",
  "recommended_action": "RATE_LIMIT_PORT",
  "recommendation_reason": "High-volume DoS detected from 192.168.1.205. Rate limit destination port 80."
}
```

### 9. Real-Time Anomaly Scoring (Isolation Forest)

Submit a flow vector to evaluate unsupervised zero-day deviation:
```bash
curl -X POST http://localhost:8000/api/predict/anomaly \
  -H "Content-Type: application/json" \
  -d '{
    "duration": 1.25,
    "packet_count": 15.0,
    "byte_count": 3200.0,
    "orig_bytes": 800.0,
    "resp_bytes": 2400.0,
    "orig_pkts": 6.0,
    "resp_pkts": 9.0,
    "syn_count": 1.0,
    "ack_count": 12.0,
    "rst_count": 0.0,
    "fin_count": 2.0,
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
    "proto_icmp": 0.0
  }'
```

---

## Quickstart & Service Execution

### 1. Installation

```bash
git clone https://github.com/AtharvaTayade2005/NetMind_AI.git
cd NetMind_AI
pip install -r requirements.txt
cp .env.example .env
```

### 2. Generate Model Artifacts

Orchestrate training of all Phase 2 model artifacts into `models/`:
```bash
python netmind/src/ml/train_all.py
```

### 3. Start the FastAPI Service

Launch the production Uvicorn server:
```bash
uvicorn src.backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger UI documentation is available at: `http://localhost:8000/docs`

### 4. Run the Full Test Suite

Execute all 28 unit and integration tests (Ingestion, ML, Decision Engine, and Backend REST APIs):
```bash
pytest -v
```

```text
============================= test session starts =============================
platform win32 -- Python 3.14.0, pytest-9.1.1
rootdir: D:\Coding\GitHub\NetMind_AI
configfile: pytest.ini
collected 28 items

netmind/tests/test_backend.py::test_host_and_event_orm_relationships PASSED [  3%]
netmind/tests/test_backend.py::test_decision_engine_risk_calculation_formula PASSED [  7%]
netmind/tests/test_backend.py::test_decision_engine_categorization_tiers PASSED [ 10%]
netmind/tests/test_backend.py::test_decision_engine_mitigation_rules PASSED [ 14%]
netmind/tests/test_backend.py::test_api_health_endpoint PASSED           [ 17%]
netmind/tests/test_backend.py::test_api_network_status_overview PASSED   [ 21%]
netmind/tests/test_backend.py::test_api_threats_and_anomalies_pagination PASSED [ 25%]
netmind/tests/test_backend.py::test_api_predictions_endpoint PASSED      [ 28%]
netmind/tests/test_backend.py::test_api_recommendations_and_review PASSED [ 32%]
netmind/tests/test_backend.py::test_api_event_review_endpoint PASSED     [ 35%]
netmind/tests/test_backend.py::test_api_predict_attack_endpoint PASSED   [ 39%]
netmind/tests/test_backend.py::test_api_predict_anomaly_endpoint PASSED  [ 42%]
netmind/tests/test_ingestion.py::test_zeek_tsv_parser PASSED             [ 46%]
netmind/tests/test_ingestion.py::test_zeek_json_parser PASSED            [ 50%]
netmind/tests/test_ingestion.py::test_suricata_eve_parser PASSED         [ 53%]
netmind/tests/test_ingestion.py::test_feature_engineering_flow_metrics PASSED [ 57%]
netmind/tests/test_ingestion.py::test_feature_engineering_rate_metrics PASSED [ 60%]
netmind/tests/test_ingestion.py::test_feature_engineering_tcp_flags PASSED [ 64%]
netmind/tests/test_ingestion.py::test_aggregated_connection_patterns PASSED [ 67%]
netmind/tests/test_ingestion.py::test_ip_exclusion_to_avoid_memorization PASSED [ 71%]
netmind/tests/test_ingestion.py::test_end_to_end_pipeline_with_mock_files PASSED [ 75%]
netmind/tests/test_ml.py::test_preprocessor_robust_scaling_and_imputation PASSED [ 78%]
netmind/tests/test_ml.py::test_dataset_stratified_partitioning PASSED    [ 82%]
netmind/tests/test_ml.py::test_anomaly_detector_scoring_and_indicators PASSED [ 85%]
netmind/tests/test_ml.py::test_attack_classifier_evaluation_and_serialization PASSED [ 89%]
netmind/tests/test_ml.py::test_traffic_predictor_lag_windows_and_regression PASSED [ 92%]
netmind/tests/test_ml.py::test_treeshap_explainer_and_human_readable_reasons PASSED [ 96%]
netmind/tests/test_ml.py::test_pipeline_saved_model_artifacts_exist PASSED [100%]

======================== 28 passed, 1 warning in 2.38s ========================
```

---

## Phase 4: Frontend Monitoring & Decision Support Portal (`frontend/`)

NetMind AI provides a clean, authentic, human-engineered monitoring and decision support portal built for network operations and security analysts, adhering to standard, disciplined frontend design practices.

### Design Principles & Visual Style
- **Neutral Canvas**: Clean light neutral canvas (`#f8fafc` / `#f1f5f9`), solid white cards (`#ffffff`) with 1px structural borders (`#e2e8f0`), and realistic subtle shadows (`shadow-sm`).
- **Utilitarian Colors**:
  - Primary Theme: Deep navy/slate (`#0f172a` and `#1e3a8a`).
  - Normal / Healthy: Forest Green (`bg-emerald-100 text-emerald-800 border-emerald-300`).
  - Warning / Anomaly: Amber (`bg-amber-100 text-amber-800 border-amber-300`).
  - High / Critical Threat: Dark Crimson (`bg-rose-100 text-rose-800 border-rose-300`).
  - Telemetry / Informational: Slate/Blue (`bg-blue-100 text-blue-800 border-blue-300`).
- **Typography**: Google Font **Inter** for clean UI labels, metrics, and navigation; standard monospace (`font-mono`) exclusively for IP addresses, MAC addresses, ports, hex, and timestamps.
- **Icons**: Standard **Font Awesome** icons via `@fortawesome/react-fontawesome` (`faNetworkWired`, `faServer`, `faShieldHalved`, `faTriangleExclamation`, `faChartLine`, `faBrain`, `faEye`, `faCheck`).

### Technology Stack
- **Framework**: React 18 (`react@18.3.1`, `react-dom@18.3.1`)
- **Language**: TypeScript (`typescript@5.6.3`)
- **Styling**: Tailwind CSS (`tailwindcss@3.4.14`)
- **Iconography**: Font Awesome (`@fortawesome/react-fontawesome`, `@fortawesome/free-solid-svg-icons`)
- **Charts & Graphs**: Recharts (`recharts@2.13.3`)
- **Build Tool**: Vite (`vite@5.4.10`)

### Core Views & Modules
1. **Global Header & Navigation**:
   - `Navbar`: System title, solid green ingestion indicator dot ("Ingestion Active: Zeek / Suricata"), and active interface selector (`Interface: eth0 [192.168.1.0/24]`).
   - `Sidebar`: Deep navy active states with badge counters for classified threats, anomalies, and recommendations.
2. **System Overview & Health (`Overview.tsx`)**:
   - Top Metric HUD: Monitored Endpoints (32 Active), Telemetry Packet Rate (2,840 pkts/sec), Overall Risk Index (68/100 HIGH), and Active Flagged Incidents (4 Requiring Review).
   - Recharts Inbound vs. Outbound throughput (Mbps) dual-line visualizer.
   - Live Zeek flow stream table with crisp borders, monospace sockets, and connection states (`SF`, `S0`).
   - Flagged incidents queue with quick-action inspection triggers.
3. **Decision Support Inspection Dialog (`ThreatDetailModal.tsx`)**:
   - Implements the core NetMind workflow: **Observe -> Understand -> Predict -> Recommend**.
   - Technical evidence: duration, packet intensity, bytes/sec, SYN/ACK ratio.
   - Explainable AI: Horizontal Recharts bar chart showing exact TreeSHAP feature attributions (`+0.44 SYN/ACK Ratio`, `+0.32 Pkts/sec delta`, `-0.08 Flow Duration`).
   - Decision Engine callout with suggested CLI command and "Acknowledge" & "Simulate Remediation" review buttons.
4. **Specialized Operations Modules**:
   - `FlowTelemetryView`: Comprehensive network flow stream with IP/service/protocol filtering.
   - `ClassifiedAttacksView`: Supervised XGBoost multiclass threat ledger.
   - `AnomaliesView`: Unsupervised Isolation Forest statistical outliers exceeding calibrated thresholds.
   - `TrafficForecastView`: Historical ingress vs. autoregressive forecast curve with $\pm 1\sigma$ confidence envelope and capacity limit warnings.
   - `RecommendationsView`: Decision Engine containment playbooks queue with executable CLI rules.

### Running the Frontend Locally (Dev Server)
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173/` in your browser.

---

## Phase 5: Local Packaging, Automated Telemetry Processing & Reproducible Testing Lab

Phase 5 completes the production deployment and automation layer for NetMind AI. It introduces:
1. **Multi-Container Orchestration (`docker-compose.yml`)**: Packages PostgreSQL, FastAPI backend, log-tailing background worker, and React/Nginx frontend into an orchestrated, production-ready stack.
2. **Rotation-Resilient Background Worker (`src/worker/log_tailer.py`)**: Continuously ingests streaming Zeek `conn.log` and Suricata `eve.json` telemetry, executes the full ML inference and risk pipeline, and updates PostgreSQL.
3. **Reproducible Testing Lab (`scripts/traffic_generator.py`)**: Generates safe, reproducible synthetic test traffic (Baseline, Port Probe, Volumetric Burst) bound defensively to loopback (`127.0.0.1`) with telemetry log emission.

---

### Multi-Container Architecture (`docker-compose.yml`)

```
                          ┌───────────────────────────┐
                          │     User / SOC Analyst    │
                          └─────────────┬─────────────┘
                                        │ HTTP:80
                                        ▼
                          ┌───────────────────────────┐
                          │   netmind-frontend        │
                          │   (React 18 + Nginx)      │
                          └─────────────┬─────────────┘
                                        │ Reverse Proxy (/api/)
                                        ▼
┌───────────────────────────┐     ┌───────────────────────────┐
│     netmind-worker        │     │    netmind-backend        │
│ (Streaming Log Daemon)    │     │   (FastAPI REST + ML)     │
└─────────────┬─────────────┘     └─────────────┬─────────────┘
              │                                 │
              │ Writes Telemetry & Alerts       │ Queries & Actions
              ▼                                 ▼
       ┌───────────────────────────────────────────────┐
       │             netmind-postgres                  │
       │     (PostgreSQL 15 Relational Store)          │
       └───────────────────────────────────────────────┘
```

The stack coordinates four interconnected container services:
- **`postgres`**: PostgreSQL 15 persistent relational store with built-in `pg_isready` healthcheck.
- **`backend`**: FastAPI application service waiting on the database healthcheck, exposing `/api/` endpoints and interactive OpenAPI documentation (`/docs`).
- **`worker`**: Background daemon continuously watching `logs/conn.log` and `logs/eve.json` with byte offset checkpointing (`logs/.tailer_checkpoint.json`).
- **`frontend`**: React 18 single-page application built via multi-stage Docker build and served via Nginx with automated reverse proxying of API calls to `backend:8000`.

---

### Quickstart: Running NetMind AI

#### Option A: Docker Compose (Recommended for Production & Packaging)

1. **Clone and Configure Environment**:
   ```bash
   cp .env.example .env
   ```

2. **Launch All Services**:
   ```bash
   docker compose up --build -d
   ```

3. **Verify Service Health**:
   ```bash
   docker compose ps
   ```
   All services (`netmind-postgres`, `netmind-backend`, `netmind-worker`, `netmind-frontend`) will report `healthy` or `running`.

4. **Access Applications**:
   - **SOC Monitoring Portal**: [http://localhost:80](http://localhost:80)
   - **FastAPI Interactive Docs (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
   - **Backend Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

5. **Stop Containers**:
   ```bash
   docker compose down
   ```

---

#### Option B: Standalone Local Setup (Development Mode)

If developing locally without Docker:

1. **Install Python & Node Dependencies**:
   ```bash
   pip install -r requirements.txt
   cd frontend && npm install && cd ..
   ```

2. **Start the FastAPI Backend Service**:
   ```bash
   uvicorn src.backend.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Start the Background Log Tailer Worker** (in a separate terminal):
   ```bash
   python src/worker/log_tailer.py --loop --poll-interval 1.0
   ```

4. **Start the React Frontend** (in a separate terminal):
   ```bash
   cd frontend
   npm run dev
   ```
   Open [http://localhost:5173](http://localhost:5173).

---

### Reproducible Testing Lab (`scripts/traffic_generator.py`)

The traffic generator simulates synthetic network activity safely within loopback (`127.0.0.1`) or private sandbox networks. It includes defensive rate-limiting and emits matching Zeek `conn.log` (TSV) and Suricata `eve.json` records to disk.

#### 1. Normal Baseline Traffic Simulation
Simulates standard HTTP requests (GET `/api/v1/health`) and DNS lookups at typical enterprise intervals:
```bash
python scripts/traffic_generator.py --scenario baseline --count 15 --target 127.0.0.1 --port 8000
```
- **Observed Behavior**: Connection state `SF`, balanced SYN/ACK ratios, low anomaly score (~0.20-0.45), classified as `Normal`.

#### 2. Sequential Port Probe Reconnaissance
Simulates an adversary scanning sequential TCP ports (`8000` to `8015` plus common services `21`, `22`, `25`, `3306`, `3389`):
```bash
python scripts/traffic_generator.py --scenario probe --target 127.0.0.1 --port 8000
```
- **Observed Behavior**: Rapid TCP connection attempts with `S0` (no response) and `REJ` (rejected) states, classified by XGBoost as `Port Scan` with high anomaly scores ($\ge 0.55$). Suricata alerts emitted.

#### 3. High-Volume Volumetric Burst Simulation
Dispatches a dense burst of synthetic packets at a controlled rate (e.g., 100 pps) to test queue ingestion, rate threshold alarms, and time-series traffic forecasting:
```bash
python scripts/traffic_generator.py --scenario burst --count 10 --rate 100 --target 127.0.0.1 --port 8000
```
- **Observed Behavior**: High packet rate and byte saturation, triggering `DoS` attack classification and immediate rate limiting mitigation proposals.

#### 4. Complete End-to-End Test Suite
Executes all three scenarios sequentially and syncs telemetry to `logs/`:
```bash
python scripts/traffic_generator.py --scenario all --emit-logs --log-dir logs
```

---

### End-to-End Validation Guide: The SOC Operational Workflow

When testing the system end-to-end, observe the data flow through the 5 core stages in the NetMind SOC Dashboard:

```
[ Step 1: Telemetry Ingestion ]
           │
           ▼
[ Step 2: Anomaly / Threat Detection ]
           │
           ▼
[ Step 3: TreeSHAP Feature Attribution ]
           │
           ▼
[ Step 4: Traffic Forecasting ]
           │
           ▼
[ Step 5: Administrative Decision Review ]
```

#### Step 1: Telemetry Ingestion
1. Start the Docker stack or local services and launch the traffic generator (`--scenario all`).
2. Open the **Overview** page at [http://localhost:80](http://localhost:80).
3. In the **Live Network Flow Telemetry** table, observe incoming Zeek connection records:
   - Source and destination IP/port pairs (e.g. `192.168.1.200:41234 -> 10.0.0.50:22`).
   - Protocols (`TCP`, `UDP`) and services (`http`, `ssl`, `dns`).
   - Connection states (`SF` for established, `S0` for SYN sent without reply, `REJ` for reset).

#### Step 2: Anomaly & Threat Detection
1. Check the **Security Posture & Risk Metric HUD**:
   - Monitored Endpoints count updates.
   - Overall Risk Index reflects the highest active threat severity (`HIGH` or `CRITICAL`).
   - Flagged Security Incidents queue lists detected attacks (`Port Scan`, `DoS`).
2. Navigate to **Classified Attacks** to view the supervised XGBoost multiclass threat ledger.
3. Navigate to **Detected Anomalies** to review unsupervised Isolation Forest statistical outliers where the anomaly score exceeds the calibrated 95th-percentile threshold.

#### Step 3: TreeSHAP Feature Attribution & Deep Dive
1. In the **Flagged Incidents** table, click the **Investigate** button next to a critical incident (e.g. `192.168.1.200` Port Scan or `192.168.1.188` DoS).
2. The **Decision Support Inspection Dialog** opens, presenting a structured 4-step hierarchy:
   - **Step 1: Incident Summary**: Event classification, timestamp, source/destination sockets, and severity.
   - **Step 2: Technical Telemetry Evidence**: Flow duration, packet intensity, bytes/sec rate, and SYN/ACK ratio.
   - **Step 3: Machine Learning & Explainability (TreeSHAP)**:
     - An interactive horizontal Recharts bar chart displays exact Shapley attribution values.
     - Explains *why* the model made its decision (e.g. `+0.44 syn_ack_ratio`, `+0.32 failed_connections`, `+0.28 packets_per_second`).
   - **Step 4: Decision Engine Recommendation**: Automated mitigation proposal with recommended firewall/ACL rules.

#### Step 4: Traffic Forecasting & Capacity Analysis
1. Navigate to the **Traffic Forecast** view in the sidebar.
2. The dual-line chart illustrates historical network ingress bandwidth against the autoregressive XGBoost regressor forecast.
3. Review the predicted $t+1$ bandwidth and packet rates along with the $\pm 1\sigma$ uncertainty envelope.
4. If a volumetric burst was simulated, observe how the model forecasts capacity stress before complete link exhaustion occurs.

#### Step 5: Administrative Decision Review & Containment
1. Navigate to the **Recommendations** view in the sidebar.
2. Review pending mitigation actions generated according to NIST SP 800-61 incident response guidelines:
   - `RATE_LIMIT_PORT`: Restricts destination port bandwidth to protect upstream pools.
   - `BLOCK_SOURCE_IP`: Applies perimeter firewall drop rules for hostile scanning IPs.
   - `QUARANTINE_HOST`: Isolates compromised endpoints into restricted VLANs.
3. Click **Approve & Apply** to accept the recommendation, or **Simulate Remediation** to run dry-run validation.
4. Verify that the recommendation status transitions from `pending` to `applied` / `approved`, and the host's risk score and quarantine status update accordingly.

---

### Automated Testing & Validation

Execute the full automated test suite covering all 5 phases:
```bash
pytest -v
```

Output confirms 33 passing tests across the entire architecture:
```text
netmind/tests/test_backend.py (12 passed)      # ORM, Repositories, REST API, Decision Engine
netmind/tests/test_ingestion.py (9 passed)     # Zeek TSV/JSON, Suricata EVE, Feature Engineering
netmind/tests/test_ml.py (7 passed)            # Isolation Forest, XGBoost, TreeSHAP, Forecaster
netmind/tests/test_integration.py (5 passed)   # Traffic Generator, Worker Tailer, Offset Tracking

======================= 33 passed, 1 warning in 12.53s =======================
```

---

## License

This project is licensed under the Apache 2.0 License.


