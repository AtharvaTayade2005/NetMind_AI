# NetMind AI — Intelligent Network Monitoring, Prediction & Decision Support System

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![SQLAlchemy 2.0](https://img.shields.io/badge/SQLAlchemy-2.0+-red.svg)](https://www.sqlalchemy.org/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2+-e92063.svg)](https://docs.pydantic.dev/)
[![Docker](https://img.shields.io/badge/Docker-Compose%20v2-2496ED.svg)](https://www.docker.com/)
[![React 18](https://img.shields.io/badge/React-18.3+-61DAFB.svg)](https://react.dev/)
[![Tests](https://img.shields.io/badge/tests-33%20passed-green.svg)](#6-automated-validation--testing-suite)
[![Architecture Docs](https://img.shields.io/badge/Docs-workflow.md-purple.svg)](workflow.md)

**NetMind AI** is an end-to-end, autonomous network intelligence platform engineered to ingest wire-speed telemetry, detect zero-day and signature threats, forecast interface congestion, explain machine decisions, and execute human-reviewed containment actions.

> 📖 **Comprehensive File & Library Reference:** For an exhaustive, file-by-file, package-by-package, and library-by-library breakdown of the entire architecture, see [workflow.md](workflow.md).

---

## 1. The Tri-Domain Technical Foundation

NetMind AI is architecturally organized across three foundational disciplines:

```
                            ┌───────────────────────────────────────────┐
                            │                NETMIND AI                 │
                            │      Intelligent Network Monitoring       │
                            └─────────────────────┬─────────────────────┘
                                                  │
                 ┌────────────────────────────────┼────────────────────────────────┐
                 ▼                                ▼                                ▼
   ┌───────────────────────────┐    ┌───────────────────────────┐    ┌───────────────────────────┐
   │     CYBERSECURITY         │    │       DATA SCIENCE        │    │  ARTIFICIAL INTELLIGENCE  │
   │   (Detection & Ops)       │    │    (Features & Scale)     │    │   (Inference & Reason)    │
   ├───────────────────────────┤    ├───────────────────────────┤    ├───────────────────────────┤
   │ • Zeek & Suricata Sensors │    │ • Non-memorizing features │    │ • Isolation Forest (Zero- │
   │ • 5-Tuple Normalization   │    │ • Heavy-tail RobustScaler │    │   Day Anomaly Detection)  │
   │ • Threat Taxonomy (DoS,   │    │ • Stratified partitioning │    │ • XGBoost Multiclass      │
   │   Port Scan, Web, Brute)  │    │ • Autoregressive lag      │    │   Classifier (Threats)    │
   │ • NIST SP 800-61 Playbooks│    │   sliding windows         │    │ • TreeSHAP Exact Shapley  │
   │ • Host Risk Scoring &     │    │ • Memory-efficient stream │    │   Feature Attributions    │
   │   Containment Enforcement │    │   generators & pipelines  │    │ • XGBoost Rate Regressor  │
   └───────────────────────────┘    └───────────────────────────┘    └───────────────────────────┘
```

### Domain A: Cybersecurity & Security Operations (SOC)
- **High-Throughput Ingestion**: Parses stateful Zeek connection logs (`conn.log`) and Suricata signature alerts (`eve.json`).
- **5-Tuple Flow Normalization**: Normalizes `(src_ip, dst_ip, src_port, dst_port, proto)` and state machines (`SF`, `S0`, `REJ`, `RSTO`).
- **Threat Taxonomy**: Detects DoS / SYN floods, sequential port scans, credential brute forcing, and Layer-7 web attacks.
- **Incident Response Playbooks**: Aligns with **NIST SP 800-61** (`RATE_LIMIT_PORT`, `BLOCK_SOURCE_IP`, `QUARANTINE_HOST`, `LOCK_USER_CREDENTIALS`).
- **Multi-Vector Risk Scoring**: Computes a balanced 0–100 host risk metric across security, anomaly, performance, and historical recurrence dimensions.

### Domain B: Data Science & Telemetry Engineering
- **Lab-Memorization Avoidance**: Strips raw static IPs (`src_ip`, `dst_ip`) from the predictive matrix to prevent models from memorizing ephemeral test addresses. Extracts non-memorizing topological features (`is_src_private_ip`, `is_dst_well_known_port`, `is_src_ephemeral_port`).
- **Heavy-Tail Resistant Scaling**: Telemetry byte rates and durations exhibit extreme power-law (Pareto) distributions. Uses `RobustScaler` (median & Interquartile Range $Q_3 - Q_1$) to prevent volumetric DoS spikes from distorting normalization.
- **Data Leakage Prevention**: Fits imputer and scaling parameters strictly on training partitions before validation/test transformation.
- **Stratified Partitioning**: Guarantees identical representation of rare cyber attack classes across train/validation/test splits.
- **Time-Series Lag Windowing**: Constructs multi-step autoregressive lag windows ($t-1, t-2, t-5$) and rolling statistical windows ($w=3, w=5$).

### Domain C: Artificial Intelligence & Explainability (XAI)
- **Unsupervised Zero-Day Detection (Isolation Forest)**: Partitions feature space using random hyperplanes to isolate rare, structurally distinct traffic near decision tree roots without requiring pre-labeled training signatures.
- **Dynamic Threshold Calibration**: Automatically calibrates anomaly flags against the empirical 95th-percentile of benign baseline traffic.
- **Supervised Attack Classification (XGBoost)**: Gradient-boosted decision trees using second-order Taylor expansion loss with `multi:softprob` posterior probabilities.
- **Explainable AI (TreeSHAP)**: Employs game-theoretic polynomial TreeSHAP ($O(T \cdot L \cdot D^2)$) to compute exact local Shapley values for each alert, translating math attributions into plain-English SOC analyst narratives.
- **Predictive Capacity Forecasting (XGBoost Regressor)**: Forecasts network bandwidth (Mbps) and packet rates at $t+1$ with $\pm 1\sigma$ confidence envelopes.

---

## 2. Tri-Domain Architecture Matrix

| Phase | Core Objective | Cybersecurity Dimension | Data Science Dimension | Artificial Intelligence Dimension |
|:---|:---|:---|:---|:---|
| **Phase 1** | **Ingestion & Feature Engineering** | Zeek TSV & Suricata EVE parsing; TCP state machines (`SF`, `S0`, `REJ`); 5-tuple mapping. | 30-dim behavioral vector; rate metrics (`bps`, `pps`); TCP flag ratios; IP memorization avoidance. | Foundation feature matrix ready for unsupervised and supervised estimators. |
| **Phase 2** | **Machine Learning & Explainability** | Zero-day detection; threat taxonomy (DoS, Port Scan, Brute Force, Web Attack); SOC alert fatigue reduction. | Heavy-tail `RobustScaler` (median & IQR); stratified splits; autoregressive lag window construction. | Isolation Forest (150 trees); XGBoost Multiclass Classifier; TreeSHAP exact game-theoretic attributions. |
| **Phase 3** | **Persistence & Decision Engine** | NIST SP 800-61 playbooks (`QUARANTINE_HOST`, `RATE_LIMIT_PORT`); composite risk scoring. | PostgreSQL / SQLAlchemy 2.0 ORM with composite indexes; Pydantic v2 data contracts; repository pattern. | Real-time REST inference endpoints (`/api/predict/attack`, `/api/predict/anomaly`). |
| **Phase 4** | **Clean Neutral SOC Interface** | High-density analyst portal; live telemetry stream; incident queue; one-click containment execution. | Dual-axis throughput graphs; historical vs. forecast curve with confidence envelope; metric distributions. | 4-step Decision Support Modal with interactive horizontal Recharts TreeSHAP attribution bar chart. |
| **Phase 5** | **Packaging, Worker & Testing Lab** | Safe loopback traffic generation (Baseline, Port Probe, Burst); continuous log tailing daemon. | Checkpoint manager tracking byte offsets in `.tailer_checkpoint.json`; log rotation handling (inode / size shrink). | End-to-end streaming ML inference pipeline running inside containerized Docker Compose stack. |

---

## 3. Phase-by-Phase Technical Breakdown

```
[ Raw Network Wire / Loopback Telemetry ]
                 │
                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 1: Telemetry Ingestion & Feature Engineering (src/ingestion/)    │
│ • zeek_parser.py: TSV & NDJSON parsing, missing-value sanitization     │
│ • suricata_parser.py: Memory-efficient streaming alert generator       │
│ • engineer.py: 30-dim behavioral vector, IP-memorization avoidance     │
└────────────────────────────────────────────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 2: Machine Learning & Explainability Layer (src/ml/)             │
│ • dataset.py: RobustScaler (median/IQR), stratified partitioning       │
│ • anomaly_detector.py: Isolation Forest (150 trees, 95th-percentile)   │
│ • attack_classifier.py: Supervised Multiclass XGBoost (5 classes)      │
│ • traffic_predictor.py: Autoregressive lag window rate forecaster      │
│ • explainer.py: Polynomial TreeSHAP exact Shapley feature attribution  │
└────────────────────────────────────────────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 3: Persistence, Scoring & API Serving Layer (src/backend/)       │
│ • database.py & models.py: SQLAlchemy 2.0 ORM, composite time/IP index │
│ • decision_engine.py: Composite Risk = 0.40*Sec+0.25*Anom+0.20*Perf... │
│ • repository.py: Repository pattern isolating SQL queries & mutations  │
│ • main.py & routers/: FastAPI endpoints (/api/network/status, etc.)   │
└────────────────────────────────────────────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 4: High-Density SOC Frontend Portal (frontend/)                  │
│ • Overview HUD: Monitored endpoints, live throughput, threat stream    │
│ • ThreatDetailModal.tsx: 4-step Alert -> Evidence -> TreeSHAP -> Action│
│ • TrafficForecastView.tsx: Ingress curve with ±1σ confidence bands     │
│ • RecommendationsView.tsx: NIST mitigation review and approval         │
└────────────────────────────────────────────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Phase 5: Packaging, Ingestion Worker & Testing Lab (Phase 5 Complete)  │
│ • scripts/traffic_generator.py: Safe loopback traffic generator        │
│ • src/worker/log_tailer.py: Streaming daemon with offset tracking      │
│ • docker-compose.yml: Postgres, Backend, Worker, Frontend orchestration│
└────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 1: Telemetry Ingestion & Behavioral Feature Engineering
- **Cybersecurity Role**: Collects raw traffic from Zeek sensors (`conn.log`) and Suricata alert files (`eve.json`), normalizes protocols into standardized 5-tuples, and tracks TCP state transitions.
- **Data Science Role**: Eliminates missing value pollution (`-` to nulls) and constructs a 30-dimensional behavioral feature schema. By removing raw IPs, it prevents model over-fitting to specific lab IP addresses.
- **Key Modules**:
  - `src/ingestion/zeek_parser.py`: TSV and JSON parser handling Zeek `#fields` headers and aliases.
  - `src/ingestion/suricata_parser.py`: Generator yielding normalized intrusion alert dictionaries.
  - `src/features/engineer.py`: Scikit-Learn transformer computing rate, packet, flag, and connection patterns.

---

### Phase 2: Machine Learning, Forecasting & Explainable AI (XAI)
- **Data Science Role**: Implements median imputation and `RobustScaler` (median & IQR) scaling to withstand extreme volumetric outliers. Builds stratified splits to preserve rare attack distributions.
- **AI & Explainability Role**:
  - Fits an unsupervised **Isolation Forest** (150 trees) on benign baseline telemetry; calibrates a dynamic 95th-percentile threshold.
  - Fits an **XGBoost Classifier** to attribute flows into: `Normal`, `DoS`, `Port Scan`, `Brute Force`, or `Web Attack`.
  - Constructs autoregressive lag windows ($t-1, t-2, t-5$) and rolling averages to predict bandwidth stress via an **XGBoost Regressor**.
  - Uses **TreeSHAP** ($O(T \cdot L \cdot D^2)$) to generate exact feature attributions and translate them into human-readable SOC explanations.
- **Key Modules**:
  - `src/ml/dataset.py`: `NetMindPreprocessor` and stratified split generator.
  - `src/ml/anomaly_detector.py`: `NetworkAnomalyDetector` with baseline z-score indicators.
  - `src/ml/attack_classifier.py`: `AttackClassifier` with classification reports and confusion matrices.
  - `src/ml/traffic_predictor.py`: `NetworkTrafficPredictor` with multi-horizon lag features.
  - `src/ml/explainer.py`: `NetMindExplainer` generating local Shapley values and SOC narratives.
  - `src/ml/train_all.py`: Synthetic generator, trainer, benchmarker, and serializer (`models/*.joblib`).

---

### Phase 3: Persistence, Scoring & API Serving Layer
- **Cybersecurity Role**: Houses the **Decision Engine**, synthesizing threats into a composite risk score:
  $$\text{Risk} = 0.40 \cdot \text{SecurityRisk} + 0.25 \cdot \text{AnomalyScore} + 0.20 \cdot \text{PerformanceRisk} + 0.15 \cdot \text{HistoricalRisk}$$
  Maps detected vectors to NIST SP 800-61 containment playbooks (`QUARANTINE_HOST`, `RATE_LIMIT_PORT`, `BLOCK_SOURCE_IP`).
- **Data Science Role**: Defines high-performance relational schemas with composite indexing (`(src_ip, dst_ip, timestamp)`) and clean Repository patterns.
- **Key Modules**:
  - `src/backend/database.py`: SQLAlchemy 2.0 session factory with PostgreSQL and SQLite support.
  - `src/backend/models.py`: Typed ORM models (`Host`, `NetworkFlow`, `SecurityEvent`, `Anomaly`, `Prediction`, `RiskScore`, `Recommendation`).
  - `src/backend/schemas.py`: Pydantic v2 data contracts.
  - `src/backend/repository.py`: Centralized database query repositories.
  - `src/backend/decision_engine.py`: Multi-vector risk calculator and mitigation rule generator.
  - `src/backend/main.py`: FastAPI application entrypoint with lifespan event management.
  - `src/backend/routers/`: Modular REST routers (`status.py`, `threats.py`, `predictions.py`, `recommendations.py`, `inference.py`).

---

### Phase 4: Production SOC Interface & Decision Support Portal
- **Cybersecurity Role**: High-density Security Operations Center portal built with clean neutral aesthetics (slate/navy palette, solid structural borders, subtle shadows). Allows tier-1 and tier-2 analysts to monitor telemetry, review AI explanations, and approve mitigation playbooks.
- **Data Science Role**: Recharts visualization rendering dual-line throughput metrics, empirical distributions, and autoregressive forecasting curves with $\pm 1\sigma$ confidence bands.
- **AI Role**: **Decision Support Inspection Dialog (`ThreatDetailModal.tsx`)**:
  - Step 1: Incident Summary & Network Sockets
  - Step 2: Technical Telemetry Evidence (BPS, PPS, SYN/ACK ratio)
  - Step 3: Interactive TreeSHAP Horizontal Bar Chart displaying exact mathematical Shapley contributions
  - Step 4: Decision Engine Action Callout with approval and dry-run simulation triggers.
- **Key Modules**:
  - `frontend/src/App.tsx`: Main layout, sidebar, and state container.
  - `frontend/src/components/ThreatDetailModal.tsx`: 4-step explainable AI inspection modal.
  - `frontend/src/views/Overview.tsx`: Main HUD, live flow stream table, and active threat queue.
  - `frontend/src/views/TrafficForecastView.tsx`: Bandwidth forecast curve with capacity limits.
  - `frontend/src/views/RecommendationsView.tsx`: NIST mitigation review queue.

---

### Phase 5: Packaging, Ingestion Worker & Reproducible Testing Lab
- **Cybersecurity Role**:
  - `scripts/traffic_generator.py`: Generates reproducible synthetic network traffic safely inside loopback (`127.0.0.1`) with rate-limiting. Emits matching Zeek `conn.log` and Suricata `eve.json` telemetry.
  - Scenarios: Normal Baseline, Sequential Port Probe (SYN sweep), and Volumetric Burst.
- **Data Science & Systems Role**:
  - `src/worker/log_tailer.py`: Rotation-resilient background daemon tracking file byte offsets in `logs/.tailer_checkpoint.json`. Detects log rotation across platforms via inode changes and size shrinkage.
  - Pipeline per entry: Reads line -> Extracts features -> Scales with `preprocessor.joblib` -> Predicts anomaly & attack class -> Evaluates risk -> Writes to PostgreSQL.
  - `docker-compose.yml`: Coordinates `postgres`, `backend`, `worker`, and `frontend` (Nginx reverse proxy).

---

## 4. Quickstart Deployment Guide

### Option A: Multi-Container Docker Compose (Recommended)

1. **Configure Environment Variables**:
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
   All 4 containers (`netmind-postgres`, `netmind-backend`, `netmind-worker`, `netmind-frontend`) will report `healthy` or `running`.

4. **Access the Application**:
   - **SOC Monitoring Portal**: [http://localhost:80](http://localhost:80)
   - **FastAPI Interactive Docs (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
   - **Backend Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

5. **Stop Containers**:
   ```bash
   docker compose down
   ```

---

### Option B: Local Standalone Execution (Development Mode)

1. **Install Python & Node Dependencies**:
   ```bash
   pip install -r requirements.txt
   cd frontend && npm install && cd ..
   ```

2. **Start the FastAPI Backend**:
   ```bash
   uvicorn src.backend.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Start the Background Log Tailer Worker** (in a separate terminal):
   ```bash
   python src/worker/log_tailer.py --loop --poll-interval 1.0
   ```

4. **Start the Frontend Development Server** (in a separate terminal):
   ```bash
   cd frontend && npm run dev
   ```
   Open [http://localhost:5173](http://localhost:5173).

---

## 5. Reproducible Testing Lab (`scripts/traffic_generator.py`)

The synthetic generator safely generates traffic bound strictly to loopback (`127.0.0.1`):

1. **Normal Baseline Simulation** (HTTP GET & DNS lookups):
   ```bash
   python scripts/traffic_generator.py --scenario baseline --count 15
   ```
2. **Sequential Port Probe Sweep** (Reconnaissance scanner detection):
   ```bash
   python scripts/traffic_generator.py --scenario probe --port 8000
   ```
3. **High-Volume Volumetric Burst** (Rate alarms & DoS forecasting):
   ```bash
   python scripts/traffic_generator.py --scenario burst --count 10 --rate 100
   ```
4. **Complete End-to-End Suite** (Runs all scenarios and syncs logs):
   ```bash
   python scripts/traffic_generator.py --scenario all --emit-logs --log-dir logs
   ```

---

## 6. Automated Validation & Testing Suite

Execute the comprehensive automated test suite covering all 5 architectural phases:

```bash
pytest -v
```

All 33 tests execute and pass:
```text
netmind/tests/test_backend.py (12 passed)      # ORM, Repositories, REST API, Decision Engine
netmind/tests/test_ingestion.py (9 passed)     # Zeek TSV/JSON, Suricata EVE, Feature Engineering
netmind/tests/test_ml.py (7 passed)            # Isolation Forest, XGBoost, TreeSHAP, Forecaster
netmind/tests/test_integration.py (5 passed)   # Traffic Generator, Worker Tailer, Offset Tracking

======================= 33 passed, 1 warning in 5.17s =======================
```

Verify the frontend production bundle:
```bash
cd frontend && npm run build
```
Built in 3.67s (`dist/assets/index-B4Zkzt99.js`, `dist/assets/index-DKRFL3Nf.css`).

---

## 7. Granular Technical Reference

For exhaustive, line-by-line and file-by-file explanations of:
- **What package is doing what**
- **What file is doing what**
- **What library/dependency is doing what**
- **The complete mathematical, statistical, and security formulation**

👉 **Read the comprehensive companion document: [workflow.md](workflow.md)**.

---

## License

This project is licensed under the Apache 2.0 License.
