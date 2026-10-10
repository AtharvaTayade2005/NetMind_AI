# NetMind AI — Complete End-to-End Workflow & Architecture Reference

> **Document Purpose:** This document provides an exhaustive, granular reference detailing the entire architecture and execution flow of **NetMind AI**. It systematically explains **what is happening where**, **what package is doing what**, **what file is doing what**, and **what library/dependency is doing what**, categorized across the three core technical domains: **Cybersecurity**, **Data Science**, and **Artificial Intelligence**.

---

## Table of Contents
1. [System Executive Summary & Tri-Domain Foundation](#1-system-executive-summary--tri-domain-foundation)
2. [Global End-to-End Telemetry Lifecycle](#2-global-end-to-end-telemetry-lifecycle)
3. [Tri-Domain Technical Deep Dive](#3-tri-domain-technical-deep-dive)
   - [Domain A: Cybersecurity & Security Operations (SOC)](#domain-a-cybersecurity--security-operations-soc)
   - [Domain B: Data Science & Telemetry Engineering](#domain-b-data-science--telemetry-engineering)
   - [Domain C: Artificial Intelligence & Explainability (XAI)](#domain-c-artificial-intelligence--explainability-xai)
4. [Package Architecture: What Package Does What](#4-package-architecture-what-package-does-what)
5. [File Directory Reference: What Every File Does](#5-file-directory-reference-what-every-file-does)
6. [Library & Dependency Index: What Every Library Does](#6-library--dependency-index-what-every-library-does)
7. [Phase-by-Phase Implementation Mapping](#7-phase-by-phase-implementation-mapping)

---

## 1. System Executive Summary & Tri-Domain Foundation

NetMind AI is an autonomous, AI-driven network monitoring, zero-day threat detection, time-series forecasting, and automated decision-support system. It fuses three foundational disciplines into a single production pipeline:

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
   │ • Zeek & Suricata Sniffing│    │ • Non-memorizing features │    │ • Isolation Forest (Zero- │
   │ • 5-Tuple Normalization   │    │ • Heavy-tail RobustScaler │    │   Day Anomaly Detection)  │
   │ • Threat Taxonomy (DoS,   │    │ • Stratified partitioning │    │ • XGBoost Multiclass      │
   │   Port Scan, Web, Brute)  │    │ • Autoregressive lag      │    │   Classifier (Threats)    │
   │ • NIST SP 800-61 Playbooks│    │   sliding windows         │    │ • TreeSHAP Exact Shapley  │
   │ • Host Risk Scoring &     │    │ • Memory-efficient stream │    │   Feature Attributions    │
   │   Containment Enforcement │    │   generators & pipelines  │    │ • XGBoost Rate Regressor  │
   └───────────────────────────┘    └───────────────────────────┘    └───────────────────────────┘
```

---

## 2. Global End-to-End Telemetry Lifecycle

The diagram below traces the end-to-end journey of a single network packet from loopback wire generation to analyst remediation:

```
[ Step 1: Network Traffic Generation / Packet Capture ]
   └── scripts/traffic_generator.py (Safe socket / Scapy loopback generation)
       ├── Normal Baseline: Periodic HTTP GET & DNS queries
       ├── Sequential Port Probe: Rapid TCP SYN sweeps
       └── High-Volume Burst: Volumetric UDP/SYN packet saturation
                               │
                               ▼
[ Step 2: Log Emission & Streaming Ingestion ]
   ├── logs/conn.log  (Zeek TSV bidirectional flow records)
   └── logs/eve.json  (Suricata EVE NDJSON alert events)
                               │
                               ▼
[ Step 3: Rotation-Resilient Background Log Tailer ]
   └── src/worker/log_tailer.py (tracks byte offsets via logs/.tailer_checkpoint.json)
       ├── Inode & size-shrink rotation detection
       ├── Missing value ('-') sanitization & type casting
       └── Normalized 5-tuple: (src_ip, dst_ip, src_port, dst_port, proto)
                               │
                               ▼
[ Step 4: Behavioral Feature Engineering ]
   └── src/features/engineer.py (NetMindFeatureEngineer)
       ├── Computes 30-dim behavioral vector: duration, bps, pps, syn_ack_ratio, etc.
       └── Strictly excludes static raw IPs (prevents memorization of lab addresses)
                               │
                               ▼
[ Step 5: Data Science Preprocessing ]
   └── models/preprocessor.joblib (NetMindPreprocessor)
       ├── Median missing-value imputation
       └── Heavy-tail RobustScaler normalization (immune to extreme attack outliers)
                               │
                               ▼
[ Step 6: Dual-Engine AI Inference Layer ]
   ├── models/anomaly_detector.joblib (NetworkAnomalyDetector - Isolation Forest)
   │   └── Outputs unsupervised anomaly score [0.0 - 1.0] calibrated against 95th percentile
   └── models/attack_classifier.joblib (AttackClassifier - Supervised XGBoost)
       └── Outputs softprob probabilities: Normal, DoS, Port Scan, Brute Force, Web Attack
                               │
                               ▼
[ Step 7: Explainable AI (XAI) Attribution ]
   └── src/ml/explainer.py (NetMindExplainer - TreeSHAP)
       ├── Computes exact local Shapley feature attributions
       └── Generates human-readable SOC narrative: e.g. "Elevated SYN/ACK ratio (+3.97) drove DoS alert"
                               │
                               ▼
[ Step 8: Multi-Vector Decision Engine & Playbook Synthesis ]
   └── src/backend/decision_engine.py (DecisionEngine)
       ├── Composite Risk = 0.40*SecurityRisk + 0.25*AnomalyScore + 0.20*PerformanceRisk + 0.15*HistoricalRisk
       └── Aligns with NIST SP 800-61: generates RATE_LIMIT_PORT, BLOCK_SOURCE_IP, QUARANTINE_HOST
                               │
                               ▼
[ Step 9: Database Persistence & ORM Relational Mapping ]
   └── src/backend/database.py & repository.py
       └── Atomically writes NetworkFlow, Anomaly, SecurityEvent, Recommendation, and Host RiskScore
                               │
                               ▼
[ Step 10: High-Density SOC Dashboard & Analyst Review ]
   └── frontend/ (React 18 + Vite + Tailwind CSS + Recharts + FontAwesome)
       ├── Overview HUD: Global Risk Gauge, Inbound/Outbound Throughput, Live Telemetry Stream
       ├── AI Analytics Modal: 4-step Alert -> Evidence -> TreeSHAP Chart -> Mitigation Playbook
       ├── Forecast View: XGBoost Autoregressive Ingress Curve with ±1σ Confidence Envelope
       └── Recommendations View: One-click "Approve & Apply" or "Simulate Remediation" containment
```

---

## 3. Tri-Domain Technical Deep Dive

### Domain A: Cybersecurity & Security Operations (SOC)
1. **Telemetry Sensors & Network Protocols**:
   - **Zeek (Bro)**: Translates wire packets into structured stateful connection dialogues (`conn.log`). Records connection state machines (`SF`, `S0`, `REJ`, `RSTO`, `SHR`), TCP historical flag sequences (`ShADadfF`), and application protocol detection (`http`, `ssl`, `dns`).
   - **Suricata**: Multi-threaded Network Threat Detection Engine that inspects payloads using signature rulebases (Emerging Threats / ET rules) and emits newline-delimited JSON (`eve.json`) alerts.
2. **Adversarial Attack Taxonomy**:
   - **Class 0: Normal**: Benign enterprise client-server sessions.
   - **Class 1: Denial of Service (DoS)**: Volumetric SYN floods and high-rate packet saturation designed to exhaust firewall state tables and service bandwidth.
   - **Class 2: Port Scan / Reconnaissance**: Sequential and random destination port sweeps (`S0` / `REJ` states) probing for listening daemon ports.
   - **Class 3: Brute Force**: Repeated authentication handshake failures targeting SSH (22), RDP (3389), or database endpoints.
   - **Class 4: Web Application Attack**: Layer-7 exploits in HTTP headers and URI query parameters (SQL Injection, Cross-Site Scripting, Directory Traversal).
3. **NIST SP 800-61 Containment Playbooks**:
   - `RATE_LIMIT_PORT`: Restricts destination port bandwidth to prevent upstream connection starvation.
   - `BLOCK_SOURCE_IP`: Applies edge BGP blackhole or perimeter firewall drop rules for confirmed adversarial IPs.
   - `QUARANTINE_HOST`: Isolates compromised internal endpoints into an isolated remediation VLAN.
   - `LOCK_USER_CREDENTIALS`: Enforces credential revocation and step-up multi-factor authentication upon repeated credential brute forcing.
   - `WAF_BLOCK_URI_PATTERN`: Deploys virtual patch rules to the Web Application Firewall.

---

### Domain B: Data Science & Telemetry Engineering
1. **Heavy-Tailed Distributions in Network Telemetry**:
   - Real-world telemetry metrics (bytes per second, flow durations, packet counts) follow **power-law and log-normal distributions (Pareto distributions)**. A single multi-gigabit DoS flood can distort classical Gaussian mean ($\mu$) and standard deviation ($\sigma$).
   - **Solution (`RobustScaler`)**: Normalizes metrics using the median and Interquartile Range ($\text{IQR} = Q_3 - Q_1$), ensuring feature scaling remains resilient against extreme attack outliers.
2. **Preventing Lab IP Address Memorization**:
   - A common failure in applied network intrusion ML is **data leakage through static IP memorization** (where models learn that `192.168.1.200` is always an attacker).
   - **Solution (`NetMindFeatureEngineer`)**: Raw static IPs (`src_ip`, `dst_ip`) and connection UIDs are strictly excluded from the ML feature matrix. Instead, only non-memorizing topological features are extracted:
     - `is_src_private_ip`, `is_dst_private_ip`
     - `is_dst_well_known_port` ($< 1024$), `is_dst_registered_port` ($1024 \le p < 49152$)
     - `is_src_ephemeral_port` ($\ge 49152$)
     - Connection ratios (`syn_ack_ratio`, `failed_conn_ratio`)
3. **Autoregressive Time-Series Lag Windowing**:
   - Network bandwidth is temporally correlated. `NetworkTrafficPredictor` synthesizes historical telemetry into multi-step autoregressive sliding windows:
     - Lag features: $y_{t-1}, y_{t-2}, y_{t-5}$
     - Rolling statistics: Rolling mean and rolling standard deviation over $w=3$ and $w=5$ step horizons.

---

### Domain C: Artificial Intelligence & Explainability (XAI)
1. **Unsupervised Zero-Day Anomaly Detection (Isolation Forest)**:
   - **Mathematical Principle**: Novel zero-day attacks do not match existing signatures, but are "few and different". By partitioning feature space through random orthogonal hyperplanes, anomalous flows are isolated near tree roots with short path lengths $h(x)$.
   - **Anomaly Score Formulation**:
     $$s(x, n) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$
     where $c(n) = 2 \cdot (\ln(n - 1) + 0.5772156649) - \frac{2(n - 1)}{n}$ is the average search path length in a binary search tree.
   - **Dynamic Threshold Calibration**: Automatically calibrated against the empirical 95th-percentile of benign enterprise baseline traffic.
2. **Supervised Attack Classification (XGBoost)**:
   - Evaluates complex, non-linear interactions across the 30-dimensional behavioral matrix using second-order Taylor expansions of cross-entropy loss:
     $$w_j^* = - \frac{\sum_{i \in I_j} g_i}{\sum_{i \in I_j} h_i + \lambda}$$
   - Uses `multi:softprob` objective to calibrate posterior probability distributions across all 5 attack categories.
3. **Game-Theoretic Explainability (TreeSHAP)**:
   - Eliminates "black-box" distrust in the SOC by calculating exact Shapley values via polynomial-time TreeSHAP ($O(T \cdot L \cdot D^2)$):
     $$\phi_i(x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f_x(S \cup \{i\}) - f_x(S) \right]$$
   - Maps exact mathematical attributions to human-readable explanations (e.g. `syn_ack_ratio` added $+0.44$ to the DoS probability).
4. **Multi-Vector Composite Risk Formulation**:
   - Synthesizes four orthogonal risk vectors into a calibrated 0–100 index:
     $$\text{Risk} = 0.40 \cdot \text{SecurityRisk} + 0.25 \cdot \text{AnomalyScore} + 0.20 \cdot \text{PerformanceRisk} + 0.15 \cdot \text{HistoricalRisk}$$

---

## 4. Package Architecture: What Package Does What

```
netmind/ (or root)
├── src/
│   ├── ingestion/       # Module 1: Telemetry Parser & Stream Normalizer
│   ├── features/        # Module 2: Non-memorizing Feature Engineering Transformer
│   ├── ml/              # Module 3: ML Models, Training Pipelines & TreeSHAP
│   ├── backend/         # Module 4: FastAPI REST API, ORM Persistence & Decision Engine
│   └── worker/          # Module 5: Continuous Log-Tailing Daemon & Checkpoint Manager
├── frontend/            # Module 6: Clean Neutral React 18 / TypeScript SOC Portal
├── scripts/             # Module 7: Loopback Synthetic Traffic Generator & Testing Lab
└── tests/               # Module 8: Comprehensive Pytest Validation Suite (33 tests)
```

| Package / Directory | Core Technical Domain | Primary Responsibility |
|:---|:---|:---|
| `src.ingestion` | **Cybersecurity & Data Science** | Reads Zeek TSV/JSON logs and Suricata EVE NDJSON alerts; cleans `-` nulls; normalizes 5-tuples. |
| `src.features` | **Data Science** | Transforms raw connection tuples into 30 non-memorizing behavioral features. |
| `src.ml` | **Artificial Intelligence** | Contains Isolation Forest, XGBoost classifier, XGBoost regressor, TreeSHAP explainer, and trainer. |
| `src.backend` | **Cybersecurity & Systems Arch** | FastAPI application, SQLAlchemy 2.0 ORM models, Pydantic contracts, and the Decision Engine. |
| `src.worker` | **Cybersecurity & Data Science** | Asynchronous daemon watching `conn.log` and `eve.json`; tracks byte offsets; runs ML inference; writes to DB. |
| `scripts` | **Cybersecurity Testing** | Safe loopback packet generator simulating Baseline, Port Probe, and DoS bursts with log emission. |
| `frontend` | **Cybersecurity Operations (SOC)** | Production React 18 / TypeScript single-page app served via Nginx for real-time security monitoring. |
| `tests` | **Quality Assurance** | 33 comprehensive unit and integration tests covering all 5 architectural phases. |

---

## 5. File Directory Reference: What Every File Does

### Ingestion Layer (`src/ingestion/`)
- **`src/ingestion/zeek_parser.py`**:
  - *Class `ZeekConnLogParser`*: Parses both tab-separated (TSV) with `#fields` headers and newline-delimited JSON (NDJSON) Zeek connection logs.
  - Normalizes missing fields (`-`, `(empty)`) to nulls, casts network ports and IP counters to numeric types, and creates standardized aliases (`src_ip`, `dst_ip`, `src_port`, `dst_port`).
- **`src/ingestion/suricata_parser.py`**:
  - *Class `SuricataEveParser`*: Provides memory-efficient streaming of Suricata `eve.json` NDJSON logs via Python generators.
  - Filters `event_type == "alert"`, parses Suricata signature IDs (`signature_id`), categories, alert severity levels (1=Critical to 4=Info), and IPS actions (`allowed`, `blocked`).

---

### Feature Engineering Layer (`src/features/`)
- **`src/features/engineer.py`**:
  - *Class `NetMindFeatureEngineer`*: A Scikit-Learn compatible transformer (`fit`/`transform`) that converts raw connection telemetry into the 30-feature behavioral matrix.
  - Computes rate metrics (`packets_per_second`, `bytes_per_second`), flow intensity (`avg_packet_size`), TCP flag ratios (`syn_ack_ratio`), and aggregated connection patterns (`failed_conn_ratio`, `unique_dest_ports`).
  - Implements the strict lab-memorization avoidance policy by removing static raw IPs from the output matrix.

---

### Machine Learning & Explainability Layer (`src/ml/`)
- **`src/ml/dataset.py`**:
  - *Class `NetMindPreprocessor`*: Serialized preprocessor pipeline (`preprocessor.joblib`). Implements median imputation for missing values and `RobustScaler` (median & IQR) normalization.
  - *Function `prepare_train_val_test_splits`*: Deterministic train/validation/test partitioner with stratified sampling across rare attack classes to prevent data leakage.
- **`src/ml/anomaly_detector.py`**:
  - *Class `NetworkAnomalyDetector`*: Serialized Isolation Forest model (`anomaly_detector.joblib`). Constructs an ensemble of 150 isolation trees trained on benign baseline network traffic.
  - Calibrates a dynamic threshold at the 95th empirical percentile and extracts per-sample ranked driving indicators using z-score baseline deviations.
- **`src/ml/attack_classifier.py`**:
  - *Class `AttackClassifier`*: Serialized XGBoost multiclass classifier (`attack_classifier.joblib`).
  - Trains on tabular telemetry features using second-order gradients and regularization to classify flows into `Normal`, `DoS`, `Port Scan`, `Brute Force`, or `Web Attack`.
- **`src/ml/traffic_predictor.py`**:
  - *Class `NetworkTrafficPredictor`*: Serialized XGBoost regressor (`traffic_predictor.joblib`). Constructs autoregressive lag windows ($t-1, t-2, t-5$) and forecasts $t+1$ bandwidth and packet rates.
- **`src/ml/explainer.py`**:
  - *Class `NetMindExplainer`*: TreeSHAP explanation engine. Translates game-theoretic Shapley vectors into ranked feature importance contributions and natural language narratives for SOC analysts.
- **`src/ml/train_all.py`**:
  - End-to-end synthesizer, trainer, benchmarker, and artifact serializer. Generates statistically grounded synthetic telemetry, fits all models, evaluates classification reports, and serializes artifacts to `models/`.

---

### Backend API & Decision Support Layer (`src/backend/`)
- **`src/backend/database.py`**:
  - Connection lifecycle management and SQLAlchemy 2.0 session factory. Uses PostgreSQL via `DATABASE_URL` with resilient SQLite fallback (`data/netmind.db`) for isolated test runs.
- **`src/backend/models.py`**:
  - Typed SQLAlchemy 2.0 ORM models with composite indexing:
    - `Host`: Network endpoint status, last seen, composite risk score.
    - `NetworkFlow`: Ingested 5-tuple flow record with bytes, packets, and duration.
    - `SecurityEvent`: Flagged intrusion event with type, severity, and confidence.
    - `Anomaly`: Zero-day statistical outlier linked to a `NetworkFlow`.
    - `Prediction`: Ingress rate forecast target with confidence bounds.
    - `RiskScore`: Historical audit log of composite host risk evaluations.
    - `Recommendation`: Proposed incident containment action linked to a `SecurityEvent`.
- **`src/backend/schemas.py`**:
  - Pydantic v2 data validation and response schemas with `ConfigDict(from_attributes=True)`.
- **`src/backend/repository.py`**:
  - Clean Repository pattern isolating SQL queries, pagination, filtering, and database mutations (`HostRepository`, `NetworkFlowRepository`, `SecurityEventRepository`, `AnomalyRepository`, `RecommendationRepository`, `RiskScoreRepository`, `PredictionRepository`).
- **`src/backend/decision_engine.py`**:
  - *Class `DecisionEngine`*: Mathematical risk scoring and rule-based mitigation playbooks.
  - Implements the 4-factor risk algorithm and maps threats to NIST SP 800-61 playbooks.
- **`src/backend/main.py`**:
  - FastAPI application entrypoint with asynchronous lifespan lifecycle, database table auto-initialization, CORS middleware, and API router aggregation.
- **`src/backend/routers/`**:
  - `status.py`: Endpoint `GET /api/network/status` (HUD metrics and live flow streams).
  - `threats.py`: Endpoints `GET /api/threats`, `GET /api/anomalies`, and `POST /api/events/{id}/review`.
  - `predictions.py`: Endpoint `GET /api/predictions` (historical vs. forecasted bandwidth).
  - `recommendations.py`: Endpoints `GET /api/recommendations` and `POST /api/recommendations/{id}/review`.
  - `inference.py`: Real-time ML endpoints `POST /api/predict/attack` and `POST /api/predict/anomaly`.

---

### Background Ingestion Worker (`src/worker/`)
- **`src/worker/log_tailer.py`**:
  - Continuous streaming daemon. Implements `CheckpointManager` for persistent byte offset tracking in `logs/.tailer_checkpoint.json`.
  - Handles log file truncation and inode rotations, passes new entries through feature extraction and serialized ML models, evaluates the Decision Engine, and commits records to PostgreSQL.

---

### Testing Lab & Traffic Generator (`scripts/`)
- **`scripts/traffic_generator.py`**:
  - Safe, educational Python synthetic traffic generator.
  - Enforces loopback binding (`127.0.0.1`), defensive IP checks, and rate-limiting.
  - Simulates Baseline (HTTP/DNS), Sequential Port Probes (TCP SYN sweep), and Volumetric Bursts.
  - Synchronously emits matching Zeek `conn.log` and Suricata `eve.json` records to disk for reproducible end-to-end testing.

---

### Frontend Single-Page Application (`frontend/`)
- **`frontend/src/App.tsx`**: Main application shell with sidebar navigation, active view switcher, and detail inspection modal state.
- **`frontend/src/components/Navbar.tsx`**: System header displaying real-time ingestion status indicators, active interface selector, and SOC notifications badge.
- **`frontend/src/components/Sidebar.tsx`**: Navigation menu with real-time incident counters for threats, anomalies, and pending recommendations.
- **`frontend/src/components/ThreatDetailModal.tsx`**: 4-step SOC decision-support inspection dialog:
  - Step 1: Alert Summary & Sockets
  - Step 2: Technical Telemetry Evidence
  - Step 3: Interactive Recharts TreeSHAP Horizontal Bar Chart
  - Step 4: Decision Engine Containment Action & Approval Buttons
- **`frontend/src/views/Overview.tsx`**: Main dashboard featuring top HUD metric cards, Recharts dual-line throughput visualizer, recent flow stream table, and critical alerts queue.
- **`frontend/src/views/ClassifiedAttacksView.tsx`**: Supervised XGBoost multiclass threat ledger.
- **`frontend/src/views/AnomaliesView.tsx`**: Unsupervised Isolation Forest statistical outlier audit table.
- **`frontend/src/views/TrafficForecastView.tsx`**: Autoregressive bandwidth and packet rate forecast curve with $\pm 1\sigma$ uncertainty envelope.
- **`frontend/src/views/RecommendationsView.tsx`**: Mitigation queue for administrative review and approval of proposed containment playbooks.

---

### Containerization & Deployment
- **`docker-compose.yml`**: Multi-container orchestration coordinating `postgres`, `backend`, `worker`, and `frontend` services with network isolation and volume mounts.
- **`Dockerfile`**: Multi-stage Python 3.11-slim container for the backend API and worker daemon.
- **`frontend/Dockerfile`**: Multi-stage Node.js builder + Nginx alpine runner serving the built React assets.
- **`frontend/nginx.conf`**: Nginx configuration serving single-page application routes and reverse proxying `/api/` calls to `backend:8000`.
- **`.env.example`**: Complete environment variable template with database credentials, ports, and file paths.

---

## 6. Library & Dependency Index: What Every Library Does

### Python Backend & Data Science Libraries

| Library | Version | Technical Domain | What It Does in NetMind AI |
|:---|:---|:---|:---|
| **`fastapi`** | $\ge 0.100.0$ | **Systems / API** | High-performance asynchronous web framework providing the REST API layer, OpenAPI documentation, and dependency injection (`Depends(get_db)`). |
| **`uvicorn`** | $\ge 0.23.0$ | **Systems / Server** | Lightning-fast ASGI web server hosting the FastAPI application across development and Docker containers. |
| **`pydantic`** | $\ge 2.0.0$ | **Data Science / Contracts** | Data validation, type enforcement, and schema serialization for all API request payloads and responses using `from_attributes=True`. |
| **`sqlalchemy`** | $\ge 2.0.0$ | **Data Engineering** | Modern typed ORM providing declarative mapping (`Mapped[...]`, `mapped_column[...]`), session lifecycle management, and connection pooling (`pool_pre_ping=True`). |
| **`psycopg2-binary`**| $\ge 2.9.0$ | **Database Driver** | Low-level C-optimized PostgreSQL database adapter connecting SQLAlchemy to the PostgreSQL/TimescaleDB container. |
| **`pandas`** | $\ge 2.0.0$ | **Data Science** | High-performance tabular data structures (`DataFrame`, `Series`) used throughout log parsing, feature engineering, and model dataset preparation. |
| **`numpy`** | $\ge 1.24.0$ | **Data Science / Math** | Vectorized array computing, numerical operations, percentile calculations, and mathematical transformations. |
| **`scikit-learn`** | $\ge 1.3.0$ | **Artificial Intelligence** | Provides `IsolationForest` for unsupervised anomaly detection, `RobustScaler` for heavy-tail scaling, and `SimpleImputer` for median imputation. |
| **`xgboost`** | $\ge 2.0.0$ | **Artificial Intelligence** | Extreme Gradient Boosting library powering `XGBClassifier` (multiclass threat classification) and `XGBRegressor` (bandwidth forecasting). |
| **`shap`** | $\ge 0.44.0$ | **Explainable AI (XAI)** | TreeSHAP library computing exact local Shapley feature attributions explaining the root cause of every AI threat detection. |
| **`joblib`** | $\ge 1.3.0$ | **Data Engineering** | High-performance object serialization and deserialization used to save and load trained pipelines (`models/*.joblib`). |
| **`pytest`** | $\ge 7.4.0$ | **Testing & QA** | Automated testing framework executing the 33 unit, integration, and end-to-end tests across all 5 phases. |
| **`python-dotenv`** | $\ge 1.0.0$ | **Configuration** | Loads environment variables from `.env` files into application runtime configuration. |
| **`scapy`** | Optional | **Cybersecurity Testing** | Packet manipulation tool used optionally in `traffic_generator.py` for raw socket probe crafting. |

---

### Frontend Web Technologies & Libraries

| Library | Version | Technical Domain | What It Does in NetMind AI |
|:---|:---|:---|:---|
| **`react`** | `^18.3.1` | **UI Framework** | Modern declarative component framework rendering the interactive SOC dashboard. |
| **`typescript`** | `^5.6.3` | **Language** | Static typing ensuring interface contracts, schema safety, and maintainability across frontend components. |
| **`vite`** | `^5.4.10` | **Build Tool** | Next-generation frontend build tool and local development server featuring Hot Module Replacement (HMR). |
| **`tailwindcss`** | `^3.4.14` | **CSS Framework** | Utility-first styling framework implementing the clean neutral aesthetic (slate/navy palette, solid structural borders, subtle shadows). |
| **`recharts`** | `^2.13.3` | **Data Visualization** | Composable charting library rendering the dual-line throughput visualizers, bandwidth forecast curves, and TreeSHAP horizontal attribution bar charts. |
| **`@fortawesome/react-fontawesome`**| `^0.2.2` | **Iconography** | High-density SVG icons (`faNetworkWired`, `faShieldHalved`, `faBrain`, `faChartLine`, etc.) across navigation bars and metric cards. |

---

## 7. Phase-by-Phase Implementation Mapping

| Phase | Title | Primary Deliverables | Key Files Involved |
|:---|:---|:---|:---|
| **Phase 1** | **Ingestion & Feature Engineering** | Parsers for Zeek TSV and Suricata EVE; 30-dim non-memorizing feature transformer. | `zeek_parser.py`, `suricata_parser.py`, `engineer.py`, `test_ingestion.py` |
| **Phase 2** | **Machine Learning & Explainable AI** | Isolation Forest zero-day detector, XGBoost multiclass threat classifier, XGBoost regressor, TreeSHAP explainer. | `dataset.py`, `anomaly_detector.py`, `attack_classifier.py`, `traffic_predictor.py`, `explainer.py`, `train_all.py`, `test_ml.py` |
| **Phase 3** | **Persistence, Scoring & API Serving** | PostgreSQL ORM models, Pydantic contracts, Repositories, Multi-vector Decision Engine, FastAPI REST routers. | `database.py`, `models.py`, `schemas.py`, `repository.py`, `decision_engine.py`, `main.py`, `routers/*.py`, `test_backend.py` |
| **Phase 4** | **Clean Neutral SOC Interface** | React 18 single-page application, Overview HUD, TreeSHAP inspection dialog, forecasting and mitigation views. | `frontend/src/App.tsx`, `frontend/src/components/*`, `frontend/src/views/*`, `frontend/src/api/*` |
| **Phase 5** | **Packaging, Telemetry Worker & Testing Lab** | Docker Compose orchestration, background log tailer daemon with offset checkpointing, safe traffic generator. | `traffic_generator.py`, `log_tailer.py`, `docker-compose.yml`, `Dockerfile`, `frontend/Dockerfile`, `test_integration.py` |

---

*Document maintained as part of the NetMind AI Systems Integration Architecture.*
