# NetMind AI — Telemetry Input, Packet Processing & Tri-Domain Fusion Architecture

> **Document Scope:** This document explains the exact nature of the **network input**, details how **raw packets** are captured and structured, and explains the step-by-step pipeline that unifies **Cybersecurity**, **Data Science**, and **Artificial Intelligence/Machine Learning**. For every phase, it explicitly identifies **what folder is involved**, **what file is executing**, **what package/library is used**, and **what mathematical and security logic is applied**.

---

## Table of Contents
1. [What Is the Input? Demystifying Network Packets vs. Telemetry](#1-what-is-the-input-demystifying-network-packets-vs-telemetry)
2. [Why Pure Approaches Fail: The Need for Tri-Domain Fusion](#2-why-pure-approaches-fail-the-need-for-tri-domain-fusion)
3. [The Unified 10-Step Pipeline: Folder, File & Library Mapping](#3-the-unified-10-step-pipeline-folder-file--library-mapping)
   - [Step 1: Wire Packet Sniffing & Flow Dialogue Reassembly](#step-1-wire-packet-sniffing--flow-dialogue-reassembly)
   - [Step 2: Asynchronous Streaming & Rotation-Resilient Tailing](#step-2-asynchronous-streaming--rotation-resilient-tailing)
   - [Step 3: Canonical Parsing & 5-Tuple Normalization](#step-3-canonical-parsing--5-tuple-normalization)
   - [Step 4: Non-Memorizing Behavioral Feature Engineering](#step-4-non-memorizing-behavioral-feature-engineering)
   - [Step 5: Heavy-Tail Resistant Preprocessing (RobustScaler)](#step-5-heavy-tail-resistant-preprocessing-robustscaler)
   - [Step 6: Dual-Engine AI Inference (Isolation Forest & XGBoost)](#step-6-dual-engine-ai-inference-isolation-forest--xgboost)
   - [Step 7: Game-Theoretic Explainability (TreeSHAP)](#step-7-game-theoretic-explainability-treeshap)
   - [Step 8: Multi-Vector Risk Calculation & Playbook Generation](#step-8-multi-vector-risk-calculation--playbook-generation)
   - [Step 9: Relational Persistence & Atomic Database Commits](#step-9-relational-persistence--atomic-database-commits)
   - [Step 10: High-Density SOC Portal & Human-in-the-Loop Review](#step-10-high-density-soc-portal--human-in-the-loop-review)
4. [Concrete Walkthrough: Tracing an Attack Packet End-to-End](#4-concrete-walkthrough-tracing-an-attack-packet-end-to-end)
5. [Comprehensive Folder, File & Library Reference Matrix](#5-comprehensive-folder-file--library-reference-matrix)

---

## 1. What Is the Input? Demystifying Network Packets vs. Telemetry

### The Origin: Raw Packets on the Network Interface
The ultimate source of all data in NetMind AI is **raw binary network packets** traversing a network interface card (NIC):
- **In an enterprise deployment**: Traffic arrives from a physical TAP, SPAN mirror port, or cloud virtual network interface (`eth0`, `ens33`, `wlan0`).
- **In a local developer/testing environment**: Traffic originates on the loopback adapter (`127.0.0.1` / `localhost`) or local subnet (`192.168.1.0/24`).

Each raw packet contains binary Ethernet frames, IP headers (Source IP, Destination IP, TTL), transport headers (TCP flags: `SYN`, `ACK`, `RST`, `FIN`, port numbers), and application layer payloads (HTTP GET strings, DNS query names, TLS handshakes).

### The Engineering Dilemma: Why ML Cannot Ingest Raw 10Gbps Packets Directly
In network security engineering, **raw packet bytes cannot be fed directly into Python machine learning algorithms**:
1. **CPU Saturation**: Enterprise links run at 1Gbps–100Gbps, transmitting up to **14.8 million packets per second**. Python-based ML estimators would experience buffer overflow and packet drops within milliseconds.
2. **Lack of Conversation State**: A single packet (e.g. an isolated TCP `ACK`) carries zero context. You cannot determine if it represents normal browsing or an attack without knowing whether a valid `SYN` handshake preceded it.
3. **Data Overfitting**: Training deep neural networks directly on raw payload bytes causes models to overfit on ephemeral payload contents (e.g. user session tokens, timestamps, hostnames) rather than structural adversarial behaviors.

### The Solution: The Two-Tier Sensor Architecture
NetMind AI ingests traffic through two industry-standard network protocol analyzers (**Zeek** and **Suricata**):

```
                        [ Physical / Virtual NIC / Loopback Wire ]
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
       ┌───────────────────────────┐   ┌───────────────────────────┐
       │ Zeek (formerly Bro)       │   │ Suricata IDS/IPS          │
       │ Protocol State Machine    │   │ Deep Packet Inspection    │
       ├───────────────────────────┤   ├───────────────────────────┤
       │ • Reassembles packets     │   │ • Inspects raw payloads   │
       │   into bidirectional      │   │   against signature rules │
       │   conversations (flows).  │   │   (Emerging Threats / ET).│
       │ • Tracks TCP handshakes:  │   │ • Emits alert categories: │
       │   SYN -> SYN-ACK -> ACK.  │   │   SQLi, Scan, DoS, Brute. │
       │ • Outputs: conn.log       │   │ • Outputs: eve.json       │
       └─────────────┬─────────────┘   └─────────────┬─────────────┘
                     │                               │
                     ▼                               ▼
       ┌───────────────────────────────────────────────────────────┐
       │ NetMind AI Ingestion Stream                               │
       │ Structured, stateful, memory-efficient network telemetry   │
       └───────────────────────────────────────────────────────────┘
```

- **Zeek (`conn.log`)**: Assembles thousands of individual packets into a single **session record** (5-tuple socket, duration, byte counts, packet counts, TCP state flags, history strings).
- **Suricata (`eve.json`)**: Performs real-time signature matching on raw payload bytes, emitting structured alert records when malicious patterns (SQL injections, shellcode, scans) are detected.
- **Testing Generator (`scripts/traffic_generator.py`)**: Safely emits identical Zeek and Suricata telemetry format locally over loopback (`127.0.0.1`).

---

## 2. Why Pure Approaches Fail: The Need for Tri-Domain Fusion

```
           CYBERSECURITY                     DATA SCIENCE                         AI / ML
    (Threats, Protocols, Rules)        (Features, Scaling, Drift)        (Pattern Discovery & XAI)
                 │                                │                                │
                 ▼                                ▼                                ▼
    Understands TCP handshakes,       Prevents static IP memorization,  Discovers novel zero-day anomalies
    ports, NIST response playbooks,   handles heavy-tailed Pareto       without signatures (Isolation Forest),
    and attack taxonomies.            distributions via RobustScaler,   classifies non-linear threats (XGBoost),
                                      and structures lag windows.       and explains decisions (TreeSHAP).
                 │                                │                                │
                 └────────────────────────────────┼────────────────────────────────┘
                                                  ▼
                                      ┌───────────────────────┐
                                      │      NETMIND AI       │
                                      │   Unified Pipeline    │
                                      └───────────────────────┘
```

1. **Pure Cybersecurity (Rule-based IDS alone)**: Blind to novel zero-day attacks, encrypted channels, and behavioral anomalies. Creates massive alert fatigue.
2. **Pure Data Science (Statistics alone)**: Blind to protocol semantics (treats a TCP SYN flag as an arbitrary floating-point number rather than a transport handshake).
3. **Pure AI/ML (Black-box models alone)**: Memorizes static training IP addresses (data leakage), lacks interpretability (SOC analysts cannot trust unexplainable flags), and has no deterministic containment playbooks.

**NetMind AI blends all three:**
- **Cybersecurity** provides the domain rules, protocol parsing, and incident response actions.
- **Data Science** extracts non-memorizing features, normalizes power-law distributions, and prevents leakage.
- **AI/ML** performs non-linear threat classification, zero-day anomaly detection, bandwidth forecasting, and game-theoretic explainability.

---

## 3. The Unified 10-Step Pipeline: Folder, File & Library Mapping

Below is the complete journey of incoming network traffic through every folder, file, package, and library in the repository:

---

### Step 1: Wire Packet Sniffing & Flow Dialogue Reassembly
* **Domain:** **Cybersecurity (Network Protocol Engineering)**
* **Folder Involved:** `scripts/` (for simulation) / Kernel Packet Socket (`PF_PACKET` / `libpcap`)
* **File Involved:** [`scripts/traffic_generator.py`](file:///d:/Coding/GitHub/NetMind_AI/scripts/traffic_generator.py)
* **Packages / Libraries Used:** Python `socket`, `time`, `ipaddress`, `argparse`, (optional `scapy`)
* **What Happens:**
  1. Packets hit the network interface.
  2. For controlled testing, `traffic_generator.py` binds defensively to `127.0.0.1` using standard Python `socket` calls.
  3. It generates three canonical network behaviors:
     - **Baseline**: Periodic HTTP requests (port 8000) and DNS lookups (port 53).
     - **Sequential Port Probe**: Rapid TCP connect probes across consecutive ports (`8000`–`8015`) to simulate reconnaissance scanner behavior.
     - **Volumetric Burst**: High-rate datagram bursts (~100–250 pps) simulating link congestion / DoS floods.
  4. The script's `TelemetryLogEmitter` synchronously writes matching Zeek TSV (`logs/conn.log`) and Suricata NDJSON (`logs/eve.json`) records.

---

### Step 2: Asynchronous Streaming & Rotation-Resilient Tailing
* **Domain:** **Data Engineering & Systems Architecture**
* **Folder Involved:** `src/worker/` and `netmind/src/worker/`
* **File Involved:** [`src/worker/log_tailer.py`](file:///d:/Coding/GitHub/NetMind_AI/src/worker/log_tailer.py)
* **Packages / Libraries Used:** Python standard library `json`, `pathlib`, `time`, `signal`, `logging`
* **What Happens:**
  1. The `NetMindLogTailer` daemon wakes up every second (`POLL_INTERVAL=1.0`).
  2. It queries `CheckpointManager` which tracks the exact byte offset for `conn.log` and `eve.json` in `logs/.tailer_checkpoint.json`.
  3. **Cross-Platform Rotation Detection:**
     - On Linux/Unix: Compares `stat.st_ino` (inode number). If the inode changed, the log was rotated by `logrotate`.
     - On Windows / all platforms: If current file size is less than stored byte offset (`stat.st_size < offset`), the file was truncated/re-created.
     - When rotation is detected, the offset resets to `0` automatically, preventing duplicate reads or missed entries.
  4. Seeks to `offset`, reads only newly appended lines, and updates the checkpoint atomically.

---

### Step 3: Canonical Parsing & 5-Tuple Normalization
* **Domain:** **Cybersecurity & Data Ingestion**
* **Folder Involved:** `src/ingestion/` and `netmind/src/ingestion/`
* **Files Involved:** [`src/ingestion/zeek_parser.py`](file:///d:/Coding/GitHub/NetMind_AI/src/ingestion/zeek_parser.py), [`src/ingestion/suricata_parser.py`](file:///d:/Coding/GitHub/NetMind_AI/src/ingestion/suricata_parser.py)
* **Packages / Libraries Used:** `pandas`, `json`, `logging`
* **What Happens:**
  1. **Zeek Parsing (`ZeekConnLogParser`)**:
     - Strips header comments (`#fields`, `#types`).
     - Normalizes empty indicators: Zeek records unset fields as `-` or `(empty)`. The parser converts these into typed Python `None` / `np.nan` values.
     - Extracts canonical 5-tuples: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`.
     - Casts metrics: `duration` $\rightarrow$ float, `orig_bytes`/`resp_bytes` $\rightarrow$ int, `orig_pkts`/`resp_pkts` $\rightarrow$ int.
     - Preserves connection state strings: `conn_state` (`SF`, `S0`, `REJ`, `RSTO`) and TCP flag history (`history`).
  2. **Suricata Parsing (`SuricataEveParser`)**:
     - Streams JSON alert records via memory-efficient Python generators (`stream_alerts`).
     - Extracts signature ID, category, severity rating (1=Critical to 4=Low), and IPS action (`allowed`/`blocked`).

---

### Step 4: Non-Memorizing Behavioral Feature Engineering
* **Domain:** **Data Science (Feature Engineering)**
* **Folder Involved:** `src/features/` and `netmind/src/features/`
* **File Involved:** [`src/features/engineer.py`](file:///d:/Coding/GitHub/NetMind_AI/src/features/engineer.py)
* **Packages / Libraries Used:** `pandas`, `numpy`, `ipaddress`
* **What Happens:**
  The `NetMindFeatureEngineer` transformer transforms raw connection rows into a clean 30-dimensional behavioral vector:
  1. **Flow & Rate Metrics:**
     $$\text{packets\_per\_second} = \frac{\text{total\_pkts}}{\max(\text{duration}, 10^{-4})}, \quad \text{bytes\_per\_second} = \frac{\text{total\_bytes}}{\max(\text{duration}, 10^{-4})}$$
     $$\text{avg\_packet\_size} = \frac{\text{total\_bytes}}{\max(\text{total\_pkts}, 1)}$$
  2. **TCP Asymmetry Behavioral Ratios:**
     $$\text{syn\_ack\_ratio} = \frac{\text{syn\_count}}{\text{ack\_count} + 10^{-5}}$$
     During normal web browsing, `syn_ack_ratio` $\approx 0.05$–$0.2$. During a SYN flood or port scan, `syn_ack_ratio` $\rightarrow 1000.0$.
  3. **Connection Failure Patterns:**
     - Checks if `conn_state` belongs to `{"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}`.
     - Computes `is_failed_connection` and `failed_conn_ratio`.
  4. **Strict IP-Memorization Avoidance:**
     - Static strings `src_ip`, `dst_ip`, and `uid` are **strictly deleted** from the feature matrix.
     - Abstract structural features are extracted instead:
       - `is_src_private_ip`, `is_dst_private_ip` via `ipaddress.ip_address.is_private`
       - `is_dst_well_known_port` ($\text{port} < 1024$)
       - `is_dst_registered_port` ($1024 \le \text{port} < 49152$)
       - `is_src_ephemeral_port` ($\text{port} \ge 49152$)
       - One-hot transport encoding: `proto_tcp`, `proto_udp`, `proto_icmp`.

---

### Step 5: Heavy-Tail Resistant Preprocessing (`RobustScaler`)
* **Domain:** **Data Science (Statistical Hygiene)**
* **Folder Involved:** `src/ml/` and `models/`
* **Files Involved:** [`src/ml/dataset.py`](file:///d:/Coding/GitHub/NetMind_AI/src/ml/dataset.py), [`models/preprocessor.joblib`](file:///d:/Coding/GitHub/NetMind_AI/models/preprocessor.joblib)
* **Packages / Libraries Used:** `scikit-learn` (`RobustScaler`, `SimpleImputer`), `joblib`, `numpy`, `pandas`
* **What Happens:**
  1. **Median Imputation**: `SimpleImputer(strategy="median")` fills any missing feature values with training medians (immune to extreme attack outlier pollution).
  2. **Robust Quantile Normalization**:
     $$\hat{x} = \frac{x - \text{median}(X)}{Q_3(X) - Q_1(X)}$$
     Because network traffic features (byte counts, durations) follow power-law (Pareto) distributions, Gaussian $z$-score scaling fails. `RobustScaler` scales features using the Interquartile Range ($\text{IQR} = Q_3 - Q_1$), keeping feature bounds stable even during multi-gigabit DoS floods.
  3. The fitted transformer is saved as `models/preprocessor.joblib` and applied identically during inference.

---

### Step 6: Dual-Engine AI Inference (Isolation Forest & XGBoost)
* **Domain:** **Artificial Intelligence & Machine Learning**
* **Folder Involved:** `src/ml/` and `models/`
* **Files Involved:** [`src/ml/anomaly_detector.py`](file:///d:/Coding/GitHub/NetMind_AI/src/ml/anomaly_detector.py), [`src/ml/attack_classifier.py`](file:///d:/Coding/GitHub/NetMind_AI/src/ml/attack_classifier.py), [`models/anomaly_detector.joblib`](file:///d:/Coding/GitHub/NetMind_AI/models/anomaly_detector.joblib), [`models/attack_classifier.joblib`](file:///d:/Coding/GitHub/NetMind_AI/models/attack_classifier.joblib)
* **Packages / Libraries Used:** `scikit-learn` (`IsolationForest`), `xgboost` (`XGBClassifier`), `joblib`, `numpy`
* **What Happens:**
  Every scaled feature vector is processed through two concurrent AI models:

  ```
                       Scaled Behavioral Feature Vector (30 dimensions)
                                       │
                      ┌────────────────┴────────────────┐
                      ▼                                 ▼
      ┌──────────────────────────────┐  ┌──────────────────────────────┐
      │ Unsupervised Isolation Forest│  │ Supervised Multiclass XGBoost│
      │ (models/anomaly_detector)    │  │ (models/attack_classifier)   │
      ├──────────────────────────────┤  ├──────────────────────────────┤
      │ • 150 Isolation Trees        │  │ • 180 Regularized Trees      │
      │ • Measures path length h(x)  │  │ • Objective: multi:softprob  │
      │ • Output: Anomaly Score      │  │ • Classes: Normal, DoS,      │
      │   in [0.0, 1.0]              │  │   Port Scan, Brute, Web      │
      │ • Flag: Score >= 0.55 cutoff │  │ • Output: Class + Confidence │
      └──────────────────────────────┘  └──────────────────────────────┘
  ```

  1. **Isolation Forest (Zero-Day Anomaly Engine)**:
     - Evaluates path lengths across 150 isolation trees. Anomalous instances require few hyperplane splits to isolate.
     - Calculates anomaly score: $s(x, n) = 2^{-\mathbb{E}(h(x)) / c(n)}$.
     - If $s(x, n) \ge 0.55$ (the dynamically calibrated 95th-percentile baseline threshold), the flow is flagged as an `Anomaly`.
  2. **XGBoost Classifier (Attribution Engine)**:
     - Computes softprob posterior probabilities across all 5 attack categories.
     - Returns the predicted attack label (e.g. `Port Scan`) and probability confidence (e.g. `98.4%`).

---

### Step 7: Game-Theoretic Explainability (TreeSHAP)
* **Domain:** **Explainable AI (XAI)**
* **Folder Involved:** `src/ml/`
* **File Involved:** [`src/ml/explainer.py`](file:///d:/Coding/GitHub/NetMind_AI/src/ml/explainer.py)
* **Packages / Libraries Used:** `shap` (`TreeExplainer`), `numpy`, `pandas`
* **What Happens:**
  1. To prevent SOC analyst alert fatigue and provide legal/audit accountability, the explainer runs Lundberg & Lee's **TreeSHAP algorithm** ($O(T \cdot L \cdot D^2)$).
  2. Computes the exact Shapley attribution value $\phi_i$ for each behavioral feature:
     $$\phi_i(x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f_x(S \cup \{i\}) - f_x(S) \right]$$
  3. Translates mathematical Shapley values into human-readable SOC narratives:
     - $\phi_{\text{syn\_ack\_ratio}} = +0.44 \longrightarrow$ *"Abnormal SYN/ACK ratio (+0.44) drove DoS alert."*
     - $\phi_{\text{failed\_conn\_ratio}} = +0.32 \longrightarrow$ *"High connection failure rate (+0.32) confirms reconnaissance sweep."*

---

### Step 8: Multi-Vector Risk Calculation & Playbook Generation
* **Domain:** **Cybersecurity & Decision Support**
* **Folder Involved:** `src/backend/` and `netmind/src/backend/`
* **File Involved:** [`src/backend/decision_engine.py`](file:///d:/Coding/GitHub/NetMind_AI/src/backend/decision_engine.py)
* **Packages / Libraries Used:** Python dataclasses, `schemas.py`
* **What Happens:**
  1. **The 4-Factor Risk Formulation:**
     $$\text{Composite Risk} = 0.40 \cdot \text{SecurityRisk} + 0.25 \cdot \text{AnomalyScore} + 0.20 \cdot \text{PerformanceRisk} + 0.15 \cdot \text{HistoricalRisk}$$
     - $\text{SecurityRisk}$ (40%): Attack base score (`DoS`=90, `Web`=85, `Port Scan`=55) scaled by model confidence.
     - $\text{AnomalyScore}$ (25%): Isolation Forest score scaled to $[0, 100]$.
     - $\text{PerformanceRisk}$ (20%): Interface queue stress based on bytes/sec and pkts/sec.
     - $\text{HistoricalRisk}$ (15%): Host recurrence penalty (elevated to 80.0 if host was previously quarantined).
  2. **Categorization Tiers**:
     - `0`–`25`: **LOW** (Normal baseline)
     - `26`–`50`: **MEDIUM** (Elevated variance)
     - `51`–`75`: **HIGH** (Confirmed adversary)
     - `76`–`100`: **CRITICAL** (Severe ongoing attack)
  3. **NIST SP 800-61 Playbook Mapping:**
     - If DoS + High/Critical $\longrightarrow$ Generates `RATE_LIMIT_PORT` and `BLOCK_SOURCE_IP`.
     - If Port Scan $\longrightarrow$ Generates `BLOCK_SOURCE_IP`.
     - If Brute Force $\longrightarrow$ Generates `LOCK_USER_CREDENTIALS` and `QUARANTINE_HOST`.
     - If Web Attack $\longrightarrow$ Generates `WAF_BLOCK_URI_PATTERN`.

---

### Step 9: Relational Persistence & Atomic Database Commits
* **Domain:** **Data Engineering & Backend Systems**
* **Folder Involved:** `src/backend/` and `netmind/src/backend/`
* **Files Involved:** [`src/backend/database.py`](file:///d:/Coding/GitHub/NetMind_AI/src/backend/database.py), [`src/backend/models.py`](file:///d:/Coding/GitHub/NetMind_AI/src/backend/models.py), [`src/backend/repository.py`](file:///d:/Coding/GitHub/NetMind_AI/src/backend/repository.py)
* **Packages / Libraries Used:** `sqlalchemy 2.0`, `psycopg2-binary` (PostgreSQL), `sqlite3`
* **What Happens:**
  Inside an atomic database transaction:
  1. `NetworkFlowRepository.create()`: Inserts raw flow with 5-tuple, byte count, packet count, and timestamp.
  2. If anomaly flagged $\longrightarrow$ `AnomalyRepository.create()` inserts `Anomaly` linked via foreign key `flow_id`.
  3. If attack detected $\longrightarrow$ `SecurityEventRepository.create()` inserts `SecurityEvent`.
  4. For each mitigation $\longrightarrow$ `RecommendationRepository.create()` inserts `Recommendation` (`status="pending"`).
  5. `HostRepository.get_or_create()` updates `Host.last_seen`, `Host.risk_score`, and records a new entry in `risk_scores`.
  6. `db.commit()` commits the transaction, and the worker updates `.tailer_checkpoint.json`.

---

### Step 10: High-Density SOC Portal & Human-in-the-Loop Review
* **Domain:** **Security Operations (SOC Frontend)**
* **Folder Involved:** `frontend/src/`
* **Files Involved:** [`frontend/src/views/Overview.tsx`](file:///d:/Coding/GitHub/NetMind_AI/frontend/src/views/Overview.tsx), [`frontend/src/components/ThreatDetailModal.tsx`](file:///d:/Coding/GitHub/NetMind_AI/frontend/src/components/ThreatDetailModal.tsx), [`frontend/src/views/RecommendationsView.tsx`](file:///d:/Coding/GitHub/NetMind_AI/frontend/src/views/RecommendationsView.tsx)
* **Packages / Libraries Used:** `react 18`, `typescript`, `recharts`, `tailwindcss`, `@fortawesome/react-fontawesome`
* **What Happens:**
  1. **Overview HUD**: Displays live Monitored Endpoints, active Ingestion indicators, throughput dual-line visualizer, and the recent Zeek connection stream.
  2. **Analyst Threat Investigation**: Clicking **Investigate** opens `ThreatDetailModal.tsx`:
     - Shows technical evidence (duration, BPS, PPS, SYN/ACK ratio).
     - Renders horizontal Recharts bar chart displaying exact TreeSHAP contributions.
     - Displays the proposed Decision Engine mitigation command (e.g. `iptables -A INPUT -s 192.168.1.200 -j DROP`).
  3. **Containment Enforcement**: The analyst clicks **Approve & Apply** or **Simulate Remediation**, updating `Recommendation.status = "approved"`, marking the incident as resolved, and quarantining the hostile endpoint.

---

## 4. Concrete Walkthrough: Tracing an Attack Packet End-to-End

To illustrate how all three domains work in practice, let's trace an adversarial scan sweep:

```
[ Attack Packet Generator ]
An adversary executes an nmap TCP SYN sweep: sends 30 rapid packets from 192.168.1.200
targeting ports 8000, 8001, 8002... on 127.0.0.1.
                           │
                           ▼
[ Step 1: Wire Traffic & Zeek Sniffing ]
• Raw Packet: TCP [SYN] seq=1000 win=1024 dport=8001
• Zeek records session in logs/conn.log:
  ts=1728468002.30  id.orig_h=192.168.1.200  id.resp_p=8001  proto=tcp  conn_state=S0  history=S
                           │
                           ▼
[ Step 2: Ingestion & Feature Engineering ]
• src/worker/log_tailer.py reads new bytes at offset 1377.
• src/features/engineer.py strips '192.168.1.200' (prevents lab IP memorization).
• Computes: syn_ack_ratio = 1000.0, failed_conn_ratio = 1.0, is_dst_registered_port = 1.0.
• models/preprocessor.joblib applies RobustScaler: scales metrics by median & IQR.
                           │
                           ▼
[ Step 3: Dual-Engine AI Inference ]
• Isolation Forest: Anomaly Score = 0.88 (exceeds 0.55 threshold -> Anomaly Flagged).
• XGBoost Classifier: Attributed as "Port Scan" with 98.4% Confidence.
• TreeSHAP Explainer: Identifies syn_ack_ratio (+0.44) and failed_conns (+0.32) as primary drivers.
                           │
                           ▼
[ Step 4: Decision Engine & NIST Playbook ]
• Composite Risk = 0.40*(55*0.984) + 0.25*(88) + 0.20*(35) + 0.15*(15) = 78.4 (CRITICAL).
• Generates Playbook: BLOCK_SOURCE_IP (Drop connection attempts to suppress target mapping).
                           │
                           ▼
[ Step 5: Database Commit & SOC Review ]
• Committed to PostgreSQL: NetworkFlow #104, Anomaly #12, SecurityEvent #8, Recommendation #14.
• Frontend SOC Dashboard notifies analyst with CRITICAL badge.
• Analyst inspects TreeSHAP explanation chart in modal and clicks "Approve & Apply".
```

---

## 5. Comprehensive Folder, File & Library Reference Matrix

| Step / Pipeline Phase | Primary Folder | Key Files | Libraries & Technologies | Core Domain |
|:---|:---|:---|:---|:---|
| **1. Wire Simulation** | `scripts/` | `traffic_generator.py` | Python `socket`, `time`, `ipaddress` | **Cybersecurity** |
| **2. Log Tailer Daemon** | `src/worker/` | `log_tailer.py` | `pathlib`, `json`, `signal`, `logging` | **Data Engineering** |
| **3. Canonical Ingestion** | `src/ingestion/` | `zeek_parser.py`, `suricata_parser.py` | `pandas`, `json` | **Cybersecurity** |
| **4. Feature Engineering** | `src/features/` | `engineer.py` | `pandas`, `numpy`, `ipaddress` | **Data Science** |
| **5. Preprocessing & Scaling** | `src/ml/`, `models/` | `dataset.py`, `preprocessor.joblib` | `scikit-learn` (`RobustScaler`), `joblib` | **Data Science** |
| **6. AI Zero-Day Detection** | `src/ml/`, `models/` | `anomaly_detector.py`, `anomaly_detector.joblib` | `scikit-learn` (`IsolationForest`) | **Artificial Intelligence** |
| **7. AI Threat Classification** | `src/ml/`, `models/` | `attack_classifier.py`, `attack_classifier.joblib` | `xgboost` (`XGBClassifier`) | **Artificial Intelligence** |
| **8. Rate Forecasting** | `src/ml/`, `models/` | `traffic_predictor.py`, `traffic_predictor.joblib` | `xgboost` (`XGBRegressor`) | **Artificial Intelligence** |
| **9. Game-Theoretic XAI** | `src/ml/` | `explainer.py` | `shap` (`TreeExplainer`) | **Explainable AI (XAI)** |
| **10. Risk & Mitigation Engine** | `src/backend/` | `decision_engine.py` | Python `dataclasses`, `schemas.py` | **Cybersecurity** |
| **11. Relational Persistence** | `src/backend/` | `database.py`, `models.py`, `repository.py` | `sqlalchemy 2.0`, `psycopg2-binary` | **Data Engineering** |
| **12. REST Serving Layer** | `src/backend/` | `main.py`, `routers/*.py` | `fastapi`, `uvicorn`, `pydantic v2` | **Systems / Backend** |
| **13. SOC Web Interface** | `frontend/src/` | `Overview.tsx`, `ThreatDetailModal.tsx` | `react 18`, `typescript`, `recharts`, `tailwind` | **Cybersecurity (SOC)** |
| **14. Multi-Container Orchestration** | Repository Root | `docker-compose.yml`, `Dockerfile` | Docker, Nginx alpine | **DevOps & Packaging** |

---

*Authored for the NetMind AI Autonomous Cyber Intelligence System.*
