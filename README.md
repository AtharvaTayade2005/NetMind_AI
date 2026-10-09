# NetMind AI - Network Telemetry Ingestion & Feature Engineering Foundation

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Architecture](https://img.shields.io/badge/architecture-data--ingestion-brightgreen.svg)](#architecture)
[![Tests](https://img.shields.io/badge/tests-passing-green.svg)](#testing)

**NetMind AI** is an intelligent network monitoring and decision support system. This foundational package provides robust, production-grade telemetry ingestion from **Zeek** and **Suricata**, coupled with ML feature engineering designed specifically to avoid laboratory IP memorization.

---

## Directory Structure

```text
netmind/
├── data/
│   ├── raw/                 # Raw ingested telemetry
│   └── processed/           # Normalized, ML-ready feature tables
├── logs/                    # Mock & production Zeek and Suricata logs
│   ├── conn.log             # Tab-separated Zeek conn log
│   ├── zeek_conn.json       # NDJSON Zeek conn log
│   └── eve.json             # Suricata EVE JSON alert log
├── src/
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── zeek_parser.py   # TSV & NDJSON Zeek conn parser (cleans '-' & '(empty)')
│   │   └── suricata_parser.py # Streaming & batch Suricata EVE alert parser
│   └── features/
│       ├── __init__.py
│       └── engineer.py      # NetMind flow metrics, rate metrics, TCP flag ratios,
│                            # host aggregations, and IP memorization avoidance
├── tests/
│   └── test_ingestion.py    # Comprehensive unit and integration test suite
├── requirements.txt
└── .env.example
```

---

## Key Components

### 1. Zeek Connection Log Parser (`src/ingestion/zeek_parser.py`)
- **Dual Format Support**: Robustly ingests both standard tab-separated (`conn.log` with `#fields` / `#types` directives) and streaming newline-delimited JSON (`zeek_conn.json`).
- **Missing Value Handling**: Translates Zeek unset indicators (`-`, `(empty)`, `null`) cleanly to `NaN` / typed nulls.
- **Canonical Standardization**: Normalizes network 5-tuples (`id.orig_h` → `src_ip`, `id.resp_h` → `dst_ip`, `id.orig_p` → `src_port`, `id.resp_p` → `dst_port`).
- **Timestamp & Numeric Coercion**: Epoch floats coerced into UTC `datetime64[ns]` and flow counters into `float64` / `Int64`.

### 2. Suricata EVE Alert Parser (`src/ingestion/suricata_parser.py`)
- **Memory-Efficient Streaming**: Implements Python generators (`stream_alerts()`) for streaming gigabyte-scale production `eve.json` files without high memory overhead.
- **Alert Event Filtering**: Filters for `event_type == "alert"` records while safely skipping auxiliary events (flow, stats, DNS).
- **Security Metadata Extraction**: Normalizes `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `alert_signature`, `alert_category`, `alert_severity` (1=High to 4=Info), `signature_id`, and `action`.

### 3. NetMind Feature Engineering (`src/features/engineer.py`)
Transforms raw network flows into normalized tabular features ready for ML training (e.g., XGBoost, Random Forest, PyTorch):
- **Flow Metrics**: `duration`, `packet_count`, `byte_count`, `avg_packet_size`.
- **Rate Metrics**: `packets_per_second`, `bytes_per_second` (with `epsilon`-smoothing to handle zero-duration / sub-millisecond flows).
- **TCP Flag Behavior**: Parses Zeek history flags (`S`, `s`, `A`, `a`, `R`, `r`, `F`, `f`) to compute `syn_count`, `ack_count`, `rst_count`, and the `syn_ack_ratio` (vital for SYN flood / scan detection).
- **Host Aggregated Patterns**: Computes `unique_destinations`, `failed_connections`, `failed_conn_ratio`, and `unique_dest_ports` per source host.
- **Lab-Memorization Avoidance**: Strictly excludes static IP addresses (`src_ip`, `dst_ip`, `uid`) from the direct ML feature matrix `X` while retaining them in incident triage metadata for analyst investigations. Extracts generalized topology features instead (`is_src_private_ip`, `is_dst_private_ip`, `is_dst_well_known_port`).

---

## Quickstart

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Configuration

```bash
cp .env.example .env
```

### 3. Running Tests

Run the standalone verification runner:
```bash
python netmind/tests/test_ingestion.py
```

Or via pytest:
```bash
pytest -v
```
