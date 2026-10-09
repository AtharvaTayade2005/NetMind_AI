"""Standalone Integration & Unit Tests for NetMind AI Data Ingestion Pipeline.

Verifies:
1. Zeek TSV and JSON parsing with missing value ('-') sanitization.
2. Suricata EVE JSON streaming and alert parsing with severity extraction.
3. Feature engineering schema transformation:
   - Flow metrics (duration, packet_count, byte_count, avg_packet_size)
   - Rate metrics (packets_per_second, bytes_per_second, zero-duration safety)
   - TCP flag behaviors (SYN, ACK, RST counts, SYN/ACK ratio)
   - Host aggregated patterns (unique_destinations, failed_connections)
4. Lab-memorization avoidance: verifies exclusion of raw IP addresses from ML features.
5. End-to-end flow from raw logs to clean tabular ML-ready matrix without NaNs/Infs.

Can be run via `pytest` or directly with `python test_ingestion.py`.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
import pytest

# Ensure repo root and netmind paths are in sys.path
TEST_FILE_DIR = Path(__file__).resolve().parent
NETMIND_DIR = TEST_FILE_DIR.parent
WORKSPACE_DIR = NETMIND_DIR.parent

for p in [str(WORKSPACE_DIR), str(NETMIND_DIR), str(NETMIND_DIR / "src")]:
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from netmind.src.ingestion.zeek_parser import ZeekConnLogParser, parse_zeek_conn_log
    from netmind.src.ingestion.suricata_parser import SuricataEveParser, parse_eve_alerts
    from netmind.src.features.engineer import NetMindFeatureEngineer, extract_netmind_features
except ImportError:
    from src.ingestion.zeek_parser import ZeekConnLogParser, parse_zeek_conn_log
    from src.ingestion.suricata_parser import SuricataEveParser, parse_eve_alerts
    from src.features.engineer import NetMindFeatureEngineer, extract_netmind_features


# ==============================================================================
# Synthetic Test Fixtures
# ==============================================================================

SYNTHETIC_ZEEK_TSV = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2026-10-09-12-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	string	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1728468000.100	C_SYN01	192.168.1.100	50001	10.0.0.10	80	tcp	http	1.250000	500	5000	SF	T	T	0	ShADdfFa	10	900	15	5800	-
1728468001.200	C_SYN02	192.168.1.200	40001	10.0.0.10	22	tcp	-	-	-	-	S0	T	T	0	S	1	60	0	0	-
1728468001.250	C_SYN03	192.168.1.200	40002	10.0.0.20	445	tcp	-	0.001000	0	0	REJ	T	T	0	Sr	1	60	1	40	-
1728468002.300	C_SYN04	192.168.1.100	50002	8.8.8.8	53	udp	dns	0.020000	60	180	SF	T	F	0	Dd	1	88	1	208	-
#close	2026-10-09-12-05-00
"""

SYNTHETIC_ZEEK_JSON = """{"ts":1728468000.100,"uid":"CJ_01","id.orig_h":"192.168.1.100","id.orig_p":50001,"id.resp_h":"10.0.0.10","id.resp_p":80,"proto":"tcp","service":"http","duration":1.25,"orig_bytes":500,"resp_bytes":5000,"conn_state":"SF","history":"ShADdfFa","orig_pkts":10,"resp_pkts":15}
{"ts":1728468001.200,"uid":"CJ_02","id.orig_h":"192.168.1.200","id.orig_p":40001,"id.resp_h":"10.0.0.10","id.resp_p":22,"proto":"tcp","service":"-","duration":"-","orig_bytes":"-","resp_bytes":"-","conn_state":"S0","history":"S","orig_pkts":1,"resp_pkts":0}
{"ts":1728468002.300,"uid":"CJ_03","id.orig_h":"192.168.1.100","id.orig_p":50002,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","service":"dns","duration":0.02,"orig_bytes":60,"resp_bytes":180,"conn_state":"SF","history":"Dd","orig_pkts":1,"resp_pkts":1}
"""

SYNTHETIC_EVE_JSON = """{"timestamp":"2026-10-09T12:00:01.000000+0000","event_type":"alert","src_ip":"192.168.1.200","src_port":40001,"dest_ip":"10.0.0.10","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":1,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2026-10-09T12:00:01.500000+0000","event_type":"flow","src_ip":"192.168.1.100","dest_ip":"10.0.0.10","proto":"TCP","flow":{"pkts":25}}
{"timestamp":"2026-10-09T12:00:02.000000+0000","event_type":"alert","src_ip":"192.168.1.250","src_port":52100,"dest_ip":"10.0.0.50","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2010001,"rev":5,"signature":"ET EXPLOIT SQL Injection Detected","category":"Web Application Attack","severity":1}}
{"timestamp":"2026-10-09T12:00:03.000000+0000","event_type":"stats","stats":{"uptime":100}}
"""


# ==============================================================================
# Unit & Integration Tests
# ==============================================================================

def test_zeek_tsv_parser() -> None:
    """Test Zeek TSV parser cleans '-' values, coerces numeric metrics, and adds aliases."""
    parser = ZeekConnLogParser(add_canonical_aliases=True)
    df = parser.parse(SYNTHETIC_ZEEK_TSV, format="tsv")

    assert not df.empty, "Parsed DataFrame should not be empty."
    assert len(df) == 4, f"Expected 4 rows, got {len(df)}"

    # Verify canonical alias mapping
    assert "src_ip" in df.columns
    assert "dst_ip" in df.columns
    assert "src_port" in df.columns
    assert "dst_port" in df.columns

    # Verify missing value handling: row 1 (C_SYN02) duration and bytes were '-'
    row_scan = df.iloc[1]
    assert pd.isna(row_scan["duration"]), "Missing duration '-' should be parsed as NaN"
    assert pd.isna(row_scan["orig_bytes"]), "Missing orig_bytes '-' should be parsed as NaN"
    assert row_scan["conn_state"] == "S0"

    # Verify row 0 established connection metrics
    row_est = df.iloc[0]
    assert row_est["duration"] == pytest.approx(1.25)
    assert row_est["orig_bytes"] == 500
    assert row_est["resp_bytes"] == 5000
    assert row_est["orig_pkts"] == 10
    assert row_est["resp_pkts"] == 15
    assert pd.notna(row_est["timestamp"]), "Timestamp should be parsed into datetime"


def test_zeek_json_parser() -> None:
    """Test Zeek JSON / NDJSON parser."""
    parser = ZeekConnLogParser()
    df = parser.parse(SYNTHETIC_ZEEK_JSON, format="json")

    assert len(df) == 3
    assert "src_ip" in df.columns
    assert "dst_ip" in df.columns
    # Check that '-' in json is converted to NaN
    assert pd.isna(df.iloc[1]["duration"])
    assert df.iloc[0]["duration"] == pytest.approx(1.25)


def test_suricata_eve_parser() -> None:
    """Test Suricata EVE parser streams and tabularizes alerts with correct fields."""
    parser = SuricataEveParser()
    df = parser.parse_alerts(SYNTHETIC_EVE_JSON)

    # 4 lines total, but only 2 are alerts (flow and stats skipped)
    assert len(df) == 2, f"Expected 2 alerts, got {len(df)}"

    expected_cols = [
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "proto",
        "alert_signature",
        "alert_severity",
        "signature_id",
        "action",
    ]
    for col in expected_cols:
        assert col in df.columns, f"Missing expected alert column: {col}"

    # Verify extracted alert metadata
    assert df.iloc[0]["alert_signature"] == "ET SCAN Potential SSH Scan"
    assert df.iloc[0]["alert_severity"] == 2
    assert df.iloc[0]["src_ip"] == "192.168.1.200"
    assert df.iloc[0]["dst_port"] == 22

    assert df.iloc[1]["alert_signature"] == "ET EXPLOIT SQL Injection Detected"
    assert df.iloc[1]["alert_severity"] == 1
    assert df.iloc[1]["action"] == "blocked"


def test_feature_engineering_flow_metrics() -> None:
    """Test flow metrics: duration, packet_count, byte_count, avg_packet_size."""
    zeek_df = parse_zeek_conn_log(SYNTHETIC_ZEEK_TSV)
    engineer = NetMindFeatureEngineer(exclude_raw_ips=False)
    features, _ = engineer.extract_features_with_metadata(zeek_df)

    assert "duration" in features.columns
    assert "packet_count" in features.columns
    assert "byte_count" in features.columns
    assert "avg_packet_size" in features.columns

    # Row 0: 10 orig_pkts + 15 resp_pkts = 25 pkts; 500 orig_bytes + 5000 resp_bytes = 5500 bytes
    assert features.iloc[0]["packet_count"] == 25
    assert features.iloc[0]["byte_count"] == 5500
    assert features.iloc[0]["avg_packet_size"] == pytest.approx(5500 / 25)

    # Check zero packet flow edge case
    zero_df = pd.DataFrame([{
        "duration": 0.0,
        "orig_pkts": 0,
        "resp_pkts": 0,
        "orig_bytes": 0,
        "resp_bytes": 0,
    }])
    feat_zero = engineer.transform(zero_df)
    assert feat_zero.iloc[0]["avg_packet_size"] == 0.0, "Avg packet size should safely be 0.0 when packet_count is 0"


def test_feature_engineering_rate_metrics() -> None:
    """Test rate metrics: packets_per_second and bytes_per_second with zero-duration safety."""
    zeek_df = parse_zeek_conn_log(SYNTHETIC_ZEEK_TSV)
    engineer = NetMindFeatureEngineer(epsilon=1e-6)
    features = engineer.transform(zeek_df)

    assert "packets_per_second" in features.columns
    assert "bytes_per_second" in features.columns

    # Row 0: duration = 1.25s, pkts = 25, bytes = 5500
    assert features.iloc[0]["packets_per_second"] == pytest.approx(25 / 1.25, rel=1e-3)
    assert features.iloc[0]["bytes_per_second"] == pytest.approx(5500 / 1.25, rel=1e-3)

    # Row 1: duration = 0.0 / missing (scan attempt). Rates must be finite without ZeroDivisionError
    row_scan = features.iloc[1]
    assert np.isfinite(row_scan["packets_per_second"])
    assert np.isfinite(row_scan["bytes_per_second"])
    assert not np.isnan(row_scan["packets_per_second"])


def test_feature_engineering_tcp_flags() -> None:
    """Test TCP flag extraction: SYN, ACK, RST counts, and SYN/ACK ratio."""
    zeek_df = parse_zeek_conn_log(SYNTHETIC_ZEEK_TSV)
    engineer = NetMindFeatureEngineer(epsilon=1e-6)
    features = engineer.transform(zeek_df)

    assert "syn_count" in features.columns
    assert "ack_count" in features.columns
    assert "rst_count" in features.columns
    assert "syn_ack_ratio" in features.columns

    # Row 0: history 'ShADdfFa' -> S=1, A=2, R=0
    assert features.iloc[0]["syn_count"] == 1
    assert features.iloc[0]["ack_count"] == 2
    assert features.iloc[0]["rst_count"] == 0
    assert features.iloc[0]["syn_ack_ratio"] == pytest.approx(1 / (2 + 1e-6), rel=1e-3)

    # Row 1: history 'S' (SYN scan) -> S=1, A=0, R=0 -> SYN/ACK ratio very high!
    assert features.iloc[1]["syn_count"] == 1
    assert features.iloc[1]["ack_count"] == 0
    assert features.iloc[1]["syn_ack_ratio"] > 1000.0, "SYN scan should have elevated SYN/ACK ratio"

    # Row 2: history 'Sr' (REJ) -> S=1, A=0, R=1
    assert features.iloc[2]["rst_count"] == 1


def test_aggregated_connection_patterns() -> None:
    """Test host-aggregated patterns: unique_destinations, failed_connections."""
    zeek_df = parse_zeek_conn_log(SYNTHETIC_ZEEK_TSV)
    engineer = NetMindFeatureEngineer()
    features, _ = engineer.extract_features_with_metadata(zeek_df)

    assert "unique_destinations" in features.columns
    assert "failed_connections" in features.columns

    # In synthetic data:
    # 192.168.1.200 connects to 10.0.0.10 (row 1, S0) and 10.0.0.20 (row 2, REJ)
    # Both are failed connections! So unique_destinations=2, failed_connections=2.0
    row_192_168_1_200 = features.iloc[1]
    assert row_192_168_1_200["unique_destinations"] == 2
    assert row_192_168_1_200["failed_connections"] == 2.0
    assert row_192_168_1_200["failed_conn_ratio"] == 1.0


def test_ip_exclusion_to_avoid_memorization() -> None:
    """Verify that raw static IP addresses and flow UIDs are strictly excluded from predictive features."""
    zeek_df = parse_zeek_conn_log(SYNTHETIC_ZEEK_TSV)
    engineer = NetMindFeatureEngineer(exclude_raw_ips=True)
    features, metadata = engineer.extract_features_with_metadata(zeek_df)

    # ML Feature matrix check: NO static IP columns allowed
    forbidden_features = ["src_ip", "dst_ip", "id.orig_h", "id.resp_h", "uid", "history", "conn_state"]
    for col in forbidden_features:
        assert col not in features.columns, (
            f"Found forbidden identifier '{col}' in ML predictive features! "
            "Raw static IPs must be excluded to prevent lab-memorization."
        )

    # Topology and behavior features SHOULD be present
    assert "is_src_private_ip" in features.columns
    assert "is_dst_private_ip" in features.columns
    assert "is_dst_well_known_port" in features.columns

    # Metadata check: Triage identifiers MUST be preserved in metadata for analyst investigations
    assert "src_ip" in metadata.columns
    assert "dst_ip" in metadata.columns
    assert metadata.iloc[0]["src_ip"] == "192.168.1.100"


def test_end_to_end_pipeline_with_mock_files() -> None:
    """End-to-end integration test reading files from logs/ directory and generating ML-ready matrix."""
    mock_conn_path = NETMIND_DIR / "logs" / "conn.log"
    assert mock_conn_path.is_file(), f"Mock log file not found at {mock_conn_path}"

    # 1. Parse Zeek conn.log
    df_raw = parse_zeek_conn_log(mock_conn_path)
    assert not df_raw.empty, "Failed to parse mock conn.log"

    # 2. Extract NetMind features
    engineer = NetMindFeatureEngineer(exclude_raw_ips=True)
    X_ml = engineer.fit_transform(df_raw)

    # 3. Assert ML readiness
    assert isinstance(X_ml, pd.DataFrame)
    assert len(X_ml) == len(df_raw)
    assert X_ml.shape[1] >= 15, f"Expected at least 15 features, got {X_ml.shape[1]}"

    # No missing or infinite values
    assert not X_ml.isna().any().any(), "ML feature matrix contains unexpected NaN values"
    assert np.all(np.isfinite(X_ml.to_numpy())), "ML feature matrix contains non-finite values (Inf/-Inf)"

    # Check all dtypes are numeric (float or int)
    for col in X_ml.columns:
        assert pd.api.types.is_numeric_dtype(X_ml[col]), f"Column '{col}' is not numeric dtype: {X_ml[col].dtype}"


# ==============================================================================
# Standalone CLI Test Runner
# ==============================================================================

def run_all_tests() -> bool:
    """Run all tests directly and print structured Senior Engineer report."""
    test_suite = [
        ("Zeek TSV Parsing & Missing Handling", test_zeek_tsv_parser),
        ("Zeek JSON Parsing", test_zeek_json_parser),
        ("Suricata EVE Parsing & Severity Extraction", test_suricata_eve_parser),
        ("Feature Engineering: Flow Metrics", test_feature_engineering_flow_metrics),
        ("Feature Engineering: Rate Metrics & Zero Safety", test_feature_engineering_rate_metrics),
        ("Feature Engineering: TCP Flag Behavior", test_feature_engineering_tcp_flags),
        ("Aggregated Connection Patterns", test_aggregated_connection_patterns),
        ("Lab-Memorization Avoidance (IP Exclusion)", test_ip_exclusion_to_avoid_memorization),
        ("End-to-End Pipeline & ML-Readiness", test_end_to_end_pipeline_with_mock_files),
    ]

    print("=" * 78)
    print("NetMind AI - Ingestion & Feature Engineering Pipeline Verification")
    print("=" * 78)

    passed = 0
    failed = 0

    for name, test_func in test_suite:
        try:
            test_func()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed += 1

    print("-" * 78)
    print(f"Summary: {passed} passed, {failed} failed out of {len(test_suite)} tests.")
    print("=" * 78)
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
