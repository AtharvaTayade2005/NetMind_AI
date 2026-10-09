"""NetMind AI - Network Flow Feature Engineering Pipeline.

Transforms raw network flow telemetry (e.g. Zeek conn logs, IPFIX/NetFlow, Suricata flows)
into the NetMind ML-ready feature schema:
- Flow metrics: duration, packet_count, byte_count, avg_packet_size
- Rate metrics: packets_per_second, bytes_per_second
- TCP flag behavior: SYN count, ACK count, RST count, SYN/ACK ratio
- Aggregated connection patterns: unique_destinations, failed_connections
- Topology & Port features: private IP indicators, well-known port indicators
- Lab-memorization avoidance: Strictly excludes raw static IPs and connection UIDs
  from direct predictive features while preserving them in incident metadata.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Zeek conn_state values representing failed or rejected connection attempts:
# S0: Connection attempt seen, no reply (SYN scan / unreachable host)
# REJ: Connection attempt rejected (RST returned)
# RSTOS0: Originator sent a SYN followed by a RST, never saw SYN-ACK
# RSTRH: Responder sent a SYN-ACK followed by a RST
# SH: Originator sent a SYN followed by a FIN without SYN-ACK
# SHR: Responder sent a SYN-ACK followed by a FIN
FAILED_CONN_STATES: Set[str] = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}

# Raw identifier columns strictly excluded from ML predictive features
STATIC_IDENTIFIER_COLUMNS: Set[str] = {
    "src_ip",
    "dst_ip",
    "id.orig_h",
    "id.resp_h",
    "uid",
    "flow_id",
    "ts",
    "timestamp",
    "history",
    "conn_state",
    "service",
    "tunnel_parents",
    "local_orig",
    "local_resp",
}


class NetMindFeatureEngineer:
    """Scikit-Learn compatible Feature Engineering Transformer for Network Telemetry.

    Extracts flow metrics, rate metrics, TCP flag behaviors, and host-level aggregated
    connection patterns while strictly preventing raw IP memorization in ML models.
    """

    def __init__(
        self,
        epsilon: float = 1e-6,
        exclude_raw_ips: bool = True,
        include_protocol_dummies: bool = True,
    ) -> None:
        """Initialize the feature engineer.

        Args:
            epsilon: Small float added to denominators to prevent division by zero.
            exclude_raw_ips: Whether to exclude static IP addresses and flow UIDs
                from the transformed output feature matrix.
            include_protocol_dummies: Whether to encode transport protocol as one-hot columns.
        """
        self.epsilon = epsilon
        self.exclude_raw_ips = exclude_raw_ips
        self.include_protocol_dummies = include_protocol_dummies
        self.feature_names_: List[str] = []
        self._is_fitted = False

    def fit(self, X: pd.DataFrame, y: Optional[Any] = None) -> "NetMindFeatureEngineer":
        """Fit the transformer on input network flow records.

        Args:
            X: Input DataFrame containing raw or parsed flow logs.
            y: Optional target labels (ignored).

        Returns:
            self
        """
        # Transform a small sample to determine feature column schema
        sample_transformed, _ = self._extract_features(X.iloc[: min(5, len(X))])
        self.feature_names_ = list(sample_transformed.columns)
        self._is_fitted = True
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """Transform network flow records into the ML-ready feature matrix.

        Args:
            X: Input DataFrame of flow records.

        Returns:
            pd.DataFrame: Clean, numeric, finite feature matrix without raw IP identifiers.
        """
        features_df, _ = self._extract_features(X)

        # Align columns if fitted
        if self._is_fitted and self.feature_names_:
            for col in self.feature_names_:
                if col not in features_df.columns:
                    features_df[col] = 0.0
            features_df = features_df[self.feature_names_]

        return features_df

    def fit_transform(self, X: pd.DataFrame, y: Optional[Any] = None) -> pd.DataFrame:
        """Fit and transform input flow records."""
        return self.fit(X, y).transform(X)

    def extract_features_with_metadata(
        self, X: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Extract both the predictive ML feature matrix and incident triage metadata.

        Args:
            X: Input raw flow records DataFrame.

        Returns:
            Tuple[pd.DataFrame, pd.DataFrame]:
                - X_features: Clean numeric predictive feature matrix for ML.
                - metadata_df: Preserved IP addresses, timestamps, and identifiers for triage.
        """
        return self._extract_features(X)

    def get_feature_names(self) -> List[str]:
        """Get the list of predictive feature column names."""
        return list(self.feature_names_)

    def get_metadata_columns(self) -> List[str]:
        """Get the list of static identifier columns retained in incident metadata."""
        return sorted(list(STATIC_IDENTIFIER_COLUMNS))

    def _extract_features(
        self, df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Core feature extraction routine."""
        if df.empty:
            return pd.DataFrame(), pd.DataFrame()

        df_in = df.copy()

        # Helper functions to guarantee Series output
        def _get_num_series(primary: str, fallback: Optional[str] = None, default: float = 0.0) -> pd.Series:
            if primary in df_in.columns:
                s = df_in[primary]
            elif fallback and fallback in df_in.columns:
                s = df_in[fallback]
            else:
                s = pd.Series(default, index=df_in.index)
            return pd.to_numeric(s, errors="coerce").fillna(default)

        def _get_str_series(primary: str, fallback: Optional[str] = None, default: str = "") -> pd.Series:
            if primary in df_in.columns:
                s = df_in[primary]
            elif fallback and fallback in df_in.columns:
                s = df_in[fallback]
            else:
                s = pd.Series(default, index=df_in.index)
            return s.fillna(default).astype(str)

        # ----------------------------------------------------------------------
        # 1. Normalize Canonical Column Aliases
        # ----------------------------------------------------------------------
        src_ip = _get_str_series("src_ip", "id.orig_h", default="0.0.0.0")
        dst_ip = _get_str_series("dst_ip", "id.resp_h", default="0.0.0.0")
        src_port = _get_num_series("src_port", "id.orig_p", default=0.0)
        dst_port = _get_num_series("dst_port", "id.resp_p", default=0.0)
        proto = _get_str_series("proto", default="tcp").str.lower()
        history = _get_str_series("history", default="")
        conn_state = _get_str_series("conn_state", default="")

        # ----------------------------------------------------------------------
        # 2. Flow Metrics: duration, packet_count, byte_count, avg_packet_size
        # ----------------------------------------------------------------------
        duration = _get_num_series("duration", default=0.0).clip(lower=0.0)

        # Handle packet counts (from orig_pkts/resp_pkts or pre-computed packet_count)
        orig_pkts = _get_num_series("orig_pkts", default=0.0).clip(lower=0.0)
        resp_pkts = _get_num_series("resp_pkts", default=0.0).clip(lower=0.0)
        if "packet_count" in df_in.columns:
            packet_count = _get_num_series("packet_count", default=0.0).clip(lower=0.0)
        else:
            packet_count = orig_pkts + resp_pkts

        # Handle byte counts (from orig_bytes/resp_bytes or orig_ip_bytes/resp_ip_bytes)
        orig_bytes = _get_num_series("orig_bytes", default=0.0).clip(lower=0.0)
        resp_bytes = _get_num_series("resp_bytes", default=0.0).clip(lower=0.0)
        orig_ip_bytes = _get_num_series("orig_ip_bytes", default=0.0).clip(lower=0.0)
        resp_ip_bytes = _get_num_series("resp_ip_bytes", default=0.0).clip(lower=0.0)

        # Use payload bytes if available, otherwise IP bytes
        effective_orig_bytes = np.where(orig_bytes > 0, orig_bytes, orig_ip_bytes)
        effective_resp_bytes = np.where(resp_bytes > 0, resp_bytes, resp_ip_bytes)

        if "byte_count" in df_in.columns:
            byte_count = _get_num_series("byte_count", default=0.0).clip(lower=0.0)
        else:
            byte_count = pd.Series(effective_orig_bytes + effective_resp_bytes, index=df_in.index)

        # Average packet size (safe divide)
        avg_packet_size = np.where(packet_count > 0, byte_count / np.maximum(packet_count, 1.0), 0.0)

        # ----------------------------------------------------------------------
        # 3. Rate Metrics: packets_per_second, bytes_per_second
        # ----------------------------------------------------------------------
        effective_duration = np.maximum(duration, self.epsilon)
        packets_per_second = packet_count / effective_duration
        bytes_per_second = byte_count / effective_duration

        # ----------------------------------------------------------------------
        # 4. TCP Flag Behavior: SYN count, ACK count, RST count, SYN/ACK ratio
        # ----------------------------------------------------------------------
        if "syn_count" in df_in.columns:
            syn_count = _get_num_series("syn_count", default=0.0)
        else:
            syn_count = history.apply(lambda h: float(h.count("S") + h.count("s")))

        if "ack_count" in df_in.columns:
            ack_count = _get_num_series("ack_count", default=0.0)
        else:
            ack_count = history.apply(lambda h: float(h.count("A") + h.count("a")))

        if "rst_count" in df_in.columns:
            rst_count = _get_num_series("rst_count", default=0.0)
        else:
            rst_count = history.apply(lambda h: float(h.count("R") + h.count("r")))

        fin_count = history.apply(lambda h: float(h.count("F") + h.count("f")))

        # SYN/ACK ratio: high ratio indicates SYN scan or SYN flooding
        syn_ack_ratio = syn_count / (ack_count + self.epsilon)

        # ----------------------------------------------------------------------
        # 5. Failed Connection Detection
        # ----------------------------------------------------------------------
        is_failed_flow = conn_state.isin(FAILED_CONN_STATES) | (
            (proto == "tcp") & (orig_pkts > 0) & (resp_pkts == 0)
        )
        is_failed_flow_numeric = is_failed_flow.astype(float)

        # ----------------------------------------------------------------------
        # 6. Aggregated Connection Patterns (per source host)
        # ----------------------------------------------------------------------
        # Group by source IP to compute behavior patterns without using the IP as a feature
        temp_group_df = pd.DataFrame({
            "_src": src_ip,
            "_dst": dst_ip,
            "_dport": dst_port,
            "_failed": is_failed_flow_numeric,
        }, index=df_in.index)

        unique_destinations = temp_group_df.groupby("_src")["_dst"].transform("nunique")
        failed_connections = temp_group_df.groupby("_src")["_failed"].transform("sum")
        src_conn_count = temp_group_df.groupby("_src")["_dst"].transform("count")
        failed_conn_ratio = failed_connections / np.maximum(src_conn_count, 1.0)

        # Unique destination ports targeted (vital for port scan detection)
        unique_dest_ports = temp_group_df.groupby("_src")["_dport"].transform("nunique")

        # ----------------------------------------------------------------------
        # 7. Topology & Port Classification (Generalized, Non-memorized)
        # ----------------------------------------------------------------------
        is_src_private_ip = src_ip.apply(self._is_private_ip).astype(float)
        is_dst_private_ip = dst_ip.apply(self._is_private_ip).astype(float)

        is_dst_well_known_port = (dst_port < 1024).astype(float)
        is_dst_registered_port = ((dst_port >= 1024) & (dst_port < 49152)).astype(float)
        is_src_ephemeral_port = (src_port >= 1024).astype(float)

        # ----------------------------------------------------------------------
        # 8. Assemble Feature Dictionary
        # ----------------------------------------------------------------------
        features: Dict[str, Any] = {
            # Flow metrics
            "duration": duration,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "avg_packet_size": avg_packet_size,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            # Rate metrics
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            # TCP flag behavior
            "syn_count": syn_count,
            "ack_count": ack_count,
            "rst_count": rst_count,
            "fin_count": fin_count,
            "syn_ack_ratio": syn_ack_ratio,
            # Aggregated connection patterns
            "unique_destinations": unique_destinations,
            "failed_connections": failed_connections,
            "failed_conn_ratio": failed_conn_ratio,
            "unique_dest_ports": unique_dest_ports,
            "src_conn_count": src_conn_count,
            "is_failed_connection": is_failed_flow_numeric,
            # Topology & Port metrics
            "is_src_private_ip": is_src_private_ip,
            "is_dst_private_ip": is_dst_private_ip,
            "is_dst_well_known_port": is_dst_well_known_port,
            "is_dst_registered_port": is_dst_registered_port,
            "is_src_ephemeral_port": is_src_ephemeral_port,
            "dst_port": dst_port.astype(float),
        }

        # Protocol one-hot encoding if requested
        if self.include_protocol_dummies:
            features["proto_tcp"] = (proto == "tcp").astype(float)
            features["proto_udp"] = (proto == "udp").astype(float)
            features["proto_icmp"] = (proto == "icmp").astype(float)

        features_df = pd.DataFrame(features, index=df_in.index)

        # Clean infinities and NaNs resulting from divisions
        features_df.replace([np.inf, -np.inf], np.nan, inplace=True)
        features_df.fillna(0.0, inplace=True)

        # ----------------------------------------------------------------------
        # 9. Isolate Incident Triage Metadata (Contains IPs and Identifiers)
        # ----------------------------------------------------------------------
        metadata_cols = [c for c in df_in.columns if c in STATIC_IDENTIFIER_COLUMNS or c in ("src_ip", "dst_ip")]
        metadata_df = df_in[metadata_cols].copy() if metadata_cols else pd.DataFrame(index=df_in.index)
        if "src_ip" not in metadata_df.columns:
            metadata_df["src_ip"] = src_ip
        if "dst_ip" not in metadata_df.columns:
            metadata_df["dst_ip"] = dst_ip

        # Ensure no raw static IP identifiers are in the predictive feature matrix
        if self.exclude_raw_ips:
            for ident_col in STATIC_IDENTIFIER_COLUMNS:
                if ident_col in features_df.columns:
                    features_df.drop(columns=[ident_col], inplace=True)

        return features_df, metadata_df

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if an IP string is an RFC 1918 private IP address."""
        if not ip_str or ip_str in ("-", "(empty)", "none"):
            return False
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False


def extract_netmind_features(
    df: pd.DataFrame,
    exclude_raw_ips: bool = True,
    epsilon: float = 1e-6,
) -> pd.DataFrame:
    """Convenience helper to extract NetMind features from flow DataFrame.

    Args:
        df: Input DataFrame containing flow records.
        exclude_raw_ips: Whether to exclude static IP addresses from the result.
        epsilon: Small epsilon for numerical stability.

    Returns:
        pd.DataFrame: Ready-to-train numeric feature matrix.
    """
    engineer = NetMindFeatureEngineer(
        epsilon=epsilon,
        exclude_raw_ips=exclude_raw_ips,
    )
    return engineer.fit_transform(df)
