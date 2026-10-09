"""Suricata EVE JSON Alert Parser for NetMind AI.

Provides memory-efficient streaming and tabular parsing of Suricata `eve.json` logs,
specifically filtering and extracting security alerting events, including timestamp,
network tuples (src_ip, dst_ip, src_port, dst_port, proto), alert signature, and severity.
"""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path
from typing import IO, Any, Dict, Generator, Iterator, List, Optional, Union

import pandas as pd

logger = logging.getLogger(__name__)


class SuricataParseError(Exception):
    """Raised when an error occurs during parsing of Suricata EVE logs."""


class SuricataEveParser:
    """Stream and tabular parser for Suricata EVE JSON event logs."""

    def __init__(self, filter_event_type: str = "alert") -> None:
        """Initialize parser.

        Args:
            filter_event_type: Event type to filter for (default: 'alert').
        """
        self.filter_event_type = filter_event_type

    def stream_alerts(
        self,
        source: Union[str, Path, IO[str], io.StringIO],
    ) -> Generator[Dict[str, Any], None, None]:
        """Stream Suricata alert records one-by-one from a file path or stream.

        Yields:
            Dict[str, Any]: Normalized dictionary containing:
                - timestamp: ISO-8601 string or parsed timestamp
                - src_ip: Source IP
                - src_port: Source port
                - dst_ip: Destination IP
                - dst_port: Destination port
                - proto: Transport protocol
                - alert_signature: Suricata signature text
                - alert_category: Alert classification category
                - alert_severity: Numeric severity rating (1=High, 2=Medium, 3=Low, 4=Info)
                - signature_id: Suricata rule SID
                - action: IPS action (e.g., allowed, blocked)
                - flow_id: Correlation flow ID if present
        """
        line_iterator = self._get_line_iterator(source)

        for line_num, raw_line in enumerate(line_iterator, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning(f"Skipping malformed JSON line {line_num} in Suricata EVE log: {exc}")
                continue

            # Check if this is an alert event
            event_type = record.get("event_type")
            alert_data = record.get("alert")

            if self.filter_event_type and event_type != self.filter_event_type:
                # Also allow records where alert dict exists even if event_type wasn't explicit
                if not alert_data:
                    continue

            if not alert_data and not isinstance(alert_data, dict):
                continue

            # Extract normalized alert representation
            parsed_alert = self._extract_alert_fields(record, alert_data)
            yield parsed_alert

    def parse_alerts(
        self,
        source: Union[str, Path, IO[str], io.StringIO],
    ) -> pd.DataFrame:
        """Parse all Suricata alerts from source into a Pandas DataFrame.

        Args:
            source: File path, stream, or log text.

        Returns:
            pd.DataFrame: Tabular DataFrame containing normalized alert records.
        """
        alerts = list(self.stream_alerts(source))
        if not alerts:
            return pd.DataFrame(
                columns=[
                    "timestamp",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "proto",
                    "alert_signature",
                    "alert_category",
                    "alert_severity",
                    "signature_id",
                    "action",
                    "flow_id",
                ]
            )

        df = pd.DataFrame(alerts)

        # Standardize timestamp to UTC datetime
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

        # Standardize numeric types
        if "alert_severity" in df.columns:
            df["alert_severity"] = pd.to_numeric(df["alert_severity"], errors="coerce").astype("Int64")

        if "src_port" in df.columns:
            df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").astype("Int64")

        if "dst_port" in df.columns:
            df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").astype("Int64")

        if "signature_id" in df.columns:
            df["signature_id"] = pd.to_numeric(df["signature_id"], errors="coerce").astype("Int64")

        return df

    @staticmethod
    def _extract_alert_fields(
        record: Dict[str, Any], alert_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract and normalize individual alert fields from raw Suricata event."""
        # Destination IP can be keyed as 'dest_ip' or 'dst_ip'
        dst_ip = record.get("dest_ip") or record.get("dst_ip")
        dst_port = record.get("dest_port") or record.get("dst_port")

        return {
            "timestamp": record.get("timestamp"),
            "flow_id": record.get("flow_id"),
            "src_ip": record.get("src_ip"),
            "src_port": record.get("src_port"),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": record.get("proto"),
            "alert_signature": alert_data.get("signature"),
            "alert_category": alert_data.get("category"),
            "alert_severity": alert_data.get("severity"),
            "signature_id": alert_data.get("signature_id"),
            "action": alert_data.get("action", "allowed"),
        }

    @staticmethod
    def _get_line_iterator(
        source: Union[str, Path, IO[str], io.StringIO],
    ) -> Iterator[str]:
        """Produce an iterator over lines from various input sources."""
        if isinstance(source, Path):
            with source.open("r", encoding="utf-8", errors="replace") as f:
                yield from f
            return

        if isinstance(source, str):
            # Check if source is a file path
            try:
                p = Path(source)
                if p.is_file():
                    with p.open("r", encoding="utf-8", errors="replace") as f:
                        yield from f
                    return
            except (OSError, ValueError):
                pass
            # Otherwise treat as string content
            yield from source.splitlines()
            return

        if hasattr(source, "__iter__"):
            yield from source
            return

        raise SuricataParseError(f"Unsupported source type: {type(source)}")


def stream_eve_alerts(
    source: Union[str, Path, IO[str], io.StringIO],
) -> Generator[Dict[str, Any], None, None]:
    """Convenience generator for streaming Suricata alerts."""
    parser = SuricataEveParser()
    yield from parser.stream_alerts(source)


def parse_eve_alerts(
    source: Union[str, Path, IO[str], io.StringIO],
) -> pd.DataFrame:
    """Convenience helper to parse Suricata EVE alerts into a Pandas DataFrame."""
    parser = SuricataEveParser()
    return parser.parse_alerts(source)
