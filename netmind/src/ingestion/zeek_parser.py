"""Zeek Network Connection Log Parser for NetMind AI.

Supports robust ingestion of both tab-separated (TSV) `conn.log` and newline-delimited
JSON (NDJSON) Zeek connection logs into Pandas DataFrames. Cleanly handles missing values
('-', '(empty)', null) and coerces networking types into standard representations.
"""

from __future__ import annotations

import io
import json
import logging
from pathlib import Path
from typing import IO, Any, Dict, List, Optional, Union

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Standard canonical column mappings from Zeek field names to NetMind schema
ZEEK_CANONICAL_COLUMNS: Dict[str, str] = {
    "id.orig_h": "src_ip",
    "id.orig_p": "src_port",
    "id.resp_h": "dst_ip",
    "id.resp_p": "dst_port",
    "proto": "proto",
}

NUMERIC_COLUMNS = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "missed_bytes",
]

PORT_COLUMNS = ["id.orig_p", "id.resp_p", "src_port", "dst_port"]


class ZeekParseError(Exception):
    """Raised when an error occurs during parsing of Zeek log files."""


class ZeekConnLogParser:
    """Robust parser for Zeek connection logs in TSV or JSON formats."""

    def __init__(self, add_canonical_aliases: bool = True) -> None:
        """Initialize the Zeek parser.

        Args:
            add_canonical_aliases: If True, adds standardized NetMind aliases
                (e.g., 'src_ip', 'dst_ip') alongside the raw Zeek field names.
        """
        self.add_canonical_aliases = add_canonical_aliases

    def parse(
        self,
        source: Union[str, Path, IO[str], io.StringIO],
        format: str = "auto",
    ) -> pd.DataFrame:
        """Parse Zeek conn logs from a file path, file-like object, or string buffer.

        Args:
            source: File path, IO stream, or text buffer containing Zeek log data.
            format: 'auto', 'tsv', or 'json'. When 'auto', format is inferred.

        Returns:
            pd.DataFrame: Clean tabular DataFrame with normalized network telemetry.
        """
        content = self._read_content(source)
        if not content.strip():
            logger.warning("Empty Zeek log provided. Returning empty DataFrame.")
            return pd.DataFrame()

        fmt = format.lower()
        if fmt == "auto":
            fmt = self._detect_format(content)

        if fmt == "tsv":
            df = self.parse_tsv(content)
        elif fmt in ("json", "ndjson"):
            df = self.parse_json(content)
        else:
            raise ZeekParseError(f"Unsupported Zeek format '{format}'. Expected 'auto', 'tsv', or 'json'.")

        return self._post_process(df)

    def parse_tsv(self, content_or_source: Union[str, Path, IO[str]]) -> pd.DataFrame:
        """Parse Zeek TSV formatted conn.log content."""
        content = self._read_content(content_or_source)
        lines = content.splitlines()

        separator = "\t"
        unset_field = "-"
        empty_field = "(empty)"
        field_names: Optional[List[str]] = None
        data_lines: List[str] = []

        for line in lines:
            line = line.strip("\r\n")
            if not line:
                continue
            if line.startswith("#"):
                parts = line.split(maxsplit=1)
                directive = parts[0]
                val = parts[1] if len(parts) > 1 else ""

                if directive == "#separator":
                    # Zeek separator can be specified e.g. \x09 for tab
                    sep_val = val.strip()
                    if sep_val == r"\x09":
                        separator = "\t"
                    elif sep_val:
                        separator = sep_val
                elif directive == "#unset_field":
                    unset_field = val.strip()
                elif directive == "#empty_field":
                    empty_field = val.strip()
                elif directive == "#fields":
                    # Fields are separated by whatever the separator is (typically tab or spaces)
                    field_names = [f.strip() for f in val.split(separator) if f.strip()]
                    if not field_names:
                        # Fallback to whitespace split if separator was not matched
                        field_names = val.split()
                continue

            # Data line
            data_lines.append(line)

        if not field_names:
            raise ZeekParseError("Zeek TSV log missing '#fields' header directive.")

        if not data_lines:
            return pd.DataFrame(columns=field_names)

        # Build DataFrame directly from lines using StringIO
        tsv_data = "\n".join(data_lines)
        try:
            df = pd.read_csv(
                io.StringIO(tsv_data),
                sep=separator,
                names=field_names,
                header=None,
                na_values=[unset_field, empty_field, "-", "(empty)"],
                keep_default_na=True,
                low_memory=False,
                dtype=str,
            )
        except Exception as e:
            raise ZeekParseError(f"Failed to parse TSV data: {e}") from e

        return df

    def parse_json(self, content_or_source: Union[str, Path, IO[str]]) -> pd.DataFrame:
        """Parse Zeek JSON / NDJSON formatted conn log content."""
        content = self._read_content(content_or_source)
        records: List[Dict[str, Any]] = []

        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                # If first character is '[', might be a JSON array
                if line.startswith("["):
                    try:
                        array_items = json.loads(content)
                        records = [self._flatten_zeek_record(r) for r in array_items]
                        break
                    except Exception:
                        pass
                logger.warning(f"Skipping malformed JSON line {line_num}: {exc}")
                continue

            flattened = self._flatten_zeek_record(item)
            records.append(flattened)

        if not records:
            return pd.DataFrame()

        df = pd.DataFrame(records)
        # Clean Zeek unset placeholders in JSON
        df.replace({"-": np.nan, "(empty)": np.nan}, inplace=True)
        return df

    def _post_process(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize types, timestamps, and column aliases."""
        if df.empty:
            return df

        df = df.copy()

        # Clean string '-' representations
        df.replace({"-": np.nan, "(empty)": np.nan}, inplace=True)

        # Standardize timestamp (ts)
        if "ts" in df.columns:
            df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
            # Convert epoch float to UTC datetime
            df["timestamp"] = pd.to_datetime(df["ts"], unit="s", utc=True, errors="coerce")

        # Coerce numeric flow metrics
        for col in NUMERIC_COLUMNS:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        # Coerce port columns to nullable Int64
        for col in PORT_COLUMNS:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")

        # Add canonical NetMind aliases if requested
        if self.add_canonical_aliases:
            for raw_col, canonical_col in ZEEK_CANONICAL_COLUMNS.items():
                if raw_col in df.columns and canonical_col not in df.columns:
                    df[canonical_col] = df[raw_col]

        return df

    @staticmethod
    def _flatten_zeek_record(record: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten nested Zeek JSON objects (e.g. `id: {orig_h: ...}`)."""
        flattened: Dict[str, Any] = {}
        for k, v in record.items():
            if isinstance(v, dict) and k == "id":
                for sub_k, sub_v in v.items():
                    flattened[f"id.{sub_k}"] = sub_v
            else:
                flattened[k] = v
        return flattened

    @staticmethod
    def _detect_format(content: str) -> str:
        """Infer whether content is TSV or JSON based on initial non-empty lines."""
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#separator") or stripped.startswith("#fields") or "\t" in stripped:
                return "tsv"
            if stripped.startswith("{") or stripped.startswith("["):
                return "json"
        return "tsv"

    @staticmethod
    def _read_content(source: Union[str, Path, IO[str], io.StringIO]) -> str:
        """Read source into string content."""
        if isinstance(source, Path):
            return source.read_text(encoding="utf-8", errors="replace")
        if isinstance(source, str):
            # Check if source is an existing file path
            try:
                p = Path(source)
                if p.is_file():
                    return p.read_text(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
            return source
        if hasattr(source, "read"):
            return source.read()
        raise ZeekParseError(f"Unsupported source type: {type(source)}")


def parse_zeek_conn_log(
    source: Union[str, Path, IO[str], io.StringIO],
    format: str = "auto",
    add_canonical_aliases: bool = True,
) -> pd.DataFrame:
    """Convenience helper to parse Zeek conn.log files or streams.

    Args:
        source: File path, stream, or log text.
        format: 'auto', 'tsv', or 'json'.
        add_canonical_aliases: Whether to inject 'src_ip', 'dst_ip', etc.

    Returns:
        pd.DataFrame: Parsed and cleaned connection records.
    """
    parser = ZeekConnLogParser(add_canonical_aliases=add_canonical_aliases)
    return parser.parse(source, format=format)
