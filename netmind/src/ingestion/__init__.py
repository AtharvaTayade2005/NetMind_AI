"""NetMind AI - Ingestion Package.

Provides high-performance parsers for Zeek network telemetry and Suricata intrusion detection logs.
"""

from netmind.src.ingestion.suricata_parser import (
    SuricataEveParser,
    SuricataParseError,
    parse_eve_alerts,
    stream_eve_alerts,
)
from netmind.src.ingestion.zeek_parser import (
    ZeekConnLogParser,
    ZeekParseError,
    parse_zeek_conn_log,
)

__all__ = [
    "ZeekConnLogParser",
    "ZeekParseError",
    "parse_zeek_conn_log",
    "SuricataEveParser",
    "SuricataParseError",
    "stream_eve_alerts",
    "parse_eve_alerts",
]
