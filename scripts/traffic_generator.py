#!/usr/bin/env python3
"""NetMind AI - Synthetic Network Traffic Generator & Testing Lab.

Educational & Defensive System Rationale:
------------------------------------------
In cybersecurity and network operations engineering, machine learning intrusion
detection models, time-series capacity forecasters, and automated decision engines
must be validated against controlled, reproducible telemetry.

This script safely generates synthetic network traffic inside loopback (127.0.0.1)
and local test networks. It reproduces three canonical behavioral profiles:
1. Normal Baseline:
   Periodic HTTP GET requests and DNS queries modeling standard enterprise traffic.
2. Sequential Port Probe:
   Clean TCP SYN/connect sweeps across consecutive destination ports modeling
   adversarial network reconnaissance (scanner detection validation).
3. High-Volume Volumetric Burst:
   High-rate synthetic traffic bursts evaluating queue ingestion, rate threshold
   alarms, and time-series congestion forecasting.

Defensive Safeguards:
---------------------
- Defaults strictly to localhost (127.0.0.1).
- Disallows targeting public routable IP addresses unless --allow-external is explicitly set.
- Enforces strict rate-limiting to prevent local system CPU or socket exhaustion.
- Fallback Architecture: Uses standard Python `socket` by default (requiring zero
  root/administrator privileges). Optionally supports Scapy if installed and permitted.
- Telemetry Sync (--emit-logs): Appends corresponding Zeek conn.log (TSV) and
  Suricata eve.json records to the log directory, enabling immediate end-to-end
  validation of the background ingestion worker (log_tailer.py).
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import logging
import math
import os
import random
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("netmind.traffic_generator")

# Optional Scapy import
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, UDP, Raw, send, sr1  # type: ignore

    SCAPY_AVAILABLE = True
except (ImportError, Exception):
    SCAPY_AVAILABLE = False


def is_safe_target_ip(ip_str: str, allow_external: bool = False) -> bool:
    """Validate that the target IP is loopback or local private address."""
    if allow_external:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_private
    except ValueError:
        # If hostname, resolve to check
        try:
            resolved = socket.gethostbyname(ip_str)
            ip = ipaddress.ip_address(resolved)
            return ip.is_loopback or ip.is_private
        except Exception:
            return False


class DefensiveRateLimiter:
    """Enforces defensive packet/request rate limiting to prevent host exhaustion."""

    def __init__(self, max_rate_per_sec: float = 50.0) -> None:
        self.max_rate = max(1.0, float(max_rate_per_sec))
        self.min_interval = 1.0 / self.max_rate
        self.last_time = time.monotonic()

    def wait(self) -> None:
        """Sleep if necessary to remain under the maximum rate ceiling."""
        now = time.monotonic()
        elapsed = now - self.last_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_time = time.monotonic()


class TelemetryLogEmitter:
    """Synchronously emits matching Zeek conn.log and Suricata eve.json records.

    Allows reproducible testing of the full ingestion -> ML -> decision engine
    pipeline without requiring root packet-sniffing daemons on local machines.
    """

    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.conn_log_path = self.log_dir / "conn.log"
        self.eve_json_path = self.log_dir / "eve.json"
        self._ensure_zeek_header()

    def _ensure_zeek_header(self) -> None:
        """Ensure standard Zeek conn.log TSV header exists if file is new or empty."""
        if not self.conn_log_path.exists() or self.conn_log_path.stat().st_size == 0:
            header_lines = [
                "#separator \\x09\n",
                "#set_separator\t,\n",
                "#empty_field\t(empty)\n",
                "#unset_field\t-\n",
                "#path\tconn\n",
                f"#open\t{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d-%H-%M-%S')}\n",
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n",
                "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n",
            ]
            with open(self.conn_log_path, "w", encoding="utf-8") as f:
                f.writelines(header_lines)

    def emit_zeek_conn(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str,
        service: str,
        duration: float,
        orig_bytes: int,
        resp_bytes: int,
        conn_state: str,
        history: str,
        orig_pkts: int,
        resp_pkts: int,
    ) -> None:
        """Append a single TSV connection record to conn.log."""
        now_ts = f"{time.time():.6f}"
        uid = f"C{''.join(random.choices('0123456789ABCDEF', k=16))}"
        orig_ip_bytes = orig_bytes + (orig_pkts * 40)
        resp_ip_bytes = resp_bytes + (resp_pkts * 40) if resp_pkts > 0 else 0

        fields = [
            now_ts,
            uid,
            src_ip,
            str(src_port),
            dst_ip,
            str(dst_port),
            proto.lower(),
            service if service else "-",
            f"{duration:.6f}" if duration > 0 else "-",
            str(orig_bytes) if orig_bytes > 0 else "-",
            str(resp_bytes) if resp_bytes > 0 else "-",
            conn_state,
            "T",
            "T" if is_safe_target_ip(dst_ip) else "F",
            "0",
            history,
            str(orig_pkts),
            str(orig_ip_bytes),
            str(resp_pkts),
            str(resp_ip_bytes),
            "-",
        ]
        line = "\t".join(fields) + "\n"
        with open(self.conn_log_path, "a", encoding="utf-8") as f:
            f.write(line)

    def emit_suricata_alert(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str,
        signature: str,
        category: str,
        severity: int,
    ) -> None:
        """Append a single Suricata eve.json alert record."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
        flow_id = random.randint(100000000, 999999999)
        record = {
            "timestamp": now_iso,
            "flow_id": flow_id,
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "proto": proto.upper(),
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": random.randint(2000000, 2099999),
                "rev": 1,
                "signature": signature,
                "category": category,
                "severity": severity,
            },
        }
        line = json.dumps(record) + "\n"
        with open(self.eve_json_path, "a", encoding="utf-8") as f:
            f.write(line)


class SyntheticTrafficGenerator:
    """Safe, reproducible network traffic generator for NetMind AI."""

    def __init__(
        self,
        target_ip: str = "127.0.0.1",
        target_port: int = 8000,
        rate: float = 50.0,
        allow_external: bool = False,
        use_scapy: bool = False,
        emit_logs: bool = True,
        log_dir: str = "logs",
    ) -> None:
        if not is_safe_target_ip(target_ip, allow_external=allow_external):
            raise ValueError(
                f"Defensive check failed: Target IP '{target_ip}' is outside loopback (127.0.0.1) "
                f"and private RFC 1918 subnets. Use --allow-external to override."
            )
        self.target_ip = target_ip
        self.target_port = target_port
        self.rate_limiter = DefensiveRateLimiter(max_rate_per_sec=rate)
        self.use_scapy = use_scapy and SCAPY_AVAILABLE
        self.emit_logs = emit_logs
        self.log_emitter = TelemetryLogEmitter(Path(log_dir)) if emit_logs else None

        logger.info(
            f"Initialized SyntheticTrafficGenerator (Target: {self.target_ip}:{self.target_port}, "
            f"Rate: {rate} pps, Engine: {'Scapy' if self.use_scapy else 'Python Socket'}, "
            f"Log Emitter: {'Active' if emit_logs else 'Disabled'})"
        )

    # --------------------------------------------------------------------------
    # Scenario A: Normal Baseline Traffic Simulation
    # --------------------------------------------------------------------------
    def run_normal_baseline(self, count: int = 15, delay_range: Tuple[float, float] = (0.2, 0.6)) -> Dict[str, Any]:
        """Simulate benign enterprise HTTP requests and DNS lookups."""
        logger.info(f"==> [Scenario A] Starting Normal Baseline Simulation ({count} cycles)...")
        stats = {"http_success": 0, "http_failed": 0, "dns_queries": 0}

        domains_to_lookup = ["localhost", "127.0.0.1"]
        simulated_src_ip = "192.168.1.105"

        for i in range(1, count + 1):
            self.rate_limiter.wait()
            src_port = random.randint(49152, 65535)

            # 1. Simulate HTTP GET
            t0 = time.monotonic()
            http_ok = False
            duration = 0.05
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                # Attempt connection to local target port
                try:
                    s.connect((self.target_ip, self.target_port))
                    request = f"GET /api/v1/health HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: NetMind-SyntheticClient/1.0\r\nConnection: close\r\n\r\n"
                    s.sendall(request.encode("utf-8"))
                    _ = s.recv(1024)
                    http_ok = True
                    stats["http_success"] += 1
                except (ConnectionRefusedError, socket.timeout):
                    # Service not listening on target port - still valid network probe
                    stats["http_failed"] += 1
                finally:
                    s.close()
            except Exception as e:
                stats["http_failed"] += 1
                logger.debug(f"HTTP socket error: {e}")

            duration = max(0.01, time.monotonic() - t0)

            # Emit Zeek conn.log record
            if self.log_emitter:
                orig_bytes = random.randint(150, 450)
                resp_bytes = random.randint(300, 2500) if http_ok else 0
                conn_state = "SF" if http_ok else "REJ"
                history = "ShADadfF" if http_ok else "Sr"
                orig_pkts = random.randint(4, 8)
                resp_pkts = random.randint(5, 12) if http_ok else 1
                self.log_emitter.emit_zeek_conn(
                    src_ip=simulated_src_ip,
                    src_port=src_port,
                    dst_ip=self.target_ip,
                    dst_port=self.target_port,
                    proto="tcp",
                    service="http",
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                    conn_state=conn_state,
                    history=history,
                    orig_pkts=orig_pkts,
                    resp_pkts=resp_pkts,
                )

            # 2. Simulate standard DNS query
            target_domain = random.choice(domains_to_lookup)
            try:
                _ = socket.gethostbyname(target_domain)
                stats["dns_queries"] += 1
            except Exception:
                stats["dns_queries"] += 1

            if self.log_emitter and (i % 2 == 0):
                dns_src_port = random.randint(49152, 65535)
                self.log_emitter.emit_zeek_conn(
                    src_ip=simulated_src_ip,
                    src_port=dns_src_port,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    proto="udp",
                    service="dns",
                    duration=0.015,
                    orig_bytes=48,
                    resp_bytes=164,
                    conn_state="SF",
                    history="Dd",
                    orig_pkts=1,
                    resp_pkts=1,
                )

            logger.info(f"  [Baseline {i}/{count}] HTTP {self.target_ip}:{self.target_port} -> {'OK' if http_ok else 'SENT'} | DNS: {target_domain}")
            time.sleep(random.uniform(*delay_range))

        logger.info(f"==> [Scenario A Complete] Results: {stats}")
        return stats

    # --------------------------------------------------------------------------
    # Scenario B: Sequential Port Probe Sweep Simulation
    # --------------------------------------------------------------------------
    def run_port_probe(
        self,
        start_port: int = 8000,
        end_port: int = 8030,
        delay_per_port: float = 0.03,
    ) -> Dict[str, Any]:
        """Simulate sequential TCP SYN port reconnaissance sweep across port range."""
        ports_to_probe = list(range(start_port, end_port + 1))
        # Include a few common service ports for realistic scanner behavior
        ports_to_probe.extend([21, 22, 23, 25, 3306, 3389])
        random.shuffle(ports_to_probe)

        logger.info(f"==> [Scenario B] Starting Sequential Port Probe Sweep ({len(ports_to_probe)} ports)...")
        stats = {"ports_probed": len(ports_to_probe), "open": 0, "closed_or_filtered": 0}
        simulated_scanner_ip = "192.168.1.200"

        for idx, port in enumerate(ports_to_probe, start=1):
            self.rate_limiter.wait()
            src_port = random.randint(40000, 60000)
            is_open = False

            if self.use_scapy:
                # Scapy TCP SYN Probe
                try:
                    pkt = IP(dst=self.target_ip) / TCP(dport=port, sport=src_port, flags="S")
                    resp = sr1(pkt, timeout=0.1, verbose=0)
                    if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        is_open = True
                except Exception:
                    pass
            else:
                # Standard Python non-blocking TCP connect probe
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.04)
                try:
                    res = s.connect_ex((self.target_ip, port))
                    if res == 0:
                        is_open = True
                except Exception:
                    pass
                finally:
                    s.close()

            if is_open:
                stats["open"] += 1
            else:
                stats["closed_or_filtered"] += 1

            # Emit Zeek conn.log & Suricata eve.json records
            if self.log_emitter:
                conn_state = "SF" if is_open else "S0"
                history = "ShADadfF" if is_open else "S"
                self.log_emitter.emit_zeek_conn(
                    src_ip=simulated_scanner_ip,
                    src_port=src_port,
                    dst_ip=self.target_ip,
                    dst_port=port,
                    proto="tcp",
                    service="-",
                    duration=0.001 if not is_open else 0.05,
                    orig_bytes=60,
                    resp_bytes=40 if is_open else 0,
                    conn_state=conn_state,
                    history=history,
                    orig_pkts=1,
                    resp_pkts=1 if is_open else 0,
                )
                # Emit Suricata scanner alert every 5 probed ports
                if idx % 5 == 0:
                    self.log_emitter.emit_suricata_alert(
                        src_ip=simulated_scanner_ip,
                        src_port=src_port,
                        dst_ip=self.target_ip,
                        dst_port=port,
                        proto="TCP",
                        signature=f"ET SCAN Potential TCP Port Scan Detected (Port {port})",
                        category="Attempted Information Leak",
                        severity=2,
                    )

            logger.info(f"  [Probe {idx}/{len(ports_to_probe)}] Port {port:5d}/tcp -> {'OPEN' if is_open else 'CLOSED/FILTERED'}")
            time.sleep(delay_per_port)

        logger.info(f"==> [Scenario B Complete] Results: {stats}")
        return stats

    # --------------------------------------------------------------------------
    # Scenario C: High-Volume Volumetric Burst Simulation
    # --------------------------------------------------------------------------
    def run_high_volume_burst(
        self,
        burst_packets: int = 120,
        rate_ceiling: float = 150.0,
    ) -> Dict[str, Any]:
        """Simulate high-rate synthetic burst to evaluate queue handling & DoS classifiers."""
        logger.info(f"==> [Scenario C] Starting High-Volume Burst Simulation ({burst_packets} packets @ ~{rate_ceiling} pps)...")
        burst_limiter = DefensiveRateLimiter(max_rate_per_sec=rate_ceiling)
        simulated_dos_ip = "192.168.1.188"
        bytes_sent = 0

        t_start = time.monotonic()
        for i in range(1, burst_packets + 1):
            burst_limiter.wait()
            src_port = random.randint(1024, 65535)

            # Send rapid UDP or TCP datagram to loopback test port
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                payload = b"NETMIND_BURST_TELEMETRY_" + os.urandom(64)
                sock.sendto(payload, (self.target_ip, self.target_port))
                bytes_sent += len(payload)
                sock.close()
            except Exception as e:
                logger.debug(f"Burst socket error: {e}")

            if i % 30 == 0 or i == burst_packets:
                logger.info(f"  [Burst Progress] Dispatched {i}/{burst_packets} packets ({bytes_sent:,} payload bytes)")

        t_elapsed = max(0.001, time.monotonic() - t_start)
        actual_rate = burst_packets / t_elapsed
        stats = {
            "packets": burst_packets,
            "bytes": bytes_sent,
            "duration_sec": round(t_elapsed, 3),
            "actual_pps": round(actual_rate, 1),
        }

        # Emit Zeek conn.log & Suricata eve.json records for volumetric attack profile
        if self.log_emitter:
            total_orig_bytes = burst_packets * 128
            self.log_emitter.emit_zeek_conn(
                src_ip=simulated_dos_ip,
                src_port=random.randint(40000, 50000),
                dst_ip=self.target_ip,
                dst_port=self.target_port,
                proto="tcp",
                service="http",
                duration=round(t_elapsed, 4),
                orig_bytes=total_orig_bytes,
                resp_bytes=0,
                conn_state="S0",
                history="S",
                orig_pkts=burst_packets,
                resp_pkts=0,
            )
            # Suricata high-volume DoS alert
            self.log_emitter.emit_suricata_alert(
                src_ip=simulated_dos_ip,
                src_port=random.randint(40000, 50000),
                dst_ip=self.target_ip,
                dst_port=self.target_port,
                proto="TCP",
                signature="ET DOS High Volume Inbound Flow / SYN Flood Anomaly",
                category="Denial of Service",
                severity=1,
            )

        logger.info(f"==> [Scenario C Complete] Results: {stats}")
        return stats


def main() -> None:
    """CLI entrypoint for NetMind AI Synthetic Traffic Generator."""
    parser = argparse.ArgumentParser(
        description="NetMind AI - Synthetic Network Traffic Generator & Reproducible Testing Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        choices=["baseline", "probe", "burst", "all"],
        default="all",
        help="Traffic scenario to execute: baseline (HTTP/DNS), probe (Port scan), burst (High-rate DoS), or all.",
    )
    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target IP address (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Target service port (default: 8000).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of iterations for baseline or burst packets (default: 10).",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=50.0,
        help="Defensive rate ceiling in packets per second (default: 50.0).",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory to write simulated Zeek conn.log and Suricata eve.json files (default: 'logs').",
    )
    parser.add_argument(
        "--no-emit-logs",
        action="store_true",
        help="Disable emitting Zeek and Suricata log telemetry to disk.",
    )
    parser.add_argument(
        "--use-scapy",
        action="store_true",
        help="Attempt using Scapy for packet generation if installed.",
    )
    parser.add_argument(
        "--allow-external",
        action="store_true",
        help="Explicitly permit targeting non-loopback / non-RFC1918 addresses (Defensive override).",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("NetMind AI - Phase 5 Synthetic Traffic Generator & Testing Lab")
    print("=" * 80)

    try:
        generator = SyntheticTrafficGenerator(
            target_ip=args.target,
            target_port=args.port,
            rate=args.rate,
            allow_external=args.allow_external,
            use_scapy=args.use_scapy,
            emit_logs=not args.no_emit_logs,
            log_dir=args.log_dir,
        )
    except Exception as exc:
        logger.error(f"Initialization failed: {exc}")
        sys.exit(1)

    t0 = time.time()
    if args.scenario in ("baseline", "all"):
        generator.run_normal_baseline(count=args.count)
        if args.scenario == "all":
            time.sleep(1.0)

    if args.scenario in ("probe", "all"):
        generator.run_port_probe(start_port=args.port, end_port=args.port + 15)
        if args.scenario == "all":
            time.sleep(1.0)

    if args.scenario in ("burst", "all"):
        burst_cnt = max(50, args.count * 10)
        generator.run_high_volume_burst(burst_packets=burst_cnt, rate_ceiling=args.rate * 2)

    total_time = round(time.time() - t0, 2)
    print("=" * 80)
    logger.info(f"All traffic scenarios completed successfully in {total_time}s.")
    if not args.no_emit_logs:
        logger.info(f"Simulated telemetry written to '{args.log_dir}/conn.log' and '{args.log_dir}/eve.json'.")
        logger.info("Log tailer worker (src/worker/log_tailer.py) can now ingest these events.")
    print("=" * 80)


if __name__ == "__main__":
    main()
