"""NetMind AI - Fault Scenario Management Module.

Architectural Rationale:
------------------------
1. State-Modifying Injections:
   Scenario operations directly mutate the topology and traffic states, rather than
   returning passive simulation flags.
2. Comprehensive Fault Modes:
   Supports:
   - Link Failure (status='down', available capacity=0)
   - Link Recovery (status='up', capacity restored)
   - Link Congestion (elevated utilization & packet loss)
   - Latency Spike (bounded latency increase on target link)
   - Traffic Surge (global multiplier on offered rate)
3. Snapshot & Restoration:
   Caches pristine link and traffic baselines prior to injection, ensuring deterministic,
   exact restoration when scenarios are cleared or expired.
4. Robust Validation:
   Rejects invalid identifiers, nonexistent links, incompatible actions, or out-of-bounds metrics.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from netmind.src.simulation.topology import NetworkTopology, canonical_link_id


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


@dataclass
class ScenarioRecord:
    """Represents an active or historic simulation fault scenario."""

    scenario_id: str
    scenario_type: str  # "link_failure" | "link_recovery" | "congestion" | "latency_spike" | "traffic_surge"
    affected_resource: str
    status: str = "active"  # "active" | "cleared" | "expired"
    parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    start_time: datetime = field(default_factory=utc_now)
    end_time: Optional[datetime] = None
    remaining_ticks: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["start_time"] = self.start_time.isoformat()
        if self.end_time:
            d["end_time"] = self.end_time.isoformat()
        return d


class ScenarioManager:
    """Coordinates fault injection, tracking, and clean rollback."""

    def __init__(self, topology: NetworkTopology) -> None:
        self.topology = topology
        self._active_scenarios: Dict[str, ScenarioRecord] = {}
        self._scenario_history: List[ScenarioRecord] = []
        # Store original link baselines: link_id -> original parameters dict
        self._link_baselines: Dict[str, Dict[str, Any]] = {}
        # Traffic surge multiplier active
        self.active_surge_multiplier: float = 1.0

    def _get_or_store_baseline(self, link_id: str) -> Dict[str, Any]:
        """Save initial link metrics if not already stored."""
        if link_id not in self._link_baselines:
            link = self.topology.get_link_by_id(link_id)
            self._link_baselines[link_id] = {
                "bandwidth_mbps": link.bandwidth_mbps,
                "latency_ms": link.latency_ms,
                "packet_loss_pct": link.packet_loss_pct,
                "utilization_pct": link.utilization_pct,
                "status": link.status,
            }
        return self._link_baselines[link_id]

    def inject_link_failure(
        self,
        source: str,
        target: str,
        duration_ticks: Optional[int] = None,
    ) -> ScenarioRecord:
        """Mark a link down and make it immediately unavailable to routing."""
        link = self.topology.get_link(source, target)
        if link.status == "down":
            raise ValueError(f"Link '{link.link_id}' is already down")

        self._get_or_store_baseline(link.link_id)
        self.topology.set_link_status(source, target, "down")

        sid = f"fail-{link.link_id}-{uuid.uuid4().hex[:6]}"
        rec = ScenarioRecord(
            scenario_id=sid,
            scenario_type="link_failure",
            affected_resource=link.link_id,
            status="active",
            parameters={"source": source, "target": target},
            description=f"Physical link failure injected on {link.link_id}",
            remaining_ticks=duration_ticks,
        )
        self._active_scenarios[sid] = rec
        return rec

    def inject_link_recovery(self, source: str, target: str) -> ScenarioRecord:
        """Restore a failed link to operational status ('up')."""
        link = self.topology.get_link(source, target)
        if link.status == "up":
            raise ValueError(f"Link '{link.link_id}' is already operational ('up')")

        # Clear any active link failure scenarios on this link
        for sid, s in list(self._active_scenarios.items()):
            if s.affected_resource == link.link_id and s.scenario_type == "link_failure":
                s.status = "cleared"
                s.end_time = utc_now()
                self._scenario_history.append(s)
                del self._active_scenarios[sid]

        self.topology.set_link_status(source, target, "up")

        sid = f"recov-{link.link_id}-{uuid.uuid4().hex[:6]}"
        rec = ScenarioRecord(
            scenario_id=sid,
            scenario_type="link_recovery",
            affected_resource=link.link_id,
            status="cleared",
            parameters={"source": source, "target": target},
            description=f"Link {link.link_id} recovered to operational state",
            end_time=utc_now(),
        )
        self._scenario_history.append(rec)
        return rec

    def inject_congestion(
        self,
        source: str,
        target: str,
        utilization_pct: float = 95.0,
        packet_loss_pct: float = 8.5,
        latency_increase_ms: float = 40.0,
        duration_ticks: Optional[int] = None,
    ) -> ScenarioRecord:
        """Inject congestion on a link by elevating utilization, queueing latency, and packet loss."""
        link = self.topology.get_link(source, target)
        if link.status != "up":
            raise ValueError(f"Cannot inject congestion on link '{link.link_id}' because it is down")
        if not (0.0 <= utilization_pct <= 100.0):
            raise ValueError("utilization_pct must be between 0.0 and 100.0")

        self._get_or_store_baseline(link.link_id)

        new_latency = link.latency_ms + max(0.0, latency_increase_ms)
        self.topology.set_link_metrics(
            source,
            target,
            latency_ms=new_latency,
            utilization_pct=utilization_pct,
            packet_loss_pct=packet_loss_pct,
        )

        sid = f"cong-{link.link_id}-{uuid.uuid4().hex[:6]}"
        rec = ScenarioRecord(
            scenario_id=sid,
            scenario_type="congestion",
            affected_resource=link.link_id,
            status="active",
            parameters={
                "source": source,
                "target": target,
                "utilization_pct": utilization_pct,
                "packet_loss_pct": packet_loss_pct,
                "latency_increase_ms": latency_increase_ms,
            },
            description=f"Congestion injected on {link.link_id}: util={utilization_pct}%, loss={packet_loss_pct}%",
            remaining_ticks=duration_ticks,
        )
        self._active_scenarios[sid] = rec
        return rec

    def inject_latency_spike(
        self,
        source: str,
        target: str,
        additional_latency_ms: float = 80.0,
        duration_ticks: Optional[int] = None,
    ) -> ScenarioRecord:
        """Inject latency spike on a selected link."""
        link = self.topology.get_link(source, target)
        if link.status != "up":
            raise ValueError(f"Cannot inject latency spike on link '{link.link_id}' because it is down")
        if additional_latency_ms <= 0:
            raise ValueError("additional_latency_ms must be positive")

        self._get_or_store_baseline(link.link_id)

        new_latency = min(1000.0, link.latency_ms + additional_latency_ms)
        self.topology.set_link_metrics(source, target, latency_ms=new_latency)

        sid = f"lat-{link.link_id}-{uuid.uuid4().hex[:6]}"
        rec = ScenarioRecord(
            scenario_id=sid,
            scenario_type="latency_spike",
            affected_resource=link.link_id,
            status="active",
            parameters={
                "source": source,
                "target": target,
                "additional_latency_ms": additional_latency_ms,
                "result_latency_ms": new_latency,
            },
            description=f"Latency spike +{additional_latency_ms}ms on {link.link_id}",
            remaining_ticks=duration_ticks,
        )
        self._active_scenarios[sid] = rec
        return rec

    def inject_traffic_surge(
        self,
        multiplier: float = 3.0,
        duration_ticks: Optional[int] = None,
    ) -> ScenarioRecord:
        """Inject aggregate traffic demand surge across the network."""
        if multiplier <= 0.0 or multiplier > 50.0:
            raise ValueError("Surge multiplier must be between 0.1 and 50.0")

        self.active_surge_multiplier = multiplier

        sid = f"surge-{uuid.uuid4().hex[:6]}"
        rec = ScenarioRecord(
            scenario_id=sid,
            scenario_type="traffic_surge",
            affected_resource="network",
            status="active",
            parameters={"multiplier": multiplier},
            description=f"Traffic demand surge: {multiplier}x multiplier",
            remaining_ticks=duration_ticks,
        )
        self._active_scenarios[sid] = rec
        return rec

    def clear_scenario(self, scenario_id: str) -> ScenarioRecord:
        """Clear an active scenario and restore affected resources."""
        if scenario_id not in self._active_scenarios:
            raise ValueError(f"Scenario '{scenario_id}' is not currently active")

        scen = self._active_scenarios.pop(scenario_id)
        scen.status = "cleared"
        scen.end_time = utc_now()
        self._scenario_history.append(scen)

        # Restore affected resource
        if scen.scenario_type in ("link_failure", "congestion", "latency_spike"):
            link_id = scen.affected_resource
            if link_id in self._link_baselines:
                base = self._link_baselines[link_id]
                parts = link_id.split("-")
                u, v = parts[0], parts[1]
                self.topology.set_link_status(u, v, base["status"])
                self.topology.set_link_metrics(
                    u,
                    v,
                    bandwidth_mbps=base["bandwidth_mbps"],
                    latency_ms=base["latency_ms"],
                    packet_loss_pct=base["packet_loss_pct"],
                    utilization_pct=base["utilization_pct"],
                )
        elif scen.scenario_type == "traffic_surge":
            self.active_surge_multiplier = 1.0

        return scen

    def clear_all(self) -> None:
        """Clear all active scenarios and revert all link baselines."""
        for sid in list(self._active_scenarios.keys()):
            self.clear_scenario(sid)
        self.active_surge_multiplier = 1.0
        self._link_baselines.clear()

    def tick(self) -> None:
        """Advance time for duration-bounded scenarios, auto-expiring finished ones."""
        for sid, scen in list(self._active_scenarios.items()):
            if scen.remaining_ticks is not None:
                scen.remaining_ticks -= 1
                if scen.remaining_ticks <= 0:
                    self.clear_scenario(sid)

    def get_active_scenarios(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._active_scenarios.values()]

    def get_history(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._scenario_history]
