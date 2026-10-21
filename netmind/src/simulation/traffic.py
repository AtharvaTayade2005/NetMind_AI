"""NetMind AI - Dynamic Telemetry Traffic Generator.

Architectural Rationale:
------------------------
1. Physics-Consistent Telemetry Generation:
   Metrics (throughput, utilization, latency, and packet loss) are derived directly
   from the underlying topology, path bottlenecks, and queueing models rather than
   independent random numbers.
2. Comprehensive Traffic Dynamics:
   - Baseline traffic with bounded stochastic fluctuations (Gaussian / uniform drift)
   - Gradual linear or exponential growth per tick
   - Probabilistic traffic bursts
   - Congestion queueing delays (M/M/1-approximated queueing rise when utilization > 80%)
   - Packet loss proportional to buffer drops when offered traffic exceeds link bandwidth
3. State Synchronization:
   Updates actual link utilizations and available capacities along the traversed route.
   A failed link drops traffic to 0 bps or 100% loss.
4. Reproducibility & Bounded Storage:
   Supports an explicit random seed for deterministic unit test execution and uses a
   rolling deque to prevent unbounded memory growth.
"""

from __future__ import annotations

import collections
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from netmind.src.simulation.routing import DeterministicRouter, RoutingResult
from netmind.src.simulation.scenarios import ScenarioManager
from netmind.src.simulation.topology import NetworkTopology, canonical_link_id


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


@dataclass
class TelemetrySample:
    """Timestamped network telemetry sample generated during simulation."""

    timestamp: datetime
    source: str
    destination: str
    active_route: List[str]
    traffic_rate_mbps: float
    bandwidth_utilization_pct: float
    latency_ms: float
    packet_loss_pct: float
    link_status: Dict[str, str]
    available_capacity_mbps: float
    scenario_identifier: Optional[str] = None
    source_mode: str = "simulated"
    tick: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


class TrafficGenerator:
    """Generates continuous, dynamic network telemetry driven by topology state and active scenarios."""

    def __init__(
        self,
        topology: NetworkTopology,
        router: DeterministicRouter,
        scenario_mgr: ScenarioManager,
        base_traffic_mbps: float = 120.0,
        fluctuation_pct: float = 4.0,
        growth_rate_per_tick: float = 0.0,
        burst_probability: float = 0.05,
        burst_multiplier: float = 2.0,
        seed: Optional[int] = None,
        history_limit: int = 1000,
    ) -> None:
        self.topology = topology
        self.router = router
        self.scenario_mgr = scenario_mgr
        self.base_traffic_mbps = base_traffic_mbps
        self.fluctuation_pct = fluctuation_pct
        self.growth_rate_per_tick = growth_rate_per_tick
        self.burst_probability = burst_probability
        self.burst_multiplier = burst_multiplier
        self.history_limit = history_limit

        self._history: collections.deque[TelemetrySample] = collections.deque(maxlen=history_limit)
        self._tick_count: int = 0
        self._current_offered_mbps: float = base_traffic_mbps

        self._rng = random.Random(seed)

    def set_seed(self, seed: Optional[int]) -> None:
        """Seed RNG for deterministic test runs."""
        self._rng = random.Random(seed)

    def reset(self) -> None:
        """Reset internal generator state and telemetry history."""
        self._history.clear()
        self._tick_count = 0
        self._current_offered_mbps = self.base_traffic_mbps

    def generate_tick(
        self,
        source: str = "R1",
        destination: str = "R4",
        sim_time: Optional[datetime] = None,
    ) -> TelemetrySample:
        """Advance one simulation tick and compute derived telemetry."""
        self._tick_count += 1
        now = sim_time or utc_now()

        # 1. Compute dynamic routing over operational subgraph
        route_res: RoutingResult = self.router.find_routes(self.topology, source=source, destination=destination)

        # 2. Determine offered traffic demand
        # Growth
        self._current_offered_mbps += self.growth_rate_per_tick
        # Bounded fluctuation (-fluctuation_pct to +fluctuation_pct)
        delta_pct = self._rng.uniform(-self.fluctuation_pct, self.fluctuation_pct)
        offered = self._current_offered_mbps * (1.0 + delta_pct / 100.0)

        # Traffic burst
        is_burst = self._rng.random() < self.burst_probability
        if is_burst:
            offered *= self.burst_multiplier

        # Scenario Surge Multiplier
        surge_mult = self.scenario_mgr.active_surge_multiplier
        offered *= surge_mult

        offered = round(max(5.0, offered), 2)

        # Active scenario identifier if present
        active_scenarios = self.scenario_mgr.get_active_scenarios()
        primary_scenario_id = active_scenarios[0]["scenario_id"] if active_scenarios else None

        # Build link status map
        link_status_map = {l.link_id: l.status for l in self.topology.get_links()}

        # 3. If no operational route exists
        if not route_res.is_route_available or not route_res.primary_path:
            sample = TelemetrySample(
                timestamp=now,
                source=source,
                destination=destination,
                active_route=[],
                traffic_rate_mbps=0.0,
                bandwidth_utilization_pct=0.0,
                latency_ms=0.0,
                packet_loss_pct=100.0,
                link_status=link_status_map,
                available_capacity_mbps=0.0,
                scenario_identifier=primary_scenario_id,
                source_mode="simulated",
                tick=self._tick_count,
            )
            self._history.append(sample)
            return sample

        # 4. Route is operational: calculate along active path
        active_path = route_res.primary_path.path
        path_links = []
        path_bottleneck_bandwidth = float("inf")
        path_base_latency = 0.0
        path_base_loss = 0.0

        for i in range(len(active_path) - 1):
            u, v = active_path[i], active_path[i + 1]
            link = self.topology.get_link(u, v)
            path_links.append(link)
            path_bottleneck_bandwidth = min(path_bottleneck_bandwidth, link.bandwidth_mbps)
            path_base_latency += link.latency_ms
            path_base_loss = max(path_base_loss, link.packet_loss_pct)

        # Actual carried throughput capped by bottleneck link bandwidth
        carried_traffic_mbps = min(offered, path_bottleneck_bandwidth)
        bottleneck_utilization_pct = min(100.0, (offered / path_bottleneck_bandwidth) * 100.0)

        # Update link utilizations on topology for traversed links
        for link in path_links:
            link_util = min(100.0, (carried_traffic_mbps / link.bandwidth_mbps) * 100.0)
            self.topology.set_link_metrics(
                link.source,
                link.target,
                utilization_pct=link_util,
            )

        # Available capacity along active route
        available_cap = max(0.0, path_bottleneck_bandwidth - carried_traffic_mbps)

        # Congestion effects:
        # If offered > bottleneck: packet loss occurs due to tail-drop queue exhaustion
        if offered > path_bottleneck_bandwidth:
            drop_ratio = (offered - path_bottleneck_bandwidth) / offered
            congestion_loss = drop_ratio * 100.0
            total_loss = min(100.0, path_base_loss + congestion_loss)
            # Queueing latency spike under full saturation
            queueing_latency = 50.0 + (offered - path_bottleneck_bandwidth) * 0.1
        elif bottleneck_utilization_pct > 80.0:
            # Non-linear queueing delay as utilization approaches 100%
            congestion_factor = (bottleneck_utilization_pct - 80.0) / 20.0
            queueing_latency = congestion_factor * 25.0
            total_loss = path_base_loss
        else:
            queueing_latency = 0.0
            total_loss = path_base_loss

        total_latency = round(path_base_latency + queueing_latency, 2)
        total_loss = round(total_loss, 2)

        sample = TelemetrySample(
            timestamp=now,
            source=source,
            destination=destination,
            active_route=active_path,
            traffic_rate_mbps=round(carried_traffic_mbps, 2),
            bandwidth_utilization_pct=round(bottleneck_utilization_pct, 2),
            latency_ms=total_latency,
            packet_loss_pct=total_loss,
            link_status=link_status_map,
            available_capacity_mbps=round(available_cap, 2),
            scenario_identifier=primary_scenario_id,
            source_mode="simulated",
            tick=self._tick_count,
        )

        self._history.append(sample)
        return sample

    def get_latest_sample(self) -> Optional[TelemetrySample]:
        """Return the most recently generated telemetry sample."""
        if self._history:
            return self._history[-1]
        return None

    def get_history(self, limit: int = 50) -> List[TelemetrySample]:
        """Return the most recent telemetry samples up to limit."""
        if limit <= 0:
            return []
        items = list(self._history)
        return items[-limit:]
