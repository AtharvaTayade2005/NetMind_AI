"""NetMind AI - Deterministic Dynamic Routing Service.

Architectural Rationale:
------------------------
1. Operational-Only Path Traversal:
   Routes are computed strictly over the operational subgraph of operational routers and operational links.
   Unavailable links cannot be traversed.
2. Multi-Metric Cost Modeling:
   Evaluates path cost using a weighted combination of link latency, packet loss, and utilization:
     Cost(e) = W_lat * Latency(e) + W_loss * PacketLoss(e) + W_util * (Utilization(e) / 10.0)
3. Deterministic Selection:
   When candidate paths have identical costs, ties are resolved deterministically using
   (cost, hop_count, path_tuple) order.
4. Candidate Path Discovery:
   Exposes the primary path, backup path, and all valid alternative paths.
5. Transparent Separation:
   Finds and exposes optimal and backup paths without conflating route selection with
   autonomous remediation or executing OS network changes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from netmind.src.simulation.topology import NetworkTopology, canonical_link_id


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


@dataclass
class PathOption:
    """Represents a computed route between source and destination."""

    path: List[str]
    total_cost: float
    total_latency_ms: float
    bottleneck_capacity_mbps: float
    avg_utilization_pct: float
    max_packet_loss_pct: float
    hops: int
    link_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RoutingResult:
    """Structured response containing primary, backup, and alternative paths."""

    source: str
    destination: str
    primary_path: Optional[PathOption]
    backup_path: Optional[PathOption]
    all_valid_paths: List[PathOption]
    is_route_available: bool
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "destination": self.destination,
            "is_route_available": self.is_route_available,
            "primary_path": self.primary_path.to_dict() if self.primary_path else None,
            "backup_path": self.backup_path.to_dict() if self.backup_path else None,
            "all_valid_paths": [p.to_dict() for p in self.all_valid_paths],
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
        }


class DeterministicRouter:
    """Computes deterministic optimal and backup routes across the simulated network topology."""

    def __init__(
        self,
        weight_latency: float = 1.0,
        weight_loss: float = 1.0,
        weight_utilization: float = 0.5,
    ) -> None:
        self.weight_latency = weight_latency
        self.weight_loss = weight_loss
        self.weight_utilization = weight_utilization

    def compute_link_cost(self, link_data: Dict[str, Any]) -> float:
        """Derive the deterministic link traversal cost from dynamic metrics."""
        latency = float(link_data.get("latency_ms", 0.0))
        loss = float(link_data.get("packet_loss_pct", 0.0))
        util = float(link_data.get("utilization_pct", 0.0))

        cost = (
            self.weight_latency * latency
            + self.weight_loss * loss
            + self.weight_utilization * (util / 10.0)
        )
        return max(0.001, round(cost, 4))

    def evaluate_path(self, topology: NetworkTopology, path: List[str]) -> PathOption:
        """Calculate aggregate telemetry metrics and total cost for a path."""
        total_cost = 0.0
        total_latency = 0.0
        bottlenecks = []
        utilizations = []
        losses = []
        link_ids = []

        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            link = topology.get_link(u, v)
            link_data = link.to_dict()
            cost = self.compute_link_cost(link_data)

            total_cost += cost
            total_latency += link.latency_ms
            bottlenecks.append(link.available_capacity_mbps)
            utilizations.append(link.utilization_pct)
            losses.append(link.packet_loss_pct)
            link_ids.append(link.link_id)

        hops = len(path) - 1
        bottleneck_cap = min(bottlenecks) if bottlenecks else 0.0
        avg_util = sum(utilizations) / len(utilizations) if utilizations else 0.0
        max_loss = max(losses) if losses else 0.0

        return PathOption(
            path=path,
            total_cost=round(total_cost, 4),
            total_latency_ms=round(total_latency, 2),
            bottleneck_capacity_mbps=round(bottleneck_cap, 2),
            avg_utilization_pct=round(avg_util, 2),
            max_packet_loss_pct=round(max_loss, 2),
            hops=hops,
            link_ids=link_ids,
        )

    def find_routes(
        self,
        topology: NetworkTopology,
        source: str = "R1",
        destination: str = "R4",
    ) -> RoutingResult:
        """Find primary and backup routes between source and destination using operational graph."""
        # Validate existence of source and destination nodes
        if source not in topology._routers:
            return RoutingResult(
                source=source,
                destination=destination,
                primary_path=None,
                backup_path=None,
                all_valid_paths=[],
                is_route_available=False,
                error_message=f"Source router '{source}' does not exist in topology",
            )
        if destination not in topology._routers:
            return RoutingResult(
                source=source,
                destination=destination,
                primary_path=None,
                backup_path=None,
                all_valid_paths=[],
                is_route_available=False,
                error_message=f"Destination router '{destination}' does not exist in topology",
            )

        # Source equals destination
        if source == destination:
            trivial_path = PathOption(
                path=[source],
                total_cost=0.0,
                total_latency_ms=0.0,
                bottleneck_capacity_mbps=float("inf"),
                avg_utilization_pct=0.0,
                max_packet_loss_pct=0.0,
                hops=0,
                link_ids=[],
            )
            return RoutingResult(
                source=source,
                destination=destination,
                primary_path=trivial_path,
                backup_path=None,
                all_valid_paths=[trivial_path],
                is_route_available=True,
            )

        # Build operational-only subgraph
        op_graph = topology.get_operational_subgraph()

        if source not in op_graph or destination not in op_graph:
            return RoutingResult(
                source=source,
                destination=destination,
                primary_path=None,
                backup_path=None,
                all_valid_paths=[],
                is_route_available=False,
                error_message=f"One or both endpoints are non-operational or isolated",
            )

        if not nx.has_path(op_graph, source, destination):
            return RoutingResult(
                source=source,
                destination=destination,
                primary_path=None,
                backup_path=None,
                all_valid_paths=[],
                is_route_available=False,
                error_message=f"No operational path available between '{source}' and '{destination}'",
            )

        # Enumerate all simple operational paths
        raw_paths = list(nx.all_simple_paths(op_graph, source, destination))
        if not raw_paths:
            return RoutingResult(
                source=source,
                destination=destination,
                primary_path=None,
                backup_path=None,
                all_valid_paths=[],
                is_route_available=False,
                error_message="No valid paths exist between specified routers",
            )

        # Evaluate metrics for each path
        evaluated_paths = [self.evaluate_path(topology, p) for p in raw_paths]

        # Sort deterministically: cost asc, hops asc, path lexicographical asc
        evaluated_paths.sort(key=lambda x: (x.total_cost, x.hops, tuple(x.path)))

        primary = evaluated_paths[0]
        backup = evaluated_paths[1] if len(evaluated_paths) > 1 else None

        return RoutingResult(
            source=source,
            destination=destination,
            primary_path=primary,
            backup_path=backup,
            all_valid_paths=evaluated_paths,
            is_route_available=True,
        )
