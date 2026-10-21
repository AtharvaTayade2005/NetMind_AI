"""NetMind AI - Dynamic Network Topology Module.

Architectural Rationale:
------------------------
1. Graph-First Representation:
   Uses NetworkX (Graph) to represent an undirected network topology of routers and links.
2. In-Memory Dynamic State:
   Maintains stateful operational status (up/down), capacity, utilization, latency, and packet loss
   per router and link.
3. Available Capacity Recalculation:
   Dynamically derives remaining capacity whenever utilization or operational status changes.
4. Clean Serialization:
   Provides dictionary and schema-compliant outputs for REST endpoints and routing calculations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


def canonical_link_id(source: str, target: str) -> str:
    """Create a deterministic, canonical link identifier for an undirected link."""
    u, v = sorted([source.strip(), target.strip()])
    return f"{u}-{v}"


@dataclass
class RouterNode:
    """Represents a simulated router network element."""

    node_id: str
    display_name: str
    status: str = "up"  # "up" | "down"
    router_type: str = "core"  # "edge" | "core" | "gateway"
    location: str = "Datacenter"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkLink:
    """Represents a simulated bidirectional physical or logical link between two routers."""

    link_id: str
    source: str
    target: str
    bandwidth_mbps: float = 1000.0
    latency_ms: float = 5.0
    packet_loss_pct: float = 0.0
    utilization_pct: float = 0.0
    status: str = "up"  # "up" | "down"
    available_capacity_mbps: float = 1000.0
    last_updated: datetime = field(default_factory=utc_now)

    def recalculate_capacity(self) -> None:
        """Update available capacity based on status and utilization."""
        if self.status != "up":
            self.available_capacity_mbps = 0.0
        else:
            clamped_util = max(0.0, min(100.0, self.utilization_pct))
            self.available_capacity_mbps = round(
                max(0.0, self.bandwidth_mbps * (1.0 - clamped_util / 100.0)), 2
            )
        self.last_updated = utc_now()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["last_updated"] = self.last_updated.isoformat()
        return d


class NetworkTopology:
    """In-memory dynamic network graph supporting routers, links, and operational status."""

    def __init__(self, build_default: bool = True) -> None:
        self._graph: nx.Graph = nx.Graph()
        self._routers: Dict[str, RouterNode] = {}
        self._links: Dict[str, NetworkLink] = {}

        if build_default:
            self.load_default_topology()

    @property
    def graph(self) -> nx.Graph:
        """Return the underlying NetworkX graph."""
        return self._graph

    def load_default_topology(self) -> None:
        """Initialize the default NetMinds AI topology:
        
        Routers: R1 (Edge), R2 (Core A), R3 (Core B), R4 (Gateway)
        Links:
          - R1 <-> R2 (1000 Mbps, 5.0ms) - Primary segment 1
          - R2 <-> R4 (1000 Mbps, 5.0ms) - Primary segment 2
          - R1 <-> R3 (500 Mbps, 15.0ms) - Backup segment 1
          - R3 <-> R4 (500 Mbps, 15.0ms) - Backup segment 2
          - R2 <-> R3 (500 Mbps, 10.0ms) - Cross-connect
        Candidate Paths:
          - Primary: R1 -> R2 -> R4 (Total base latency 10ms, cost lowest)
          - Backup:  R1 -> R3 -> R4 (Total base latency 30ms, cost higher)
        """
        self._graph.clear()
        self._routers.clear()
        self._links.clear()

        # Add default routers
        self.add_router("R1", display_name="Edge Router R1", router_type="edge", location="DC-North Ingress")
        self.add_router("R2", display_name="Core Router R2 (Primary Spine)", router_type="core", location="DC-Core Alpha")
        self.add_router("R3", display_name="Core Router R3 (Backup Spine)", router_type="core", location="DC-Core Beta")
        self.add_router("R4", display_name="Gateway Router R4", router_type="gateway", location="DC-South Egress")

        # Add default links
        self.add_link("R1", "R2", bandwidth_mbps=1000.0, latency_ms=5.0, packet_loss_pct=0.0, utilization_pct=10.0)
        self.add_link("R2", "R4", bandwidth_mbps=1000.0, latency_ms=5.0, packet_loss_pct=0.0, utilization_pct=10.0)
        self.add_link("R1", "R3", bandwidth_mbps=500.0, latency_ms=15.0, packet_loss_pct=0.0, utilization_pct=10.0)
        self.add_link("R3", "R4", bandwidth_mbps=500.0, latency_ms=15.0, packet_loss_pct=0.0, utilization_pct=10.0)
        self.add_link("R2", "R3", bandwidth_mbps=500.0, latency_ms=10.0, packet_loss_pct=0.0, utilization_pct=5.0)

    def add_router(
        self,
        node_id: str,
        display_name: Optional[str] = None,
        status: str = "up",
        router_type: str = "core",
        location: str = "Datacenter",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RouterNode:
        """Register a new router in the topology graph."""
        node_id = node_id.strip()
        if not node_id:
            raise ValueError("Router node_id must be a non-empty string")

        if status not in ("up", "down"):
            raise ValueError(f"Invalid router status '{status}'. Must be 'up' or 'down'")

        router = RouterNode(
            node_id=node_id,
            display_name=display_name or f"Router {node_id}",
            status=status,
            router_type=router_type,
            location=location,
            metadata=metadata or {},
        )
        self._routers[node_id] = router
        self._graph.add_node(node_id, **router.to_dict())
        return router

    def get_router(self, node_id: str) -> RouterNode:
        """Fetch router by node_id or raise ValueError."""
        if node_id not in self._routers:
            raise ValueError(f"Router '{node_id}' does not exist in topology")
        return self._routers[node_id]

    def set_router_status(self, node_id: str, status: str) -> RouterNode:
        """Update operational status of a router."""
        if status not in ("up", "down"):
            raise ValueError(f"Invalid router status '{status}'. Must be 'up' or 'down'")
        router = self.get_router(node_id)
        router.status = status
        self._graph.nodes[node_id]["status"] = status
        return router

    def add_link(
        self,
        source: str,
        target: str,
        bandwidth_mbps: float = 1000.0,
        latency_ms: float = 5.0,
        packet_loss_pct: float = 0.0,
        utilization_pct: float = 0.0,
        status: str = "up",
    ) -> NetworkLink:
        """Register or update an undirected link between two existing routers."""
        if source not in self._routers:
            raise ValueError(f"Source router '{source}' does not exist")
        if target not in self._routers:
            raise ValueError(f"Target router '{target}' does not exist")
        if source == target:
            raise ValueError(f"Self-loop links (from '{source}' to itself) are not permitted")
        if bandwidth_mbps <= 0:
            raise ValueError("bandwidth_mbps must be positive")
        if latency_ms < 0:
            raise ValueError("latency_ms cannot be negative")
        if not (0.0 <= packet_loss_pct <= 100.0):
            raise ValueError("packet_loss_pct must be between 0.0 and 100.0")
        if not (0.0 <= utilization_pct <= 100.0):
            raise ValueError("utilization_pct must be between 0.0 and 100.0")
        if status not in ("up", "down"):
            raise ValueError(f"Invalid link status '{status}'. Must be 'up' or 'down'")

        lid = canonical_link_id(source, target)
        link = NetworkLink(
            link_id=lid,
            source=source,
            target=target,
            bandwidth_mbps=float(bandwidth_mbps),
            latency_ms=float(latency_ms),
            packet_loss_pct=float(packet_loss_pct),
            utilization_pct=float(utilization_pct),
            status=status,
            last_updated=utc_now(),
        )
        link.recalculate_capacity()

        self._links[lid] = link
        self._graph.add_edge(source, target, **link.to_dict())
        return link

    def get_link(self, source: str, target: str) -> NetworkLink:
        """Retrieve link between source and target routers."""
        lid = canonical_link_id(source, target)
        if lid not in self._links:
            raise ValueError(f"No link exists between router '{source}' and router '{target}'")
        return self._links[lid]

    def get_link_by_id(self, link_id: str) -> NetworkLink:
        """Retrieve link by canonical or hyphenated identifier."""
        if link_id in self._links:
            return self._links[link_id]
        parts = link_id.split("-")
        if len(parts) == 2:
            canonical = canonical_link_id(parts[0], parts[1])
            if canonical in self._links:
                return self._links[canonical]
        raise ValueError(f"Link '{link_id}' does not exist in topology")

    def set_link_status(self, source: str, target: str, status: str) -> NetworkLink:
        """Set link status to 'up' or 'down' and recalculate available capacity."""
        if status not in ("up", "down"):
            raise ValueError(f"Invalid status '{status}'. Must be 'up' or 'down'")
        link = self.get_link(source, target)
        link.status = status
        link.recalculate_capacity()
        if self._graph.has_edge(source, target):
            self._graph.edges[source, target]["status"] = status
            self._graph.edges[source, target]["available_capacity_mbps"] = link.available_capacity_mbps
            self._graph.edges[source, target]["last_updated"] = link.last_updated.isoformat()
        return link

    def set_link_metrics(
        self,
        source: str,
        target: str,
        bandwidth_mbps: Optional[float] = None,
        latency_ms: Optional[float] = None,
        packet_loss_pct: Optional[float] = None,
        utilization_pct: Optional[float] = None,
    ) -> NetworkLink:
        """Update metrics for an existing link and recompute available capacity."""
        link = self.get_link(source, target)
        if bandwidth_mbps is not None:
            if bandwidth_mbps <= 0:
                raise ValueError("bandwidth_mbps must be positive")
            link.bandwidth_mbps = float(bandwidth_mbps)
        if latency_ms is not None:
            if latency_ms < 0:
                raise ValueError("latency_ms cannot be negative")
            link.latency_ms = float(latency_ms)
        if packet_loss_pct is not None:
            if not (0.0 <= packet_loss_pct <= 100.0):
                raise ValueError("packet_loss_pct must be between 0.0 and 100.0")
            link.packet_loss_pct = float(packet_loss_pct)
        if utilization_pct is not None:
            if not (0.0 <= utilization_pct <= 100.0):
                raise ValueError("utilization_pct must be between 0.0 and 100.0")
            link.utilization_pct = float(utilization_pct)

        link.recalculate_capacity()

        if self._graph.has_edge(source, target):
            for k, v in link.to_dict().items():
                self._graph.edges[source, target][k] = v

        return link

    def get_operational_subgraph(self) -> nx.Graph:
        """Return a subgraph containing only operational ('up') nodes and links."""
        active_nodes = [n for n, d in self._graph.nodes(data=True) if d.get("status") == "up"]
        sub = self._graph.subgraph(active_nodes).copy()
        edges_to_remove = [
            (u, v) for u, v, d in sub.edges(data=True) if d.get("status") != "up"
        ]
        sub.remove_edges_from(edges_to_remove)
        return sub

    def get_routers(self) -> List[RouterNode]:
        """Return list of all registered routers."""
        return list(self._routers.values())

    def get_links(self) -> List[NetworkLink]:
        """Return list of all registered links."""
        return list(self._links.values())

    def to_dict(self) -> Dict[str, Any]:
        """Serialize topology into dictionary for API and engine use."""
        return {
            "node_count": len(self._routers),
            "link_count": len(self._links),
            "nodes": [r.to_dict() for r in self._routers.values()],
            "links": [l.to_dict() for l in self._links.values()],
            "timestamp": utc_now().isoformat(),
        }

    def reset(self) -> None:
        """Reset topology to default baseline."""
        self.load_default_topology()
