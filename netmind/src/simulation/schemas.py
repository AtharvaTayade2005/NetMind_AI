"""NetMind AI - Pydantic v2 Schemas for Network Simulation API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RouterResponse(BaseModel):
    node_id: str
    display_name: str
    status: str
    router_type: str
    location: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    model_config = ConfigDict(from_attributes=True)


class LinkResponse(BaseModel):
    link_id: str
    source: str
    target: str
    bandwidth_mbps: float
    latency_ms: float
    packet_loss_pct: float
    utilization_pct: float
    status: str
    available_capacity_mbps: float
    last_updated: str
    model_config = ConfigDict(from_attributes=True)


class TopologyResponse(BaseModel):
    node_count: int
    link_count: int
    nodes: List[RouterResponse]
    links: List[LinkResponse]
    timestamp: str


class PathOptionResponse(BaseModel):
    path: List[str]
    total_cost: float
    total_latency_ms: float
    bottleneck_capacity_mbps: float
    avg_utilization_pct: float
    max_packet_loss_pct: float
    hops: int
    link_ids: List[str] = Field(default_factory=list)


class RoutingDetailResponse(BaseModel):
    source: str
    destination: str
    is_route_available: bool
    primary_path: Optional[PathOptionResponse] = None
    backup_path: Optional[PathOptionResponse] = None
    all_valid_paths: List[PathOptionResponse] = Field(default_factory=list)
    error_message: Optional[str] = None
    timestamp: str


class SimulationStatusResponse(BaseModel):
    state: str
    tick_count: int
    simulation_time: str
    start_wall_time: Optional[str] = None
    is_route_available: bool
    primary_path: List[str]
    backup_path: List[str]
    active_scenarios_count: int
    latest_traffic_rate_mbps: float
    latest_latency_ms: float
    latest_utilization_pct: float
    latest_packet_loss_pct: float
    source_mode: str = "simulated"


class SimulationMetricsResponse(BaseModel):
    simulation_time: str
    state: str
    tick_count: int
    aggregate: Dict[str, Any]
    links: List[LinkResponse]
    routes: RoutingDetailResponse
    source_mode: str = "simulated"


class TelemetrySampleResponse(BaseModel):
    timestamp: str
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
    tick: int


class LinkFailureRequest(BaseModel):
    source: str = Field(..., description="Source router ID (e.g. 'R1')")
    target: str = Field(..., description="Target router ID (e.g. 'R2')")
    duration_ticks: Optional[int] = Field(None, ge=1, description="Optional auto-recovery tick limit")


class LinkRecoveryRequest(BaseModel):
    source: str = Field(..., description="Source router ID (e.g. 'R1')")
    target: str = Field(..., description="Target router ID (e.g. 'R2')")


class CongestionRequest(BaseModel):
    source: str = Field(..., description="Source router ID (e.g. 'R1')")
    target: str = Field(..., description="Target router ID (e.g. 'R2')")
    utilization_pct: float = Field(95.0, ge=0.0, le=100.0, description="Injected link utilization")
    packet_loss_pct: float = Field(8.5, ge=0.0, le=100.0, description="Injected packet loss pct")
    latency_increase_ms: float = Field(40.0, ge=0.0, description="Additional queueing latency")
    duration_ticks: Optional[int] = Field(None, ge=1, description="Optional auto-clear tick limit")


class LatencySpikeRequest(BaseModel):
    source: str = Field(..., description="Source router ID (e.g. 'R1')")
    target: str = Field(..., description="Target router ID (e.g. 'R2')")
    additional_latency_ms: float = Field(80.0, gt=0.0, le=2000.0, description="Latency increment in ms")
    duration_ticks: Optional[int] = Field(None, ge=1, description="Optional auto-clear tick limit")


class TrafficSurgeRequest(BaseModel):
    multiplier: float = Field(3.0, gt=0.0, le=50.0, description="Traffic demand surge multiplier")
    duration_ticks: Optional[int] = Field(None, ge=1, description="Optional auto-clear tick limit")


class ScenarioResponse(BaseModel):
    scenario_id: str
    scenario_type: str
    affected_resource: str
    status: str
    parameters: Dict[str, Any]
    description: str
    start_time: str
    end_time: Optional[str] = None
    remaining_ticks: Optional[int] = None
