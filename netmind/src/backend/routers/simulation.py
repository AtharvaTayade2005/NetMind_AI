"""NetMind AI - Network Simulator API Router.

Exposes REST endpoints for:
1. Simulator Lifecycle: Start, Pause, Resume, Stop, Reset, Step/Tick.
2. Dynamic Topology Inspection: Routers, Links, and Availability.
3. Live Simulation Telemetry & Real-Time Metrics.
4. Deterministic Multi-Metric Routing & Backup Path Discovery.
5. Fault Scenario Injections: Link Failure, Link Recovery, Congestion, Latency Spikes, Traffic Surges.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from netmind.src.simulation.engine import SimulationEngine, get_simulation_engine
from netmind.src.simulation.schemas import (
    CongestionRequest,
    LatencySpikeRequest,
    LinkFailureRequest,
    LinkRecoveryRequest,
    RoutingDetailResponse,
    ScenarioResponse,
    SimulationMetricsResponse,
    SimulationStatusResponse,
    TelemetrySampleResponse,
    TopologyResponse,
    TrafficSurgeRequest,
)

router = APIRouter(tags=["Network Simulation"])


# ==============================================================================
# 1. Simulator Lifecycle Endpoints
# ==============================================================================

@router.get("/api/simulation/status", response_model=SimulationStatusResponse)
def get_simulation_status() -> Dict[str, Any]:
    """Retrieve current simulation engine state, tick count, and simulation clock."""
    engine = get_simulation_engine()
    return engine.get_status()


@router.post("/api/simulation/start", response_model=SimulationStatusResponse)
def start_simulation() -> Dict[str, Any]:
    """Start or resume the background simulation worker."""
    engine = get_simulation_engine()
    return engine.start()


@router.post("/api/simulation/pause", response_model=SimulationStatusResponse)
def pause_simulation() -> Dict[str, Any]:
    """Pause the simulation clock and advancement."""
    engine = get_simulation_engine()
    return engine.pause()


@router.post("/api/simulation/resume", response_model=SimulationStatusResponse)
def resume_simulation() -> Dict[str, Any]:
    """Resume a paused simulation loop."""
    engine = get_simulation_engine()
    return engine.resume()


@router.post("/api/simulation/stop", response_model=SimulationStatusResponse)
def stop_simulation() -> Dict[str, Any]:
    """Stop the simulation loop and halt the background worker."""
    engine = get_simulation_engine()
    return engine.stop()


@router.post("/api/simulation/reset", response_model=SimulationStatusResponse)
def reset_simulation() -> Dict[str, Any]:
    """Reset topology, scenarios, routing, and traffic to default baseline."""
    engine = get_simulation_engine()
    return engine.reset()


@router.post("/api/simulation/tick", response_model=TelemetrySampleResponse)
def advance_simulation_tick(time_delta_seconds: float = Query(1.0, ge=0.01, le=60.0)) -> Dict[str, Any]:
    """Manually advance the simulation by one tick for deterministic testing/inspection."""
    engine = get_simulation_engine()
    sample = engine.tick(time_delta_seconds=time_delta_seconds)
    return sample.to_dict()


# ==============================================================================
# 2. Topology & Metric Inspection Endpoints
# ==============================================================================

@router.get("/api/topology", response_model=TopologyResponse)
@router.get("/api/simulation/topology", response_model=TopologyResponse)
def get_network_topology() -> Dict[str, Any]:
    """Retrieve all simulated router nodes, physical links, capacities, and statuses."""
    engine = get_simulation_engine()
    return engine.topology.to_dict()


@router.get("/api/simulation/metrics", response_model=SimulationMetricsResponse)
def get_simulation_metrics() -> Dict[str, Any]:
    """Retrieve instantaneous aggregate and link telemetry metrics."""
    engine = get_simulation_engine()
    return engine.get_metrics()


@router.get("/api/simulation/telemetry", response_model=List[TelemetrySampleResponse])
def get_simulation_telemetry(limit: int = Query(50, ge=1, le=500)) -> List[Dict[str, Any]]:
    """Retrieve recent simulation telemetry time-series samples."""
    engine = get_simulation_engine()
    return engine.get_telemetry_history(limit=limit)


@router.get("/api/simulation/routes", response_model=RoutingDetailResponse)
def get_simulation_routes(
    source: str = Query("R1", description="Source router identifier"),
    destination: str = Query("R4", description="Destination router identifier"),
) -> Dict[str, Any]:
    """Compute and return primary, backup, and alternative operational routes."""
    engine = get_simulation_engine()
    res = engine.router.find_routes(engine.topology, source=source, destination=destination)
    return res.to_dict()


# ==============================================================================
# 3. Fault Scenario Injections
# ==============================================================================

@router.post("/api/simulation/scenarios/link-failure", response_model=ScenarioResponse)
def inject_link_failure(req: LinkFailureRequest) -> Dict[str, Any]:
    """Inject a link failure, marking the link down and removing it from routing."""
    engine = get_simulation_engine()
    try:
        rec = engine.scenario_mgr.inject_link_failure(
            source=req.source,
            target=req.target,
            duration_ticks=req.duration_ticks,
        )
        return rec.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/api/simulation/scenarios/link-recovery", response_model=ScenarioResponse)
def inject_link_recovery(req: LinkRecoveryRequest) -> Dict[str, Any]:
    """Recover a down link, restoring operational status and capacity."""
    engine = get_simulation_engine()
    try:
        rec = engine.scenario_mgr.inject_link_recovery(
            source=req.source,
            target=req.target,
        )
        return rec.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/api/simulation/scenarios/congestion", response_model=ScenarioResponse)
def inject_congestion(req: CongestionRequest) -> Dict[str, Any]:
    """Inject congestion on a link by driving up utilization, queueing latency, and loss."""
    engine = get_simulation_engine()
    try:
        rec = engine.scenario_mgr.inject_congestion(
            source=req.source,
            target=req.target,
            utilization_pct=req.utilization_pct,
            packet_loss_pct=req.packet_loss_pct,
            latency_increase_ms=req.latency_increase_ms,
            duration_ticks=req.duration_ticks,
        )
        return rec.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/api/simulation/scenarios/latency-spike", response_model=ScenarioResponse)
def inject_latency_spike(req: LatencySpikeRequest) -> Dict[str, Any]:
    """Inject a latency spike on a target link."""
    engine = get_simulation_engine()
    try:
        rec = engine.scenario_mgr.inject_latency_spike(
            source=req.source,
            target=req.target,
            additional_latency_ms=req.additional_latency_ms,
            duration_ticks=req.duration_ticks,
        )
        return rec.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/api/simulation/scenarios/traffic-surge", response_model=ScenarioResponse)
def inject_traffic_surge(req: TrafficSurgeRequest) -> Dict[str, Any]:
    """Inject a traffic demand surge across the network."""
    engine = get_simulation_engine()
    try:
        rec = engine.scenario_mgr.inject_traffic_surge(
            multiplier=req.multiplier,
            duration_ticks=req.duration_ticks,
        )
        return rec.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/api/simulation/scenarios", response_model=List[ScenarioResponse])
def get_simulation_scenarios(include_history: bool = Query(False)) -> List[Dict[str, Any]]:
    """List active and optionally historical fault scenarios."""
    engine = get_simulation_engine()
    active = engine.scenario_mgr.get_active_scenarios()
    if include_history:
        return active + engine.scenario_mgr.get_history()
    return active


@router.post("/api/simulation/scenarios/clear")
def clear_all_scenarios() -> Dict[str, str]:
    """Clear all active fault scenarios and restore link baselines."""
    engine = get_simulation_engine()
    engine.scenario_mgr.clear_all()
    return {"status": "success", "message": "All active simulation scenarios cleared"}


@router.delete("/api/simulation/scenarios/{scenario_id}", response_model=ScenarioResponse)
def clear_single_scenario(scenario_id: str) -> Dict[str, Any]:
    """Clear a specific active simulation scenario by ID."""
    engine = get_simulation_engine()
    try:
        rec = engine.scenario_mgr.clear_scenario(scenario_id)
        return rec.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
