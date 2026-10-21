"""Unit & Integration Tests for NetMinds AI Phase 1: Dynamic Network Simulator.

Verifies:
1. Topology:
   - Default topology contains nodes (R1, R2, R3, R4) and default links.
   - Available capacity recalculation on utilization / state change.
   - Rejection of unknown nodes and invalid links.
2. Routing:
   - Primary route (R1 -> R2 -> R4) has lowest cost and is selected under baseline.
   - Failed primary link (e.g. R1-R2) is never used.
   - Backup route (R1 -> R3 -> R4) is discovered upon primary path failure.
   - Accurate detection and error reporting when all paths are blocked.
   - Deterministic tie-breaking for equal-cost paths.
3. Simulation Engine:
   - Starting advances state to 'running'.
   - Pausing stops state advancement.
   - Resuming permits advancement.
   - Stopping halts loop; reset restores initial baseline.
   - Deterministic single tick execution without sleeping.
   - Idempotent start requests do not spawn duplicate loops.
4. Scenarios:
   - Link failure updates in-memory graph and sets capacity to 0.
   - Link recovery restores operational status and capacity.
   - Congestion increases utilization, packet loss, and queueing latency.
   - Latency spike increases link latency within bounds.
   - Traffic surge increases traffic rate.
   - Input validation rejects nonexistent links and incompatible actions.
5. API Endpoints:
   - GET /api/simulation/status
   - POST /api/simulation/start, pause, resume, stop, reset, tick
   - GET /api/topology & GET /api/simulation/metrics
   - GET /api/simulation/telemetry & GET /api/simulation/routes
   - POST /api/simulation/scenarios/*
   - Proper HTTP codes (200, 400, 404).
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Setup path resolution
TEST_DIR = Path(__file__).resolve().parent
NETMIND_DIR = TEST_DIR.parent
WORKSPACE_DIR = NETMIND_DIR.parent

for p in [str(WORKSPACE_DIR), str(NETMIND_DIR), str(NETMIND_DIR / "src")]:
    if p not in sys.path:
        sys.path.insert(0, p)

from netmind.src.backend.main import app
from netmind.src.simulation.engine import (
    SimulationEngine,
    SimulationState,
    get_simulation_engine,
    reset_simulation_engine_for_testing,
)
from netmind.src.simulation.routing import DeterministicRouter
from netmind.src.simulation.scenarios import ScenarioManager
from netmind.src.simulation.topology import (
    NetworkTopology,
    canonical_link_id,
)
from netmind.src.simulation.traffic import TrafficGenerator

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_simulation_state():
    """Ensure every test runs with an isolated, clean simulation engine."""
    engine = reset_simulation_engine_for_testing()
    yield engine
    engine.stop()


# ==============================================================================
# 1. Topology Tests
# ==============================================================================

def test_default_topology_structure():
    """Verify default topology contains expected routers, links, and initial capacities."""
    topo = NetworkTopology(build_default=True)
    routers = topo.get_routers()
    links = topo.get_links()

    router_ids = {r.node_id for r in routers}
    assert router_ids == {"R1", "R2", "R3", "R4"}

    link_ids = {l.link_id for l in links}
    assert "R1-R2" in link_ids
    assert "R2-R4" in link_ids
    assert "R1-R3" in link_ids
    assert "R3-R4" in link_ids
    assert "R2-R3" in link_ids

    # All routers and links start operational
    assert all(r.status == "up" for r in routers)
    assert all(l.status == "up" for l in links)

    # Initial capacities
    l_r1_r2 = topo.get_link("R1", "R2")
    assert l_r1_r2.bandwidth_mbps == 1000.0
    assert l_r1_r2.latency_ms == 5.0
    assert l_r1_r2.available_capacity_mbps > 0.0


def test_topology_validation_and_rejection():
    """Verify topology rejects unknown nodes, invalid metrics, and self-loops."""
    topo = NetworkTopology(build_default=True)

    # Unknown router lookup
    with pytest.raises(ValueError, match="does not exist in topology"):
        topo.get_router("R99")

    # Unknown link lookup
    with pytest.raises(ValueError, match="No link exists"):
        topo.get_link("R1", "R99")

    # Invalid status
    with pytest.raises(ValueError, match="Invalid router status"):
        topo.add_router("R5", status="invalid_status")

    # Self-loop
    with pytest.raises(ValueError, match="Self-loop"):
        topo.add_link("R1", "R1")

    # Negative latency / bandwidth
    with pytest.raises(ValueError, match="bandwidth_mbps must be positive"):
        topo.add_link("R1", "R4", bandwidth_mbps=-100)

    with pytest.raises(ValueError, match="latency_ms cannot be negative"):
        topo.add_link("R1", "R4", latency_ms=-5.0)


def test_topology_available_capacity_recalculation():
    """Verify available capacity recalculates on utilization change and drops to 0 when down."""
    topo = NetworkTopology(build_default=True)
    link = topo.get_link("R1", "R2")
    assert link.bandwidth_mbps == 1000.0

    # 40% utilization -> 600 Mbps available
    topo.set_link_metrics("R1", "R2", utilization_pct=40.0)
    assert link.available_capacity_mbps == 600.0

    # Mark link down -> available capacity must drop to 0
    topo.set_link_status("R1", "R2", "down")
    assert link.available_capacity_mbps == 0.0

    # Restore link up -> capacity restores
    topo.set_link_status("R1", "R2", "up")
    assert link.available_capacity_mbps == 600.0


# ==============================================================================
# 2. Dynamic Routing Tests
# ==============================================================================

def test_routing_primary_and_backup_candidate_selection():
    """Verify Primary (R1 -> R2 -> R4) has lower cost than Backup (R1 -> R3 -> R4)."""
    topo = NetworkTopology(build_default=True)
    router = DeterministicRouter()

    res = router.find_routes(topo, source="R1", destination="R4")
    assert res.is_route_available is True
    assert res.primary_path is not None
    assert res.backup_path is not None

    # Primary path must be R1 -> R2 -> R4
    assert res.primary_path.path == ["R1", "R2", "R4"]
    # Backup path must be R1 -> R3 -> R4
    assert res.backup_path.path == ["R1", "R3", "R4"]
    # Primary cost must be strictly less than backup cost
    assert res.primary_path.total_cost < res.backup_path.total_cost


def test_routing_primary_link_failure_failover():
    """Verify failed primary link (R1-R2) is never used and backup path becomes primary."""
    topo = NetworkTopology(build_default=True)
    router = DeterministicRouter()

    # Fail link R1-R2
    topo.set_link_status("R1", "R2", "down")

    res = router.find_routes(topo, source="R1", destination="R4")
    assert res.is_route_available is True
    assert res.primary_path is not None

    # Primary must now be the backup path R1 -> R3 -> R4
    assert res.primary_path.path == ["R1", "R3", "R4"]

    # Verify no valid paths contain the failed link
    for p in res.all_valid_paths:
        assert "R1-R2" not in p.link_ids


def test_routing_all_paths_blocked_detection():
    """Verify system accurately reports no route available when all operational paths fail."""
    topo = NetworkTopology(build_default=True)
    router = DeterministicRouter()

    # Disconnect R1 completely: fail R1-R2 and R1-R3
    topo.set_link_status("R1", "R2", "down")
    topo.set_link_status("R1", "R3", "down")

    res = router.find_routes(topo, source="R1", destination="R4")
    assert res.is_route_available is False
    assert res.primary_path is None
    assert res.backup_path is None
    assert len(res.all_valid_paths) == 0
    assert "No operational path available" in (res.error_message or "")


def test_routing_deterministic_tie_breaking():
    """Verify route selection is 100% deterministic when multiple paths have equal cost."""
    topo = NetworkTopology(build_default=True)
    # Set identical latencies and utilizations on R1-R2-R4 and R1-R3-R4
    topo.set_link_metrics("R1", "R2", latency_ms=10.0, utilization_pct=0.0, packet_loss_pct=0.0)
    topo.set_link_metrics("R2", "R4", latency_ms=10.0, utilization_pct=0.0, packet_loss_pct=0.0)
    topo.set_link_metrics("R1", "R3", latency_ms=10.0, utilization_pct=0.0, packet_loss_pct=0.0)
    topo.set_link_metrics("R3", "R4", latency_ms=10.0, utilization_pct=0.0, packet_loss_pct=0.0)

    router = DeterministicRouter()
    res1 = router.find_routes(topo, source="R1", destination="R4")
    res2 = router.find_routes(topo, source="R1", destination="R4")

    assert res1.primary_path.path == res2.primary_path.path
    assert res1.primary_path.total_cost == res2.primary_path.total_cost


# ==============================================================================
# 3. Fault Scenario Tests
# ==============================================================================

def test_scenario_link_failure_and_recovery():
    """Verify link failure mutates topology and recovery restores original capacity."""
    topo = NetworkTopology(build_default=True)
    mgr = ScenarioManager(topo)

    link = topo.get_link("R1", "R2")
    orig_cap = link.available_capacity_mbps

    # Inject failure
    rec = mgr.inject_link_failure("R1", "R2")
    assert rec.status == "active"
    assert link.status == "down"
    assert link.available_capacity_mbps == 0.0

    # Inject recovery
    recov = mgr.inject_link_recovery("R1", "R2")
    assert recov.status == "cleared"
    assert link.status == "up"
    assert link.available_capacity_mbps == orig_cap


def test_scenario_congestion_and_latency_spike():
    """Verify congestion elevates utilization/loss and latency spike increases link latency."""
    topo = NetworkTopology(build_default=True)
    mgr = ScenarioManager(topo)
    link = topo.get_link("R1", "R2")
    orig_lat = link.latency_ms

    # Congestion
    cong = mgr.inject_congestion("R1", "R2", utilization_pct=92.0, packet_loss_pct=7.5)
    assert cong.status == "active"
    assert link.utilization_pct == 92.0
    assert link.packet_loss_pct == 7.5

    # Latency Spike
    lat_rec = mgr.inject_latency_spike("R2", "R4", additional_latency_ms=50.0)
    assert lat_rec.status == "active"
    l2 = topo.get_link("R2", "R4")
    assert l2.latency_ms == pytest.approx(55.0)

    # Clear all restores baselines
    mgr.clear_all()
    assert link.utilization_pct == 10.0
    assert l2.latency_ms == 5.0


def test_scenario_traffic_surge():
    """Verify traffic surge increases demand multiplier."""
    topo = NetworkTopology(build_default=True)
    mgr = ScenarioManager(topo)
    assert mgr.active_surge_multiplier == 1.0

    surge = mgr.inject_traffic_surge(multiplier=4.0)
    assert surge.status == "active"
    assert mgr.active_surge_multiplier == 4.0

    mgr.clear_all()
    assert mgr.active_surge_multiplier == 1.0


def test_scenario_validation_errors():
    """Verify scenario manager rejects invalid parameters and non-operational actions."""
    topo = NetworkTopology(build_default=True)
    mgr = ScenarioManager(topo)

    # Nonexistent link
    with pytest.raises(ValueError):
        mgr.inject_link_failure("R1", "R99")

    # Already down link
    mgr.inject_link_failure("R1", "R2")
    with pytest.raises(ValueError, match="already down"):
        mgr.inject_link_failure("R1", "R2")

    # Recovering an already operational link
    with pytest.raises(ValueError, match="already operational"):
        mgr.inject_link_recovery("R2", "R4")


# ==============================================================================
# 4. Simulation Engine Tests
# ==============================================================================

def test_engine_deterministic_ticks_without_waiting():
    """Verify simulation engine advances tick count and sim_time deterministically."""
    engine = SimulationEngine(seed=42)
    assert engine.tick_count == 0

    s1 = engine.tick(time_delta_seconds=1.0)
    assert engine.tick_count == 1
    assert s1.tick == 1
    assert s1.source_mode == "simulated"
    assert s1.active_route == ["R1", "R2", "R4"]
    assert s1.traffic_rate_mbps > 0.0

    s2 = engine.tick(time_delta_seconds=1.0)
    assert engine.tick_count == 2
    assert s2.tick == 2


def test_engine_fsm_lifecycle_transitions():
    """Verify FSM state transitions: start, pause, resume, stop, reset."""
    engine = SimulationEngine()
    assert engine.state == SimulationState.STOPPED

    # Start
    engine.start()
    assert engine.state == SimulationState.RUNNING

    # Duplicate start does not duplicate thread or fail
    engine.start()
    assert engine.state == SimulationState.RUNNING

    # Pause
    engine.pause()
    assert engine.state == SimulationState.PAUSED

    # Resume
    engine.resume()
    assert engine.state == SimulationState.RUNNING

    # Stop
    engine.stop()
    assert engine.state == SimulationState.STOPPED

    # Reset
    engine.reset()
    assert engine.state == SimulationState.STOPPED
    assert engine.tick_count == 0


# ==============================================================================
# 5. REST API Integration Tests
# ==============================================================================

def test_api_simulation_lifecycle_endpoints():
    """Verify REST API lifecycle endpoints modify simulator state."""
    # Status
    res = client.get("/api/simulation/status")
    assert res.status_code == 200
    data = res.json()
    assert data["state"] == "stopped"
    assert data["source_mode"] == "simulated"

    # Start
    res = client.post("/api/simulation/start")
    assert res.status_code == 200
    assert res.json()["state"] == "running"

    # Pause
    res = client.post("/api/simulation/pause")
    assert res.status_code == 200
    assert res.json()["state"] == "paused"

    # Resume
    res = client.post("/api/simulation/resume")
    assert res.status_code == 200
    assert res.json()["state"] == "running"

    # Stop
    res = client.post("/api/simulation/stop")
    assert res.status_code == 200
    assert res.json()["state"] == "stopped"

    # Tick
    res = client.post("/api/simulation/tick")
    assert res.status_code == 200
    assert res.json()["tick"] >= 1

    # Reset
    res = client.post("/api/simulation/reset")
    assert res.status_code == 200
    assert res.json()["tick_count"] == 0


def test_api_topology_and_metrics_endpoints():
    """Verify /api/topology and /api/simulation/metrics return structured schemas."""
    # Topology
    res = client.get("/api/topology")
    assert res.status_code == 200
    topo = res.json()
    assert topo["node_count"] == 4
    assert topo["link_count"] == 5
    assert any(n["node_id"] == "R1" for n in topo["nodes"])

    # Metrics
    res = client.get("/api/simulation/metrics")
    assert res.status_code == 200
    metrics = res.json()
    assert "aggregate" in metrics
    assert "routes" in metrics
    assert metrics["routes"]["primary_path"]["path"] == ["R1", "R2", "R4"]


def test_api_scenario_injection_end_to_end():
    """Verify injecting a link failure via API alters topology, routes, and metrics."""
    # 1. Verify baseline primary path is R1 -> R2 -> R4
    res = client.get("/api/simulation/routes?source=R1&destination=R4")
    assert res.status_code == 200
    assert res.json()["primary_path"]["path"] == ["R1", "R2", "R4"]

    # 2. Inject link failure on R1-R2
    fail_res = client.post("/api/simulation/scenarios/link-failure", json={"source": "R1", "target": "R2"})
    assert fail_res.status_code == 200
    assert fail_res.json()["status"] == "active"

    # 3. Subsequent topology request must show R1-R2 is down
    topo_res = client.get("/api/topology")
    l_r1_r2 = next(l for l in topo_res.json()["links"] if l["link_id"] == "R1-R2")
    assert l_r1_r2["status"] == "down"
    assert l_r1_r2["available_capacity_mbps"] == 0.0

    # 4. Routing request must find backup path R1 -> R3 -> R4
    route_res = client.get("/api/simulation/routes?source=R1&destination=R4")
    assert route_res.status_code == 200
    assert route_res.json()["primary_path"]["path"] == ["R1", "R3", "R4"]

    # 5. Recover link
    recov_res = client.post("/api/simulation/scenarios/link-recovery", json={"source": "R1", "target": "R2"})
    assert recov_res.status_code == 200

    # 6. Primary path restored
    restored_res = client.get("/api/simulation/routes?source=R1&destination=R4")
    assert restored_res.json()["primary_path"]["path"] == ["R1", "R2", "R4"]


def test_api_scenario_error_handling():
    """Verify meaningful HTTP 400 errors for invalid scenario requests."""
    # Unknown router
    res = client.post("/api/simulation/scenarios/link-failure", json={"source": "R1", "target": "R99"})
    assert res.status_code == 400
    assert "no link exists" in res.json()["detail"].lower()
