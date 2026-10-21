"""NetMind AI - Simulation Engine Coordinator.

Architectural Rationale:
------------------------
1. Coordinated Simulation Loop:
   Orchestrates the dynamic interaction between Topology, Deterministic Routing,
   Fault Scenarios, and Traffic Generation.
2. Robust Finite State Machine:
   Explicit states: 'stopped', 'running', 'paused'.
   Safe, idempotent state transitions (start, pause, resume, stop, reset).
3. Thread-Safe Concurrency:
   Protects concurrent REST requests and background simulation ticks using re-entrant locks.
   Background simulation loop runs on a controlled daemon thread with non-blocking sleep.
4. Deterministic Test Advancement:
   Provides `tick(time_delta_seconds=1.0)` so unit tests advance the simulation deterministically
   without wall-clock sleeps or background thread flakiness.
5. Lifecycle Cleanliness:
   Never starts background threads at import time. Provides graceful shutdown hooks for FastAPI lifespan.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from netmind.src.simulation.routing import DeterministicRouter, RoutingResult
from netmind.src.simulation.scenarios import ScenarioManager, ScenarioRecord
from netmind.src.simulation.topology import NetworkTopology
from netmind.src.simulation.traffic import TelemetrySample, TrafficGenerator

logger = logging.getLogger("netmind.simulation.engine")


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class SimulationState(str, Enum):
    """Lifecycle states of the simulation engine."""

    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"


class SimulationEngine:
    """Core coordinator managing the lifecycle, routing, traffic, and fault state of the network."""

    def __init__(
        self,
        topology: Optional[NetworkTopology] = None,
        router: Optional[DeterministicRouter] = None,
        tick_interval_seconds: float = 1.0,
        seed: Optional[int] = None,
    ) -> None:
        self.tick_interval_seconds = tick_interval_seconds
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Components
        self.topology = topology or NetworkTopology(build_default=True)
        self.router = router or DeterministicRouter()
        self.scenario_mgr = ScenarioManager(self.topology)
        self.traffic_gen = TrafficGenerator(
            self.topology,
            self.router,
            self.scenario_mgr,
            seed=seed,
        )

        # State
        self.state = SimulationState.STOPPED
        self.sim_time = utc_now()
        self.start_wall_time: Optional[datetime] = None
        self.tick_count: int = 0

    @property
    def is_running(self) -> bool:
        return self.state == SimulationState.RUNNING

    @property
    def is_paused(self) -> bool:
        return self.state == SimulationState.PAUSED

    @property
    def is_stopped(self) -> bool:
        return self.state == SimulationState.STOPPED

    def start(self) -> Dict[str, Any]:
        """Start or unpause the simulation loop safely."""
        with self._lock:
            if self.state == SimulationState.RUNNING:
                return self.get_status()

            if self.state == SimulationState.PAUSED:
                return self.resume()

            self.state = SimulationState.RUNNING
            self.start_wall_time = utc_now()
            self._stop_event.clear()
            self._pause_event.set()

            # Ensure any previous dead thread reference is cleared
            if self._worker_thread is not None and not self._worker_thread.is_alive():
                self._worker_thread = None

            if self._worker_thread is None:
                self._worker_thread = threading.Thread(
                    target=self._run_loop,
                    name="NetMindsSimulationWorker",
                    daemon=True,
                )
                self._worker_thread.start()
                logger.info("Simulation engine started.")

            return self.get_status()

    def pause(self) -> Dict[str, Any]:
        """Pause simulation advancement."""
        with self._lock:
            if self.state == SimulationState.RUNNING:
                self.state = SimulationState.PAUSED
                self._pause_event.clear()
                logger.info("Simulation engine paused.")
            return self.get_status()

    def resume(self) -> Dict[str, Any]:
        """Resume a paused simulation."""
        with self._lock:
            if self.state == SimulationState.PAUSED:
                self.state = SimulationState.RUNNING
                self._pause_event.set()
                logger.info("Simulation engine resumed.")
            return self.get_status()

    def stop(self) -> Dict[str, Any]:
        """Stop simulation and terminate background thread."""
        with self._lock:
            if self.state == SimulationState.STOPPED:
                return self.get_status()

            self.state = SimulationState.STOPPED
            self._stop_event.set()
            self._pause_event.set()  # Wake up if waiting on pause

            worker = self._worker_thread
            self._worker_thread = None

        if worker and worker.is_alive() and threading.current_thread() != worker:
            worker.join(timeout=2.0)
            logger.info("Simulation engine stopped.")

        return self.get_status()

    def reset(self) -> Dict[str, Any]:
        """Reset topology, scenarios, routing, and traffic to clean initial state."""
        self.stop()
        with self._lock:
            self.topology.reset()
            self.scenario_mgr.clear_all()
            self.traffic_gen.reset()
            self.sim_time = utc_now()
            self.start_wall_time = None
            self.tick_count = 0
            logger.info("Simulation engine reset to initial state.")
            return self.get_status()

    def tick(self, time_delta_seconds: float = 1.0) -> TelemetrySample:
        """Advance the simulation exactly one tick deterministically."""
        with self._lock:
            self.tick_count += 1
            self.sim_time += timedelta(seconds=time_delta_seconds)

            # Advance scenario durations
            self.scenario_mgr.tick()

            # Generate new telemetry sample
            sample = self.traffic_gen.generate_tick(
                source="R1",
                destination="R4",
                sim_time=self.sim_time,
            )
            return sample

    def _run_loop(self) -> None:
        """Internal daemon worker executing the background simulation loop."""
        while not self._stop_event.is_set():
            # Wait if paused
            self._pause_event.wait()
            if self._stop_event.is_set():
                break

            try:
                self.tick(time_delta_seconds=self.tick_interval_seconds)
            except Exception as e:
                logger.exception(f"Error during simulation tick: {e}")

            time.sleep(self.tick_interval_seconds)

    def get_status(self) -> Dict[str, Any]:
        """Return high-level simulation state, tick count, and simulation clock."""
        with self._lock:
            routes = self.router.find_routes(self.topology, source="R1", destination="R4")
            active_scenarios = self.scenario_mgr.get_active_scenarios()
            latest_sample = self.traffic_gen.get_latest_sample()

            return {
                "state": self.state.value,
                "tick_count": self.tick_count,
                "simulation_time": self.sim_time.isoformat(),
                "start_wall_time": self.start_wall_time.isoformat() if self.start_wall_time else None,
                "is_route_available": routes.is_route_available,
                "primary_path": routes.primary_path.path if routes.primary_path else [],
                "backup_path": routes.backup_path.path if routes.backup_path else [],
                "active_scenarios_count": len(active_scenarios),
                "latest_traffic_rate_mbps": latest_sample.traffic_rate_mbps if latest_sample else 0.0,
                "latest_latency_ms": latest_sample.latency_ms if latest_sample else 0.0,
                "latest_utilization_pct": latest_sample.bandwidth_utilization_pct if latest_sample else 0.0,
                "latest_packet_loss_pct": latest_sample.packet_loss_pct if latest_sample else 0.0,
                "source_mode": "simulated",
            }

    def get_metrics(self) -> Dict[str, Any]:
        """Return instantaneous aggregate and per-link simulation metrics."""
        with self._lock:
            latest = self.traffic_gen.get_latest_sample()
            routes = self.router.find_routes(self.topology, source="R1", destination="R4")
            links = [l.to_dict() for l in self.topology.get_links()]

            return {
                "simulation_time": self.sim_time.isoformat(),
                "state": self.state.value,
                "tick_count": self.tick_count,
                "aggregate": {
                    "traffic_rate_mbps": latest.traffic_rate_mbps if latest else 0.0,
                    "latency_ms": latest.latency_ms if latest else 0.0,
                    "utilization_pct": latest.bandwidth_utilization_pct if latest else 0.0,
                    "packet_loss_pct": latest.packet_loss_pct if latest else 0.0,
                    "available_capacity_mbps": latest.available_capacity_mbps if latest else 0.0,
                    "active_route": latest.active_route if latest else [],
                    "is_route_available": routes.is_route_available,
                },
                "links": links,
                "routes": routes.to_dict(),
                "source_mode": "simulated",
            }

    def get_telemetry_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent simulation telemetry samples."""
        with self._lock:
            samples = self.traffic_gen.get_history(limit=limit)
            return [s.to_dict() for s in samples]


# Singleton engine accessor for API routing and lifecycle integration
_global_engine: Optional[SimulationEngine] = None
_engine_lock = threading.Lock()


def get_simulation_engine() -> SimulationEngine:
    """Retrieve or initialize the process-wide SimulationEngine instance."""
    global _global_engine
    with _engine_lock:
        if _global_engine is None:
            _global_engine = SimulationEngine()
        return _global_engine


def reset_simulation_engine_for_testing() -> SimulationEngine:
    """Helper to obtain a pristine simulation engine instance for test isolation."""
    global _global_engine
    with _engine_lock:
        if _global_engine is not None:
            _global_engine.stop()
        _global_engine = SimulationEngine()
        return _global_engine
