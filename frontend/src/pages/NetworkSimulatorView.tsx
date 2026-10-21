import React, { useState, useEffect, useCallback } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faPlay,
  faPause,
  faStop,
  faRotateRight,
  faForwardStep,
  faCircleCheck,
  faTriangleExclamation,
  faCircleXmark,
  faNetworkWired,
  faWaveSquare,
  faBolt,
  faClock,
  faArrowRight,
  faSliders,
  faRoute,
  faCheck,
  faBan,
  faGaugeHigh,
} from '@fortawesome/free-solid-svg-icons';
import {
  apiService,
} from '../services/api';
import {
  SimulationStatus,
  SimulatedTopology,
  SimulationMetrics,
  SimulationTelemetrySample,
  SimulationScenario,
} from '../types';

export const NetworkSimulatorView: React.FC = () => {
  const [status, setStatus] = useState<SimulationStatus | null>(null);
  const [metrics, setMetrics] = useState<SimulationMetrics | null>(null);
  const [topology, setTopology] = useState<SimulatedTopology | null>(null);
  const [telemetry, setTelemetry] = useState<SimulationTelemetrySample[]>([]);
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState<boolean>(false);

  // Poll simulator state from real backend API
  const fetchSimulatorState = useCallback(async () => {
    try {
      const [s, m, t, tel, scens] = await Promise.all([
        apiService.getSimulationStatus(),
        apiService.getSimulationMetrics(),
        apiService.getTopology(),
        apiService.getSimulationTelemetry(20),
        apiService.getSimulationScenarios(false),
      ]);
      setStatus(s);
      setMetrics(m);
      setTopology(t);
      setTelemetry(tel);
      setScenarios(scens);
      setError(null);
    } catch (err: any) {
      setError(err?.message || 'Failed to connect to simulation service');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSimulatorState();
    const interval = setInterval(fetchSimulatorState, 1500);
    return () => clearInterval(interval);
  }, [fetchSimulatorState]);

  // Lifecycle action handlers
  const handleStart = async () => {
    setSubmitting(true);
    try {
      const s = await apiService.startSimulation();
      setStatus(s);
      showNotice('Simulator started. Background traffic loop active.');
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handlePause = async () => {
    setSubmitting(true);
    try {
      const s = await apiService.pauseSimulation();
      setStatus(s);
      showNotice('Simulator paused.');
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleResume = async () => {
    setSubmitting(true);
    try {
      const s = await apiService.resumeSimulation();
      setStatus(s);
      showNotice('Simulator resumed.');
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleStop = async () => {
    setSubmitting(true);
    try {
      const s = await apiService.stopSimulation();
      setStatus(s);
      showNotice('Simulator stopped.');
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleReset = async () => {
    setSubmitting(true);
    try {
      const s = await apiService.resetSimulation();
      setStatus(s);
      showNotice('Simulator reset to initial topology and clean baseline.');
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTick = async () => {
    setSubmitting(true);
    try {
      await apiService.tickSimulation(1.0);
      showNotice('Executed single deterministic tick.');
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  // Scenario injection handlers
  const handleFailLink = async (source: string, target: string) => {
    setSubmitting(true);
    try {
      await apiService.injectLinkFailure(source, target);
      showNotice(`Injected Link Failure on ${source}-${target}.`);
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRecoverLink = async (source: string, target: string) => {
    setSubmitting(true);
    try {
      await apiService.injectLinkRecovery(source, target);
      showNotice(`Recovered Link ${source}-${target} to operational state.`);
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleCongestLink = async (source: string, target: string) => {
    setSubmitting(true);
    try {
      await apiService.injectCongestion(source, target, 96.0, 8.5, 45.0);
      showNotice(`Injected Congestion on ${source}-${target} (96% util, 8.5% loss).`);
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleLatencySpike = async (source: string, target: string) => {
    setSubmitting(true);
    try {
      await apiService.injectLatencySpike(source, target, 80.0);
      showNotice(`Injected +80ms Latency Spike on ${source}-${target}.`);
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTrafficSurge = async () => {
    setSubmitting(true);
    try {
      await apiService.injectTrafficSurge(3.0);
      showNotice('Injected 3.0x Traffic Surge across network.');
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleClearAllScenarios = async () => {
    setSubmitting(true);
    try {
      await apiService.clearAllSimulationScenarios();
      showNotice('Cleared all fault scenarios and restored link baselines.');
      fetchSimulatorState();
    } catch (e: any) {
      setError(e?.message);
    } finally {
      setSubmitting(false);
    }
  };

  const showNotice = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 4000);
  };

  if (loading && !status) {
    return (
      <div className="p-8 flex flex-col items-center justify-center min-h-[400px] text-slate-500">
        <FontAwesomeIcon icon={faRotateRight} className="animate-spin text-2xl mb-3 text-blue-600" />
        <span className="text-sm font-medium">Connecting to NetMinds Network Simulator...</span>
      </div>
    );
  }

  const isRunning = status?.state === 'running';
  const isPaused = status?.state === 'paused';
  const isStopped = status?.state === 'stopped';

  const agg = metrics?.aggregate;
  const primaryPathStr = status?.primary_path?.join(' → ') || 'None';
  const backupPathStr = status?.backup_path?.join(' → ') || 'None';
  const isRouteAvail = status?.is_route_available ?? false;

  return (
    <div className="space-y-6">
      {/* Top Banner: Distinguishing Simulated vs Hardware Telemetry */}
      <div className="bg-gradient-to-r from-slate-900 to-indigo-950 text-white rounded-lg p-5 shadow-sm border border-slate-800 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-blue-500/20 text-blue-300 border border-blue-500/30">
              Simulation Mode (Phase 1)
            </span>
            <span className="text-xs text-slate-300 font-mono">
              In-Memory Graph Environment — Host Operating System Protected
            </span>
          </div>
          <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <FontAwesomeIcon icon={faSliders} className="text-blue-400" />
            Dynamic Network Simulator & Deterministic Routing
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time topology state, failure injection, deterministic multi-metric path failover, and dynamic telemetry generation.
          </p>
        </div>

        {/* State Badge & Action Bar */}
        <div className="flex items-center flex-wrap gap-2">
          {/* Status Badge */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-800/80 border border-slate-700 text-xs">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                isRunning
                  ? 'bg-emerald-400 animate-pulse'
                  : isPaused
                  ? 'bg-amber-400'
                  : 'bg-slate-400'
              }`}
            />
            <span className="font-semibold uppercase tracking-wider text-[11px]">
              {status?.state || 'STOPPED'}
            </span>
            <span className="text-slate-400 font-mono border-l border-slate-700 pl-2">
              Tick: {status?.tick_count ?? 0}
            </span>
          </div>

          {/* Lifecycle Buttons */}
          {isStopped ? (
            <button
              onClick={handleStart}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <FontAwesomeIcon icon={faPlay} />
              Start
            </button>
          ) : isRunning ? (
            <button
              onClick={handlePause}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <FontAwesomeIcon icon={faPause} />
              Pause
            </button>
          ) : (
            <button
              onClick={handleResume}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <FontAwesomeIcon icon={faPlay} />
              Resume
            </button>
          )}

          {!isStopped && (
            <button
              onClick={handleStop}
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <FontAwesomeIcon icon={faStop} />
              Stop
            </button>
          )}

          <button
            onClick={handleTick}
            disabled={submitting}
            title="Advance one simulation tick without waiting"
            className="px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
          >
            <FontAwesomeIcon icon={faForwardStep} />
            Step Tick
          </button>

          <button
            onClick={handleReset}
            disabled={submitting}
            className="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
          >
            <FontAwesomeIcon icon={faRotateRight} />
            Reset
          </button>
        </div>
      </div>

      {/* Action Notification or Error Banner */}
      {actionNotice && (
        <div className="bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs px-4 py-2.5 rounded flex items-center justify-between animate-fade-in">
          <div className="flex items-center gap-2">
            <FontAwesomeIcon icon={faCircleCheck} className="text-emerald-600" />
            <span className="font-medium">{actionNotice}</span>
          </div>
          <button onClick={() => setActionNotice(null)} className="text-emerald-500 hover:text-emerald-800 font-bold">
            ×
          </button>
        </div>
      )}

      {error && (
        <div className="bg-rose-50 border border-rose-200 text-rose-800 text-xs px-4 py-2.5 rounded flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FontAwesomeIcon icon={faCircleXmark} className="text-rose-600" />
            <span className="font-medium">Error: {error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-rose-500 hover:text-rose-800 font-bold">
            ×
          </button>
        </div>
      )}

      {/* Live Telemetry KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-white border border-slate-200 rounded p-3.5 shadow-xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">
            Carried Traffic
          </span>
          <div className="text-lg font-bold text-slate-900 mt-1 flex items-baseline gap-1">
            {agg ? agg.traffic_rate_mbps.toFixed(1) : '0.0'}
            <span className="text-xs font-normal text-slate-500">Mbps</span>
          </div>
          <span className="text-[10px] text-slate-400 mt-1 block">Dynamic throughput</span>
        </div>

        <div className="bg-white border border-slate-200 rounded p-3.5 shadow-xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">
            End-to-End Latency
          </span>
          <div className="text-lg font-bold text-slate-900 mt-1 flex items-baseline gap-1">
            {agg ? agg.latency_ms.toFixed(1) : '0.0'}
            <span className="text-xs font-normal text-slate-500">ms</span>
          </div>
          <span className="text-[10px] text-slate-400 mt-1 block">Base + Queueing delay</span>
        </div>

        <div className="bg-white border border-slate-200 rounded p-3.5 shadow-xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">
            Link Utilization
          </span>
          <div className="text-lg font-bold text-slate-900 mt-1 flex items-baseline gap-1">
            {agg ? agg.utilization_pct.toFixed(1) : '0.0'}
            <span className="text-xs font-normal text-slate-500">%</span>
          </div>
          <div className="w-full bg-slate-100 rounded-full h-1.5 mt-2 overflow-hidden">
            <div
              className={`h-1.5 rounded-full ${
                (agg?.utilization_pct || 0) > 85 ? 'bg-rose-500' : 'bg-blue-600'
              }`}
              style={{ width: `${Math.min(100, agg?.utilization_pct || 0)}%` }}
            />
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded p-3.5 shadow-xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">
            Packet Loss
          </span>
          <div
            className={`text-lg font-bold mt-1 flex items-baseline gap-1 ${
              (agg?.packet_loss_pct || 0) > 0 ? 'text-rose-600' : 'text-slate-900'
            }`}
          >
            {agg ? agg.packet_loss_pct.toFixed(1) : '0.0'}
            <span className="text-xs font-normal text-slate-500">%</span>
          </div>
          <span className="text-[10px] text-slate-400 mt-1 block">Queue drop / impairment</span>
        </div>

        <div className="bg-white border border-slate-200 rounded p-3.5 shadow-xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">
            Available Capacity
          </span>
          <div className="text-lg font-bold text-slate-900 mt-1 flex items-baseline gap-1">
            {agg ? agg.available_capacity_mbps.toFixed(0) : '0'}
            <span className="text-xs font-normal text-slate-500">Mbps</span>
          </div>
          <span className="text-[10px] text-slate-400 mt-1 block">Bottleneck headroom</span>
        </div>

        <div className="bg-white border border-slate-200 rounded p-3.5 shadow-xs">
          <span className="text-[11px] font-medium text-slate-500 uppercase tracking-wider block">
            Active Routing State
          </span>
          <div className="mt-1">
            {isRouteAvail ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200">
                <FontAwesomeIcon icon={faCheck} className="text-[10px]" />
                Operational
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-rose-50 text-rose-800 border border-rose-200">
                <FontAwesomeIcon icon={faBan} className="text-[10px]" />
                Blocked
              </span>
            )}
          </div>
          <span className="text-[10px] text-slate-500 mt-1.5 truncate block font-mono">
            {agg?.active_route && agg.active_route.length > 0
              ? agg.active_route.join(' → ')
              : 'No valid path'}
          </span>
        </div>
      </div>

      {/* Main Grid: Network Topology Visualizer & Dynamic Path Selection */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Topology & Router Graph (2 Cols) */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <FontAwesomeIcon icon={faNetworkWired} className="text-slate-600" />
                Network Topology & Operational Link Mesh
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                4 Routers (R1-R4) with live bandwidth, latency, capacity, and operational statuses.
              </p>
            </div>
            <span className="text-[11px] bg-slate-100 text-slate-600 px-2 py-1 rounded font-mono">
              Nodes: {topology?.node_count || 4} | Links: {topology?.link_count || 5}
            </span>
          </div>

          {/* Router Diagram */}
          <div className="bg-slate-50 border border-slate-200 rounded p-4">
            <div className="grid grid-cols-3 items-center gap-4 text-center">
              {/* R1 (Source) */}
              <div className="flex flex-col items-center">
                <div className="w-16 h-16 rounded-lg bg-slate-900 text-white flex flex-col items-center justify-center shadow-sm border border-slate-800">
                  <span className="text-xs font-bold">R1</span>
                  <span className="text-[9px] text-blue-300">Ingress</span>
                </div>
                <span className="text-[11px] font-medium text-slate-700 mt-1">Edge R1</span>
                <span className="text-[9px] text-emerald-600 font-semibold">● UP</span>
              </div>

              {/* Middle Spine: R2 (Primary) & R3 (Backup) */}
              <div className="flex flex-col gap-6 items-center">
                {/* R2 */}
                <div className="flex flex-col items-center">
                  <div
                    className={`w-16 h-16 rounded-lg flex flex-col items-center justify-center shadow-sm border ${
                      topology?.links.find((l) => l.link_id === 'R1-R2')?.status === 'down'
                        ? 'bg-rose-50 text-rose-800 border-rose-300'
                        : 'bg-white text-slate-900 border-slate-300'
                    }`}
                  >
                    <span className="text-xs font-bold">R2</span>
                    <span className="text-[9px] text-slate-500">Core Alpha</span>
                  </div>
                  <span className="text-[11px] font-medium text-slate-700 mt-1">Core R2 (Primary)</span>
                </div>

                {/* Cross Link indicator */}
                <div className="text-[10px] text-slate-400 font-mono">
                  ↕ R2-R3 (500M, 10ms)
                </div>

                {/* R3 */}
                <div className="flex flex-col items-center">
                  <div
                    className={`w-16 h-16 rounded-lg flex flex-col items-center justify-center shadow-sm border ${
                      topology?.links.find((l) => l.link_id === 'R1-R3')?.status === 'down'
                        ? 'bg-rose-50 text-rose-800 border-rose-300'
                        : 'bg-white text-slate-900 border-slate-300'
                    }`}
                  >
                    <span className="text-xs font-bold">R3</span>
                    <span className="text-[9px] text-slate-500">Core Beta</span>
                  </div>
                  <span className="text-[11px] font-medium text-slate-700 mt-1">Core R3 (Backup)</span>
                </div>
              </div>

              {/* R4 (Destination) */}
              <div className="flex flex-col items-center">
                <div className="w-16 h-16 rounded-lg bg-slate-900 text-white flex flex-col items-center justify-center shadow-sm border border-slate-800">
                  <span className="text-xs font-bold">R4</span>
                  <span className="text-[9px] text-emerald-300">Egress</span>
                </div>
                <span className="text-[11px] font-medium text-slate-700 mt-1">Gateway R4</span>
                <span className="text-[9px] text-emerald-600 font-semibold">● UP</span>
              </div>
            </div>
          </div>

          {/* Links Detail Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-2 px-3">Link</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3">Bandwidth</th>
                  <th className="py-2 px-3">Latency</th>
                  <th className="py-2 px-3">Utilization</th>
                  <th className="py-2 px-3">Available Cap</th>
                  <th className="py-2 px-3 text-right">Quick Fault Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {topology?.links.map((link) => {
                  const isDown = link.status === 'down';
                  const isTraversed = agg?.active_route?.some(
                    (node, idx, arr) =>
                      idx < arr.length - 1 &&
                      ((node === link.source && arr[idx + 1] === link.target) ||
                        (node === link.target && arr[idx + 1] === link.source))
                  );

                  return (
                    <tr
                      key={link.link_id}
                      className={`hover:bg-slate-50 transition-colors ${
                        isDown ? 'bg-rose-50/50' : isTraversed ? 'bg-blue-50/30' : ''
                      }`}
                    >
                      <td className="py-2 px-3 font-semibold text-slate-800">
                        {link.link_id}
                        {isTraversed && (
                          <span className="ml-2 text-[9px] bg-blue-100 text-blue-800 px-1 py-0.2 rounded font-sans">
                            ACTIVE
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3">
                        <span
                          className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border ${
                            isDown
                              ? 'bg-rose-100 text-rose-800 border-rose-200'
                              : 'bg-emerald-100 text-emerald-800 border-emerald-200'
                          }`}
                        >
                          {isDown ? 'DOWN' : 'UP'}
                        </span>
                      </td>
                      <td className="py-2 px-3">{link.bandwidth_mbps} Mbps</td>
                      <td className="py-2 px-3">{link.latency_ms} ms</td>
                      <td className="py-2 px-3">
                        <div className="flex items-center gap-1.5">
                          <span>{link.utilization_pct.toFixed(1)}%</span>
                        </div>
                      </td>
                      <td className="py-2 px-3 font-semibold text-slate-700">
                        {link.available_capacity_mbps.toFixed(1)} Mbps
                      </td>
                      <td className="py-2 px-3 text-right font-sans">
                        {isDown ? (
                          <button
                            onClick={() => handleRecoverLink(link.source, link.target)}
                            disabled={submitting}
                            className="text-[11px] px-2 py-0.5 rounded bg-emerald-600 hover:bg-emerald-700 text-white font-medium cursor-pointer"
                          >
                            Recover
                          </button>
                        ) : (
                          <div className="inline-flex gap-1">
                            <button
                              onClick={() => handleFailLink(link.source, link.target)}
                              disabled={submitting}
                              className="text-[10px] px-2 py-0.5 rounded bg-rose-600 hover:bg-rose-700 text-white font-medium cursor-pointer"
                            >
                              Fail
                            </button>
                            <button
                              onClick={() => handleCongestLink(link.source, link.target)}
                              disabled={submitting}
                              className="text-[10px] px-1.5 py-0.5 rounded bg-amber-600 hover:bg-amber-700 text-white font-medium cursor-pointer"
                            >
                              Congest
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Dynamic Route Comparison & Scenario Controls (1 Col) */}
        <div className="space-y-6">
          {/* Dynamic Route Selection Card */}
          <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <FontAwesomeIcon icon={faRoute} className="text-slate-600" />
              Dynamic Route Computation
            </h3>

            {/* Primary Path */}
            <div className="p-3 rounded bg-slate-50 border border-slate-200">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="font-semibold text-slate-700">Primary Candidate Path</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-blue-100 text-blue-800 font-medium">
                  R1 → R2 → R4
                </span>
              </div>
              <div className="text-xs font-mono font-bold text-slate-900">
                {primaryPathStr}
              </div>
              <span className="text-[10px] text-slate-500 mt-1 block">
                Lowest cost path under baseline conditions (5ms + 5ms = 10ms base latency).
              </span>
            </div>

            {/* Backup Path */}
            <div className="p-3 rounded bg-slate-50 border border-slate-200">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="font-semibold text-slate-700">Backup Candidate Path</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-200 text-slate-800 font-medium">
                  R1 → R3 → R4
                </span>
              </div>
              <div className="text-xs font-mono text-slate-700">
                {backupPathStr}
              </div>
              <span className="text-[10px] text-slate-500 mt-1 block">
                Discovered and traversed upon failure of primary link R1-R2 or R2-R4.
              </span>
            </div>
          </div>

          {/* Fault Scenarios Injection Panel */}
          <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <FontAwesomeIcon icon={faBolt} className="text-amber-500" />
                Fault Scenario Injections
              </h3>
              {scenarios.length > 0 && (
                <button
                  onClick={handleClearAllScenarios}
                  disabled={submitting}
                  className="text-[11px] text-rose-600 hover:text-rose-800 font-semibold cursor-pointer"
                >
                  Clear All ({scenarios.length})
                </button>
              )}
            </div>

            <p className="text-xs text-slate-500">
              Mutate in-memory network parameters to test routing resiliency and ML telemetry pipelines.
            </p>

            <div className="grid grid-cols-2 gap-2 pt-1">
              <button
                onClick={() => handleFailLink('R1', 'R2')}
                disabled={submitting}
                className="px-2.5 py-2 rounded bg-rose-50 hover:bg-rose-100 text-rose-800 border border-rose-200 text-xs font-medium text-left transition-colors cursor-pointer"
              >
                <div className="font-semibold">Fail R1-R2</div>
                <div className="text-[10px] text-rose-600">Primary route failover</div>
              </button>

              <button
                onClick={() => handleRecoverLink('R1', 'R2')}
                disabled={submitting}
                className="px-2.5 py-2 rounded bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-200 text-xs font-medium text-left transition-colors cursor-pointer"
              >
                <div className="font-semibold">Recover R1-R2</div>
                <div className="text-[10px] text-emerald-600">Restore primary</div>
              </button>

              <button
                onClick={() => handleCongestLink('R1', 'R2')}
                disabled={submitting}
                className="px-2.5 py-2 rounded bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 text-xs font-medium text-left transition-colors cursor-pointer"
              >
                <div className="font-semibold">Congest Link</div>
                <div className="text-[10px] text-amber-600">+96% util & drops</div>
              </button>

              <button
                onClick={() => handleLatencySpike('R2', 'R4')}
                disabled={submitting}
                className="px-2.5 py-2 rounded bg-indigo-50 hover:bg-indigo-100 text-indigo-800 border border-indigo-200 text-xs font-medium text-left transition-colors cursor-pointer"
              >
                <div className="font-semibold">Latency Spike</div>
                <div className="text-[10px] text-indigo-600">+80ms on R2-R4</div>
              </button>

              <button
                onClick={handleTrafficSurge}
                disabled={submitting}
                className="col-span-2 px-2.5 py-2 rounded bg-purple-50 hover:bg-purple-100 text-purple-800 border border-purple-200 text-xs font-medium text-left transition-colors cursor-pointer"
              >
                <div className="font-semibold">Global Traffic Surge (3x Multiplier)</div>
                <div className="text-[10px] text-purple-600">Elevate offered network demand across routers</div>
              </button>
            </div>

            {/* Active Scenarios List */}
            {scenarios.length > 0 && (
              <div className="pt-2 border-t border-slate-100 space-y-1.5">
                <span className="text-[11px] font-semibold text-slate-700 block">
                  Active Injected Scenarios ({scenarios.length}):
                </span>
                {scenarios.map((scen) => (
                  <div
                    key={scen.scenario_id}
                    className="p-2 rounded bg-slate-50 border border-slate-200 text-xs flex items-center justify-between"
                  >
                    <div>
                      <span className="font-semibold text-slate-800 uppercase text-[10px]">
                        {scen.scenario_type.replace('_', ' ')}
                      </span>
                      <span className="text-slate-600 ml-1.5 font-mono text-[11px]">
                        [{scen.affected_resource}]
                      </span>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-100 text-amber-800 font-semibold">
                      ACTIVE
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Generated Telemetry History Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-3">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <FontAwesomeIcon icon={faClock} className="text-slate-600" />
              Generated Simulation Telemetry Stream (Bounded Window)
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Timestamped telemetry samples generated as simulation clock advances. Ready for Phase 2 ML ingestion.
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            {telemetry.length} Samples Cached
          </span>
        </div>

        {telemetry.length === 0 ? (
          <div className="p-6 text-center text-slate-400 text-xs">
            No simulation telemetry points generated yet. Click "Start" or "Step Tick" to produce samples.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase tracking-wider text-[10px]">
                <tr>
                  <th className="py-2 px-3">Tick</th>
                  <th className="py-2 px-3">Timestamp (UTC)</th>
                  <th className="py-2 px-3">Active Route</th>
                  <th className="py-2 px-3">Traffic Rate</th>
                  <th className="py-2 px-3">Utilization</th>
                  <th className="py-2 px-3">Latency</th>
                  <th className="py-2 px-3">Packet Loss</th>
                  <th className="py-2 px-3">Available Cap</th>
                  <th className="py-2 px-3">Scenario Marker</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {telemetry.slice(-15).reverse().map((t, idx) => (
                  <tr key={`${t.tick}-${idx}`} className="hover:bg-slate-50 transition-colors">
                    <td className="py-2 px-3 text-slate-500">#{t.tick}</td>
                    <td className="py-2 px-3 text-slate-700">
                      {new Date(t.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2 px-3 font-semibold text-slate-800">
                      {t.active_route.length > 0 ? t.active_route.join(' → ') : (
                        <span className="text-rose-600 font-sans font-normal text-[11px]">BLOCKED</span>
                      )}
                    </td>
                    <td className="py-2 px-3">{t.traffic_rate_mbps.toFixed(1)} Mbps</td>
                    <td className="py-2 px-3">{t.bandwidth_utilization_pct.toFixed(1)}%</td>
                    <td className="py-2 px-3">{t.latency_ms.toFixed(1)} ms</td>
                    <td className={`py-2 px-3 ${t.packet_loss_pct > 0 ? 'text-rose-600 font-bold' : ''}`}>
                      {t.packet_loss_pct.toFixed(1)}%
                    </td>
                    <td className="py-2 px-3">{t.available_capacity_mbps.toFixed(0)} Mbps</td>
                    <td className="py-2 px-3 font-sans">
                      {t.scenario_identifier ? (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 font-medium font-mono">
                          {t.scenario_identifier.split('-')[0]}
                        </span>
                      ) : (
                        <span className="text-slate-400 text-[11px]">baseline</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
