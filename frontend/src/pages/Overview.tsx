import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faServer,
  faNetworkWired,
  faTriangleExclamation,
  faShieldHalved,
  faArrowRight,
  faEye,
} from '@fortawesome/free-solid-svg-icons';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
} from 'recharts';
import { Badge } from '../components/common/Badge';
import {
  RiskIndex,
  SecurityAlert,
  FlowTelemetry,
  TelemetryDataPoint,
} from '../types';

interface OverviewProps {
  riskIndex: RiskIndex;
  alerts: SecurityAlert[];
  flows: FlowTelemetry[];
  telemetrySeries: TelemetryDataPoint[];
  onSelectAlert: (alert: SecurityAlert) => void;
  onNavigateTab: (tab: any) => void;
}

/**
 * Overview: Executive Network Monitoring & Decision Support Dashboard.
 * Clean, authentic UI with solid white cards, 1px structural borders, and standard data tables.
 */
export const Overview: React.FC<OverviewProps> = ({
  riskIndex,
  alerts,
  flows,
  telemetrySeries,
  onSelectAlert,
  onNavigateTab,
}) => {
  const pendingAlerts = alerts.filter(
    (a) => a.status === 'PENDING' || a.status === 'ACKNOWLEDGED'
  );

  // Standard Recharts tooltip
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white border border-slate-300 shadow-sm rounded p-2 text-xs font-sans">
          <div className="font-semibold text-slate-800 pb-1 mb-1 border-b border-slate-100">
            Timestamp: {label}
          </div>
          <div className="space-y-1">
            <div className="flex items-center justify-between gap-4 text-blue-700">
              <span className="flex items-center gap-1 font-medium">
                <span className="w-2 h-2 rounded-full bg-blue-600 inline-block" /> Inbound Throughput:
              </span>
              <span className="font-semibold">{payload[0]?.value} Mbps</span>
            </div>
            <div className="flex items-center justify-between gap-4 text-slate-700">
              <span className="flex items-center gap-1 font-medium">
                <span className="w-2 h-2 rounded-full bg-slate-600 inline-block" /> Outbound Throughput:
              </span>
              <span className="font-semibold">{payload[1]?.value} Mbps</span>
            </div>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="space-y-5">
      {/* =========================================================================
          1. TOP METRIC HUD (Solid White Cards with 1px Border and Icon Badges)
          ========================================================================= */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Monitored Endpoints / Hosts */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-sm flex items-start justify-between">
          <div className="space-y-1">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
              Monitored Endpoints
            </span>
            <div className="text-2xl font-bold text-slate-900 tabular-nums">
              {riskIndex.monitoredHostsCount}
              <span className="text-xs font-normal text-emerald-700 ml-1.5 font-medium">
                Active
              </span>
            </div>
            <p className="text-[11px] text-slate-500">Subnet segment 192.168.1.0/24</p>
          </div>
          <div className="w-9 h-9 rounded bg-blue-50 border border-blue-200 text-blue-700 flex items-center justify-center shrink-0">
            <FontAwesomeIcon icon={faServer} className="text-sm" />
          </div>
        </div>

        {/* Metric 2: Real-Time Telemetry Rate */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-sm flex items-start justify-between">
          <div className="space-y-1">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
              Telemetry Packet Rate
            </span>
            <div className="text-2xl font-bold text-slate-900 tabular-nums">
              {riskIndex.currentIngressPps.toLocaleString()}
              <span className="text-xs font-normal text-slate-500 ml-1">pkts/sec</span>
            </div>
            <p className="text-[11px] text-slate-500">
              Egress: {riskIndex.currentEgressPps.toLocaleString()} pkts/sec
            </p>
          </div>
          <div className="w-9 h-9 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center shrink-0">
            <FontAwesomeIcon icon={faNetworkWired} className="text-sm" />
          </div>
        </div>

        {/* Metric 3: Overall Risk Index */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-sm flex flex-col justify-between">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
                Overall Risk Index
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-slate-900 tabular-nums">
                  {riskIndex.currentScore.toFixed(0)}/100
                </span>
                <Badge severity={riskIndex.tier} size="sm">
                  {riskIndex.tier}
                </Badge>
              </div>
            </div>
            <div className="w-9 h-9 rounded bg-amber-50 border border-amber-200 text-amber-700 flex items-center justify-center shrink-0">
              <FontAwesomeIcon icon={faTriangleExclamation} className="text-sm" />
            </div>
          </div>

          {/* Color-coded severity progress bar */}
          <div className="mt-2.5">
            <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
              <div
                className={`h-full ${
                  riskIndex.currentScore >= 75
                    ? 'bg-rose-600'
                    : riskIndex.currentScore >= 50
                    ? 'bg-amber-500'
                    : 'bg-emerald-600'
                }`}
                style={{ width: `${riskIndex.currentScore}%` }}
              />
            </div>
            <span className="text-[10px] text-slate-400 mt-1 block">
              {riskIndex.historicalDelta}
            </span>
          </div>
        </div>

        {/* Metric 4: Active Flagged Incidents */}
        <div className="bg-white border border-slate-200 rounded p-4 shadow-sm flex items-start justify-between">
          <div className="space-y-1">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
              Active Flagged Incidents
            </span>
            <div className="text-2xl font-bold text-rose-700 tabular-nums">
              {riskIndex.activeIncidentsCount}
              <span className="text-xs font-normal text-slate-500 ml-1.5 font-medium">
                Requiring Review
              </span>
            </div>
            <p className="text-[11px] text-slate-500">
              {riskIndex.unresolvedAnomaliesCount} anomalies pending triage
            </p>
          </div>
          <div className="w-9 h-9 rounded bg-rose-50 border border-rose-200 text-rose-700 flex items-center justify-center shrink-0">
            <FontAwesomeIcon icon={faShieldHalved} className="text-sm" />
          </div>
        </div>
      </div>

      {/* =========================================================================
          2. TELEMETRY VISUALIZER (Clean Dual-Line Recharts Throughput Graph)
          ========================================================================= */}
      <div className="bg-white border border-slate-200 rounded p-5 shadow-sm space-y-3">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-2 border-b border-slate-100">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 tracking-tight">
              Network Telemetry Throughput: Inbound vs. Outbound Rate
            </h2>
            <p className="text-xs text-slate-500">
              Sampled across 5-minute sliding windows (Calculated in Megabits per second)
            </p>
          </div>

          <div className="flex items-center gap-3 text-xs font-medium text-slate-600">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-600 inline-block" /> Inbound
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-slate-600 inline-block" /> Outbound
            </span>
          </div>
        </div>

        {/* Recharts LineChart */}
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={telemetrySeries} margin={{ top: 10, right: 15, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
              <XAxis
                dataKey="time"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#cbd5e1' }}
              />
              <YAxis
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: '#cbd5e1' }}
                tickFormatter={(val) => `${val}M`}
              />
              <Tooltip content={<CustomTooltip />} />
              <Legend verticalAlign="top" align="right" height={24} />
              <Line
                name="Inbound Throughput (Mbps)"
                type="monotone"
                dataKey="inboundMbps"
                stroke="#2563eb"
                strokeWidth={2}
                dot={{ r: 3, fill: '#2563eb' }}
                activeDot={{ r: 5 }}
              />
              <Line
                name="Outbound Throughput (Mbps)"
                type="monotone"
                dataKey="outboundMbps"
                stroke="#475569"
                strokeWidth={2}
                dot={{ r: 3, fill: '#475569' }}
                activeDot={{ r: 5 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* =========================================================================
          3. SPLIT SECTION: Live Telemetry Stream Table & Priority Incident Queue
          ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column (7 cols): Live Network Flow Stream Table */}
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded shadow-sm overflow-hidden flex flex-col justify-between">
          <div className="p-4 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider">
                Live Network Flow Telemetry (Zeek conn.log)
              </h3>
              <p className="text-[11px] text-slate-500">Recent connection socket states</p>
            </div>
            <button
              onClick={() => onNavigateTab('flows')}
              className="text-xs font-medium text-blue-700 hover:text-blue-800 flex items-center gap-1 hover:underline"
            >
              <span>View Full Flow Stream</span>
              <FontAwesomeIcon icon={faArrowRight} className="text-[10px]" />
            </button>
          </div>

          {/* Clean HTML Data Table with light gray header */}
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-100 text-slate-600 font-semibold uppercase text-[10px] tracking-wider border-b border-slate-200">
                  <th className="py-2.5 px-3">Time</th>
                  <th className="py-2.5 px-3">Source Socket</th>
                  <th className="py-2.5 px-3">Destination Socket</th>
                  <th className="py-2.5 px-3">Proto</th>
                  <th className="py-2.5 px-3">State</th>
                  <th className="py-2.5 px-3 text-right">Volume</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-sans">
                {flows.slice(0, 6).map((flow) => (
                  <tr
                    key={flow.id}
                    className={`hover:bg-slate-50 transition-colors ${
                      flow.isAnomaly ? 'bg-amber-50/50' : ''
                    }`}
                  >
                    <td className="py-2 px-3 font-mono text-[11px] text-slate-500">
                      {flow.timestamp}
                    </td>
                    <td className="py-2 px-3 font-mono text-[11px] text-slate-900">
                      <span className={flow.isAnomaly ? 'text-rose-700 font-semibold' : ''}>
                        {flow.srcIp}
                      </span>
                      <span className="text-slate-400">:{flow.srcPort}</span>
                    </td>
                    <td className="py-2 px-3 font-mono text-[11px] text-slate-700">
                      <span>{flow.dstIp}</span>
                      <span className="text-slate-400">:{flow.dstPort}</span>
                    </td>
                    <td className="py-2 px-3">
                      <Badge protocol={flow.protocol} size="sm">
                        {flow.protocol}
                      </Badge>
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          flow.connState === 'S0' || flow.connState === 'REJ'
                            ? 'bg-rose-100 text-rose-800'
                            : 'bg-slate-100 text-slate-700'
                        }`}
                      >
                        {flow.connState}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-right font-mono text-[11px] text-slate-700 tabular-nums">
                      {(flow.origBytes + flow.respBytes).toLocaleString()} B
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="p-3 bg-slate-50 border-t border-slate-200 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Sampling: Active sliding window</span>
            <span className="font-medium text-slate-700">6 flows displayed</span>
          </div>
        </div>

        {/* Right Column (5 cols): Active Flagged Incidents Queue */}
        <div className="lg:col-span-5 bg-white border border-slate-200 rounded shadow-sm overflow-hidden flex flex-col justify-between">
          <div className="p-4 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider">
                Flagged Security Incidents ({pendingAlerts.length})
              </h3>
              <p className="text-[11px] text-slate-500">Requires administrator review</p>
            </div>
            <button
              onClick={() => onNavigateTab('threats')}
              className="text-xs font-medium text-blue-700 hover:text-blue-800 flex items-center gap-1 hover:underline"
            >
              <span>View All</span>
              <FontAwesomeIcon icon={faArrowRight} className="text-[10px]" />
            </button>
          </div>

          {/* Incident Items */}
          <div className="p-3 space-y-2.5 overflow-y-auto max-h-[310px]">
            {pendingAlerts.map((alert) => (
              <div
                key={alert.id}
                onClick={() => onSelectAlert(alert)}
                className="p-3 rounded border border-slate-200 hover:border-slate-300 hover:bg-slate-50/80 transition-all cursor-pointer group"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <Badge severity={alert.severity} size="sm">
                      {alert.severity}
                    </Badge>
                    <span className="text-xs font-semibold text-slate-900">
                      {alert.category}
                    </span>
                  </div>
                  <span className="font-mono text-[10px] text-slate-400">
                    {alert.timestamp}
                  </span>
                </div>

                <p className="text-xs text-slate-700 font-medium line-clamp-1 group-hover:text-blue-700">
                  {alert.signature}
                </p>

                <div className="mt-2 pt-2 border-t border-slate-100 flex items-center justify-between text-[11px]">
                  <span className="font-mono text-slate-500 text-[10px]">
                    {alert.srcIp} → {alert.dstIp}:{alert.dstPort}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectAlert(alert);
                    }}
                    className="font-medium text-blue-700 hover:underline flex items-center gap-1"
                  >
                    <span>Inspect Decision</span>
                    <FontAwesomeIcon icon={faEye} className="text-[10px]" />
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div className="p-3 bg-slate-50 border-t border-slate-200 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Powered by XGBoost Multi-Class v1.0</span>
            <span className="text-blue-700 font-medium">TreeSHAP Explainable</span>
          </div>
        </div>
      </div>
    </div>
  );
};
