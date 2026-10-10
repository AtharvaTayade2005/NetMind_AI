import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faServer, faFilter, faSearch } from '@fortawesome/free-solid-svg-icons';
import { Badge } from '../components/common/Badge';
import { FlowTelemetry, Protocol } from '../types';

interface FlowTelemetryViewProps {
  flows: FlowTelemetry[];
}

export const FlowTelemetryView: React.FC<FlowTelemetryViewProps> = ({ flows }) => {
  const [search, setSearch] = useState('');
  const [selectedProtocol, setSelectedProtocol] = useState<string>('ALL');

  const filteredFlows = flows.filter((f) => {
    const matchSearch =
      f.srcIp.includes(search) ||
      f.dstIp.includes(search) ||
      f.service.toLowerCase().includes(search.toLowerCase());
    const matchProto = selectedProtocol === 'ALL' || f.protocol === selectedProtocol;
    return matchSearch && matchProto;
  });

  return (
    <div className="space-y-4">
      {/* View Header */}
      <div className="bg-white border border-slate-200 rounded p-4 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-2">
            <FontAwesomeIcon icon={faServer} className="text-blue-700" />
            <span>Network Flow Telemetry Stream (Zeek conn.log)</span>
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time canonical 5-tuple socket normalization and TCP connection state metrics.
          </p>
        </div>

        {/* Filter controls */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <input
              type="text"
              placeholder="Filter by IP or service..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="text-xs py-1.5 pl-3 pr-8 bg-slate-50 border border-slate-200 rounded text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-600"
            />
          </div>

          <select
            value={selectedProtocol}
            onChange={(e) => setSelectedProtocol(e.target.value)}
            className="text-xs py-1.5 px-2 bg-slate-50 border border-slate-200 rounded text-slate-800 focus:outline-none focus:ring-1 focus:ring-blue-600"
          >
            <option value="ALL">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </div>
      </div>

      {/* Flows Table */}
      <div className="bg-white border border-slate-200 rounded shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-100 text-slate-600 font-semibold uppercase text-[10px] tracking-wider border-b border-slate-200">
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Source Socket</th>
                <th className="py-2.5 px-3">Destination Socket</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Service</th>
                <th className="py-2.5 px-3">Duration</th>
                <th className="py-2.5 px-3">State</th>
                <th className="py-2.5 px-3">Packets</th>
                <th className="py-2.5 px-3 text-right">Bytes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-sans">
              {filteredFlows.map((flow) => (
                <tr
                  key={flow.id}
                  className={`hover:bg-slate-50 transition-colors ${
                    flow.isAnomaly ? 'bg-amber-50/50' : ''
                  }`}
                >
                  <td className="py-2 px-3 font-mono text-[11px] text-slate-500">
                    {flow.timestamp}
                  </td>
                  <td className="py-2 px-3 font-mono text-[11px] text-slate-900 font-medium">
                    <span className={flow.isAnomaly ? 'text-rose-700 font-bold' : ''}>
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
                  <td className="py-2 px-3 text-slate-600 uppercase font-mono text-[11px]">
                    {flow.service}
                  </td>
                  <td className="py-2 px-3 text-slate-600 tabular-nums font-mono text-[11px]">
                    {flow.durationSec}s
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
                  <td className="py-2 px-3 text-slate-600 tabular-nums">
                    {flow.origPkts + flow.respPkts} pkts
                  </td>
                  <td className="py-2 px-3 text-right text-slate-900 font-mono text-[11px] tabular-nums">
                    {(flow.origBytes + flow.respBytes).toLocaleString()} B
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="p-3 bg-slate-50 border-t border-slate-200 text-xs text-slate-500 flex items-center justify-between">
          <span>Showing {filteredFlows.length} connection records</span>
          <span className="font-medium text-slate-700">Zeek TSV & NDJSON Parsing Active</span>
        </div>
      </div>
    </div>
  );
};
