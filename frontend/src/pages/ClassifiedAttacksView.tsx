import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShieldHalved, faEye, faFilter } from '@fortawesome/free-solid-svg-icons';
import { Badge } from '../components/common/Badge';
import { SecurityAlert, AttackCategory } from '../types';

interface ClassifiedAttacksViewProps {
  alerts: SecurityAlert[];
  onSelectAlert: (alert: SecurityAlert) => void;
}

export const ClassifiedAttacksView: React.FC<ClassifiedAttacksViewProps> = ({
  alerts,
  onSelectAlert,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  const filtered = alerts.filter(
    (a) => selectedCategory === 'ALL' || a.category === selectedCategory
  );

  return (
    <div className="space-y-4">
      {/* View Header */}
      <div className="bg-white border border-slate-200 rounded p-4 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-2">
            <FontAwesomeIcon icon={faShieldHalved} className="text-rose-700" />
            <span>Classified Attack Detections (Supervised XGBoost)</span>
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Model inferences categorized across DoS, Port Scan, Brute Force, and Web Attack classes.
          </p>
        </div>

        {/* Category Filter */}
        <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200 rounded p-1 text-xs">
          {(['ALL', 'DoS', 'Port Scan', 'Brute Force', 'Web Attack'] as const).map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                selectedCategory === cat
                  ? 'bg-slate-900 text-white font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Attacks Table */}
      <div className="bg-white border border-slate-200 rounded shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-100 text-slate-600 font-semibold uppercase text-[10px] tracking-wider border-b border-slate-200">
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Vector (Src → Dst)</th>
                <th className="py-2.5 px-3">Attack Signature</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3 text-right">Decision Triage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-sans">
              {filtered.map((alert) => (
                <tr
                  key={alert.id}
                  onClick={() => onSelectAlert(alert)}
                  className="hover:bg-slate-50 transition-colors cursor-pointer group"
                >
                  <td className="py-2 px-3">
                    <Badge severity={alert.severity} size="sm">
                      {alert.severity}
                    </Badge>
                  </td>
                  <td className="py-2 px-3 font-semibold text-slate-900">{alert.category}</td>
                  <td className="py-2 px-3 text-emerald-700 font-semibold tabular-nums">
                    {alert.confidencePercent}%
                  </td>
                  <td className="py-2 px-3 font-mono text-[11px]">
                    <span className="text-rose-700 font-medium">{alert.srcIp}</span>
                    <span className="text-slate-400 mx-1">→</span>
                    <span className="text-blue-800 font-medium">{alert.dstIp}</span>
                  </td>
                  <td className="py-2 px-3 text-slate-800 font-medium max-w-xs truncate group-hover:text-blue-700">
                    {alert.signature}
                  </td>
                  <td className="py-2 px-3">
                    <Badge actionStatus={alert.status} size="sm">
                      {alert.status}
                    </Badge>
                  </td>
                  <td className="py-2 px-3 text-slate-500 font-mono text-[11px] whitespace-nowrap">
                    {alert.timestamp}
                  </td>
                  <td className="py-2 px-3 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectAlert(alert);
                      }}
                      className="px-2.5 py-1 rounded bg-blue-50 hover:bg-blue-100 border border-blue-200 text-blue-700 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors"
                    >
                      <FontAwesomeIcon icon={faEye} className="text-[10px]" />
                      <span>Inspect</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="p-3 bg-slate-50 border-t border-slate-200 text-xs text-slate-500 flex items-center justify-between">
          <span>{filtered.length} classified incident records</span>
          <span className="text-slate-700 font-medium">TreeSHAP Explainability Active</span>
        </div>
      </div>
    </div>
  );
};
