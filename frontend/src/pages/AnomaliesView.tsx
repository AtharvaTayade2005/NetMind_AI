import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTriangleExclamation, faCheck } from '@fortawesome/free-solid-svg-icons';
import { Badge } from '../components/common/Badge';
import { AnomalyRecord } from '../types';

interface AnomaliesViewProps {
  anomalies: AnomalyRecord[];
}

export const AnomaliesView: React.FC<AnomaliesViewProps> = ({ anomalies }) => {
  return (
    <div className="space-y-4">
      {/* View Header */}
      <div className="bg-white border border-slate-200 rounded p-4 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-2">
            <FontAwesomeIcon icon={faTriangleExclamation} className="text-amber-600" />
            <span>Unsupervised Anomalies (Isolation Forest)</span>
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Zero-day deviations and statistical outliers exceeding dynamic 95th-percentile thresholds.
          </p>
        </div>

        <div className="px-3 py-1 rounded bg-amber-50 border border-amber-200 text-amber-800 text-xs font-medium">
          Calibrated Threshold: <strong className="font-mono">0.50</strong>
        </div>
      </div>

      {/* Anomalies List */}
      <div className="bg-white border border-slate-200 rounded shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-100 text-slate-600 font-semibold uppercase text-[10px] tracking-wider border-b border-slate-200">
                <th className="py-2.5 px-3">Anomaly ID</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Subject Host</th>
                <th className="py-2.5 px-3">Anomaly Score</th>
                <th className="py-2.5 px-3">Divergent Behavioral Indicators</th>
                <th className="py-2.5 px-3 text-right">Triage State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-sans">
              {anomalies.map((anom) => (
                <tr key={anom.id} className="hover:bg-slate-50 transition-colors">
                  <td className="py-2.5 px-3 font-mono font-medium text-slate-900">{anom.id}</td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-slate-500">
                    {anom.timestamp}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[11px] font-semibold text-rose-700">
                    {anom.hostIp}
                  </td>
                  <td className="py-2.5 px-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-slate-900 tabular-nums">
                        {anom.anomalyScore.toFixed(3)}
                      </span>
                      <div className="w-16 bg-slate-100 rounded-full h-1.5 overflow-hidden">
                        <div
                          className="bg-amber-600 h-full"
                          style={{ width: `${anom.anomalyScore * 100}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="py-2.5 px-3">
                    <div className="flex flex-wrap gap-1">
                      {anom.topDivergentMetrics.map((metric, i) => (
                        <span
                          key={i}
                          className="text-[10px] bg-slate-100 text-slate-700 px-1.5 py-0.5 rounded border border-slate-200"
                        >
                          {metric}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <Badge variant={anom.status === 'OPEN' ? 'amber' : 'blue'} size="sm">
                      {anom.status}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="p-3 bg-slate-50 border-t border-slate-200 text-xs text-slate-500 flex items-center justify-between">
          <span>{anomalies.length} anomaly instances tracked</span>
          <span className="font-medium text-slate-700">150 Isolation Trees (Subsample: 256)</span>
        </div>
      </div>
    </div>
  );
};
