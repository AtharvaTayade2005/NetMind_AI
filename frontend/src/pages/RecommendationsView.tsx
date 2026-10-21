import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faBrain,
  faTerminal,
  faPlay,
  faCircleCheck,
} from '@fortawesome/free-solid-svg-icons';
import { Badge } from '../components/common/Badge';
import { RecommendationAction, ActionStatus } from '../types';

interface RecommendationsViewProps {
  recommendations: RecommendationAction[];
  onExecuteRecommendation: (id: string) => void;
}

export const RecommendationsView: React.FC<RecommendationsViewProps> = ({
  recommendations,
  onExecuteRecommendation,
}) => {
  const [filter, setFilter] = useState<'ALL' | ActionStatus>('ALL');

  const filtered = recommendations.filter((r) => {
    if (filter === 'ALL') return true;
    const rStatus = String(r.status || '').toUpperCase();
    return rStatus === filter;
  });

  return (
    <div className="space-y-4">
      {/* View Header */}
      <div className="bg-white border border-slate-200 rounded p-4 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-2">
            <FontAwesomeIcon icon={faBrain} className="text-blue-800" />
            <span>Decision Support & Containment Playbooks Queue</span>
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Operational recommendations synthesized from multi-vector risk evaluations and threat severity.
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200 rounded p-1 text-xs">
          {(['ALL', 'PENDING', 'ACKNOWLEDGED', 'RESOLVED'] as const).map((s) => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                filter === s
                  ? 'bg-slate-900 text-white font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Recommendations Cards */}
      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="bg-white border border-slate-200 rounded p-12 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mx-auto text-xl border border-emerald-200">
              <FontAwesomeIcon icon={faCircleCheck} />
            </div>
            <h3 className="text-sm font-semibold text-slate-800">
              No {filter !== 'ALL' ? filter : ''} Mitigation Recommendations
            </h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              All automated playbooks for this filter have been executed or no matching events require triage.
            </p>
          </div>
        ) : (
          filtered.map((rec) => {
            const rStatus = String(rec.status || '').toUpperCase();
            const isPending = rStatus === 'PENDING';
            const isResolved = rStatus === 'RESOLVED' || rStatus === 'APPROVED' || rStatus === 'APPLIED';

            return (
              <div
                key={rec.id}
                className="bg-white border border-slate-200 rounded p-4 shadow-sm space-y-3 hover:border-slate-300 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-slate-500">{rec.id}</span>
                      <h3 className="text-sm font-semibold text-slate-900">{rec.title || 'Mitigation Action'}</h3>
                      <Badge severity={rec.severity || 'HIGH'} size="sm">
                        {rec.severity || 'HIGH'}
                      </Badge>
                      <Badge actionStatus={(isResolved ? 'RESOLVED' : (isPending ? 'PENDING' : 'ACKNOWLEDGED'))} size="sm">
                        {isResolved ? 'RESOLVED' : (isPending ? 'PENDING' : 'ACKNOWLEDGED')}
                      </Badge>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Target Host: <strong className="font-mono text-slate-800">{rec.targetHost || '192.168.1.200'}</strong>{' '}
                      • Linked Incident: <strong className="font-mono text-slate-800">#{rec.alertId}</strong>{' '}
                      • Generated at: {rec.timestamp || 'Recent'}
                    </p>
                  </div>

                  {/* Execution Button */}
                  <div>
                    {isPending && (
                      <button
                        onClick={() => onExecuteRecommendation(rec.id)}
                        className="px-3.5 py-1.5 rounded bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-xs"
                      >
                        <FontAwesomeIcon icon={faPlay} className="text-[10px]" />
                        <span>Simulate Remediation</span>
                      </button>
                    )}
                    {isResolved && (
                      <span className="text-xs font-semibold text-emerald-800 bg-emerald-50 px-2.5 py-1 rounded border border-emerald-300 inline-flex items-center gap-1.5">
                        <FontAwesomeIcon icon={faCircleCheck} className="text-emerald-600" />
                        <span>Remediation Enforced</span>
                      </span>
                    )}
                  </div>
                </div>

                <p className="text-xs text-slate-700 bg-slate-50 p-2.5 rounded border border-slate-100">
                  {rec.summary}
                </p>

                {/* Terminal command snippet */}
                {rec.commandSnippet && (
                  <div className="p-2 rounded bg-slate-100 border border-slate-200 text-xs font-mono text-slate-900 flex items-center gap-2">
                    <FontAwesomeIcon icon={faTerminal} className="text-slate-400 text-xs" />
                    <code className="font-semibold">{rec.commandSnippet}</code>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
