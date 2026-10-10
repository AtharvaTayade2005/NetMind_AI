import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faXmark,
  faShieldHalved,
  faBrain,
  faTerminal,
  faCheck,
  faClock,
  faArrowRight,
  faCircleCheck,
  faTriangleExclamation,
} from '@fortawesome/free-solid-svg-icons';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
  Cell,
  CartesianGrid,
} from 'recharts';
import { Badge } from '../components/common/Badge';
import { SecurityAlert, ActionStatus } from '../types';

interface ThreatDetailModalProps {
  alert: SecurityAlert | null;
  isOpen: boolean;
  onClose: () => void;
  onUpdateAlertStatus?: (alertId: string, status: ActionStatus, note?: string) => void;
}

/**
 * ThreatDetailModal: Decision Support Inspection Dialog.
 * Implements the core NetMind AI workflow:
 * 1. OBSERVE: Alert Signature & Target Entity Matrix
 * 2. UNDERSTAND: Technical Forensic Flow Evidence
 * 3. PREDICT: Explainable AI (TreeSHAP) Feature Attribution Waterfall
 * 4. RECOMMEND: Decision Engine Containment Plan with Remediation Simulation
 */
export const ThreatDetailModal: React.FC<ThreatDetailModalProps> = ({
  alert,
  isOpen,
  onClose,
  onUpdateAlertStatus,
}) => {
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  if (!isOpen || !alert) return null;

  // Chart data for horizontal TreeSHAP waterfall
  const shapData = alert.shapAttributions.map((s) => ({
    name: s.displayName,
    attribution: Number(s.attribution.toFixed(2)),
    observed: s.observedValue,
    baseline: s.baselineAverage,
  }));

  const CustomShapTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
      const isPositive = item.attribution >= 0;
      return (
        <div className="bg-white border border-slate-300 rounded shadow-md p-2.5 text-xs font-sans">
          <div className="font-semibold text-slate-900 pb-1 mb-1 border-b border-slate-100">
            {item.name}
          </div>
          <div className="space-y-1">
            <div className="flex justify-between gap-4 text-slate-600">
              <span>Observed Value:</span>
              <span className="font-semibold text-slate-900">{item.observed}</span>
            </div>
            <div className="flex justify-between gap-4 text-slate-600">
              <span>Baseline Mean:</span>
              <span>{item.baseline}</span>
            </div>
            <div className="flex justify-between gap-4 text-slate-600 pt-1 border-t border-slate-100">
              <span>TreeSHAP Attribution:</span>
              <span
                className={`font-bold ${
                  isPositive ? 'text-rose-700' : 'text-blue-700'
                }`}
              >
                {item.attribution > 0 ? `+${item.attribution}` : item.attribution}
              </span>
            </div>
          </div>
        </div>
      );
    }
    return null;
  };

  const handleAcknowledge = () => {
    setIsProcessing(true);
    setTimeout(() => {
      onUpdateAlertStatus?.(alert.id, 'ACKNOWLEDGED', 'Acknowledged by Administrator');
      setFeedbackMessage('Incident successfully acknowledged. Assigned to active response queue.');
      setIsProcessing(false);
      setTimeout(() => setFeedbackMessage(null), 3000);
    }, 300);
  };

  const handleSimulateRemediation = () => {
    setIsProcessing(true);
    setTimeout(() => {
      onUpdateAlertStatus?.(
        alert.id,
        'RESOLVED',
        `Simulated Remediation Applied: ${alert.recommendation.actionCode}`
      );
      setFeedbackMessage(
        `Remediation simulated successfully. Rule "${alert.recommendation.actionCode}" deployed to virtual security filter.`
      );
      setIsProcessing(false);
      setTimeout(() => setFeedbackMessage(null), 3500);
    }, 400);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-150">
      <div
        className="w-full max-w-3xl bg-white border border-slate-300 rounded-lg shadow-xl flex flex-col overflow-hidden max-h-[90vh] animate-in zoom-in-98 duration-150"
        role="dialog"
      >
        {/* =========================================================================
            1. HEADER: Observe Layer
            ========================================================================= */}
        <div className="px-5 py-4 border-b border-slate-200 bg-slate-50 flex items-start justify-between gap-4 shrink-0">
          <div className="space-y-1.5 flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono text-slate-500 font-semibold">
                INCIDENT ID: {alert.id}
              </span>
              <Badge severity={alert.severity} size="sm">
                {alert.severity}
              </Badge>
              <Badge variant="blue" size="sm">
                {alert.category}
              </Badge>
              <span className="text-xs text-slate-500 font-medium ml-auto flex items-center gap-1.5">
                <FontAwesomeIcon icon={faClock} className="text-slate-400 text-xs" />
                {alert.timestamp}
              </span>
            </div>

            <h2 className="text-base font-semibold text-slate-900 tracking-tight">
              {alert.signature}
            </h2>

            {/* Entity Routing Matrix */}
            <div className="flex items-center gap-2 text-xs font-mono bg-white px-3 py-1.5 rounded border border-slate-200 text-slate-700">
              <div>
                <span className="text-slate-400 font-normal uppercase text-[10px] mr-1">
                  SOURCE:
                </span>
                <span className="font-semibold text-rose-700">{alert.srcIp}</span>
                <span className="text-slate-400">:{alert.srcPort}</span>
              </div>
              <FontAwesomeIcon icon={faArrowRight} className="text-slate-400 text-[10px]" />
              <div>
                <span className="text-slate-400 font-normal uppercase text-[10px] mr-1">
                  DESTINATION:
                </span>
                <span className="font-semibold text-blue-800">{alert.dstIp}</span>
                <span className="text-slate-400">:{alert.dstPort}</span>
              </div>
              <div className="ml-auto font-sans text-xs">
                <span className="text-slate-500">Engine: </span>
                <span className="font-semibold text-slate-900">{alert.detectorEngine}</span>
                <span className="text-emerald-700 font-semibold ml-1.5">
                  ({alert.confidencePercent}% Confidence)
                </span>
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-200 rounded transition-colors"
          >
            <FontAwesomeIcon icon={faXmark} className="text-base" />
          </button>
        </div>

        {/* =========================================================================
            MODAL BODY: Understand, Predict, Recommend
            ========================================================================= */}
        <div className="p-5 overflow-y-auto space-y-5">
          {/* Action Feedback Banner */}
          {feedbackMessage && (
            <div className="p-3 bg-emerald-50 border border-emerald-300 rounded text-xs text-emerald-800 flex items-center gap-2 font-medium">
              <FontAwesomeIcon icon={faCircleCheck} className="text-emerald-600 text-sm" />
              <span>{feedbackMessage}</span>
            </div>
          )}

          {/* Incident Description */}
          <div className="p-3 bg-slate-50 border border-slate-200 rounded text-xs text-slate-700 leading-relaxed">
            <span className="font-semibold text-slate-900 block mb-0.5">
              Incident Behavioral Assessment:
            </span>
            {alert.description}
          </div>

          {/* 2. UNDERSTAND: Technical Evidence Grid */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <FontAwesomeIcon icon={faShieldHalved} className="text-slate-500 text-xs" />
              <span>Technical Evidence (Flow Telemetry Metrics)</span>
            </h3>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              <div className="p-2.5 rounded bg-slate-50 border border-slate-200">
                <span className="text-[10px] font-semibold text-slate-500 uppercase block">
                  Packet Intensity Rate
                </span>
                <span className="text-base font-bold text-slate-900 tabular-nums">
                  {alert.technicalEvidence.packetRatePps.toLocaleString()}
                </span>
                <span className="text-xs text-slate-500 ml-1">pps</span>
              </div>

              <div className="p-2.5 rounded bg-slate-50 border border-slate-200">
                <span className="text-[10px] font-semibold text-slate-500 uppercase block">
                  Bandwidth Ingestion
                </span>
                <span className="text-base font-bold text-slate-900 tabular-nums">
                  {(alert.technicalEvidence.bytesPerSec / (1024 * 1024)).toFixed(1)}
                </span>
                <span className="text-xs text-slate-500 ml-1">MB/s</span>
              </div>

              <div className="p-2.5 rounded bg-slate-50 border border-slate-200">
                <span className="text-[10px] font-semibold text-slate-500 uppercase block">
                  SYN / ACK Flag Ratio
                </span>
                <span className="text-base font-bold text-rose-700 tabular-nums">
                  {alert.technicalEvidence.synAckRatio} : 1
                </span>
              </div>

              <div className="p-2.5 rounded bg-slate-50 border border-slate-200">
                <span className="text-[10px] font-semibold text-slate-500 uppercase block">
                  Flow Lifetime Duration
                </span>
                <span className="text-base font-bold text-slate-900 tabular-nums">
                  {alert.technicalEvidence.durationSec}
                </span>
                <span className="text-xs text-slate-500 ml-1">sec</span>
              </div>
            </div>
          </div>

          {/* 3. PREDICT: TreeSHAP Feature Attributions Bar Chart */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <h3 className="font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <FontAwesomeIcon icon={faBrain} className="text-slate-500 text-xs" />
                <span>Explainable AI: TreeSHAP Feature Attributions</span>
              </h3>
              <div className="flex items-center gap-3 text-[11px] font-medium">
                <span className="text-rose-700 flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-xs bg-rose-600 inline-block" /> + Pushed Toward Attack
                </span>
                <span className="text-blue-700 flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-xs bg-blue-600 inline-block" /> - Reduced Threat Score
                </span>
              </div>
            </div>

            <p className="text-[11px] text-slate-500">
              Additive game-theoretic Shapley values demonstrating how each behavioral metric moved
              the XGBoost decision boundary from baseline normality.
            </p>

            {/* Horizontal Bar Chart */}
            <div className="h-48 w-full bg-slate-50 border border-slate-200 rounded p-2">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  layout="vertical"
                  data={shapData}
                  margin={{ top: 5, right: 25, left: 25, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={false} />
                  <XAxis
                    type="number"
                    stroke="#64748b"
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: '#cbd5e1' }}
                  />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#334155"
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: '#cbd5e1' }}
                    width={180}
                  />
                  <Tooltip content={<CustomShapTooltip />} />
                  <ReferenceLine x={0} stroke="#94a3b8" strokeWidth={1} />
                  <Bar dataKey="attribution" radius={[2, 2, 2, 2]}>
                    {shapData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={entry.attribution >= 0 ? '#e11d48' : '#2563eb'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* 4. RECOMMEND: Decision Engine & Administrator Action Panel */}
          <div className="space-y-3 pt-2">
            <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider">
              Decision Support & Recommended Remediation
            </h3>

            <div className="p-4 bg-amber-50/60 border border-amber-300 rounded space-y-2.5">
              <div className="flex items-start justify-between gap-2">
                <span className="text-xs font-bold text-amber-900">
                  {alert.recommendation.summary}
                </span>
                <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-amber-200 text-amber-900 border border-amber-300 shrink-0">
                  {alert.recommendation.actionCode}
                </span>
              </div>

              <p className="text-xs text-amber-950 leading-relaxed font-sans">
                {alert.recommendation.detailedPlan}
              </p>

              {/* Suggested CLI Command Snippet */}
              {alert.recommendation.suggestedCli && (
                <div className="mt-2 p-2 rounded bg-white border border-amber-200 text-xs font-mono text-slate-800 flex items-center gap-2">
                  <FontAwesomeIcon icon={faTerminal} className="text-slate-400 text-xs" />
                  <code className="text-slate-900 font-semibold flex-1 truncate">
                    {alert.recommendation.suggestedCli}
                  </code>
                </div>
              )}
            </div>

            {/* Administrator Review Buttons */}
            <div className="flex items-center justify-end gap-3 pt-1">
              <button
                onClick={handleAcknowledge}
                disabled={isProcessing || alert.status === 'ACKNOWLEDGED'}
                className="px-4 py-2 rounded bg-white hover:bg-slate-50 border border-slate-300 text-xs font-semibold text-slate-700 transition-colors disabled:opacity-50"
              >
                {alert.status === 'ACKNOWLEDGED' ? 'Acknowledged' : 'Acknowledge Incident'}
              </button>

              <button
                onClick={handleSimulateRemediation}
                disabled={isProcessing || alert.status === 'RESOLVED'}
                className="px-4 py-2 rounded bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold transition-colors disabled:opacity-50 shadow-xs"
              >
                {alert.status === 'RESOLVED' ? 'Remediation Enforced' : 'Simulate Remediation'}
              </button>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-5 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500 shrink-0">
          <span>NetMind AI Explainability Engine v1.0.0</span>
          <button onClick={onClose} className="hover:text-slate-800 font-medium underline">
            Close Dialog
          </button>
        </div>
      </div>
    </div>
  );
};
