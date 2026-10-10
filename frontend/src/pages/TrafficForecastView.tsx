import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faChartLine, faTriangleExclamation, faCircleInfo } from '@fortawesome/free-solid-svg-icons';
import {
  ResponsiveContainer,
  ComposedChart,
  Line,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
  ReferenceLine,
} from 'recharts';
import { TrafficForecast } from '../types';

interface TrafficForecastViewProps {
  forecastData: TrafficForecast[];
}

export const TrafficForecastView: React.FC<TrafficForecastViewProps> = ({ forecastData }) => {
  const trunkLimitMbps = 70.0;
  const maxProjected = Math.max(
    ...forecastData.map((d) => d.upperConfidenceBoundMbps || d.predictedThroughputMbps)
  );
  const isCongested = maxProjected >= trunkLimitMbps * 0.85;

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const dataPoint = payload[0].payload as TrafficForecast;
      return (
        <div className="bg-white border border-slate-300 rounded shadow-md p-2.5 text-xs font-sans">
          <div className="font-semibold text-slate-800 pb-1 mb-1 border-b border-slate-100">
            {label}
          </div>
          <div className="space-y-1">
            {dataPoint.actualThroughputMbps !== null && (
              <div className="flex justify-between gap-4 text-blue-700 font-medium">
                <span>Historical Actual:</span>
                <span className="font-semibold">{dataPoint.actualThroughputMbps.toFixed(1)} Mbps</span>
              </div>
            )}
            <div className="flex justify-between gap-4 text-slate-700 font-medium">
              <span>Model Projection:</span>
              <span className="font-semibold">{dataPoint.predictedThroughputMbps.toFixed(1)} Mbps</span>
            </div>
            {dataPoint.isForecast && (
              <div className="pt-1 mt-1 border-t border-slate-100 text-[10px] text-slate-500 space-y-0.5">
                <div className="flex justify-between">
                  <span>Upper Bound (+1σ):</span>
                  <span className="font-semibold text-rose-700">
                    {dataPoint.upperConfidenceBoundMbps.toFixed(1)} Mbps
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Lower Bound (-1σ):</span>
                  <span className="font-semibold text-emerald-700">
                    {dataPoint.lowerConfidenceBoundMbps.toFixed(1)} Mbps
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="space-y-4">
      {/* View Header */}
      <div className="bg-white border border-slate-200 rounded p-4 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 uppercase tracking-wider flex items-center gap-2">
            <FontAwesomeIcon icon={faChartLine} className="text-blue-700" />
            <span>Performance & Predictive Traffic Forecast (XGBoost Regressor)</span>
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            AutoRegressive lag windows (t-1, t-2, t-5) predicting future ingress volume with statistical confidence intervals.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-medium text-slate-700 bg-slate-50 px-3 py-1.5 rounded border border-slate-200">
          <span>Trunk Interface Limit:</span>
          <span className="font-bold text-slate-900">{trunkLimitMbps} Mbps</span>
        </div>
      </div>

      {/* Congestion Warning Callout if needed */}
      {isCongested && (
        <div className="p-3.5 bg-amber-50 border border-amber-300 rounded flex items-start gap-3 text-xs text-amber-900">
          <FontAwesomeIcon
            icon={faTriangleExclamation}
            className="text-amber-600 text-sm mt-0.5 shrink-0"
          />
          <div>
            <strong className="font-semibold">Capacity Warning:</strong> Projected upper throughput
            ({maxProjected.toFixed(1)} Mbps) crosses the 85% link utilization threshold. Proactive
            rate limiting recommended to maintain SLA response times.
          </div>
        </div>
      )}

      {/* Forecast Chart Card */}
      <div className="bg-white border border-slate-200 rounded p-5 shadow-sm space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-100">
          <h3 className="text-xs font-semibold text-slate-900 uppercase tracking-wider">
            Throughput Volume: Past Actual Ingress vs. Forward Forecast Curve
          </h3>
          <span className="text-xs text-slate-500 font-medium">Horizon: Next 45 Minutes</span>
        </div>

        {/* Recharts Composed Chart */}
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={forecastData} margin={{ top: 15, right: 15, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
              <XAxis
                dataKey="timeLabel"
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

              {/* Physical Trunk Capacity Threshold line */}
              <ReferenceLine
                y={trunkLimitMbps}
                stroke="#e11d48"
                strokeDasharray="4 4"
                label={{
                  value: `Trunk Threshold (${trunkLimitMbps} Mbps)`,
                  fill: '#e11d48',
                  fontSize: 10,
                  position: 'top',
                }}
              />

              {/* Shaded confidence bound area */}
              <Area
                type="monotone"
                dataKey="upperConfidenceBoundMbps"
                stroke="#94a3b8"
                strokeDasharray="2 2"
                strokeWidth={1}
                fill="#f1f5f9"
                fillOpacity={0.8}
                name="Confidence Interval (+1σ)"
              />

              {/* Actual historical line */}
              <Line
                type="monotone"
                dataKey="actualThroughputMbps"
                stroke="#2563eb"
                strokeWidth={2.5}
                dot={{ r: 3, fill: '#2563eb' }}
                name="Actual Inbound Throughput (Mbps)"
              />

              {/* Predicted volume line */}
              <Line
                type="monotone"
                dataKey="predictedThroughputMbps"
                stroke="#0f172a"
                strokeWidth={2}
                strokeDasharray="4 4"
                dot={{ r: 3, fill: '#0f172a' }}
                name="Model Projected Curve (Mbps)"
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        {/* Analytical Context */}
        <div className="p-3 bg-slate-50 border border-slate-200 rounded text-xs text-slate-600 flex items-start gap-2">
          <FontAwesomeIcon icon={faCircleInfo} className="text-blue-600 text-xs mt-0.5 shrink-0" />
          <p>
            The shaded light gray area visualizes the statistical confidence envelope $\pm 1 \sigma$
            around the rolling regression curve. If predicted volume approaches physical interface
            thresholds, the decision engine queues proactive shaping playbooks.
          </p>
        </div>
      </div>
    </div>
  );
};
