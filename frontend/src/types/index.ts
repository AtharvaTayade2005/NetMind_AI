/**
 * NetMind AI — Domain Type Definitions
 * Designed for production network monitoring, time-series prediction, and decision support.
 */

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ActionStatus = 'PENDING' | 'ACKNOWLEDGED' | 'RESOLVED';
export type Protocol = 'TCP' | 'UDP' | 'ICMP';
export type AttackCategory =
  | 'Normal'
  | 'DoS'
  | 'Port Scan'
  | 'Brute Force'
  | 'Web Attack'
  | 'Anomaly';

/**
 * Monitored network host / endpoint model
 */
export interface Host {
  id: string;
  ip: string;
  hostname: string;
  mac: string;
  subnet: string;
  firstSeen: string;
  lastSeen: string;
  riskScore: number; // 0 - 100
  status: 'ACTIVE' | 'QUARANTINED' | 'ISOLATED' | 'OFFLINE';
  activeFlows: number;
}

/**
 * Raw flow telemetry record (Zeek conn.log representation)
 */
export interface FlowTelemetry {
  id: string;
  timestamp: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: Protocol;
  service: string;
  durationSec: number;
  origBytes: number;
  respBytes: number;
  origPkts: number;
  respPkts: number;
  tcpFlags: {
    syn: number;
    ack: number;
    fin: number;
    rst: number;
  };
  connState: 'SF' | 'S0' | 'REJ' | 'RSTO' | 'RSTR' | 'SH' | 'OTH';
  isAnomaly: boolean;
}

/**
 * TreeSHAP Explainable AI attribution factor
 */
export interface ShapFactor {
  featureName: string;
  displayName: string;
  attribution: number; // Positive = pushes toward classification, Negative = reduces likelihood
  observedValue: string | number;
  baselineAverage: string | number;
}

/**
 * Classified Security Event / Threat Alert
 */
export interface SecurityAlert {
  id: string;
  timestamp: string;
  signature: string;
  category: AttackCategory;
  severity: Severity;
  confidencePercent: number; // e.g., 99.4
  detectorEngine: string; // e.g., "XGBoost Multiclass v1.0"
  status: ActionStatus;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: Protocol;
  description: string;
  technicalEvidence: {
    durationSec: number;
    packetRatePps: number;
    bytesPerSec: number;
    synAckRatio: number;
    failedConnRatio: number;
    distinctPortsProbed?: number;
  };
  shapAttributions: ShapFactor[];
  recommendation: {
    actionCode: string;
    summary: string;
    detailedPlan: string;
    suggestedCli?: string;
  };
  reviewedBy?: string;
  reviewedAt?: string;
}

/**
 * Unsupervised Anomaly record (Isolation Forest output)
 */
export interface AnomalyRecord {
  id: string;
  timestamp: string;
  hostIp: string;
  anomalyScore: number; // 0.0 - 1.0
  threshold: number;
  topDivergentMetrics: string[];
  status: 'OPEN' | 'INVESTIGATING' | 'DISMISSED';
}

/**
 * Dual-line throughput and packet rate time-series data point
 */
export interface TelemetryDataPoint {
  time: string;
  inboundMbps: number;
  outboundMbps: number;
  inboundPps: number;
  outboundPps: number;
}

/**
 * Time-series performance and predictive traffic point
 */
export interface TrafficForecast {
  timestamp: string;
  timeLabel: string;
  actualThroughputMbps: number | null;
  predictedThroughputMbps: number;
  upperConfidenceBoundMbps: number;
  lowerConfidenceBoundMbps: number;
  isForecast: boolean;
}

/**
 * Executive Risk Index breakdown
 */
export interface RiskIndex {
  currentScore: number; // 0 - 100
  tier: Severity;
  historicalDelta: string;
  monitoredHostsCount: number;
  activeIncidentsCount: number;
  unresolvedAnomaliesCount: number;
  currentIngressPps: number;
  currentEgressPps: number;
  lastUpdated: string;
}

/**
 * Decision Engine Recommendation item
 */
export interface RecommendationAction {
  id: string;
  alertId: string;
  targetHost: string;
  title: string;
  summary: string;
  commandSnippet: string;
  severity: Severity;
  status: ActionStatus;
  timestamp: string;
}
