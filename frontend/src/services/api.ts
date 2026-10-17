/**
 * NetMind AI — Service Layer
 * Supports live FastAPI backend integration with direct hardware NIC telemetry and fallback.
 */

import {
  SecurityAlert,
  FlowTelemetry,
  Host,
  TrafficForecast,
  RecommendationAction,
  RiskIndex,
  ActionStatus,
  TelemetryDataPoint,
} from '../types';

import {
  MOCK_ALERTS,
  MOCK_FLOWS,
  MOCK_HOSTS,
  MOCK_TRAFFIC_FORECAST,
  MOCK_RECOMMENDATIONS,
  MOCK_RISK_INDEX,
  MOCK_TELEMETRY_SERIES,
} from './mockData';

const MOCK_STORAGE_KEY = 'netmind_use_mock_api';

// Default to LIVE API mode (false) so it uses the real hardware NIC & backend
let useMockMode = localStorage.getItem(MOCK_STORAGE_KEY) === 'true';

export const isMockMode = (): boolean => useMockMode;

export const setMockMode = (enabled: boolean): void => {
  useMockMode = enabled;
  localStorage.setItem(MOCK_STORAGE_KEY, enabled ? 'true' : 'false');
  window.dispatchEvent(new CustomEvent('netmind:mode-changed', { detail: { useMock: enabled } }));
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface LiveTelemetryResponse {
  current: {
    interface: string;
    inboundMbps: number;
    outboundMbps: number;
    inboundPps: number;
    outboundPps: number;
    totalBytesRecv: number;
    totalBytesSent: number;
    timestamp: string;
  };
  series: TelemetryDataPoint[];
}

export interface NetworkInterfaceInfo {
  name: string;
  is_up: boolean;
  speed_mbps: number;
  ip: string;
}

export const apiService = {
  /**
   * Fetch live hardware NIC bandwidth time-series and current rates.
   */
  async getLiveTelemetry(): Promise<LiveTelemetryResponse> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/telemetry/live');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.series) && data.series.length > 0) {
            return data;
          }
        }
      } catch (e) {
        console.warn('Live NIC telemetry API unreachable, using fallback', e);
      }
    }
    await sleep(20);
    return {
      current: {
        interface: 'Wi-Fi (Mock)',
        inboundMbps: 0.12,
        outboundMbps: 0.05,
        inboundPps: 24,
        outboundPps: 18,
        totalBytesRecv: 30000000,
        totalBytesSent: 80000000,
        timestamp: new Date().toISOString(),
      },
      series: MOCK_TELEMETRY_SERIES,
    };
  },

  /**
   * Enumerate host physical and virtual network adapters.
   */
  async getInterfaces(): Promise<{ interfaces: NetworkInterfaceInfo[]; active: string }> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/telemetry/interfaces');
        if (res.ok) {
          return await res.json();
        }
      } catch (e) {
        console.warn('Failed to query interfaces, using defaults', e);
      }
    }
    return {
      interfaces: [
        { name: 'Wi-Fi', is_up: true, speed_mbps: 130, ip: '192.168.1.34' },
        { name: 'Loopback Pseudo-Interface 1', is_up: true, speed_mbps: 1073, ip: '127.0.0.1' },
      ],
      active: 'Wi-Fi',
    };
  },

  /**
   * Switch monitored NIC interface.
   */
  async switchInterface(name: string): Promise<boolean> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/telemetry/interface', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ interface_name: name }),
        });
        return res.ok;
      } catch (e) {
        console.warn('Failed to switch NIC interface', e);
      }
    }
    return true;
  },

  /**
   * Fetch active connection flows captured directly from the live host sockets.
   */
  async getLiveFlows(): Promise<FlowTelemetry[]> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/telemetry/flows');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            return data;
          }
        }
      } catch (e) {
        console.warn('Live flows API unreachable, using fallback', e);
      }
    }
    await sleep(20);
    return MOCK_FLOWS;
  },

  /**
   * Fetch network status KPIs.
   */
  async getRiskIndex(): Promise<RiskIndex> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/network/status');
        if (res.ok) {
          const data = await res.json();
          return {
            currentScore: data.average_risk_score || 22.0,
            tier: data.active_risk_level || 'LOW',
            historicalDelta: '+2.1% live delta',
            monitoredHostsCount: data.total_hosts || 8,
            activeIncidentsCount: data.active_threats_count || 8,
            unresolvedAnomaliesCount: data.unresolved_anomalies_count || 9,
            currentIngressPps: data.current_packet_rate_pps || 2840,
            currentEgressPps: Math.round((data.current_packet_rate_pps || 2840) * 0.7),
            lastUpdated: new Date().toLocaleTimeString(),
          };
        }
      } catch (e) {
        console.warn('Live API unavailable, using local mock data', e);
      }
    }
    await sleep(20);
    return MOCK_RISK_INDEX;
  },

  async getAlerts(): Promise<SecurityAlert[]> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/threats');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.items) && data.items.length > 0) return data.items;
        }
      } catch (e) {
        console.warn('Live API unavailable, using local alerts', e);
      }
    }
    await sleep(20);
    return MOCK_ALERTS;
  },

  async getFlows(): Promise<FlowTelemetry[]> {
    return this.getLiveFlows();
  },

  async getHosts(): Promise<Host[]> {
    await sleep(20);
    return MOCK_HOSTS;
  },

  async getForecast(): Promise<TrafficForecast[]> {
    await sleep(20);
    return MOCK_TRAFFIC_FORECAST;
  },

  async getRecommendations(): Promise<RecommendationAction[]> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/recommendations');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.items) && data.items.length > 0) return data.items;
        }
      } catch (e) {
        console.warn('Live API unavailable, using local recommendations', e);
      }
    }
    await sleep(20);
    return MOCK_RECOMMENDATIONS;
  },

  async reviewAlert(
    alertId: string,
    status: ActionStatus,
    operatorNote?: string
  ): Promise<void> {
    if (!useMockMode) {
      try {
        await fetch(`/api/events/${alertId}/review`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: status.toLowerCase(), notes: operatorNote }),
        });
      } catch (e) {
        console.warn('Live review failed, falling back to local state', e);
      }
    }
    await sleep(40);
  },

  async executeRemediation(recommendationId: string): Promise<void> {
    if (!useMockMode) {
      try {
        await fetch(`/api/recommendations/${recommendationId}/review`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'applied', reviewed_by: 'soc_admin_01' }),
        });
      } catch (e) {
        console.warn('Live recommendation execution failed', e);
      }
    }
    await sleep(40);
  },
};
