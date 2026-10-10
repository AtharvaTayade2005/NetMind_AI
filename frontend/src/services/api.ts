/**
 * NetMind AI — Service Layer
 * Supports live FastAPI backend integration with automatic fallback to realistic mock fixtures.
 */

import {
  SecurityAlert,
  FlowTelemetry,
  Host,
  TrafficForecast,
  RecommendationAction,
  RiskIndex,
  ActionStatus,
} from '../types';

import {
  MOCK_ALERTS,
  MOCK_FLOWS,
  MOCK_HOSTS,
  MOCK_TRAFFIC_FORECAST,
  MOCK_RECOMMENDATIONS,
  MOCK_RISK_INDEX,
} from './mockData';

const MOCK_STORAGE_KEY = 'netmind_use_mock_api';

let useMockMode = localStorage.getItem(MOCK_STORAGE_KEY) !== 'false';

export const isMockMode = (): boolean => useMockMode;

export const setMockMode = (enabled: boolean): void => {
  useMockMode = enabled;
  localStorage.setItem(MOCK_STORAGE_KEY, enabled ? 'true' : 'false');
  window.dispatchEvent(new CustomEvent('netmind:mode-changed', { detail: { useMock: enabled } }));
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const apiService = {
  async getRiskIndex(): Promise<RiskIndex> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/network/status');
        if (res.ok) {
          const data = await res.json();
          return {
            currentScore: data.average_risk_score || 68.0,
            tier: data.active_risk_level || 'HIGH',
            historicalDelta: '+4.2% vs previous hour',
            monitoredHostsCount: data.total_hosts || 32,
            activeIncidentsCount: data.active_threats_count || 4,
            unresolvedAnomaliesCount: data.unresolved_anomalies_count || 3,
            currentIngressPps: data.current_packet_rate_pps || 2840,
            currentEgressPps: 1910,
            lastUpdated: new Date().toLocaleTimeString(),
          };
        }
      } catch (e) {
        console.warn('Live API unavailable, using local mock data', e);
      }
    }
    await sleep(40);
    return MOCK_RISK_INDEX;
  },

  async getAlerts(): Promise<SecurityAlert[]> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/threats');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.items)) return data.items;
        }
      } catch (e) {
        console.warn('Live API unavailable, using local alerts', e);
      }
    }
    await sleep(60);
    return MOCK_ALERTS;
  },

  async getFlows(): Promise<FlowTelemetry[]> {
    await sleep(40);
    return MOCK_FLOWS;
  },

  async getHosts(): Promise<Host[]> {
    await sleep(40);
    return MOCK_HOSTS;
  },

  async getForecast(): Promise<TrafficForecast[]> {
    await sleep(60);
    return MOCK_TRAFFIC_FORECAST;
  },

  async getRecommendations(): Promise<RecommendationAction[]> {
    if (!useMockMode) {
      try {
        const res = await fetch('/api/recommendations');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.items)) return data.items;
        }
      } catch (e) {
        console.warn('Live API unavailable, using local recommendations', e);
      }
    }
    await sleep(50);
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
    await sleep(80);
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
    await sleep(100);
  },
};
