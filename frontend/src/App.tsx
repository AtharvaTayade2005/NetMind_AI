import React, { useState, useEffect } from 'react';
import { Navbar } from './components/layout/Navbar';
import { Sidebar, NavTab } from './components/layout/Sidebar';
import { Overview } from './pages/Overview';
import { FlowTelemetryView } from './pages/FlowTelemetryView';
import { ClassifiedAttacksView } from './pages/ClassifiedAttacksView';
import { AnomaliesView } from './pages/AnomaliesView';
import { TrafficForecastView } from './pages/TrafficForecastView';
import { RecommendationsView } from './pages/RecommendationsView';
import { ThreatDetailModal } from './pages/ThreatDetailModal';
import { NetworkSimulatorView } from './pages/NetworkSimulatorView';

import {
  MOCK_ALERTS,
  MOCK_FLOWS,
  MOCK_ANOMALIES,
  MOCK_TELEMETRY_SERIES,
  MOCK_TRAFFIC_FORECAST,
  MOCK_RECOMMENDATIONS,
  MOCK_RISK_INDEX,
} from './services/mockData';

import {
  apiService,
  NetworkInterfaceInfo,
} from './services/api';

import {
  SecurityAlert,
  FlowTelemetry,
  AnomalyRecord,
  TelemetryDataPoint,
  TrafficForecast,
  RecommendationAction,
  RiskIndex,
  ActionStatus,
} from './types';

export function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [activeSegment, setActiveSegment] = useState<string>('Wi-Fi');
  const [availableInterfaces, setAvailableInterfaces] = useState<NetworkInterfaceInfo[]>([]);

  // Core dynamic application state
  const [alerts, setAlerts] = useState<SecurityAlert[]>(MOCK_ALERTS);
  const [flows, setFlows] = useState<FlowTelemetry[]>(MOCK_FLOWS);
  const [anomalies, setAnomalies] = useState<AnomalyRecord[]>(MOCK_ANOMALIES);
  const [telemetrySeries, setTelemetrySeries] = useState<TelemetryDataPoint[]>(MOCK_TELEMETRY_SERIES);
  const [forecastData, setForecastData] = useState<TrafficForecast[]>(MOCK_TRAFFIC_FORECAST);
  const [recommendations, setRecommendations] = useState<RecommendationAction[]>(
    MOCK_RECOMMENDATIONS
  );
  const [riskIndex, setRiskIndex] = useState<RiskIndex>(MOCK_RISK_INDEX);

  // Decision Support Inspection Modal state
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  // Real-Time Live Polling Engine (1.2s Interval)
  useEffect(() => {
    let isMounted = true;

    // Discover host network interfaces
    apiService.getInterfaces().then((res) => {
      if (!isMounted) return;
      if (res.interfaces && res.interfaces.length > 0) {
        setAvailableInterfaces(res.interfaces);
      }
      if (res.active) {
        setActiveSegment(res.active);
      }
    });

    const pollLiveTelemetry = async () => {
      try {
        const [tel, r, f, a, recs] = await Promise.all([
          apiService.getLiveTelemetry(),
          apiService.getRiskIndex(),
          apiService.getLiveFlows(),
          apiService.getAlerts(),
          apiService.getRecommendations(),
        ]);

        if (!isMounted) return;

        if (tel && tel.series && tel.series.length > 0) {
          setTelemetrySeries(tel.series);
        }
        if (r) {
          setRiskIndex(r);
        }
        if (f && f.length > 0) {
          setFlows(f);
        }
        if (a && a.length > 0) {
          setAlerts(a);
        }
        if (recs && recs.length > 0) {
          setRecommendations(recs);
        }
      } catch (err) {
        console.warn('Real-time telemetry poll update notice:', err);
      }
    };

    pollLiveTelemetry();
    const interval = setInterval(pollLiveTelemetry, 1200);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleSelectSegment = async (segment: string) => {
    setActiveSegment(segment);
    await apiService.switchInterface(segment);
  };

  const handleOpenAlert = (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
  };

  const handleUpdateAlertStatus = (
    alertId: string,
    status: ActionStatus,
    note?: string
  ) => {
    setAlerts((prev) =>
      prev.map((a) =>
        a.id === alertId
          ? {
              ...a,
              status,
              reviewedBy: 'Administrator',
              reviewedAt: new Date().toLocaleTimeString(),
              description: note ? `${a.description} [${note}]` : a.description,
            }
          : a
      )
    );

    if (selectedAlert && selectedAlert.id === alertId) {
      setSelectedAlert((prev) => (prev ? { ...prev, status } : prev));
    }

    // If resolved, sync corresponding recommendation
    if (status === 'RESOLVED') {
      setRecommendations((prev) =>
        prev.map((r) => (r.alertId === alertId ? { ...r, status: 'RESOLVED' } : r))
      );
      setRiskIndex((prev) => ({
        ...prev,
        currentScore: Math.max(15, prev.currentScore - 12),
        activeIncidentsCount: Math.max(0, prev.activeIncidentsCount - 1),
      }));
    }

    apiService.reviewAlert(alertId, status, note);
  };

  const handleExecuteRecommendation = (recId: string) => {
    setRecommendations((prev) =>
      prev.map((r) => (r.id === recId ? { ...r, status: 'RESOLVED' } : r))
    );

    // Sync corresponding alert
    const rec = recommendations.find((r) => r.id === recId);
    if (rec) {
      setAlerts((prev) =>
        prev.map((a) => (a.id === rec.alertId ? { ...a, status: 'RESOLVED' } : a))
      );
    }

    apiService.executeRemediation(recId);
  };

  const pendingAlertsCount = alerts.filter(
    (a) => a.status === 'PENDING' || a.status === 'ACKNOWLEDGED'
  ).length;
  const pendingRecsCount = recommendations.filter((r) => r.status === 'PENDING').length;

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-slate-50 text-slate-900 font-sans antialiased">
      {/* 1. Global Navigation Bar with Live Interface Selector */}
      <Navbar
        activeSegment={activeSegment}
        onSelectSegment={handleSelectSegment}
        ingestionActive={true}
        availableInterfaces={availableInterfaces}
      />

      {/* 2. Main Two-Column Viewport */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          threatsCount={pendingAlertsCount}
          anomaliesCount={anomalies.filter((a) => a.status === 'OPEN').length}
          recommendationsCount={pendingRecsCount}
        />

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto p-5 sm:p-6 bg-slate-50">
          <div className="max-w-7xl mx-auto">
            {activeTab === 'overview' && (
              <Overview
                riskIndex={riskIndex}
                alerts={alerts}
                flows={flows}
                telemetrySeries={telemetrySeries}
                onSelectAlert={handleOpenAlert}
                onNavigateTab={setActiveTab}
              />
            )}

            {activeTab === 'simulator' && <NetworkSimulatorView />}

            {activeTab === 'flows' && <FlowTelemetryView flows={flows} />}

            {activeTab === 'threats' && (
              <ClassifiedAttacksView alerts={alerts} onSelectAlert={handleOpenAlert} />
            )}

            {activeTab === 'anomalies' && <AnomaliesView anomalies={anomalies} />}

            {activeTab === 'forecast' && (
              <TrafficForecastView forecastData={forecastData} />
            )}

            {activeTab === 'recommendations' && (
              <RecommendationsView
                recommendations={recommendations}
                onExecuteRecommendation={handleExecuteRecommendation}
              />
            )}
          </div>
        </main>
      </div>

      {/* 3. Decision Support Inspection Dialog (TreeSHAP Explainability) */}
      <ThreatDetailModal
        alert={selectedAlert}
        isOpen={isModalOpen}
        onClose={handleCloseModal}
        onUpdateAlertStatus={handleUpdateAlertStatus}
      />
    </div>
  );
}

export default App;
