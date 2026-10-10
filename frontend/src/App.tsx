import React, { useState } from 'react';
import { Navbar } from './components/layout/Navbar';
import { Sidebar, NavTab } from './components/layout/Sidebar';
import { Overview } from './pages/Overview';
import { FlowTelemetryView } from './pages/FlowTelemetryView';
import { ClassifiedAttacksView } from './pages/ClassifiedAttacksView';
import { AnomaliesView } from './pages/AnomaliesView';
import { TrafficForecastView } from './pages/TrafficForecastView';
import { RecommendationsView } from './pages/RecommendationsView';
import { ThreatDetailModal } from './pages/ThreatDetailModal';

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
  const [activeSegment, setActiveSegment] = useState<string>(
    'Interface: eth0 [192.168.1.0/24]'
  );

  // Core application state
  const [alerts, setAlerts] = useState<SecurityAlert[]>(MOCK_ALERTS);
  const [flows] = useState<FlowTelemetry[]>(MOCK_FLOWS);
  const [anomalies] = useState<AnomalyRecord[]>(MOCK_ANOMALIES);
  const [telemetrySeries] = useState<TelemetryDataPoint[]>(MOCK_TELEMETRY_SERIES);
  const [forecastData] = useState<TrafficForecast[]>(MOCK_TRAFFIC_FORECAST);
  const [recommendations, setRecommendations] = useState<RecommendationAction[]>(
    MOCK_RECOMMENDATIONS
  );
  const [riskIndex, setRiskIndex] = useState<RiskIndex>(MOCK_RISK_INDEX);

  // Decision Support Inspection Modal state
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

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
  };

  const pendingAlertsCount = alerts.filter(
    (a) => a.status === 'PENDING' || a.status === 'ACKNOWLEDGED'
  ).length;
  const pendingRecsCount = recommendations.filter((r) => r.status === 'PENDING').length;

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-slate-50 text-slate-900 font-sans antialiased">
      {/* 1. Global Navigation Bar */}
      <Navbar
        activeSegment={activeSegment}
        onSelectSegment={setActiveSegment}
        ingestionActive={true}
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
