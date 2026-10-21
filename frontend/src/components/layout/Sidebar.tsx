import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faNetworkWired,
  faServer,
  faShieldHalved,
  faTriangleExclamation,
  faChartLine,
  faBrain,
  faSliders,
} from '@fortawesome/free-solid-svg-icons';

export type NavTab =
  | 'overview'
  | 'simulator'
  | 'flows'
  | 'threats'
  | 'anomalies'
  | 'forecast'
  | 'recommendations';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  threatsCount?: number;
  anomaliesCount?: number;
  recommendationsCount?: number;
}

/**
 * Sidebar: Standard, disciplined navigation sidebar using Font Awesome icons.
 * Follows authentic full-stack monitoring system design with solid colors and clear states.
 */
export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  threatsCount = 0,
  anomaliesCount = 0,
  recommendationsCount = 0,
}) => {
  const navItems = [
    {
      id: 'overview' as NavTab,
      label: 'System Overview & Health',
      icon: faNetworkWired,
    },
    {
      id: 'simulator' as NavTab,
      label: 'Dynamic Network Simulator',
      icon: faSliders,
      badge: 'PHASE 1',
      badgeColor: 'bg-indigo-100 text-indigo-800 border-indigo-200',
    },
    {
      id: 'flows' as NavTab,
      label: 'Network Flow Telemetry',
      icon: faServer,
    },
    {
      id: 'threats' as NavTab,
      label: 'Classified Attack Detections',
      icon: faShieldHalved,
      badge: threatsCount > 0 ? threatsCount : undefined,
      badgeColor: 'bg-rose-100 text-rose-800 border-rose-200',
    },
    {
      id: 'anomalies' as NavTab,
      label: 'Unsupervised Anomalies',
      icon: faTriangleExclamation,
      badge: anomaliesCount > 0 ? anomaliesCount : undefined,
      badgeColor: 'bg-amber-100 text-amber-800 border-amber-200',
    },
    {
      id: 'forecast' as NavTab,
      label: 'Performance & Traffic Forecast',
      icon: faChartLine,
    },
    {
      id: 'recommendations' as NavTab,
      label: 'Decision Engine & Recommendations',
      icon: faBrain,
      badge: recommendationsCount > 0 ? recommendationsCount : undefined,
      badgeColor: 'bg-blue-100 text-blue-800 border-blue-200',
    },
  ];

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col shrink-0 select-none">
      {/* Section Header */}
      <div className="px-4 py-3 border-b border-slate-100">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Monitoring & Decision Modules
        </span>
      </div>

      {/* Navigation Links */}
      <nav className="p-2 space-y-1 flex-1 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded text-xs font-medium transition-colors text-left ${
                isActive
                  ? 'bg-slate-900 text-white shadow-xs font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <FontAwesomeIcon
                  icon={item.icon}
                  className={`w-4 text-sm ${isActive ? 'text-white' : 'text-slate-400'}`}
                />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span
                  className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                    isActive ? 'bg-white/20 text-white border-white/30' : item.badgeColor
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Sidebar Footer */}
      <div className="p-3.5 border-t border-slate-200 bg-slate-50 text-[11px] text-slate-500 flex flex-col gap-1">
        <div className="flex items-center justify-between">
          <span className="font-medium text-slate-700">NetMind Core Engine</span>
          <span className="text-emerald-700 font-semibold bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200 text-[10px]">
            ONLINE
          </span>
        </div>
        <span className="text-[10px] text-slate-400">Version 1.0.0 (Production Build)</span>
      </div>
    </aside>
  );
};
