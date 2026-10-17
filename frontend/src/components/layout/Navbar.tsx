import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faNetworkWired, faCircle, faChevronDown } from '@fortawesome/free-solid-svg-icons';
import { NetworkInterfaceInfo } from '../../services/api';

interface NavbarProps {
  activeSegment: string;
  onSelectSegment: (segment: string) => void;
  ingestionActive?: boolean;
  availableInterfaces?: NetworkInterfaceInfo[];
}

/**
 * Navbar: Clean, professional top navigation header.
 * Solid white container with 1px border and utilitarian system status indicators.
 */
export const Navbar: React.FC<NavbarProps> = ({
  activeSegment,
  onSelectSegment,
  ingestionActive = true,
  availableInterfaces = [],
}) => {
  return (
    <header className="h-14 bg-white border-b border-slate-200 px-5 flex items-center justify-between z-20 shrink-0">
      {/* Left: Brand & System Title */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded bg-slate-900 text-white flex items-center justify-center shrink-0">
          <FontAwesomeIcon icon={faNetworkWired} className="text-sm" />
        </div>
        <div className="flex flex-col">
          <h1 className="text-sm font-semibold text-slate-900 leading-none tracking-tight">
            NetMind AI
            <span className="text-xs font-normal text-slate-500 ml-2 hidden sm:inline">
              — Intelligent Network Monitoring & Decision Support System
            </span>
          </h1>
        </div>
      </div>

      {/* Right: Ingestion Health & Interface Selector */}
      <div className="flex items-center gap-4">
        {/* Telemetry Ingestion Status */}
        <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-50 border border-slate-200 text-xs text-slate-700">
          <FontAwesomeIcon
            icon={faCircle}
            className={`text-[8px] ${ingestionActive ? 'text-emerald-500 animate-pulse' : 'text-slate-400'}`}
          />
          <span className="font-medium">
            Live NIC Sniffer: <span className="text-slate-900 font-semibold">{activeSegment}</span>
          </span>
        </div>

        {/* Network Segment / Interface Selector */}
        <div className="relative">
          <select
            value={activeSegment}
            onChange={(e) => onSelectSegment(e.target.value)}
            className="text-xs bg-slate-50 border border-slate-200 hover:border-slate-300 text-slate-800 font-medium py-1 px-2.5 pr-7 rounded focus:outline-none focus:ring-1 focus:ring-blue-600 cursor-pointer appearance-none"
          >
            {availableInterfaces.length > 0 ? (
              availableInterfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  NIC: {iface.name} ({iface.ip}) {iface.is_up ? '● Up' : '○ Down'}
                </option>
              ))
            ) : (
              <>
                <option value="Wi-Fi">NIC: Wi-Fi</option>
                <option value="Ethernet">NIC: Ethernet</option>
                <option value="Loopback Pseudo-Interface 1">NIC: Loopback</option>
              </>
            )}
          </select>
          <FontAwesomeIcon
            icon={faChevronDown}
            className="text-[10px] text-slate-400 absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none"
          />
        </div>
      </div>
    </header>
  );
};
