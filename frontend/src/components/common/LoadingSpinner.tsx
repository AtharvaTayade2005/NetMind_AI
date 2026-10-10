import React from 'react';
import { Activity } from 'lucide-react';

export const LoadingSpinner: React.FC<{ label?: string; message?: string }> = ({
  label,
  message,
}) => {
  const text = message || label || 'Acquiring telemetry...';
  return (
    <div className="flex flex-col items-center justify-center p-8 space-y-3">
      <div className="relative w-12 h-12 flex items-center justify-center">
        <div className="absolute inset-0 border-2 border-soc-border rounded-full" />
        <div className="absolute inset-0 border-2 border-soc-cyan rounded-full border-t-transparent animate-spin" />
        <Activity className="w-5 h-5 text-soc-cyan animate-pulse" />
      </div>
      <p className="text-xs font-mono text-soc-muted tracking-widest uppercase">{text}</p>
    </div>
  );
};
