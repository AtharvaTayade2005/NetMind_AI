import React from 'react';
import { LucideIcon, ArrowUpRight, ArrowDownRight } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  change?: string;
  changeType?: 'positive' | 'negative' | 'neutral';
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'cyan' | 'red' | 'amber' | 'emerald' | 'purple' | 'default';
  onClick?: () => void;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  change,
  changeType = 'neutral',
  subtitle,
  icon: Icon,
  variant = 'cyan',
  onClick,
}) => {
  const accentClasses = {
    cyan: 'border-l-soc-cyan text-soc-cyan',
    red: 'border-l-soc-red text-soc-red',
    amber: 'border-l-soc-amber text-soc-amber',
    emerald: 'border-l-soc-emerald text-soc-emerald',
    purple: 'border-l-soc-purple text-soc-purple',
    default: 'border-l-soc-borderHighlight text-soc-text',
  }[variant];

  const iconBgClasses = {
    cyan: 'bg-soc-cyan/10 text-soc-cyan border-soc-cyan/20',
    red: 'bg-soc-red/10 text-soc-red border-soc-red/20',
    amber: 'bg-soc-amber/10 text-soc-amber border-soc-amber/20',
    emerald: 'bg-soc-emerald/10 text-soc-emerald border-soc-emerald/20',
    purple: 'bg-soc-purple/10 text-soc-purple border-soc-purple/20',
    default: 'bg-soc-surface text-soc-muted border-soc-border',
  }[variant];

  return (
    <div
      onClick={onClick}
      className={`bg-soc-card border border-soc-border border-l-4 ${accentClasses} rounded-xl p-4 transition-all duration-200 hover:border-soc-borderHighlight hover:shadow-lg hover:shadow-black/20 ${
        onClick ? 'cursor-pointer hover:bg-soc-surface/80' : ''
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-[11px] font-mono uppercase tracking-wider text-soc-dim font-bold">
            {title}
          </p>
          <div className="text-2xl font-mono font-extrabold text-soc-text tabular-nums tracking-tight">
            {value}
          </div>
        </div>
        <div className={`p-2.5 rounded-lg border ${iconBgClasses}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {(subtitle || change) && (
        <div className="mt-3 pt-2.5 border-t border-soc-border/50 flex items-center justify-between text-xs font-mono">
          {change && (
            <div
              className={`flex items-center gap-1 font-bold ${
                changeType === 'negative'
                  ? 'text-soc-red'
                  : changeType === 'positive'
                  ? 'text-soc-emerald'
                  : 'text-soc-dim'
              }`}
            >
              {changeType === 'negative' && <ArrowUpRight className="w-3.5 h-3.5" />}
              {changeType === 'positive' && <ArrowDownRight className="w-3.5 h-3.5" />}
              <span>{change}</span>
            </div>
          )}
          {subtitle && <span className="text-soc-dim text-[11px] truncate">{subtitle}</span>}
        </div>
      )}
    </div>
  );
};
