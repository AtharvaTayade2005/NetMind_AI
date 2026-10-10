import React from 'react';
import { Severity, ActionStatus, Protocol } from '../../types';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'emerald' | 'amber' | 'rose' | 'blue' | 'slate';
  severity?: Severity;
  actionStatus?: ActionStatus;
  protocol?: Protocol;
  size?: 'sm' | 'md';
  className?: string;
}

/**
 * Standard utilitarian indicator badge.
 * Clean, solid, human-engineered colors with clear borders and high contrast.
 */
export const Badge: React.FC<BadgeProps> = ({
  children,
  variant,
  severity,
  actionStatus,
  protocol,
  size = 'sm',
  className = '',
}) => {
  let resolvedVariant = variant || 'slate';

  if (severity) {
    if (severity === 'CRITICAL') resolvedVariant = 'rose';
    else if (severity === 'HIGH') resolvedVariant = 'amber';
    else if (severity === 'MEDIUM') resolvedVariant = 'amber';
    else if (severity === 'LOW') resolvedVariant = 'emerald';
  } else if (actionStatus) {
    if (actionStatus === 'PENDING') resolvedVariant = 'amber';
    else if (actionStatus === 'ACKNOWLEDGED') resolvedVariant = 'blue';
    else if (actionStatus === 'RESOLVED') resolvedVariant = 'emerald';
  } else if (protocol) {
    if (protocol === 'TCP') resolvedVariant = 'blue';
    else if (protocol === 'UDP') resolvedVariant = 'slate';
    else if (protocol === 'ICMP') resolvedVariant = 'slate';
  }

  const styles = {
    emerald: 'bg-emerald-100 text-emerald-800 border-emerald-300',
    amber: 'bg-amber-100 text-amber-800 border-amber-300',
    rose: 'bg-rose-100 text-rose-800 border-rose-300',
    blue: 'bg-blue-100 text-blue-800 border-blue-300',
    slate: 'bg-slate-100 text-slate-800 border-slate-300',
  }[resolvedVariant];

  const sizeClasses = size === 'md' ? 'px-2 py-0.5 text-xs' : 'px-1.5 py-0.2 text-[11px]';

  return (
    <span
      className={`inline-flex items-center gap-1 font-medium border rounded uppercase tracking-wider select-none ${sizeClasses} ${styles} ${className}`}
    >
      {children}
    </span>
  );
};
