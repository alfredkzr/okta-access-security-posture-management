import { clsx, type ClassValue } from 'clsx';

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function severityColor(s: string): string {
  switch (s.toUpperCase()) {
    case 'CRITICAL': return 'bg-red-500/15 text-red-400 border-red-500/20';
    case 'HIGH': return 'bg-orange-500/15 text-orange-400 border-orange-500/20';
    case 'MEDIUM': return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/20';
    case 'LOW': return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/20';
    default: return 'bg-slate-500/15 text-slate-400 border-slate-500/20';
  }
}

export function severityDot(s: string): string {
  switch (s.toUpperCase()) {
    case 'CRITICAL': return 'bg-red-500';
    case 'HIGH': return 'bg-orange-500';
    case 'MEDIUM': return 'bg-yellow-500';
    case 'LOW': return 'bg-cyan-500';
    default: return 'bg-slate-500';
  }
}

export function statusColor(s: string): string {
  switch (s.toUpperCase()) {
    case 'ACTIVE': case 'OPEN': case 'FAILED': return 'bg-red-500/15 text-red-400';
    case 'CLOSED': return 'bg-slate-500/15 text-slate-400';
    case 'RESOLVED': case 'COMPLETED': return 'bg-emerald-500/15 text-emerald-400';
    case 'ACKNOWLEDGED': return 'bg-blue-500/15 text-blue-400';
    case 'RUNNING': return 'bg-blue-500/15 text-blue-400';
    case 'PENDING': return 'bg-yellow-500/15 text-yellow-400';
    case 'COMPLETED_WITH_ERRORS': return 'bg-yellow-500/15 text-yellow-400';
    default: return 'bg-slate-500/15 text-slate-400';
  }
}

export function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export function riskScoreColor(score: number): string {
  if (score >= 76) return 'text-red-400';
  if (score >= 51) return 'text-orange-400';
  if (score >= 26) return 'text-yellow-400';
  return 'text-emerald-400';
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return '--';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function timeAgo(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const seconds = Math.floor((now - then) / 1000);

  if (seconds < 0) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;

  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} day${days > 1 ? 's' : ''} ago`;

  const months = Math.floor(days / 30);
  if (months < 12) return `${months} month${months > 1 ? 's' : ''} ago`;

  const years = Math.floor(months / 12);
  return `${years} year${years > 1 ? 's' : ''} ago`;
}
