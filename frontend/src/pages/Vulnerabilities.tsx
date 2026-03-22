import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { Shield, AlertTriangle, Eye, XCircle, ArrowUp, ArrowDown } from 'lucide-react';
import api from '../lib/api';
import type { PaginatedResponse, Vulnerability, VulnerabilityStats } from '../lib/api';
import { severityColor, statusColor, riskScoreColor, formatDate, cn } from '../lib/utils';
import AppIcon from '../components/AppIcon';

export default function Vulnerabilities() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || '');
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [sort, setSort] = useState('-risk_score');

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['vulnerability-stats'],
    queryFn: async () => {
      const res = await api.get<VulnerabilityStats>('/vulnerabilities/stats');
      return res.data;
    },
  });

  const { data, isLoading, isError } = useQuery({
    queryKey: ['vulnerabilities', page, statusFilter, severityFilter, categoryFilter, sort],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, page_size: 20 };
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      if (categoryFilter) params.category = categoryFilter;
      if (sort) params.sort = sort;
      const res = await api.get<PaginatedResponse<Vulnerability>>('/vulnerabilities', { params });
      return res.data;
    },
  });

  const resetFilters = () => {
    setStatusFilter('');
    setSeverityFilter('');
    setCategoryFilter('');
    setPage(1);
  };

  const statCards = [
    { label: 'Total', value: stats?.total ?? 0, icon: Shield, color: 'text-slate-300', iconColor: 'text-slate-400' },
    { label: 'Active', value: stats?.active ?? 0, icon: AlertTriangle, color: 'text-red-400', iconColor: 'text-red-400' },
    { label: 'Closed', value: stats?.closed ?? 0, icon: XCircle, color: 'text-emerald-400', iconColor: 'text-emerald-400' },
    { label: 'Acknowledged', value: stats?.acknowledged ?? 0, icon: Eye, color: 'text-blue-400', iconColor: 'text-blue-400' },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Vulnerabilities</h1>
        <p className="text-sm text-text-secondary mt-1">Security vulnerabilities detected across your Okta environment</p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((card) => (
          <div key={card.label} className="glass-panel p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-text-muted">{card.label}</p>
                <p className={cn('text-2xl font-bold mt-1', card.color)}>
                  {statsLoading ? '...' : card.value}
                </p>
              </div>
              <card.icon className={cn('w-8 h-8 opacity-50', card.iconColor)} />
            </div>
          </div>
        ))}
      </div>

      {/* Filter Bar */}
      <div className="glass-panel p-4 flex flex-wrap items-center gap-3">
        <span className="text-sm font-medium text-text-secondary">Filters:</span>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
          className="rounded-lg border border-border-glass bg-white/[0.04] px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500/40 transition-colors"
        >
          <option value="">All Statuses</option>
          <option value="ACTIVE">Active</option>
          <option value="CLOSED">Closed</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
        </select>
        <select
          value={severityFilter}
          onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
          className="rounded-lg border border-border-glass bg-white/[0.04] px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500/40 transition-colors"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select
          value={categoryFilter}
          onChange={(e) => { setCategoryFilter(e.target.value); setPage(1); }}
          className="rounded-lg border border-border-glass bg-white/[0.04] px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500/40 transition-colors"
        >
          <option value="">All Categories</option>
          <option value="auth_policy_violation">Auth Policy Violation</option>
          <option value="inactive_app_users">Inactive App Users</option>
        </select>
        {(statusFilter || severityFilter || categoryFilter) && (
          <button
            onClick={resetFilters}
            className="text-sm text-blue-400 hover:text-blue-300 font-medium transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="glass-panel overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-text-muted">Loading vulnerabilities...</div>
        ) : isError ? (
          <div className="p-12 text-center text-red-400">Failed to load vulnerabilities. Please try again.</div>
        ) : !data?.items.length ? (
          <div className="p-12 text-center text-text-muted">No vulnerabilities found matching your filters.</div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border-glass bg-white/[0.02]">
                <th className="text-left px-4 py-3 text-xs font-medium text-text-muted uppercase tracking-wider">Title</th>
                <SortHeader label="Severity" field="severity" sort={sort} onSort={(s) => { setSort(s); setPage(1); }} />
                <th className="text-left px-4 py-3 text-xs font-medium text-text-muted uppercase tracking-wider">Status</th>
                <SortHeader label="Risk Score" field="risk_score" sort={sort} onSort={(s) => { setSort(s); setPage(1); }} />
                <th className="text-left px-4 py-3 text-xs font-medium text-text-muted uppercase tracking-wider">Affected Users</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-text-muted uppercase tracking-wider">App</th>
                <SortHeader label="Last Detected" field="last_detected" sort={sort} onSort={(s) => { setSort(s); setPage(1); }} />
                <th className="px-4 py-3 text-xs font-medium text-text-muted uppercase tracking-wider"></th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((vuln) => (
                <tr
                  key={vuln.id}
                  onClick={() => navigate(`/vulnerabilities/${vuln.id}`)}
                  className="border-b border-border-glass hover:bg-white/[0.02] cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 text-sm font-medium text-text-primary max-w-xs truncate">{vuln.title}</td>
                  <td className="px-4 py-3">
                    <span className={cn('inline-block px-2 py-0.5 rounded-full text-xs font-medium border', severityColor(vuln.severity))}>
                      {vuln.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn('inline-block px-2 py-0.5 rounded-full text-xs font-medium', statusColor(vuln.status))}>
                      {vuln.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn('text-sm font-bold', riskScoreColor(vuln.risk_score))}>{vuln.risk_score}</span>
                  </td>
                  <td className="px-4 py-3 text-sm text-text-secondary">{vuln.active_impact_count}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <AppIcon appName={vuln.app_name} size="sm" />
                      <span className="text-sm text-text-secondary truncate max-w-[130px]">{vuln.app_name ?? '---'}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-text-muted">{formatDate(vuln.last_detected)}</td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/vulnerabilities/${vuln.id}`}
                      className="text-sm text-blue-400 hover:text-blue-300 hover:underline font-medium transition-colors"
                      onClick={e => e.stopPropagation()}
                    >
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="flex items-center justify-between border-t border-border-glass px-4 py-3 bg-white/[0.02]">
            <p className="text-sm text-text-muted">
              Page {data.page} of {data.pages} ({data.total} total)
            </p>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-3 py-1.5 text-sm font-medium rounded-lg border border-border-glass bg-white/[0.04] text-text-secondary hover:bg-white/[0.08] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Previous
              </button>
              <button
                disabled={page >= data.pages}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1.5 text-sm font-medium rounded-lg border border-border-glass bg-white/[0.04] text-text-secondary hover:bg-white/[0.08] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function SortHeader({ label, field, sort, onSort }: { label: string; field: string; sort: string; onSort: (s: string) => void }) {
  const isActive = sort === field || sort === `-${field}`;
  const isDesc = sort === `-${field}`;

  const handleClick = () => {
    if (!isActive) {
      onSort(`-${field}`);
    } else if (isDesc) {
      onSort(field);
    } else {
      onSort(`-${field}`);
    }
  };

  return (
    <th
      className="text-left px-4 py-3 text-xs font-medium text-text-muted uppercase tracking-wider cursor-pointer select-none hover:text-text-secondary transition-colors"
      onClick={handleClick}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {isActive ? (
          isDesc ? <ArrowDown className="w-3 h-3" /> : <ArrowUp className="w-3 h-3" />
        ) : null}
      </span>
    </th>
  );
}
