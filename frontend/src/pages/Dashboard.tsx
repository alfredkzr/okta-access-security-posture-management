import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, Link } from 'react-router-dom';
import { AlertTriangle, CheckCircle, Users, ExternalLink, X, Play, Shield } from 'lucide-react';
import AppIcon from '../components/AppIcon';
import api from '../lib/api';
import type { DashboardSummary, PaginatedResponse, Vulnerability } from '../lib/api';
import { severityColor, severityDot, statusColor, riskScoreColor, timeAgo, cn, formatDuration } from '../lib/utils';
import ScanDetailModal from '../components/ScanDetailModal';

export default function Dashboard() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [scanEmail, setScanEmail] = useState('');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showAppsModal, setShowAppsModal] = useState(false);

  const { data: summary, isLoading, error } = useQuery<DashboardSummary>({
    queryKey: ['dashboard-summary'],
    queryFn: () => api.get('/dashboard/summary').then(r => r.data),
  });

  const { data: topVulns, isLoading: vulnsLoading } = useQuery<PaginatedResponse<Vulnerability>>({
    queryKey: ['top-vulnerabilities'],
    queryFn: () => api.get('/vulnerabilities', { params: { status: 'ACTIVE', sort: '-risk_score', page: 1, page_size: 5 } }).then(r => r.data),
  });

  const { data: coverageApps, isLoading: appsLoading } = useQuery<{ app_id: string; app_name: string; user_count: number }[]>({
    queryKey: ['coverage-apps'],
    queryFn: () => api.get('/dashboard/coverage/apps').then(r => r.data),
    enabled: showAppsModal,
  });

  const scanMutation = useMutation({
    mutationFn: (email: string) => api.post('/assessments/single', { email }),
    onSuccess: () => {
      setScanEmail('');
      queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
    },
  });

  const batchScanMutation = useMutation({
    mutationFn: () => api.post('/assessments/batch', {
      user_selection: 'all',
      include_posture_checks: true,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-text-muted text-sm">Loading dashboard...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-panel p-4 border-red-500/20">
        <p className="text-red-400 text-sm">Failed to load dashboard data. Please try again later.</p>
      </div>
    );
  }

  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
  const severityBarColors: Record<string, string> = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-yellow-500',
    LOW: 'bg-cyan-500',
  };

  const total = severities.reduce((sum, sev) => {
    return sum + (summary?.by_severity?.[sev] ?? summary?.by_severity?.[sev.toLowerCase()] ?? 0);
  }, 0);

  return (
    <div className="space-y-6">
      {/* Row 1: Hero Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Active Findings */}
        <button
          onClick={() => navigate('/vulnerabilities?status=ACTIVE')}
          className="glass-panel glass-panel-hover p-6 text-left transition-all group"
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium uppercase tracking-wider text-text-muted">Active Findings</span>
            <div className="w-9 h-9 rounded-lg bg-red-500/10 flex items-center justify-center">
              <AlertTriangle className="w-4.5 h-4.5 text-red-400" />
            </div>
          </div>
          <p className="text-4xl font-bold text-red-400 tracking-tight">
            {summary?.active_vulnerabilities ?? 0}
          </p>
          <div className="flex items-center gap-2 mt-2">
            {(summary?.new_today ?? 0) > 0 ? (
              <span className="text-xs font-medium text-red-400/80">
                +{summary?.new_today} new today
              </span>
            ) : (
              <span className="text-xs text-text-muted">no new findings today</span>
            )}
          </div>
        </button>

        {/* Remediated */}
        <div className="glass-panel p-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium uppercase tracking-wider text-text-muted">Remediated</span>
            <div className="w-9 h-9 rounded-lg bg-emerald-500/10 flex items-center justify-center">
              <CheckCircle className="w-4.5 h-4.5 text-emerald-400" />
            </div>
          </div>
          <p className="text-4xl font-bold text-emerald-400 tracking-tight">
            {summary?.closed_vulnerabilities ?? 0}
          </p>
          <p className="text-xs text-text-muted mt-2">resolved findings</p>
        </div>

        {/* Coverage */}
        <button
          onClick={() => setShowAppsModal(true)}
          className="glass-panel glass-panel-hover p-6 text-left transition-all group"
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium uppercase tracking-wider text-text-muted">Coverage</span>
            <div className="w-9 h-9 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Users className="w-4.5 h-4.5 text-blue-400" />
            </div>
          </div>
          <div className="flex items-baseline gap-4">
            <div>
              <span className="text-4xl font-bold text-text-primary tracking-tight">{summary?.users_scanned ?? 0}</span>
              <span className="text-xs text-text-muted ml-1.5">users</span>
            </div>
            <div className="text-slate-600 text-lg">|</div>
            <div>
              <span className="text-4xl font-bold text-text-primary tracking-tight">{summary?.apps_scanned ?? 0}</span>
              <span className="text-xs text-text-muted ml-1.5">apps</span>
            </div>
          </div>
          <p className="text-xs text-blue-400/60 mt-2 opacity-0 group-hover:opacity-100 transition-opacity">
            Click to view applications
          </p>
        </button>
      </div>

      {/* Row 2: Severity Distribution */}
      <div className="glass-panel p-6">
        <h2 className="text-sm font-semibold text-text-secondary mb-4 tracking-wide">Severity Distribution</h2>
        {total === 0 ? (
          <div className="text-sm text-text-muted py-2">No vulnerability data available.</div>
        ) : (
          <>
            <div className="w-full h-7 rounded-lg overflow-hidden flex bg-slate-800/50">
              {severities.map(sev => {
                const count = summary?.by_severity?.[sev] ?? summary?.by_severity?.[sev.toLowerCase()] ?? 0;
                if (count === 0) return null;
                const pct = (count / total) * 100;
                return (
                  <div
                    key={sev}
                    className={cn('h-full flex items-center justify-center text-xs font-semibold text-white/90 transition-all', severityBarColors[sev])}
                    style={{ width: `${pct}%` }}
                    title={`${sev}: ${count}`}
                  >
                    {pct >= 8 ? count : ''}
                  </div>
                );
              })}
            </div>
            <div className="flex items-center gap-5 mt-3">
              {severities.map(sev => {
                const count = summary?.by_severity?.[sev] ?? summary?.by_severity?.[sev.toLowerCase()] ?? 0;
                return (
                  <div key={sev} className="flex items-center gap-1.5 text-xs text-text-muted">
                    <div className={cn('w-2 h-2 rounded-full', severityDot(sev))} />
                    <span>{sev}</span>
                    <span className="text-text-secondary font-medium">{count}</span>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>

      {/* Row 3: Two columns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Top Vulnerabilities */}
        <div className="glass-panel overflow-hidden">
          <div className="px-6 py-4 border-b border-border-glass flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-text-muted" />
              <h2 className="text-sm font-semibold text-text-secondary">Top Vulnerabilities</h2>
            </div>
            <Link to="/vulnerabilities" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
              View all
            </Link>
          </div>
          <div className="p-3">
            {vulnsLoading ? (
              <p className="text-sm text-text-muted text-center py-8">Loading...</p>
            ) : !topVulns?.items?.length ? (
              <p className="text-sm text-text-muted text-center py-8">No active vulnerabilities found.</p>
            ) : (
              <div className="space-y-1">
                {topVulns.items.map(vuln => (
                  <Link
                    key={vuln.id}
                    to={`/vulnerabilities/${vuln.id}`}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-white/[0.03] transition-colors group"
                  >
                    <AppIcon appName={vuln.app_name} size="md" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-text-primary truncate group-hover:text-blue-400 transition-colors">
                        {vuln.title}
                      </p>
                      <p className="text-xs text-text-muted truncate">{vuln.app_name ?? 'No app'}</p>
                    </div>
                    <span className={cn('inline-block px-2 py-0.5 rounded-full text-[10px] font-semibold border shrink-0', severityColor(vuln.severity))}>
                      {vuln.severity}
                    </span>
                    <span className={cn('text-sm font-bold tabular-nums shrink-0', riskScoreColor(vuln.risk_score))}>
                      {vuln.risk_score}
                    </span>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-blue-400 shrink-0 transition-colors" />
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recent Scans */}
        <div className="glass-panel overflow-hidden">
          <div className="px-6 py-4 border-b border-border-glass flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Play className="w-4 h-4 text-text-muted" />
              <h2 className="text-sm font-semibold text-text-secondary">Recent Scans</h2>
            </div>
          </div>
          <div className="p-4">
            {/* Scan Actions */}
            <div className="space-y-2 mb-4">
              <div className="flex gap-2">
                <input
                  type="email"
                  value={scanEmail}
                  onChange={e => setScanEmail(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && scanEmail.trim()) {
                      scanMutation.mutate(scanEmail.trim());
                    }
                  }}
                  placeholder="user@example.com"
                  className="flex-1 rounded-lg px-3 py-2 text-sm bg-slate-800/50 border border-border-glass text-text-primary placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500/50 focus:border-blue-500/30 transition-colors"
                />
                <button
                  onClick={() => scanEmail.trim() && scanMutation.mutate(scanEmail.trim())}
                  disabled={!scanEmail.trim() || scanMutation.isPending}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap transition-colors"
                >
                  {scanMutation.isPending ? 'Starting...' : 'Scan User'}
                </button>
              </div>
              <button
                onClick={() => batchScanMutation.mutate()}
                disabled={batchScanMutation.isPending}
                className="w-full px-4 py-2 text-sm font-medium text-white bg-blue-600/80 rounded-lg hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                {batchScanMutation.isPending ? 'Starting...' : 'Scan All Users'}
              </button>
            </div>

            {scanMutation.isError && (
              <p className="text-red-400 text-xs mb-3">
                {(scanMutation.error as Error)?.message || 'Scan failed. Please try again.'}
              </p>
            )}
            {scanMutation.isSuccess && (
              <p className="text-emerald-400 text-xs mb-3">Scan started successfully.</p>
            )}
            {batchScanMutation.isError && (
              <p className="text-red-400 text-xs mb-3">
                {(batchScanMutation.error as Error)?.message || 'Batch scan failed.'}
              </p>
            )}
            {batchScanMutation.isSuccess && (
              <p className="text-emerald-400 text-xs mb-3">Batch scan queued. Check recent scans for progress.</p>
            )}

            {/* Scan List */}
            {summary?.recent_scans && summary.recent_scans.length > 0 ? (
              <div className="space-y-1.5">
                {summary.recent_scans.slice(0, 5).map(scan => (
                  <button
                    key={scan.id}
                    onClick={() => setSelectedScanId(scan.id)}
                    className="w-full text-left flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-white/[0.03] transition-colors cursor-pointer"
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-text-primary truncate">
                        {scan.job_name || 'Manual Scan'}
                      </p>
                      <p className="text-xs text-text-muted">{timeAgo(scan.started_at)}</p>
                    </div>
                    <span className={cn('inline-block px-2 py-0.5 rounded-full text-[10px] font-semibold shrink-0', statusColor(scan.status))}>
                      {scan.status}
                    </span>
                    <span className="text-xs text-text-muted tabular-nums shrink-0">
                      {formatDuration(scan.duration_seconds)}
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-sm text-text-muted text-center py-6">No scans yet. Run your first scan above.</p>
            )}
          </div>
        </div>
      </div>

      {/* Scan Detail Modal */}
      {selectedScanId && (
        <ScanDetailModal scanId={selectedScanId} onClose={() => setSelectedScanId(null)} />
      )}

      {/* Coverage Apps Modal */}
      {showAppsModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center glass-modal-overlay"
          onClick={() => setShowAppsModal(false)}
        >
          <div
            className="glass-modal w-full max-w-lg mx-4 max-h-[80vh] flex flex-col"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-border-glass">
              <h2 className="text-lg font-semibold text-text-primary">
                Scanned Applications ({coverageApps?.length ?? 0})
              </h2>
              <button
                onClick={() => setShowAppsModal(false)}
                className="text-text-muted hover:text-text-secondary transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="overflow-y-auto flex-1">
              {appsLoading ? (
                <div className="p-8 text-center text-text-muted text-sm">Loading...</div>
              ) : !coverageApps?.length ? (
                <div className="p-8 text-center text-text-muted text-sm">No apps found.</div>
              ) : (
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border-glass">
                      <th className="text-left px-6 py-3 text-xs font-medium text-text-muted uppercase tracking-wider">
                        Application
                      </th>
                      <th className="text-right px-6 py-3 text-xs font-medium text-text-muted uppercase tracking-wider">
                        Users
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-glass">
                    {coverageApps.map(app => (
                      <tr key={app.app_id} className="hover:bg-white/[0.02]">
                        <td className="px-6 py-3">
                          <div className="flex items-center gap-2.5">
                            <AppIcon appName={app.app_name} size="sm" />
                            <span className="text-sm text-text-primary">{app.app_name}</span>
                          </div>
                        </td>
                        <td className="px-6 py-3 text-sm text-text-muted text-right tabular-nums">{app.user_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
