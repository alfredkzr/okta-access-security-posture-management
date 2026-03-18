import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, Link } from 'react-router-dom';
import { AlertTriangle, CheckCircle, Users, ExternalLink } from 'lucide-react';
import api from '../lib/api';
import type { DashboardSummary, PaginatedResponse, Vulnerability } from '../lib/api';
import { severityColor, statusColor, riskScoreColor, timeAgo, cn } from '../lib/utils';
import ScanDetailModal from '../components/ScanDetailModal';

export default function Dashboard() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [scanEmail, setScanEmail] = useState('');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  const { data: summary, isLoading, error } = useQuery<DashboardSummary>({
    queryKey: ['dashboard-summary'],
    queryFn: () => api.get('/dashboard/summary').then(r => r.data),
  });

  const { data: topVulns, isLoading: vulnsLoading } = useQuery<PaginatedResponse<Vulnerability>>({
    queryKey: ['top-vulnerabilities'],
    queryFn: () => api.get('/vulnerabilities', { params: { status: 'ACTIVE', page: 1, page_size: 5 } }).then(r => r.data),
  });

  const scanMutation = useMutation({
    mutationFn: (email: string) => api.post('/assessments/single', { email }),
    onSuccess: () => {
      setScanEmail('');
      queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500 dark:text-gray-400 text-sm">Loading dashboard...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
        <p className="text-red-700 dark:text-red-400 text-sm">Failed to load dashboard data. Please try again later.</p>
      </div>
    );
  }

  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
  const severityBarColors: Record<string, string> = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-orange-500',
    MEDIUM: 'bg-yellow-400',
    LOW: 'bg-green-500',
  };

  const total = severities.reduce((sum, sev) => {
    return sum + (summary?.by_severity?.[sev] ?? summary?.by_severity?.[sev.toLowerCase()] ?? 0);
  }, 0);

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Dashboard</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Security posture overview</p>
      </div>

      {/* Row 1: Hero Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        {/* Active Findings */}
        <button
          onClick={() => navigate('/vulnerabilities?status=ACTIVE')}
          className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6 text-left hover:border-red-300 dark:hover:border-red-700 transition-colors"
        >
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Active Findings</p>
            <AlertTriangle className="w-5 h-5 text-red-400" />
          </div>
          <p className="text-4xl font-bold text-red-600 dark:text-red-400 mt-2">{summary?.active_vulnerabilities ?? 0}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{summary?.new_today ?? 0} new today</p>
        </button>

        {/* Remediated */}
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Remediated</p>
            <CheckCircle className="w-5 h-5 text-green-400" />
          </div>
          <p className="text-4xl font-bold text-green-600 dark:text-green-400 mt-2">{summary?.remediated_vulnerabilities ?? 0}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">resolved findings</p>
        </div>

        {/* Users & Apps Scanned */}
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Coverage</p>
            <Users className="w-5 h-5 text-blue-400" />
          </div>
          <div className="flex items-baseline gap-4 mt-2">
            <div>
              <span className="text-4xl font-bold text-gray-900 dark:text-gray-100">{summary?.users_scanned ?? 0}</span>
              <span className="text-sm text-gray-500 dark:text-gray-400 ml-1">users</span>
            </div>
            <div className="text-gray-300 dark:text-gray-600">|</div>
            <div>
              <span className="text-4xl font-bold text-gray-900 dark:text-gray-100">{summary?.apps_scanned ?? 0}</span>
              <span className="text-sm text-gray-500 dark:text-gray-400 ml-1">apps</span>
            </div>
          </div>
        </div>
      </div>

      {/* Row 2: Severity Distribution Bar */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6 mb-6">
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">Severity Distribution</h2>
        {total === 0 ? (
          <div className="text-sm text-gray-400 dark:text-gray-500">No vulnerability data available.</div>
        ) : (
          <>
            <div className="w-full h-8 rounded-lg overflow-hidden flex bg-gray-100 dark:bg-gray-800">
              {severities.map(sev => {
                const count = summary?.by_severity?.[sev] ?? summary?.by_severity?.[sev.toLowerCase()] ?? 0;
                if (count === 0) return null;
                const pct = (count / total) * 100;
                return (
                  <div
                    key={sev}
                    className={cn('h-full flex items-center justify-center text-xs font-medium text-white', severityBarColors[sev])}
                    style={{ width: `${pct}%` }}
                    title={`${sev}: ${count}`}
                  >
                    {pct >= 8 ? count : ''}
                  </div>
                );
              })}
            </div>
            <div className="flex items-center gap-4 mt-3">
              {severities.map(sev => {
                const count = summary?.by_severity?.[sev] ?? summary?.by_severity?.[sev.toLowerCase()] ?? 0;
                return (
                  <div key={sev} className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-400">
                    <div className={cn('w-2.5 h-2.5 rounded-sm', severityBarColors[sev])} />
                    {sev} ({count})
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>

      {/* Row 3: Two columns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Vulnerabilities */}
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Top Vulnerabilities</h2>
            <Link to="/vulnerabilities" className="text-xs text-blue-600 dark:text-blue-400 hover:underline">View all</Link>
          </div>
          <div className="p-4">
            {vulnsLoading ? (
              <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-6">Loading...</p>
            ) : !topVulns?.items?.length ? (
              <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-6">No active vulnerabilities found.</p>
            ) : (
              <div className="space-y-2">
                {topVulns.items.map(vuln => (
                  <Link
                    key={vuln.id}
                    to={`/vulnerabilities/${vuln.id}`}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors group"
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate group-hover:text-blue-700 dark:group-hover:text-blue-400">{vuln.title}</p>
                      <p className="text-xs text-gray-500 dark:text-gray-400 truncate">{vuln.app_name ?? 'No app'}</p>
                    </div>
                    <span className={cn('inline-block px-2 py-0.5 rounded-full text-xs font-medium border shrink-0', severityColor(vuln.severity))}>
                      {vuln.severity}
                    </span>
                    <span className={cn('text-sm font-bold shrink-0', riskScoreColor(vuln.risk_score))}>{vuln.risk_score}</span>
                    <ExternalLink className="w-3.5 h-3.5 text-gray-300 dark:text-gray-600 group-hover:text-blue-500 dark:group-hover:text-blue-400 shrink-0" />
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
            <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Recent Scans</h2>
          </div>
          <div className="p-4">
            {/* Inline Scan User */}
            <div className="flex gap-2 mb-4">
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
                className="flex-1 border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <button
                onClick={() => scanEmail.trim() && scanMutation.mutate(scanEmail.trim())}
                disabled={!scanEmail.trim() || scanMutation.isPending}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
              >
                {scanMutation.isPending ? 'Starting...' : 'Scan User'}
              </button>
            </div>
            {scanMutation.isError && (
              <p className="text-red-600 dark:text-red-400 text-xs mb-3">
                {(scanMutation.error as Error)?.message || 'Scan failed. Please try again.'}
              </p>
            )}
            {scanMutation.isSuccess && (
              <p className="text-green-600 dark:text-green-400 text-xs mb-3">Scan started successfully.</p>
            )}

            {/* Scan List */}
            {summary?.recent_scans && summary.recent_scans.length > 0 ? (
              <div className="space-y-2">
                {summary.recent_scans.slice(0, 5).map(scan => (
                  <button key={scan.id} onClick={() => setSelectedScanId(scan.id)} className="w-full text-left flex items-center gap-3 px-3 py-2.5 rounded-lg border border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">{scan.job_name || 'Manual Scan'}</p>
                      <p className="text-xs text-gray-400 dark:text-gray-500">{timeAgo(scan.started_at)}</p>
                    </div>
                    <span className={cn('inline-block px-2 py-0.5 rounded-full text-xs font-medium shrink-0', statusColor(scan.status))}>
                      {scan.status}
                    </span>
                    <span className="text-xs text-gray-500 dark:text-gray-400 shrink-0">
                      {scan.duration_seconds != null ? `${Math.round(scan.duration_seconds)}s` : '--'}
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-4">No scans yet. Run your first scan above.</p>
            )}
          </div>
        </div>
      </div>

      {/* Scan Detail Modal */}
      {selectedScanId && (
        <ScanDetailModal scanId={selectedScanId} onClose={() => setSelectedScanId(null)} />
      )}
    </div>
  );
}
