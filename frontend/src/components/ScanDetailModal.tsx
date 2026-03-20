import { useQuery } from '@tanstack/react-query';
import { X, Clock, CheckCircle, XCircle, AlertTriangle, Loader } from 'lucide-react';
import api from '../lib/api';
import type { Scan } from '../lib/api';
import { formatDate, formatDuration, statusColor, cn } from '../lib/utils';

interface Props {
  scanId: string;
  onClose: () => void;
}

function statusIcon(status: string) {
  switch (status) {
    case 'completed': return <CheckCircle className="w-5 h-5 text-green-500" />;
    case 'completed_with_errors': return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
    case 'failed': return <XCircle className="w-5 h-5 text-red-500" />;
    case 'running': return <Loader className="w-5 h-5 text-blue-500 animate-spin" />;
    case 'pending': return <Clock className="w-5 h-5 text-gray-400 dark:text-gray-500" />;
    default: return <Clock className="w-5 h-5 text-gray-400 dark:text-gray-500" />;
  }
}

export default function ScanDetailModal({ scanId, onClose }: Props) {
  const { data: scan, isLoading, error } = useQuery<Scan>({
    queryKey: ['scan-detail', scanId],
    queryFn: () => api.get(`/assessments/${scanId}`).then(r => r.data),
    refetchInterval: (query) => {
      const s = query.state.data;
      return s && (s.status === 'running' || s.status === 'pending') ? 3000 : false;
    },
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-6" onClick={onClose}>
      <div
        className="bg-white dark:bg-gray-900 rounded-xl shadow-xl border border-gray-200 dark:border-gray-800 w-full max-w-2xl max-h-[85vh] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Scan Details</h2>
            {scan && (
              <span className={cn('inline-flex px-2 py-0.5 rounded-full text-xs font-medium', statusColor(scan.status))}>
                {scan.status}
              </span>
            )}
          </div>
          <button onClick={onClose} className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          {isLoading && (
            <div className="flex items-center justify-center py-12">
              <Loader className="w-6 h-6 text-blue-500 animate-spin" />
            </div>
          )}

          {error && (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-sm text-red-700 dark:text-red-400">
              Failed to load scan details.
            </div>
          )}

          {scan && (
            <>
              {/* Metadata grid */}
              <div className="grid grid-cols-2 gap-4">
                <MetaItem label="Scan Name" value={scan.job_name || 'Manual Scan'} icon={statusIcon(scan.status)} />
                <MetaItem label="Scan ID" value={scan.id.substring(0, 8) + '...'} mono />
                <MetaItem label="Started" value={formatDate(scan.started_at)} />
                <MetaItem label="Completed" value={scan.completed_at ? formatDate(scan.completed_at) : scan.status === 'running' ? 'In progress...' : '--'} />
                <MetaItem label="Duration" value={formatDuration(scan.duration_seconds)} />
                <MetaItem label="Posture Findings" value={String(scan.posture_findings_count)} />
              </div>

              {/* Progress bar */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Progress</span>
                  <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{scan.progress_pct?.toFixed(1) ?? 0}%</span>
                </div>
                <div className="w-full h-2.5 bg-gray-200 dark:bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className={cn(
                      'h-full rounded-full transition-all duration-500',
                      scan.status === 'failed' ? 'bg-red-500' :
                      scan.status === 'completed_with_errors' ? 'bg-yellow-500' :
                      scan.status === 'completed' ? 'bg-green-500' : 'bg-blue-500'
                    )}
                    style={{ width: `${Math.min(scan.progress_pct ?? 0, 100)}%` }}
                  />
                </div>
              </div>

              {/* User counts */}
              <div className="grid grid-cols-3 gap-3">
                <CountCard label="Total Users" count={scan.total_users} color="text-gray-900 dark:text-gray-100" />
                <CountCard label="Successful" count={scan.successful_users} color="text-green-600 dark:text-green-400" />
                <CountCard label="Failed" count={scan.failed_users} color={scan.failed_users > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-400 dark:text-gray-500'} />
              </div>

              {/* Error message */}
              {scan.error_message && (
                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                  <div className="flex items-start gap-2">
                    <XCircle className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-red-800 dark:text-red-300 mb-1">Scan Error</p>
                      <pre className="text-xs text-red-700 dark:text-red-400 whitespace-pre-wrap font-mono leading-relaxed">{scan.error_message}</pre>
                    </div>
                  </div>
                </div>
              )}

              {/* Failed user details */}
              {scan.failed_user_details && scan.failed_user_details.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-500" />
                    Failed Users ({scan.failed_user_details.length})
                  </h3>
                  <div className="border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden max-h-64 overflow-y-auto">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-800">
                      <thead className="bg-gray-50 dark:bg-gray-800/50 sticky top-0">
                        <tr>
                          <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">User</th>
                          <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Error</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                        {scan.failed_user_details.map((detail, idx) => (
                          <tr key={idx} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                            <td className="px-4 py-2 text-sm font-mono text-gray-900 dark:text-gray-100 whitespace-nowrap">
                              {detail.email}
                            </td>
                            <td className="px-4 py-2 text-xs text-red-600 dark:text-red-400 font-mono whitespace-pre-wrap break-all">
                              {detail.error}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Success state with no errors */}
              {scan.status === 'completed' && scan.failed_users === 0 && !scan.error_message && (
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4 flex items-center gap-3">
                  <CheckCircle className="w-5 h-5 text-green-500 shrink-0" />
                  <p className="text-sm text-green-800 dark:text-green-300">
                    Scan completed successfully. All {scan.successful_users} users were assessed without errors.
                  </p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function MetaItem({ label, value, icon, mono }: { label: string; value: string; icon?: React.ReactNode; mono?: boolean }) {
  return (
    <div className="bg-gray-50 dark:bg-gray-800 rounded-lg px-4 py-3">
      <p className="text-xs font-medium text-gray-500 dark:text-gray-300 mb-0.5">{label}</p>
      <div className="flex items-center gap-2">
        {icon}
        <p className={cn('text-sm font-medium text-gray-900 dark:text-gray-100', mono && 'font-mono')}>{value}</p>
      </div>
    </div>
  );
}

function CountCard({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="bg-gray-50 dark:bg-gray-800 rounded-lg px-4 py-3 text-center">
      <p className={cn('text-2xl font-bold', color)}>{count}</p>
      <p className="text-xs font-medium text-gray-500 dark:text-gray-300 mt-0.5">{label}</p>
    </div>
  );
}
