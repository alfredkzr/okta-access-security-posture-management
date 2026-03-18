import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { FileText, Download, Eye, X, FileSpreadsheet, FileJson, FileType, Sparkles, Users, Clock, CheckCircle, AlertTriangle } from 'lucide-react';
import api from '../lib/api';
import type { PaginatedResponse, Scan } from '../lib/api';
import { formatDate } from '../lib/utils';

interface Report {
  id: string;
  scan_id: string;
  report_type: string;
  file_path: string | null;
  content: string | null;
  generated_at: string;
  created_at: string;
}

const REPORT_TYPES = [
  {
    value: 'csv_full',
    label: 'CSV Full Export',
    description: 'Complete assessment results for all users and apps including policy decisions, MFA status, and phishing resistance.',
    icon: FileSpreadsheet,
    color: 'bg-blue-100 text-blue-800',
  },
  {
    value: 'csv_violations',
    label: 'CSV Violations Only',
    description: 'Filtered to only policy violations (ALLOW decisions) — the entries that need remediation.',
    icon: AlertTriangle,
    color: 'bg-orange-100 text-orange-800',
  },
  {
    value: 'json',
    label: 'JSON Export',
    description: 'Structured data export with violations, posture findings, and vulnerability summaries. Ideal for SIEM integration.',
    icon: FileJson,
    color: 'bg-green-100 text-green-800',
  },
  {
    value: 'pdf',
    label: 'PDF Report',
    description: 'Formatted executive report with severity breakdown, policy violation tables, and posture findings. Ready for stakeholders.',
    icon: FileType,
    color: 'bg-red-100 text-red-800',
  },
  {
    value: 'ai_summary',
    label: 'AI Analysis',
    description: 'AI-powered executive summary with prioritized remediation steps, risk analysis, and actionable Okta Admin Console instructions.',
    icon: Sparkles,
    color: 'bg-indigo-100 text-indigo-800',
  },
];

function getReportType(value: string) {
  return REPORT_TYPES.find(t => t.value === value);
}

function scanStatusIcon(status: string) {
  if (status === 'completed') return <CheckCircle className="w-4 h-4 text-green-500" />;
  if (status === 'completed_with_errors') return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
  return <Clock className="w-4 h-4 text-gray-400" />;
}

export default function Reports() {
  const queryClient = useQueryClient();
  const [scanId, setScanId] = useState('');
  const [reportType, setReportType] = useState('csv_full');
  const [viewContent, setViewContent] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const { data: reports, isLoading, error } = useQuery<Report[]>({
    queryKey: ['reports'],
    queryFn: () => api.get('/reports').then(r => r.data),
    refetchInterval: 5000,
  });

  const { data: scansData } = useQuery<PaginatedResponse<Scan>>({
    queryKey: ['assessments-recent'],
    queryFn: () => api.get('/assessments', { params: { page: 1, page_size: 50 } }).then(r => r.data),
  });

  const generateMutation = useMutation({
    mutationFn: (payload: { scan_id: string; report_type: string }) => api.post('/reports', payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['reports'] }),
  });

  function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    if (!scanId) return;
    generateMutation.mutate({ scan_id: scanId, report_type: reportType });
  }

  async function handleDownload(report: Report) {
    setDownloadError(null);
    try {
      const res = await api.get(`/reports/${report.id}/download`);
      if (res.data?.content) {
        setViewContent(res.data.content);
        return;
      }
    } catch {
      // Not a text response — try as blob
    }

    try {
      const res = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' });
      const ext = report.report_type.includes('csv') ? 'csv' : report.report_type === 'pdf' ? 'pdf' : 'json';
      const filename = `report-${report.report_type}-${report.scan_id.substring(0, 8)}.${ext}`;
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setDownloadError('Report is still being generated. Please try again in a moment.');
      setTimeout(() => setDownloadError(null), 3000);
    }
  }

  const eligibleScans = scansData?.items?.filter(s => s.status === 'completed' || s.status === 'completed_with_errors') ?? [];
  const selectedScan = eligibleScans.find(s => s.id === scanId);
  const selectedType = getReportType(reportType);

  if (isLoading) {
    return <div className="flex items-center justify-center h-64"><div className="text-gray-500 dark:text-gray-400">Loading reports...</div></div>;
  }

  if (error) {
    return <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400">Failed to load reports.</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Reports</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Generate and download assessment reports from completed scans</p>
      </div>

      {/* Generate Report */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Generate Report</h2>
        <form onSubmit={handleGenerate} className="space-y-4">
          {/* Scan selector */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Select Scan</label>
            <select
              value={scanId}
              onChange={e => setScanId(e.target.value)}
              required
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
            >
              <option value="">Select a completed scan...</option>
              {eligibleScans.map(scan => (
                <option key={scan.id} value={scan.id}>
                  {scan.job_name || 'Scan'} — {formatDate(scan.started_at)} — {scan.total_users} users, {scan.successful_users} ok
                  {scan.failed_users > 0 ? `, ${scan.failed_users} failed` : ''}
                </option>
              ))}
            </select>
          </div>

          {/* Selected scan details */}
          {selectedScan && (
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div>
                <p className="text-xs font-medium text-gray-500 dark:text-gray-400">Scan Name</p>
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mt-0.5 flex items-center gap-1.5">
                  {scanStatusIcon(selectedScan.status)}
                  {selectedScan.job_name || 'Manual Scan'}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-500 dark:text-gray-400">Users Scanned</p>
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mt-0.5 flex items-center gap-1.5">
                  <Users className="w-3.5 h-3.5 text-gray-400" />
                  {selectedScan.successful_users} / {selectedScan.total_users}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-500 dark:text-gray-400">Duration</p>
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mt-0.5">
                  {selectedScan.duration_seconds
                    ? `${Math.floor(selectedScan.duration_seconds / 60)}m ${Math.round(selectedScan.duration_seconds % 60)}s`
                    : '--'}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-500 dark:text-gray-400">Completed</p>
                <p className="text-sm font-medium text-gray-900 dark:text-gray-100 mt-0.5">{formatDate(selectedScan.completed_at)}</p>
              </div>
            </div>
          )}

          {/* Report type cards */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Report Type</label>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {REPORT_TYPES.map(t => {
                const Icon = t.icon;
                const selected = reportType === t.value;
                return (
                  <button
                    type="button"
                    key={t.value}
                    onClick={() => setReportType(t.value)}
                    className={`text-left p-3 rounded-lg border-2 transition-all ${
                      selected
                        ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20 dark:border-blue-400'
                        : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 hover:border-gray-300 dark:hover:border-gray-600'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`inline-flex p-1 rounded ${t.color}`}>
                        <Icon className="w-3.5 h-3.5" />
                      </span>
                      <span className={`text-sm font-medium ${selected ? 'text-blue-700 dark:text-blue-400' : 'text-gray-900 dark:text-gray-100'}`}>{t.label}</span>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">{t.description}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Generate button */}
          <div className="flex items-center gap-3 pt-1">
            <button
              type="submit"
              disabled={generateMutation.isPending || !scanId}
              className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <FileText className="w-4 h-4" />
              {generateMutation.isPending ? 'Generating...' : `Generate ${selectedType?.label || 'Report'}`}
            </button>
            {generateMutation.isError && (
              <p className="text-sm text-red-600 dark:text-red-400">Failed to generate report.</p>
            )}
            {generateMutation.isSuccess && (
              <p className="text-sm text-green-600 dark:text-green-400">Report queued. It will appear below shortly.</p>
            )}
          </div>
        </form>
      </div>

      {downloadError && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3 text-sm text-yellow-800 dark:text-yellow-300">{downloadError}</div>
      )}

      {/* Reports Table */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Generated Reports</h2>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{reports?.length || 0} reports</p>
        </div>
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-800">
          <thead className="bg-gray-50 dark:bg-gray-800/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Report Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Scan</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Scan Details</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Generated</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-800">
            {reports && reports.length === 0 && (
              <tr><td colSpan={5} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">No reports generated yet. Select a scan above and click Generate.</td></tr>
            )}
            {reports?.map(report => {
              const isReady = report.file_path || report.content;
              const scan = scansData?.items?.find(s => s.id === report.scan_id);
              const rt = getReportType(report.report_type);
              const Icon = rt?.icon || FileText;
              return (
                <tr key={report.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <span className={`inline-flex p-1 rounded ${rt?.color || 'bg-gray-100 text-gray-800'}`}>
                        <Icon className="w-3.5 h-3.5" />
                      </span>
                      <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                        {rt?.label || report.report_type}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-300">
                    {scan?.job_name || report.scan_id.substring(0, 8) + '...'}
                  </td>
                  <td className="px-6 py-4 text-xs text-gray-500 dark:text-gray-400">
                    {scan ? (
                      <span>{scan.total_users} users, {scan.successful_users} ok</span>
                    ) : '--'}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{formatDate(report.generated_at)}</td>
                  <td className="px-6 py-4 text-right">
                    {isReady ? (
                      <button
                        onClick={() => handleDownload(report)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/40 transition-colors"
                      >
                        {report.content ? <><Eye className="w-4 h-4" /> View</> : <><Download className="w-4 h-4" /> Download</>}
                      </button>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-xs text-gray-400 dark:text-gray-500">
                        <span className="w-3 h-3 border-2 border-gray-300 dark:border-gray-600 border-t-transparent rounded-full animate-spin" />
                        Generating...
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* AI Summary Modal */}
      {viewContent && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-8">
          <div className="bg-white dark:bg-gray-900 rounded-lg max-w-3xl w-full max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-800">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">AI Summary</h3>
              <button onClick={() => setViewContent(null)} className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="px-6 py-4 overflow-auto flex-1">
              <pre className="whitespace-pre-wrap text-sm text-gray-700 dark:text-gray-300 font-sans leading-relaxed">{viewContent}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
