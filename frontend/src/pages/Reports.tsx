import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { FileText, Download, FileSpreadsheet, FileJson, Loader2 } from 'lucide-react';
import api from '../lib/api';
import type { PaginatedResponse, Report, Scan } from '../lib/api';
import { formatDate } from '../lib/utils';

const REPORT_TYPES = [
  { value: 'csv_full', label: 'CSV Export', icon: FileSpreadsheet, description: 'All assessment results for every user and app' },
  { value: 'json', label: 'JSON Export', icon: FileJson, description: 'Structured export for SIEM and automation' },
] as const;

type ReportTypeValue = typeof REPORT_TYPES[number]['value'];

function getReportType(value: string) {
  return REPORT_TYPES.find(t => t.value === value);
}

export default function Reports() {
  const queryClient = useQueryClient();
  const [scanId, setScanId] = useState('');
  const [reportType, setReportType] = useState<ReportTypeValue>('csv_full');
  const [filterScanId, setFilterScanId] = useState('');
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const { data: reports, isLoading } = useQuery<Report[]>({
    queryKey: ['reports'],
    queryFn: () => api.get('/reports').then(r => r.data),
    refetchInterval: (query) => {
      const data = query.state.data;
      // Only poll when there are reports still generating (no file_path yet)
      return data?.some(r => !r.file_path && !r.generated_at) ? 5000 : false;
    },
  });

  const { data: scansData } = useQuery<PaginatedResponse<Scan>>({
    queryKey: ['assessments-recent'],
    queryFn: () => api.get('/assessments', { params: { page: 1, page_size: 50 } }).then(r => r.data),
  });

  const generateMutation = useMutation({
    mutationFn: (payload: { scan_id: string; report_type: string }) => api.post('/reports', payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['reports'] }),
  });

  function handleGenerate() {
    if (!scanId) return;
    generateMutation.mutate({ scan_id: scanId, report_type: reportType });
  }

  async function handleDownload(report: Report) {
    setDownloadError(null);
    try {
      const res = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' });
      const ext = report.report_type.includes('csv') ? 'csv' : 'json';
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

  const eligibleScans = scansData?.items?.filter(s =>
    (s.status === 'completed' || s.status === 'completed_with_errors') && s.successful_users > 0
  ) ?? [];

  const filteredReports = reports?.filter(r => {
    if (filterScanId && r.scan_id !== filterScanId) return false;
    return true;
  }) ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Reports</h1>
        <p className="text-sm text-text-secondary mt-1">Generate and download assessment reports</p>
      </div>

      {/* Generate Report — compact */}
      <div className="glass-panel p-5">
        <div className="flex flex-col lg:flex-row lg:items-end gap-4">
          {/* Scan selector */}
          <div className="flex-1 min-w-0">
            <label className="block text-xs font-medium text-text-muted mb-1.5">Scan</label>
            <select
              value={scanId}
              onChange={e => setScanId(e.target.value)}
              className="w-full px-3 py-2 bg-bg-input border border-border-glass rounded-lg text-sm text-text-primary focus:border-accent focus:ring-2 focus:ring-accent-glow outline-none"
            >
              <option value="">Select a completed scan...</option>
              {eligibleScans.map(scan => (
                <option key={scan.id} value={scan.id}>
                  {scan.job_name || 'Scan'} — {formatDate(scan.started_at)} — {scan.successful_users}/{scan.total_users} users
                </option>
              ))}
            </select>
          </div>

          {/* Report type selector */}
          <div className="flex gap-1.5">
            {REPORT_TYPES.map(t => {
              const Icon = t.icon;
              const active = reportType === t.value;
              return (
                <button
                  key={t.value}
                  type="button"
                  onClick={() => setReportType(t.value)}
                  title={t.description}
                  className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
                    active
                      ? 'border-blue-500 bg-blue-500/15 text-blue-400'
                      : 'border-border-glass text-text-muted hover:border-border-glass-hover hover:text-text-secondary'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span className="hidden sm:inline">{t.label}</span>
                </button>
              );
            })}
          </div>

          {/* Generate button */}
          <button
            onClick={handleGenerate}
            disabled={generateMutation.isPending || !scanId}
            className="flex items-center justify-center gap-2 px-5 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
          >
            {generateMutation.isPending ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> Generating...</>
            ) : (
              <><FileText className="w-4 h-4" /> Generate</>
            )}
          </button>
        </div>

        {/* Feedback */}
        {generateMutation.isError && (
          <p className="mt-3 text-sm text-red-400">Failed to generate report. Please try again.</p>
        )}
        {generateMutation.isSuccess && (
          <p className="mt-3 text-sm text-emerald-400">Report queued. It will appear below shortly.</p>
        )}
      </div>

      {downloadError && (
        <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 text-sm text-amber-300">{downloadError}</div>
      )}

      {/* Reports list */}
      <div className="glass-panel overflow-hidden">
        <div className="px-5 py-4 border-b border-border-glass flex items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-text-primary">Generated Reports</h2>
            <p className="text-xs text-text-muted mt-0.5">{filteredReports.length} report{filteredReports.length !== 1 ? 's' : ''}</p>
          </div>
          <select
            value={filterScanId}
            onChange={e => setFilterScanId(e.target.value)}
            className="px-3 py-1.5 bg-bg-input border border-border-glass rounded-lg text-sm text-text-primary outline-none max-w-xs focus:border-accent"
          >
            <option value="">All scans</option>
            {eligibleScans.map(scan => (
              <option key={scan.id} value={scan.id}>
                {scan.job_name || 'Scan'} — {formatDate(scan.started_at)}
              </option>
            ))}
          </select>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-5 h-5 animate-spin text-text-muted" />
          </div>
        ) : (
          <table className="min-w-full divide-y divide-border-glass">
            <thead className="bg-white/[0.02]">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Type</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Scan</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Generated</th>
                <th className="px-5 py-3 text-right text-xs font-medium text-text-muted uppercase tracking-wider w-28"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-glass">
              {filteredReports.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-5 py-12 text-center text-sm text-text-muted">
                    {reports?.length === 0
                      ? 'No reports yet. Select a scan above and generate one.'
                      : 'No reports match the selected filter.'}
                  </td>
                </tr>
              )}
              {filteredReports.map(report => {
                const isReady = report.file_path;
                const scan = scansData?.items?.find(s => s.id === report.scan_id);
                const rt = getReportType(report.report_type);
                const Icon = rt?.icon || FileText;
                return (
                  <tr key={report.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-2">
                        <Icon className="w-4 h-4 text-text-muted" />
                        <span className="text-sm font-medium text-text-primary">{rt?.label || report.report_type}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="text-sm text-text-secondary">{scan?.job_name || report.scan_id.substring(0, 8)}</span>
                      {scan && (
                        <span className="text-xs text-text-muted ml-2">
                          {scan.successful_users}/{scan.total_users} users
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3.5 text-sm text-text-muted">
                      {formatDate(report.generated_at)}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      {isReady ? (
                        <button
                          onClick={() => handleDownload(report)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-blue-400 bg-blue-500/10 rounded-lg hover:bg-blue-500/20 transition-colors"
                        >
                          <Download className="w-3.5 h-3.5" /> Download
                        </button>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs text-text-muted">
                          <Loader2 className="w-3 h-3 animate-spin" />
                          Generating
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
