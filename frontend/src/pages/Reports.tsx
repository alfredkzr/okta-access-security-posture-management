import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { FileText, Download, FileSpreadsheet, FileJson, Loader2 } from 'lucide-react';
import api from '../lib/api';
import type { PaginatedResponse, Scan } from '../lib/api';
import { formatDate } from '../lib/utils';

interface Report {
  id: string;
  scan_id: string;
  report_type: string;
  file_path: string | null;
  generated_at: string;
  created_at: string;
}

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
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Reports</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Generate and download assessment reports</p>
      </div>

      {/* Generate Report — compact */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-5">
        <div className="flex flex-col lg:flex-row lg:items-end gap-4">
          {/* Scan selector */}
          <div className="flex-1 min-w-0">
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1.5">Scan</label>
            <select
              value={scanId}
              onChange={e => setScanId(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
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
                      ? 'border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 dark:border-blue-500'
                      : 'border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:border-gray-300 dark:hover:border-gray-600 hover:text-gray-900 dark:hover:text-gray-200'
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
            className="flex items-center justify-center gap-2 px-5 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
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
          <p className="mt-3 text-sm text-red-600 dark:text-red-400">Failed to generate report. Please try again.</p>
        )}
        {generateMutation.isSuccess && (
          <p className="mt-3 text-sm text-green-600 dark:text-green-400">Report queued. It will appear below shortly.</p>
        )}
      </div>

      {downloadError && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3 text-sm text-yellow-800 dark:text-yellow-300">{downloadError}</div>
      )}

      {/* Reports list */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">Generated Reports</h2>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{filteredReports.length} report{filteredReports.length !== 1 ? 's' : ''}</p>
          </div>
          <select
            value={filterScanId}
            onChange={e => setFilterScanId(e.target.value)}
            className="px-3 py-1.5 border border-gray-300 dark:border-gray-700 rounded-lg text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 outline-none max-w-xs"
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
            <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
          </div>
        ) : (
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-800">
            <thead className="bg-gray-50 dark:bg-gray-800/50">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Type</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Scan</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Generated</th>
                <th className="px-5 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider w-28"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
              {filteredReports.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-5 py-12 text-center text-sm text-gray-500 dark:text-gray-400">
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
                  <tr key={report.id} className="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-2">
                        <Icon className="w-4 h-4 text-gray-400 dark:text-gray-500" />
                        <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{rt?.label || report.report_type}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="text-sm text-gray-700 dark:text-gray-300">{scan?.job_name || report.scan_id.substring(0, 8)}</span>
                      {scan && (
                        <span className="text-xs text-gray-400 dark:text-gray-500 ml-2">
                          {scan.successful_users}/{scan.total_users} users
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3.5 text-sm text-gray-500 dark:text-gray-400">
                      {formatDate(report.generated_at)}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      {isReady ? (
                        <button
                          onClick={() => handleDownload(report)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/40 transition-colors"
                        >
                          <Download className="w-3.5 h-3.5" /> Download
                        </button>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs text-gray-400 dark:text-gray-500">
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
