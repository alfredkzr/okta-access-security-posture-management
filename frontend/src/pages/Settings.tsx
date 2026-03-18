import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Pencil, Trash2, Play, Clock, History, Zap, CheckCircle, XCircle, AlertTriangle, Database, Server, Shield, Activity } from 'lucide-react';
import api from '../lib/api';
import type { HealthCheck, PaginatedResponse } from '../lib/api';
import { formatDate, statusColor, cn } from '../lib/utils';
import ScanDetailModal from '../components/ScanDetailModal';

// ==================== Types ====================

interface TenantConfig {
  okta_org: string;
  okta_org_type: string;
  okta_api_token_set: boolean;
  okta_api_token_masked?: string;
}

interface ScheduledJob {
  id: string;
  name: string;
  description: string | null;
  is_active: boolean;
  schedule_type: string;
  cron_expression: string | null;
  interval_seconds: number | null;
  scan_config: {
    user_selection?: string;
    max_workers?: number;
    include_posture_checks?: boolean;
    include_deactivated?: boolean;
    max_users?: number | null;
    specific_users?: string[] | null;
    api_delay?: number;
  } | null;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
}

interface JobExecution {
  id: string;
  job_id: string | null;
  job_name: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  total_users: number;
  successful_users: number;
  failed_users: number;
  duration_seconds: number | null;
  error_message: string | null;
}

interface ScheduleForm {
  name: string;
  description: string;
  schedule_type: string;
  cron_expression: string;
  interval_seconds: number;
  is_active: boolean;
  scan_config: {
    user_selection: string;
    max_workers: number;
    include_posture_checks: boolean;
    specific_users_text: string;
  };
}

interface NotificationChannel {
  id: string;
  name: string;
  channel_type: string;
  webhook_url: string;
  events: string[];
  is_active: boolean;
  hmac_secret: string | null;
  created_at: string;
  updated_at: string;
}

interface ChannelForm {
  name: string;
  channel_type: string;
  webhook_url: string;
  events: string[];
  is_active: boolean;
  hmac_secret: string;
}

// ==================== Constants ====================

const EVENT_OPTIONS = [
  { value: 'scan_completed', label: 'Scan Completed' },
  { value: 'new_vulnerabilities', label: 'New Vulnerabilities' },
  { value: 'posture_critical', label: 'Posture Critical' },
  { value: 'token_health', label: 'Token Health' },
];

const emptyScheduleForm: ScheduleForm = {
  name: '',
  description: '',
  schedule_type: 'cron',
  cron_expression: '0 0 * * *',
  interval_seconds: 3600,
  is_active: true,
  scan_config: { user_selection: 'all', max_workers: 5, include_posture_checks: true, specific_users_text: '' },
};

const emptyChannelForm: ChannelForm = {
  name: '',
  channel_type: 'webhook',
  webhook_url: '',
  events: [],
  is_active: true,
  hmac_secret: '',
};

type TabId = 'general' | 'schedules' | 'notifications';

const tabs: { id: TabId; label: string }[] = [
  { id: 'general', label: 'General' },
  { id: 'schedules', label: 'Schedules' },
  { id: 'notifications', label: 'Notifications' },
];

// ==================== Main Component ====================

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabId>('general');

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Settings</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 dark:text-gray-500 mt-1">Manage configuration, schedules, and notifications</p>
      </div>

      {/* Tab Buttons */}
      <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800 mb-6">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px',
              activeTab === tab.id
                ? 'border-blue-600 text-blue-700 dark:text-blue-400'
                : 'border-transparent text-gray-500 dark:text-gray-400 dark:text-gray-500 hover:text-gray-700 dark:text-gray-300 hover:border-gray-300'
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'general' && <GeneralTab />}
      {activeTab === 'schedules' && <SchedulesTab />}
      {activeTab === 'notifications' && <NotificationsTab />}
    </div>
  );
}

// ==================== General Tab ====================

function GeneralTab() {
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const { data: tenant, isLoading: tenantLoading, error: tenantError } = useQuery<TenantConfig>({
    queryKey: ['tenant-config'],
    queryFn: () => api.get('/settings/tenant').then(r => r.data),
  });

  const { data: health, isLoading: healthLoading } = useQuery<HealthCheck>({
    queryKey: ['health'],
    queryFn: () => api.get('/settings/health').then(r => r.data),
  });

  const testMutation = useMutation({
    mutationFn: () => api.post('/settings/tenant/test'),
    onSuccess: (res) => {
      setTestResult({ success: true, message: res.data?.message || 'Connection successful' });
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : 'Connection test failed';
      setTestResult({ success: false, message });
    },
  });

  if (tenantLoading) {
    return <div className="flex items-center justify-center h-40"><div className="text-gray-500 dark:text-gray-400 dark:text-gray-500 text-sm">Loading settings...</div></div>;
  }

  if (tenantError) {
    return <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4"><p className="text-red-700 dark:text-red-400 text-sm">Failed to load settings.</p></div>;
  }

  return (
    <div className="space-y-6">
      {/* Okta Configuration */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6">
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">Okta Configuration</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 mb-1">Organization</label>
            <div className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-900 dark:text-gray-100">
              {tenant?.okta_org || '--'}
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 mb-1">Org Type</label>
            <div className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-900 dark:text-gray-100">
              {tenant?.okta_org_type || '--'}
            </div>
          </div>
          <div className="sm:col-span-2">
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 mb-1">API Token</label>
            <div className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-900 dark:text-gray-100 font-mono">
              {tenant?.okta_api_token_masked || (tenant?.okta_api_token_set ? '****' : 'Not configured')}
            </div>
          </div>
        </div>
        <div className="mt-4 flex items-center gap-4">
          <button
            onClick={() => { setTestResult(null); testMutation.mutate(); }}
            disabled={testMutation.isPending}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {testMutation.isPending ? 'Testing...' : 'Test Okta Connection'}
          </button>
          {testResult && (
            <span className={`text-sm ${testResult.success ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
              {testResult.message}
            </span>
          )}
        </div>
      </div>

      {/* System Health */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2.5">
            <Activity className="w-4 h-4 text-gray-400" />
            <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300">System Health</h2>
          </div>
          {!healthLoading && health && (() => {
            const oktaStatus = typeof health.okta === 'string'
              ? health.okta
              : health.okta && typeof health.okta === 'object' && 'status' in (health.okta as Record<string, unknown>)
                ? String((health.okta as Record<string, string>).status)
                : 'unknown';
            const allHealthy = [health.database, health.redis, oktaStatus].every(
              s => s === 'ok' || s === 'healthy' || s === 'connected'
            );
            return (
              <span className={cn(
                'inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full',
                allHealthy
                  ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400'
                  : 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400'
              )}>
                <span className={cn(
                  'w-1.5 h-1.5 rounded-full',
                  allHealthy ? 'bg-green-500 animate-pulse' : 'bg-amber-500 animate-pulse'
                )} />
                {allHealthy ? 'All Systems Operational' : 'Degraded'}
              </span>
            );
          })()}
        </div>
        {healthLoading ? (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[0, 1, 2].map(i => (
              <div key={i} className="border border-gray-200 dark:border-gray-800 rounded-lg p-4 animate-pulse">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-gray-100 dark:bg-gray-800" />
                  <div className="space-y-2 flex-1">
                    <div className="h-3 w-16 bg-gray-100 dark:bg-gray-800 rounded" />
                    <div className="h-2.5 w-20 bg-gray-100 dark:bg-gray-800 rounded" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : health ? (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <HealthCard label="Database" subtitle="PostgreSQL" status={health.database} icon={Database} />
            <HealthCard label="Redis" subtitle="Cache & Queue" status={health.redis} icon={Server} />
            <HealthCard
              label="Okta API"
              subtitle="Identity Provider"
              icon={Shield}
              status={
                typeof health.okta === 'string'
                  ? health.okta
                  : health.okta && typeof health.okta === 'object' && 'status' in (health.okta as Record<string, unknown>)
                    ? String((health.okta as Record<string, string>).status)
                    : 'unknown'
              }
            />
          </div>
        ) : (
          <p className="text-sm text-gray-400 dark:text-gray-500">Health data unavailable</p>
        )}
      </div>

      {/* Danger Zone */}
      <DangerZone />

    </div>
  );
}

function DangerZone() {
  const queryClient = useQueryClient();
  const [step, setStep] = useState<'idle' | 'confirm' | 'typing'>('idle');
  const [typed, setTyped] = useState('');

  const resetMutation = useMutation({
    mutationFn: () => api.post('/settings/reset?confirm=RESET'),
    onSuccess: () => {
      queryClient.invalidateQueries();
      setStep('idle');
      setTyped('');
    },
  });

  return (
    <div className="bg-white dark:bg-gray-900 border-2 border-red-200 dark:border-red-800 rounded-lg p-6">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 p-2 bg-red-100 dark:bg-red-900/30 rounded-lg">
          <AlertTriangle className="w-5 h-5 text-red-600" />
        </div>
        <div className="flex-1">
          <h2 className="text-sm font-semibold text-red-700 dark:text-red-400">Danger Zone</h2>
          <p className="text-sm text-gray-600 dark:text-gray-400 dark:text-gray-500 mt-1">
            Reset the entire application to a clean state. This permanently deletes <strong>all</strong> scan
            results, vulnerabilities, posture findings, scheduled jobs, reports, notifications, and audit logs.
            Default scenarios will be re-created.
          </p>

          {step === 'idle' && (
            <button
              onClick={() => setStep('confirm')}
              className="mt-4 px-4 py-2 text-sm font-medium text-red-700 dark:text-red-400 bg-white border border-red-300 dark:border-red-700 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
            >
              Reset All Data
            </button>
          )}

          {step === 'confirm' && (
            <div className="mt-4 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg space-y-3">
              <p className="text-sm font-medium text-red-800 dark:text-red-300">
                Are you sure? This action cannot be undone.
              </p>
              <p className="text-sm text-red-700 dark:text-red-400">
                All scan history, vulnerabilities, findings, scheduled jobs, and reports will be permanently deleted.
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setStep('typing')}
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 transition-colors"
                >
                  Yes, I want to reset everything
                </button>
                <button
                  onClick={() => setStep('idle')}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {step === 'typing' && (
            <div className="mt-4 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg space-y-3">
              <p className="text-sm text-red-800 dark:text-red-300">
                Type <code className="px-1.5 py-0.5 bg-red-100 dark:bg-red-800 rounded font-mono text-red-900 dark:text-red-200 font-bold">RESET</code> to confirm:
              </p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={typed}
                  onChange={e => setTyped(e.target.value)}
                  placeholder="Type RESET"
                  className="px-3 py-2 border border-red-300 dark:border-red-700 rounded-lg text-sm font-mono focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none w-40"
                  autoFocus
                />
                <button
                  onClick={() => resetMutation.mutate()}
                  disabled={typed !== 'RESET' || resetMutation.isPending}
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  {resetMutation.isPending ? 'Resetting...' : 'Permanently Reset'}
                </button>
                <button
                  onClick={() => { setStep('idle'); setTyped(''); }}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                >
                  Cancel
                </button>
              </div>
              {resetMutation.isError && (
                <p className="text-sm text-red-600">Reset failed. Please try again.</p>
              )}
              {resetMutation.isSuccess && (
                <p className="text-sm text-green-600 dark:text-green-400 font-medium">All data has been reset successfully.</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function HealthCard({ label, subtitle, status, icon: Icon }: { label: string; subtitle: string; status: string; icon: React.ComponentType<{ className?: string }> }) {
  const isHealthy = status === 'ok' || status === 'healthy' || status === 'connected';
  return (
    <div className={cn(
      'border rounded-lg p-4 transition-colors',
      isHealthy
        ? 'border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900'
        : 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/10'
    )}>
      <div className="flex items-center gap-3">
        <div className={cn(
          'w-9 h-9 rounded-lg flex items-center justify-center shrink-0',
          isHealthy
            ? 'bg-green-50 dark:bg-green-900/20'
            : 'bg-red-50 dark:bg-red-900/20'
        )}>
          <Icon className={cn(
            'w-4.5 h-4.5',
            isHealthy ? 'text-green-600 dark:text-green-400' : 'text-red-500 dark:text-red-400'
          )} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{label}</span>
            <span className={cn(
              'inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full',
              isHealthy
                ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400'
                : 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400'
            )}>
              <span className={cn(
                'w-1.5 h-1.5 rounded-full',
                isHealthy ? 'bg-green-500' : 'bg-red-500'
              )} />
              {isHealthy ? 'Healthy' : 'Down'}
            </span>
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-500 mt-0.5">{subtitle}</p>
        </div>
      </div>
    </div>
  );
}

// ==================== Schedules Tab ====================

function SchedulesTab() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<ScheduleForm>(emptyScheduleForm);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  const { data: jobs, isLoading, error } = useQuery<ScheduledJob[]>({
    queryKey: ['schedules'],
    queryFn: () => api.get('/schedules').then(r => r.data),
  });

  const { data: historyData } = useQuery<PaginatedResponse<JobExecution>>({
    queryKey: ['schedules-history'],
    queryFn: () => api.get('/schedules/history', { params: { page: 1, page_size: 10 } }).then(r => r.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: ScheduleForm) => {
      const payload: Record<string, unknown> = {
        name: data.name,
        description: data.description || null,
        schedule_type: data.schedule_type,
        is_active: data.is_active,
        scan_config: data.scan_config,
      };
      if (data.schedule_type === 'cron') payload.cron_expression = data.cron_expression;
      if (data.schedule_type === 'interval') payload.interval_seconds = data.interval_seconds;
      return api.post('/schedules', payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
      resetForm();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: ScheduleForm }) => {
      const payload: Record<string, unknown> = {
        name: data.name,
        description: data.description || null,
        schedule_type: data.schedule_type,
        is_active: data.is_active,
        scan_config: data.scan_config,
      };
      if (data.schedule_type === 'cron') payload.cron_expression = data.cron_expression;
      if (data.schedule_type === 'interval') payload.interval_seconds = data.interval_seconds;
      return api.put(`/schedules/${id}`, payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
      resetForm();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/schedules/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
      setDeleteConfirm(null);
    },
  });

  const runNowMutation = useMutation({
    mutationFn: (id: string) => api.post(`/schedules/${id}/run-now`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
      queryClient.invalidateQueries({ queryKey: ['schedules-history'] });
    },
  });

  function resetForm() {
    setShowForm(false);
    setEditingId(null);
    setForm(emptyScheduleForm);
  }

  function startEdit(job: ScheduledJob) {
    setEditingId(job.id);
    setShowForm(true);
    setForm({
      name: job.name,
      description: job.description || '',
      schedule_type: job.schedule_type,
      cron_expression: job.cron_expression || '0 0 * * *',
      interval_seconds: job.interval_seconds || 3600,
      is_active: job.is_active,
      scan_config: {
        user_selection: job.scan_config?.user_selection || 'all',
        max_workers: job.scan_config?.max_workers || 5,
        include_posture_checks: job.scan_config?.include_posture_checks ?? true,
        specific_users_text: job.scan_config?.specific_users?.join('\n') || '',
      },
    });
  }

  function buildPayloadConfig(scanConfig: ScheduleForm['scan_config']) {
    const { specific_users_text, ...rest } = scanConfig;
    const specific_users = scanConfig.user_selection === 'specific' && specific_users_text
      ? specific_users_text.split('\n').map((s: string) => s.trim()).filter(Boolean)
      : null;
    return { ...rest, specific_users };
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const submittable = { ...form, scan_config: buildPayloadConfig(form.scan_config) };
    if (editingId) {
      updateMutation.mutate({ id: editingId, data: submittable as any });
    } else {
      createMutation.mutate(submittable as any);
    }
  }

  function formatSchedule(job: ScheduledJob): string {
    if (job.schedule_type === 'cron' && job.cron_expression) return job.cron_expression;
    if (job.schedule_type === 'interval' && job.interval_seconds) {
      const h = Math.floor(job.interval_seconds / 3600);
      const m = Math.floor((job.interval_seconds % 3600) / 60);
      if (h > 0 && m > 0) return `Every ${h}h ${m}m`;
      if (h > 0) return `Every ${h}h`;
      return `Every ${m}m`;
    }
    return job.schedule_type;
  }

  function formatDuration(seconds: number | null): string {
    if (seconds === null) return '--';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    const m = Math.floor(seconds / 60);
    const s = Math.round(seconds % 60);
    return `${m}m ${s}s`;
  }

  if (isLoading) {
    return <div className="flex items-center justify-center h-40"><div className="text-gray-500 dark:text-gray-400 dark:text-gray-500">Loading schedules...</div></div>;
  }

  if (error) {
    return <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400">Failed to load schedules.</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500 dark:text-gray-400 dark:text-gray-500">Manage automated scan schedules</p>
        <button
          onClick={() => { resetForm(); setShowForm(true); }}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700"
        >
          <Plus className="w-4 h-4" />
          New Schedule
        </button>
      </div>

      {showForm && (
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            {editingId ? 'Edit Schedule' : 'New Schedule'}
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                <input
                  type="text"
                  required
                  value={form.name}
                  onChange={e => setForm({ ...form, name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  placeholder="Schedule name"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={e => setForm({ ...form, description: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  placeholder="Optional description"
                />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Schedule Type</label>
                <select
                  value={form.schedule_type}
                  onChange={e => setForm({ ...form, schedule_type: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                >
                  <option value="cron">Cron</option>
                  <option value="interval">Interval</option>
                  <option value="once">Once</option>
                </select>
              </div>
              {form.schedule_type === 'cron' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Cron Expression</label>
                  <input
                    type="text"
                    value={form.cron_expression}
                    onChange={e => setForm({ ...form, cron_expression: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    placeholder="0 0 * * *"
                  />
                </div>
              )}
              {form.schedule_type === 'interval' && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Interval (seconds)</label>
                  <input
                    type="number"
                    min={60}
                    value={form.interval_seconds}
                    onChange={e => setForm({ ...form, interval_seconds: parseInt(e.target.value) || 3600 })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  />
                </div>
              )}
              <div className="flex items-end">
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 dark:text-gray-600">
                  <input
                    type="checkbox"
                    checked={form.is_active}
                    onChange={e => setForm({ ...form, is_active: e.target.checked })}
                    className="rounded border-gray-300"
                  />
                  Active
                </label>
              </div>
            </div>

            <div className="border-t border-gray-200 dark:border-gray-800 pt-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">Scan Configuration</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">User Selection</label>
                  <select
                    value={form.scan_config.user_selection}
                    onChange={e => setForm({ ...form, scan_config: { ...form.scan_config, user_selection: e.target.value } })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  >
                    <option value="all">All Users</option>
                    <option value="specific">Specific Users</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Concurrent Workers</label>
                  <input
                    type="number"
                    min={1}
                    max={20}
                    value={form.scan_config.max_workers}
                    onChange={e => setForm({ ...form, scan_config: { ...form.scan_config, max_workers: parseInt(e.target.value) || 5 } })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  />
                </div>
              </div>
              {form.scan_config.user_selection === 'specific' && (
                <div className="mt-3">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">User Emails (one per line)</label>
                  <textarea
                    rows={4}
                    placeholder={"user1@company.com\nuser2@company.com\nuser3@company.com"}
                    value={form.scan_config.specific_users_text || ''}
                    onChange={e => setForm({ ...form, scan_config: { ...form.scan_config, specific_users_text: e.target.value } })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none font-mono"
                  />
                  <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">Enter one email address per line</p>
                </div>
              )}
            </div>

            {(createMutation.isError || updateMutation.isError) && (
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3 text-sm text-red-700 dark:text-red-400">
                {String((createMutation.error as any)?.response?.data?.error?.message || (updateMutation.error as any)?.response?.data?.error?.message || 'Failed to save schedule. Check all fields are filled.')}
              </div>
            )}

            <div className="flex gap-2 pt-2">
              <button
                type="submit"
                disabled={createMutation.isPending || updateMutation.isPending}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {createMutation.isPending || updateMutation.isPending ? 'Saving...' : editingId ? 'Update' : 'Create'}
              </button>
              <button
                type="button"
                onClick={resetForm}
                className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Scheduled Jobs Table */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center gap-2">
          <Clock className="w-5 h-5 text-gray-400 dark:text-gray-500" />
          <h2 className="text-sm font-semibold text-gray-900 dark:text-gray-100">Scheduled Jobs</h2>
        </div>
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50 dark:bg-gray-800/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Schedule</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Active</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Last Run</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Next Run</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-800">
            {jobs && jobs.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400 dark:text-gray-500">
                  No scheduled jobs. Create one to automate scans.
                </td>
              </tr>
            )}
            {jobs?.map(job => (
              <tr key={job.id} className="hover:bg-gray-50 dark:hover:bg-gray-800 dark:bg-gray-800/50">
                <td className="px-6 py-4">
                  <div className="text-sm font-medium text-gray-900 dark:text-gray-100">{job.name}</div>
                  {job.description && <div className="text-xs text-gray-500 dark:text-gray-400 dark:text-gray-500 mt-0.5">{job.description}</div>}
                  <div className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
                    {job.scan_config?.user_selection === 'specific' && job.scan_config?.specific_users?.length
                      ? `${job.scan_config.specific_users.length} specific user${job.scan_config.specific_users.length > 1 ? 's' : ''}`
                      : job.scan_config?.user_selection === 'limited'
                        ? `Limited to ${job.scan_config?.max_users ?? '?'} users`
                        : 'All users'}
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 dark:text-gray-300 dark:text-gray-600">
                    {job.schedule_type}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 dark:text-gray-500 font-mono">{formatSchedule(job)}</td>
                <td className="px-6 py-4">
                  {job.is_active
                    ? <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400">Active</span>
                    : <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 dark:text-gray-400 dark:text-gray-500">Inactive</span>}
                </td>
                <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400 dark:text-gray-500">{formatDate(job.last_run_at)}</td>
                <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400 dark:text-gray-500">{formatDate(job.next_run_at)}</td>
                <td className="px-6 py-4 text-right">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      onClick={() => runNowMutation.mutate(job.id)}
                      disabled={runNowMutation.isPending}
                      className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-900/20 rounded"
                      title="Run Now"
                    >
                      <Play className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => startEdit(job)}
                      className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded"
                      title="Edit"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    {deleteConfirm === job.id ? (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => deleteMutation.mutate(job.id)}
                          className="px-2 py-1 text-xs font-medium text-red-700 dark:text-red-400 bg-red-100 dark:bg-red-900/30 rounded hover:bg-red-200 dark:hover:bg-red-800"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setDeleteConfirm(null)}
                          className="px-2 py-1 text-xs font-medium text-gray-600 dark:text-gray-400 dark:text-gray-500 bg-gray-100 dark:bg-gray-800 rounded hover:bg-gray-200 dark:hover:bg-gray-700"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setDeleteConfirm(job.id)}
                        className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Execution History */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center gap-2">
          <History className="w-5 h-5 text-gray-400 dark:text-gray-500" />
          <h2 className="text-sm font-semibold text-gray-900 dark:text-gray-100">Execution History</h2>
        </div>
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50 dark:bg-gray-800/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Job Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Users</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Duration</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Started At</th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-800">
            {(!historyData?.items || historyData.items.length === 0) && (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400 dark:text-gray-500">
                  No execution history yet.
                </td>
              </tr>
            )}
            {historyData?.items?.map(exec => (
              <tr
                key={exec.id}
                onClick={() => setSelectedScanId(exec.id)}
                className="hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer transition-colors"
              >
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-100">{exec.job_name}</td>
                <td className="px-6 py-4">
                  <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${statusColor(exec.status)}`}>
                    {exec.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  <span className="text-green-600 dark:text-green-400">{exec.successful_users}</span>
                  {exec.failed_users > 0 && (
                    <span className="text-red-600 dark:text-red-400">/{exec.failed_users} failed</span>
                  )}
                  <span className="text-gray-400 dark:text-gray-500"> of {exec.total_users}</span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{formatDuration(exec.duration_seconds)}</td>
                <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{formatDate(exec.started_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Scan Detail Modal */}
      {selectedScanId && (
        <ScanDetailModal scanId={selectedScanId} onClose={() => setSelectedScanId(null)} />
      )}
    </div>
  );
}

// ==================== Notifications Tab ====================

function NotificationsTab() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<ChannelForm>(emptyChannelForm);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, 'success' | 'error' | 'loading'>>({});

  const { data: channels, isLoading, error } = useQuery<NotificationChannel[]>({
    queryKey: ['notification-channels'],
    queryFn: () => api.get('/notifications/channels').then(r => r.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: ChannelForm) => {
      const payload: Record<string, unknown> = { ...data };
      if (!data.hmac_secret) delete payload.hmac_secret;
      return api.post('/notifications/channels', payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
      resetForm();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: ChannelForm }) => {
      const payload: Record<string, unknown> = { ...data };
      if (!data.hmac_secret) delete payload.hmac_secret;
      return api.put(`/notifications/channels/${id}`, payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
      resetForm();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/notifications/channels/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
      setDeleteConfirm(null);
    },
  });

  function resetForm() {
    setShowForm(false);
    setEditingId(null);
    setForm(emptyChannelForm);
  }

  function startEdit(ch: NotificationChannel) {
    setEditingId(ch.id);
    setShowForm(true);
    setForm({
      name: ch.name,
      channel_type: ch.channel_type,
      webhook_url: ch.webhook_url,
      events: ch.events,
      is_active: ch.is_active,
      hmac_secret: '',
    });
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (editingId) {
      updateMutation.mutate({ id: editingId, data: form });
    } else {
      createMutation.mutate(form);
    }
  }

  function toggleEvent(event: string) {
    setForm(prev => ({
      ...prev,
      events: prev.events.includes(event)
        ? prev.events.filter(e => e !== event)
        : [...prev.events, event],
    }));
  }

  async function handleTest(id: string) {
    setTestResults(prev => ({ ...prev, [id]: 'loading' }));
    try {
      await api.post(`/notifications/channels/${id}/test`);
      setTestResults(prev => ({ ...prev, [id]: 'success' }));
    } catch {
      setTestResults(prev => ({ ...prev, [id]: 'error' }));
    }
    setTimeout(() => {
      setTestResults(prev => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    }, 3000);
  }

  function truncateUrl(url: string, maxLen = 40): string {
    if (url.length <= maxLen) return url;
    return url.substring(0, maxLen) + '...';
  }

  if (isLoading) {
    return <div className="flex items-center justify-center h-40"><div className="text-gray-500 dark:text-gray-400 dark:text-gray-500">Loading notification channels...</div></div>;
  }

  if (error) {
    return <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400">Failed to load notification channels.</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500 dark:text-gray-400 dark:text-gray-500">Manage webhook notification channels</p>
        <button
          onClick={() => { resetForm(); setShowForm(true); }}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700"
        >
          <Plus className="w-4 h-4" />
          New Channel
        </button>
      </div>

      {showForm && (
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            {editingId ? 'Edit Channel' : 'New Channel'}
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                <input
                  type="text"
                  required
                  value={form.name}
                  onChange={e => setForm({ ...form, name: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  placeholder="Channel name"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Webhook URL</label>
                <input
                  type="url"
                  required
                  value={form.webhook_url}
                  onChange={e => setForm({ ...form, webhook_url: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  placeholder="https://hooks.example.com/..."
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Events</label>
              <div className="flex flex-wrap gap-3">
                {EVENT_OPTIONS.map(opt => (
                  <label key={opt.value} className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 dark:text-gray-600">
                    <input
                      type="checkbox"
                      checked={form.events.includes(opt.value)}
                      onChange={() => toggleEvent(opt.value)}
                      className="rounded border-gray-300"
                    />
                    {opt.label}
                  </label>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  HMAC Secret <span className="text-gray-400 dark:text-gray-500 font-normal">(optional)</span>
                </label>
                <input
                  type="password"
                  value={form.hmac_secret}
                  onChange={e => setForm({ ...form, hmac_secret: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  placeholder="Secret for webhook signature"
                />
              </div>
              <div className="flex items-end">
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 dark:text-gray-600">
                  <input
                    type="checkbox"
                    checked={form.is_active}
                    onChange={e => setForm({ ...form, is_active: e.target.checked })}
                    className="rounded border-gray-300"
                  />
                  Active
                </label>
              </div>
            </div>

            <div className="flex gap-2 pt-2">
              <button
                type="submit"
                disabled={createMutation.isPending || updateMutation.isPending}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {createMutation.isPending || updateMutation.isPending ? 'Saving...' : editingId ? 'Update' : 'Create'}
              </button>
              <button
                type="button"
                onClick={resetForm}
                className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Channels Table */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50 dark:bg-gray-800/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">URL</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Events</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Active</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Created</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 dark:text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-800">
            {channels && channels.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400 dark:text-gray-500">
                  No notification channels configured.
                </td>
              </tr>
            )}
            {channels?.map(ch => (
              <tr key={ch.id} className="hover:bg-gray-50 dark:hover:bg-gray-800 dark:bg-gray-800/50">
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-100">{ch.name}</td>
                <td className="px-6 py-4">
                  <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-400">
                    {ch.channel_type}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 dark:text-gray-500 font-mono" title={ch.webhook_url}>
                  {truncateUrl(ch.webhook_url)}
                </td>
                <td className="px-6 py-4">
                  <div className="flex flex-wrap gap-1">
                    {ch.events.map(ev => (
                      <span key={ev} className="inline-flex px-2 py-0.5 text-xs font-medium rounded bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 dark:text-blue-400">
                        {ev.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-6 py-4">
                  {ch.is_active
                    ? <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400">Active</span>
                    : <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 dark:text-gray-400 dark:text-gray-500">Inactive</span>}
                </td>
                <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400 dark:text-gray-500">{formatDate(ch.created_at)}</td>
                <td className="px-6 py-4 text-right">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      onClick={() => handleTest(ch.id)}
                      disabled={testResults[ch.id] === 'loading'}
                      className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-yellow-600 hover:bg-yellow-50 dark:hover:bg-yellow-900/20 rounded relative"
                      title="Test"
                    >
                      {testResults[ch.id] === 'loading' ? (
                        <Zap className="w-4 h-4 animate-pulse text-yellow-500" />
                      ) : testResults[ch.id] === 'success' ? (
                        <CheckCircle className="w-4 h-4 text-green-600" />
                      ) : testResults[ch.id] === 'error' ? (
                        <XCircle className="w-4 h-4 text-red-600" />
                      ) : (
                        <Zap className="w-4 h-4" />
                      )}
                    </button>
                    <button
                      onClick={() => startEdit(ch)}
                      className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded"
                      title="Edit"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    {deleteConfirm === ch.id ? (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => deleteMutation.mutate(ch.id)}
                          className="px-2 py-1 text-xs font-medium text-red-700 dark:text-red-400 bg-red-100 dark:bg-red-900/30 rounded hover:bg-red-200 dark:hover:bg-red-800"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setDeleteConfirm(null)}
                          className="px-2 py-1 text-xs font-medium text-gray-600 dark:text-gray-400 dark:text-gray-500 bg-gray-100 dark:bg-gray-800 rounded hover:bg-gray-200 dark:hover:bg-gray-700"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setDeleteConfirm(ch.id)}
                        className="p-1.5 text-gray-400 dark:text-gray-500 hover:text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
