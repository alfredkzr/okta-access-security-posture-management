import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Pencil, Trash2, Play, Clock, History, CheckCircle, XCircle, AlertTriangle, Database, Server, Shield, Activity, Globe, Bell, Eye, EyeOff, X, Send, Power, ChevronDown, ChevronUp, Link2, Key, Hash, Info } from 'lucide-react';
import api from '../lib/api';
import type { HealthCheck, PaginatedResponse } from '../lib/api';
import { formatDate, formatDuration, statusColor, cn } from '../lib/utils';
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
  has_secret: boolean;
  custom_headers: Record<string, string> | null;
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
  custom_headers: { key: string; value: string }[];
}

// ==================== Constants ====================

const EVENT_OPTIONS = [
  { value: 'scan_completed', label: 'Scan Completed', description: 'Fired when a scan finishes (success, failure, or partial)', severity: 'info' },
  { value: 'new_vulnerabilities', label: 'New Vulnerabilities', description: 'HIGH or CRITICAL vulnerabilities discovered during scan', severity: 'high' },
  { value: 'token_health', label: 'Token Health', description: 'Okta API token invalid, expiring, or rate limit critically low', severity: 'warning' },
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
  custom_headers: [],
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
        <h1 className="text-2xl font-bold text-text-primary">Settings</h1>
        <p className="text-sm text-text-secondary mt-1">Manage configuration, schedules, and notifications</p>
      </div>

      {/* Tab Buttons */}
      <div className="flex gap-1 border-b border-border-glass mb-6">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px',
              activeTab === tab.id
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-text-muted hover:text-text-secondary hover:border-border-glass-hover'
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
    return <div className="flex items-center justify-center h-40"><div className="text-text-muted text-sm">Loading settings...</div></div>;
  }

  if (tenantError) {
    return <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4"><p className="text-red-400 text-sm">Failed to load settings.</p></div>;
  }

  return (
    <div className="space-y-6">
      {/* Okta Configuration */}
      <div className="glass-panel p-6">
        <h2 className="text-sm font-semibold text-text-secondary mb-4">Okta Configuration</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1">Organization</label>
            <div className="bg-white/[0.03] border border-border-glass rounded-lg px-3 py-2 text-sm text-text-primary">
              {tenant?.okta_org || '--'}
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-text-muted mb-1">Org Type</label>
            <div className="bg-white/[0.03] border border-border-glass rounded-lg px-3 py-2 text-sm text-text-primary">
              {tenant?.okta_org_type || '--'}
            </div>
          </div>
          <div className="sm:col-span-2">
            <label className="block text-xs font-medium text-text-muted mb-1">API Token</label>
            <div className="bg-white/[0.03] border border-border-glass rounded-lg px-3 py-2 text-sm text-text-primary font-mono">
              {tenant?.okta_api_token_masked || (tenant?.okta_api_token_set ? '****' : 'Not configured')}
            </div>
          </div>
        </div>
        <div className="mt-4 flex items-center gap-4">
          <button
            onClick={() => { setTestResult(null); testMutation.mutate(); }}
            disabled={testMutation.isPending}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {testMutation.isPending ? 'Testing...' : 'Test Okta Connection'}
          </button>
          {testResult && (
            <span className={`text-sm ${testResult.success ? 'text-emerald-400' : 'text-red-400'}`}>
              {testResult.message}
            </span>
          )}
        </div>
      </div>

      {/* System Health */}
      <div className="glass-panel p-6">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2.5">
            <Activity className="w-4 h-4 text-text-muted" />
            <h2 className="text-sm font-semibold text-text-secondary">System Health</h2>
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
                  ? 'bg-emerald-500/15 text-emerald-400'
                  : 'bg-amber-500/15 text-amber-400'
              )}>
                <span className={cn(
                  'w-1.5 h-1.5 rounded-full',
                  allHealthy ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500 animate-pulse'
                )} />
                {allHealthy ? 'All Systems Operational' : 'Degraded'}
              </span>
            );
          })()}
        </div>
        {healthLoading ? (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[0, 1, 2].map(i => (
              <div key={i} className="border border-border-glass rounded-lg p-4 animate-pulse">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-white/[0.05]" />
                  <div className="space-y-2 flex-1">
                    <div className="h-3 w-16 bg-white/[0.05] rounded" />
                    <div className="h-2.5 w-20 bg-white/[0.05] rounded" />
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
          <p className="text-sm text-text-muted">Health data unavailable</p>
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
    <div className="glass-panel border-2 !border-red-500/20 p-6">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 p-2 bg-red-500/15 rounded-lg">
          <AlertTriangle className="w-5 h-5 text-red-400" />
        </div>
        <div className="flex-1">
          <h2 className="text-sm font-semibold text-red-400">Danger Zone</h2>
          <p className="text-sm text-text-secondary mt-1">
            Reset the entire application to a clean state. This permanently deletes <strong className="text-text-primary">all</strong> scan
            results, vulnerabilities, posture findings, scheduled jobs, reports, notifications, and audit logs.
            Default scenarios will be re-created.
          </p>

          {step === 'idle' && (
            <button
              onClick={() => setStep('confirm')}
              className="mt-4 px-4 py-2 text-sm font-medium text-red-400 bg-transparent border border-red-500/30 rounded-lg hover:bg-red-500/10 transition-colors"
            >
              Reset All Data
            </button>
          )}

          {step === 'confirm' && (
            <div className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg space-y-3">
              <p className="text-sm font-medium text-red-300">
                Are you sure? This action cannot be undone.
              </p>
              <p className="text-sm text-red-400">
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
                  className="px-4 py-2 text-sm font-medium text-text-secondary bg-white/[0.03] border border-border-glass rounded-lg hover:text-text-primary hover:border-border-glass-hover transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {step === 'typing' && (
            <div className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg space-y-3">
              <p className="text-sm text-red-300">
                Type <code className="px-1.5 py-0.5 bg-red-500/20 rounded font-mono text-red-200 font-bold">RESET</code> to confirm:
              </p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={typed}
                  onChange={e => setTyped(e.target.value)}
                  placeholder="Type RESET"
                  className="px-3 py-2 bg-bg-input border border-red-500/30 rounded-lg text-sm font-mono text-text-primary focus:ring-2 focus:ring-red-500/50 focus:border-red-500/50 outline-none w-40"
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
                  className="px-4 py-2 text-sm font-medium text-text-secondary bg-white/[0.03] border border-border-glass rounded-lg hover:text-text-primary hover:border-border-glass-hover transition-colors"
                >
                  Cancel
                </button>
              </div>
              {resetMutation.isError && (
                <p className="text-sm text-red-400">Reset failed. Please try again.</p>
              )}
              {resetMutation.isSuccess && (
                <p className="text-sm text-emerald-400 font-medium">All data has been reset successfully.</p>
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
        ? 'border-border-glass bg-white/[0.02]'
        : 'border-red-500/20 bg-red-500/5'
    )}>
      <div className="flex items-center gap-3">
        <div className={cn(
          'w-9 h-9 rounded-lg flex items-center justify-center shrink-0',
          isHealthy
            ? 'bg-emerald-500/15'
            : 'bg-red-500/15'
        )}>
          <Icon className={cn(
            'w-4.5 h-4.5',
            isHealthy ? 'text-emerald-400' : 'text-red-400'
          )} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-text-primary">{label}</span>
            <span className={cn(
              'inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full',
              isHealthy
                ? 'bg-emerald-500/15 text-emerald-400'
                : 'bg-red-500/15 text-red-400'
            )}>
              <span className={cn(
                'w-1.5 h-1.5 rounded-full',
                isHealthy ? 'bg-emerald-500' : 'bg-red-500'
              )} />
              {isHealthy ? 'Healthy' : 'Down'}
            </span>
          </div>
          <p className="text-xs text-text-muted mt-0.5">{subtitle}</p>
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

  const inputClass = 'w-full px-3 py-2 bg-bg-input border border-border-glass rounded-lg text-sm text-text-primary focus:border-accent focus:ring-2 focus:ring-accent-glow outline-none';
  const labelClass = 'block text-sm font-medium text-text-secondary mb-1';

  if (isLoading) {
    return <div className="flex items-center justify-center h-40"><div className="text-text-muted">Loading schedules...</div></div>;
  }

  if (error) {
    return <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">Failed to load schedules.</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-text-secondary">Manage automated scan schedules</p>
        <button
          onClick={() => { resetForm(); setShowForm(true); }}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-500"
        >
          <Plus className="w-4 h-4" />
          New Schedule
        </button>
      </div>

      {showForm && (
        <div className="glass-panel p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4">
            {editingId ? 'Edit Schedule' : 'New Schedule'}
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className={labelClass}>Name</label>
                <input
                  type="text"
                  required
                  value={form.name}
                  onChange={e => setForm({ ...form, name: e.target.value })}
                  className={inputClass}
                  placeholder="Schedule name"
                />
              </div>
              <div>
                <label className={labelClass}>Description</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={e => setForm({ ...form, description: e.target.value })}
                  className={inputClass}
                  placeholder="Optional description"
                />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className={labelClass}>Schedule Type</label>
                <select
                  value={form.schedule_type}
                  onChange={e => setForm({ ...form, schedule_type: e.target.value })}
                  className={inputClass}
                >
                  <option value="cron">Cron</option>
                  <option value="interval">Interval</option>
                  <option value="once">Once</option>
                </select>
              </div>
              {form.schedule_type === 'cron' && (
                <div>
                  <label className={labelClass}>Cron Expression</label>
                  <input
                    type="text"
                    value={form.cron_expression}
                    onChange={e => setForm({ ...form, cron_expression: e.target.value })}
                    className={cn(inputClass, 'font-mono')}
                    placeholder="0 0 * * *"
                  />
                </div>
              )}
              {form.schedule_type === 'interval' && (
                <div>
                  <label className={labelClass}>Interval (seconds)</label>
                  <input
                    type="number"
                    min={60}
                    value={form.interval_seconds}
                    onChange={e => setForm({ ...form, interval_seconds: parseInt(e.target.value) || 3600 })}
                    className={inputClass}
                  />
                </div>
              )}
              <div className="flex items-end">
                <label className="flex items-center gap-2 text-sm text-text-secondary">
                  <input
                    type="checkbox"
                    checked={form.is_active}
                    onChange={e => setForm({ ...form, is_active: e.target.checked })}
                    className="rounded border-border-glass bg-bg-input"
                  />
                  Active
                </label>
              </div>
            </div>

            <div className="border-t border-border-glass pt-4">
              <h3 className="text-sm font-medium text-text-primary mb-3">Scan Configuration</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className={labelClass}>User Selection</label>
                  <select
                    value={form.scan_config.user_selection}
                    onChange={e => setForm({ ...form, scan_config: { ...form.scan_config, user_selection: e.target.value } })}
                    className={inputClass}
                  >
                    <option value="all">All Users</option>
                    <option value="specific">Specific Users</option>
                  </select>
                </div>
                <div>
                  <label className={labelClass}>Concurrent Workers</label>
                  <input
                    type="number"
                    min={1}
                    max={20}
                    value={form.scan_config.max_workers}
                    onChange={e => setForm({ ...form, scan_config: { ...form.scan_config, max_workers: parseInt(e.target.value) || 5 } })}
                    className={inputClass}
                  />
                </div>
              </div>
              {form.scan_config.user_selection === 'specific' && (
                <div className="mt-3">
                  <label className={labelClass}>User Emails (one per line)</label>
                  <textarea
                    rows={4}
                    placeholder={"user1@company.com\nuser2@company.com\nuser3@company.com"}
                    value={form.scan_config.specific_users_text || ''}
                    onChange={e => setForm({ ...form, scan_config: { ...form.scan_config, specific_users_text: e.target.value } })}
                    className={cn(inputClass, 'font-mono')}
                  />
                  <p className="text-xs text-text-muted mt-1">Enter one email address per line</p>
                </div>
              )}
            </div>

            {(createMutation.isError || updateMutation.isError) && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-sm text-red-400">
                {String((createMutation.error as any)?.response?.data?.error?.message || (updateMutation.error as any)?.response?.data?.error?.message || 'Failed to save schedule. Check all fields are filled.')}
              </div>
            )}

            <div className="flex gap-2 pt-2">
              <button
                type="submit"
                disabled={createMutation.isPending || updateMutation.isPending}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-500 disabled:opacity-50"
              >
                {createMutation.isPending || updateMutation.isPending ? 'Saving...' : editingId ? 'Update' : 'Create'}
              </button>
              <button
                type="button"
                onClick={resetForm}
                className="px-4 py-2 text-sm font-medium text-text-secondary bg-white/[0.03] border border-border-glass rounded-lg hover:text-text-primary hover:border-border-glass-hover"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Scheduled Jobs Table */}
      <div className="glass-panel overflow-hidden">
        <div className="px-6 py-4 border-b border-border-glass flex items-center gap-2">
          <Clock className="w-5 h-5 text-text-muted" />
          <h2 className="text-sm font-semibold text-text-primary">Scheduled Jobs</h2>
        </div>
        <table className="min-w-full divide-y divide-border-glass">
          <thead className="bg-white/[0.02]">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Schedule</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Active</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Last Run</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Next Run</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-text-muted uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-glass">
            {jobs && jobs.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-text-muted">
                  No scheduled jobs. Create one to automate scans.
                </td>
              </tr>
            )}
            {jobs?.map(job => (
              <tr key={job.id} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-6 py-4">
                  <div className="text-sm font-medium text-text-primary">{job.name}</div>
                  {job.description && <div className="text-xs text-text-muted mt-0.5">{job.description}</div>}
                  <div className="text-xs text-text-muted mt-0.5">
                    {job.scan_config?.user_selection === 'specific' && job.scan_config?.specific_users?.length
                      ? `${job.scan_config.specific_users.length} specific user${job.scan_config.specific_users.length > 1 ? 's' : ''}`
                      : job.scan_config?.user_selection === 'limited'
                        ? `Limited to ${job.scan_config?.max_users ?? '?'} users`
                        : 'All users'}
                  </div>
                </td>
                <td className="px-6 py-4">
                  <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-white/[0.05] text-text-secondary">
                    {job.schedule_type}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-text-secondary font-mono">{formatSchedule(job)}</td>
                <td className="px-6 py-4">
                  {job.is_active
                    ? <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-emerald-500/15 text-emerald-400">Active</span>
                    : <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-white/[0.05] text-text-muted">Inactive</span>}
                </td>
                <td className="px-6 py-4 text-sm text-text-muted">{formatDate(job.last_run_at)}</td>
                <td className="px-6 py-4 text-sm text-text-muted">{formatDate(job.next_run_at)}</td>
                <td className="px-6 py-4 text-right">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      onClick={() => runNowMutation.mutate(job.id)}
                      disabled={runNowMutation.isPending}
                      className="p-1.5 text-text-muted hover:text-emerald-400 hover:bg-emerald-500/10 rounded"
                      title="Run Now"
                    >
                      <Play className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => startEdit(job)}
                      className="p-1.5 text-text-muted hover:text-blue-400 hover:bg-blue-500/10 rounded"
                      title="Edit"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    {deleteConfirm === job.id ? (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => deleteMutation.mutate(job.id)}
                          className="px-2 py-1 text-xs font-medium text-red-400 bg-red-500/15 rounded hover:bg-red-500/25"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setDeleteConfirm(null)}
                          className="px-2 py-1 text-xs font-medium text-text-muted bg-white/[0.05] rounded hover:text-text-secondary"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setDeleteConfirm(job.id)}
                        className="p-1.5 text-text-muted hover:text-red-400 hover:bg-red-500/10 rounded"
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
      <div className="glass-panel overflow-hidden">
        <div className="px-6 py-4 border-b border-border-glass flex items-center gap-2">
          <History className="w-5 h-5 text-text-muted" />
          <h2 className="text-sm font-semibold text-text-primary">Execution History</h2>
        </div>
        <table className="min-w-full divide-y divide-border-glass">
          <thead className="bg-white/[0.02]">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Job Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Users</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Duration</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Started At</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-glass">
            {(!historyData?.items || historyData.items.length === 0) && (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-text-muted">
                  No execution history yet.
                </td>
              </tr>
            )}
            {historyData?.items?.map(exec => (
              <tr
                key={exec.id}
                onClick={() => setSelectedScanId(exec.id)}
                className="hover:bg-white/[0.02] cursor-pointer transition-colors"
              >
                <td className="px-6 py-4 text-sm font-medium text-text-primary">{exec.job_name}</td>
                <td className="px-6 py-4">
                  <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${statusColor(exec.status)}`}>
                    {exec.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-text-secondary">
                  <span className="text-emerald-400">{exec.successful_users}</span>
                  {exec.failed_users > 0 && (
                    <span className="text-red-400">/{exec.failed_users} failed</span>
                  )}
                  <span className="text-text-muted"> of {exec.total_users}</span>
                </td>
                <td className="px-6 py-4 text-sm text-text-muted">{formatDuration(exec.duration_seconds)}</td>
                <td className="px-6 py-4 text-sm text-text-muted">{formatDate(exec.started_at)}</td>
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
  const [showSecret, setShowSecret] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const { data: channels, isLoading, error } = useQuery<NotificationChannel[]>({
    queryKey: ['notification-channels'],
    queryFn: () => api.get('/notifications/channels').then(r => r.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: ChannelForm) => {
      const headersObj: Record<string, string> = {};
      data.custom_headers.forEach(h => { if (h.key.trim()) headersObj[h.key.trim()] = h.value; });
      const payload: Record<string, unknown> = {
        name: data.name,
        channel_type: data.channel_type,
        webhook_url: data.webhook_url,
        events: data.events,
        is_active: data.is_active,
        custom_headers: Object.keys(headersObj).length > 0 ? headersObj : null,
      };
      if (data.hmac_secret) payload.hmac_secret = data.hmac_secret;
      return api.post('/notifications/channels', payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
      resetForm();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: ChannelForm }) => {
      const headersObj: Record<string, string> = {};
      data.custom_headers.forEach(h => { if (h.key.trim()) headersObj[h.key.trim()] = h.value; });
      const payload: Record<string, unknown> = {
        name: data.name,
        webhook_url: data.webhook_url,
        events: data.events,
        is_active: data.is_active,
        custom_headers: Object.keys(headersObj).length > 0 ? headersObj : null,
      };
      if (data.hmac_secret) payload.hmac_secret = data.hmac_secret;
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

  const toggleActiveMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      api.put(`/notifications/channels/${id}`, { is_active }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
    },
  });

  function resetForm() {
    setShowForm(false);
    setEditingId(null);
    setForm(emptyChannelForm);
    setShowSecret(false);
    setShowAdvanced(false);
  }

  function startEdit(ch: NotificationChannel) {
    const headers = ch.custom_headers
      ? Object.entries(ch.custom_headers).map(([key, value]) => ({ key, value }))
      : [];
    setEditingId(ch.id);
    setShowForm(true);
    setShowAdvanced(headers.length > 0 || ch.has_secret);
    setForm({
      name: ch.name,
      channel_type: ch.channel_type,
      webhook_url: ch.webhook_url,
      events: ch.events,
      is_active: ch.is_active,
      hmac_secret: '',
      custom_headers: headers,
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

  function addHeader() {
    setForm(prev => ({ ...prev, custom_headers: [...prev.custom_headers, { key: '', value: '' }] }));
  }

  function removeHeader(index: number) {
    setForm(prev => ({
      ...prev,
      custom_headers: prev.custom_headers.filter((_, i) => i !== index),
    }));
  }

  function updateHeader(index: number, field: 'key' | 'value', val: string) {
    setForm(prev => ({
      ...prev,
      custom_headers: prev.custom_headers.map((h, i) => i === index ? { ...h, [field]: val } : h),
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

  function severityDot(severity: string) {
    const colors: Record<string, string> = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      warning: 'bg-yellow-500',
      info: 'bg-blue-500',
    };
    return colors[severity] || 'bg-gray-400';
  }

  const inputClass = 'w-full px-3 py-2 bg-bg-input border border-border-glass rounded-lg text-sm text-text-primary focus:border-accent focus:ring-2 focus:ring-accent-glow outline-none';

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[0, 1].map(i => (
          <div key={i} className="glass-panel p-6 animate-pulse">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-white/[0.05]" />
              <div className="flex-1 space-y-2">
                <div className="h-4 w-32 bg-white/[0.05] rounded" />
                <div className="h-3 w-64 bg-white/[0.05] rounded" />
              </div>
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">Failed to load notification channels.</div>;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-text-secondary">
            Configure webhook endpoints to receive real-time notifications for security events.
          </p>
          <p className="text-xs text-text-muted mt-1">
            Webhooks follow the <span className="font-medium">Standard Webhooks</span> spec with HMAC-SHA256 signing and automatic retries.
          </p>
        </div>
        {!showForm && (
          <button
            onClick={() => { resetForm(); setShowForm(true); }}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-500 shrink-0"
          >
            <Plus className="w-4 h-4" />
            Add Webhook
          </button>
        )}
      </div>

      {/* Create/Edit Form */}
      {showForm && (
        <div className="glass-panel overflow-hidden">
          <div className="px-6 py-4 border-b border-border-glass flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text-primary">
              {editingId ? 'Edit Webhook' : 'New Webhook'}
            </h2>
            <button onClick={resetForm} className="p-1 text-text-muted hover:text-text-secondary rounded">
              <X className="w-4 h-4" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="p-6 space-y-6">
            {/* Name + URL */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-1">Name</label>
                <input
                  type="text"
                  required
                  value={form.name}
                  onChange={e => setForm({ ...form, name: e.target.value })}
                  className={inputClass}
                  placeholder="e.g., Slack - #security-alerts"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-1">
                  Endpoint URL
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Link2 className="w-4 h-4 text-text-muted" />
                  </div>
                  <input
                    type="url"
                    required
                    value={form.webhook_url}
                    onChange={e => setForm({ ...form, webhook_url: e.target.value })}
                    className={cn(inputClass, 'pl-9 font-mono')}
                    placeholder="https://hooks.example.com/webhooks/..."
                  />
                </div>
              </div>
            </div>

            {/* Event Subscriptions */}
            <div>
              <label className="block text-sm font-medium text-text-secondary mb-3">Event Subscriptions</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {EVENT_OPTIONS.map(opt => {
                  const isSelected = form.events.includes(opt.value);
                  return (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => toggleEvent(opt.value)}
                      className={cn(
                        'flex items-start gap-3 p-3 rounded-lg border transition-all text-left',
                        isSelected
                          ? 'border-blue-500/30 bg-blue-500/10'
                          : 'border-border-glass hover:border-border-glass-hover'
                      )}
                    >
                      <div className="mt-0.5">
                        <div className={cn(
                          'w-4 h-4 rounded border-2 flex items-center justify-center transition-colors',
                          isSelected
                            ? 'bg-blue-600 border-blue-600'
                            : 'border-border-glass-hover'
                        )}>
                          {isSelected && (
                            <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                            </svg>
                          )}
                        </div>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={cn('w-1.5 h-1.5 rounded-full', severityDot(opt.severity))} />
                          <span className={cn('text-sm font-medium', isSelected ? 'text-text-primary' : 'text-text-secondary')}>
                            {opt.label}
                          </span>
                        </div>
                        <p className="text-xs text-text-muted mt-0.5">{opt.description}</p>
                      </div>
                    </button>
                  );
                })}
              </div>
              {form.events.length === 0 && (
                <p className="text-xs text-amber-400 mt-2 flex items-center gap-1">
                  <Info className="w-3 h-3" /> Select at least one event to receive notifications.
                </p>
              )}
            </div>

            {/* Advanced Settings Toggle */}
            <div>
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="flex items-center gap-2 text-sm font-medium text-text-muted hover:text-text-secondary transition-colors"
              >
                {showAdvanced ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                Advanced Settings
              </button>

              {showAdvanced && (
                <div className="mt-4 space-y-4 pl-0">
                  {/* Signing Secret */}
                  <div>
                    <label className="flex items-center gap-2 text-sm font-medium text-text-secondary mb-1">
                      <Key className="w-3.5 h-3.5 text-text-muted" />
                      Signing Secret
                      <span className="text-xs text-text-muted font-normal">(HMAC-SHA256)</span>
                    </label>
                    {editingId && !form.hmac_secret && (
                      <p className="text-xs text-text-muted mb-1.5">
                        {(channels?.find(c => c.id === editingId)?.has_secret)
                          ? 'A signing secret is configured. Enter a new value to replace it, or leave blank to keep.'
                          : 'No signing secret configured.'}
                      </p>
                    )}
                    <div className="relative">
                      <input
                        type={showSecret ? 'text' : 'password'}
                        value={form.hmac_secret}
                        onChange={e => setForm({ ...form, hmac_secret: e.target.value })}
                        className={cn(inputClass, 'pr-10 font-mono')}
                        placeholder="whsec_..."
                      />
                      <button
                        type="button"
                        onClick={() => setShowSecret(!showSecret)}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center text-text-muted hover:text-text-secondary"
                      >
                        {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    <p className="text-xs text-text-muted mt-1">
                      Payloads are signed with <code className="px-1 py-0.5 bg-white/[0.05] rounded text-xs">Webhook-Signature</code> header per Standard Webhooks spec.
                    </p>
                  </div>

                  {/* Custom Headers */}
                  <div>
                    <label className="flex items-center gap-2 text-sm font-medium text-text-secondary mb-2">
                      <Hash className="w-3.5 h-3.5 text-text-muted" />
                      Custom Headers
                    </label>
                    <div className="space-y-2">
                      {form.custom_headers.map((header, i) => (
                        <div key={i} className="flex items-center gap-2">
                          <input
                            type="text"
                            value={header.key}
                            onChange={e => updateHeader(i, 'key', e.target.value)}
                            className={cn(inputClass, 'w-1/3 font-mono')}
                            placeholder="Header-Name"
                          />
                          <input
                            type="text"
                            value={header.value}
                            onChange={e => updateHeader(i, 'value', e.target.value)}
                            className={cn(inputClass, 'flex-1 font-mono')}
                            placeholder="value"
                          />
                          <button
                            type="button"
                            onClick={() => removeHeader(i)}
                            className="p-2 text-text-muted hover:text-red-400 rounded hover:bg-red-500/10"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        </div>
                      ))}
                      <button
                        type="button"
                        onClick={addHeader}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-text-muted border border-dashed border-border-glass rounded-lg hover:border-border-glass-hover hover:text-text-secondary transition-colors"
                      >
                        <Plus className="w-3 h-3" />
                        Add Header
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Error display */}
            {(createMutation.isError || updateMutation.isError) && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-sm text-red-400">
                {String((createMutation.error as any)?.response?.data?.error?.message || (updateMutation.error as any)?.response?.data?.error?.message || 'Failed to save webhook. Check all fields.')}
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-between pt-2 border-t border-border-glass">
              <label className="flex items-center gap-2 text-sm text-text-secondary">
                <button
                  type="button"
                  onClick={() => setForm(prev => ({ ...prev, is_active: !prev.is_active }))}
                  className={cn(
                    'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors',
                    form.is_active ? 'bg-blue-600' : 'bg-white/[0.1]'
                  )}
                >
                  <span className={cn(
                    'pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition-transform',
                    form.is_active ? 'translate-x-4' : 'translate-x-0'
                  )} />
                </button>
                {form.is_active ? 'Enabled' : 'Disabled'}
              </label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={resetForm}
                  className="px-4 py-2 text-sm font-medium text-text-secondary bg-white/[0.03] border border-border-glass rounded-lg hover:text-text-primary hover:border-border-glass-hover"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || updateMutation.isPending || form.events.length === 0}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {createMutation.isPending || updateMutation.isPending ? 'Saving...' : editingId ? 'Save Changes' : 'Create Webhook'}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* Channel Cards */}
      {channels && channels.length === 0 && !showForm ? (
        <div className="glass-panel border-dashed p-12 text-center">
          <div className="mx-auto w-12 h-12 rounded-full bg-white/[0.05] flex items-center justify-center mb-4">
            <Bell className="w-6 h-6 text-text-muted" />
          </div>
          <h3 className="text-sm font-semibold text-text-primary mb-1">No webhooks configured</h3>
          <p className="text-sm text-text-muted mb-4 max-w-sm mx-auto">
            Add a webhook to receive real-time alerts for scan results, new vulnerabilities, and security events.
          </p>
          <button
            onClick={() => { resetForm(); setShowForm(true); }}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-500"
          >
            <Plus className="w-4 h-4" />
            Add Your First Webhook
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {channels?.map(ch => {
            const headersCount = ch.custom_headers ? Object.keys(ch.custom_headers).length : 0;

            return (
              <div
                key={ch.id}
                className={cn(
                  'glass-panel transition-colors',
                  !ch.is_active && 'opacity-60'
                )}
              >
                <div className="p-5">
                  {/* Top Row: Icon, Name, Toggle, Actions */}
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3 min-w-0 flex-1">
                      <div className={cn(
                        'w-9 h-9 rounded-lg flex items-center justify-center shrink-0',
                        ch.is_active
                          ? 'bg-blue-500/15'
                          : 'bg-white/[0.05]'
                      )}>
                        <Globe className={cn(
                          'w-4.5 h-4.5',
                          ch.is_active ? 'text-blue-400' : 'text-text-muted'
                        )} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <h3 className="text-sm font-semibold text-text-primary truncate">{ch.name}</h3>
                          <span className={cn(
                            'inline-flex items-center px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider rounded',
                            ch.is_active
                              ? 'bg-emerald-500/15 text-emerald-400'
                              : 'bg-white/[0.05] text-text-muted'
                          )}>
                            {ch.is_active ? 'Active' : 'Paused'}
                          </span>
                        </div>
                        <p className="text-xs text-text-muted font-mono mt-0.5 truncate">{ch.webhook_url}</p>
                      </div>
                    </div>

                    <div className="flex items-center gap-1 shrink-0">
                      {/* Toggle Active */}
                      <button
                        onClick={() => toggleActiveMutation.mutate({ id: ch.id, is_active: !ch.is_active })}
                        className={cn(
                          'p-1.5 rounded transition-colors',
                          ch.is_active
                            ? 'text-emerald-400 hover:bg-emerald-500/10'
                            : 'text-text-muted hover:bg-white/[0.05]'
                        )}
                        title={ch.is_active ? 'Pause webhook' : 'Enable webhook'}
                      >
                        <Power className="w-4 h-4" />
                      </button>

                      {/* Test */}
                      <button
                        onClick={() => handleTest(ch.id)}
                        disabled={testResults[ch.id] === 'loading'}
                        className="p-1.5 text-text-muted hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors"
                        title="Send test event"
                      >
                        {testResults[ch.id] === 'loading' ? (
                          <Send className="w-4 h-4 animate-pulse text-blue-400" />
                        ) : testResults[ch.id] === 'success' ? (
                          <CheckCircle className="w-4 h-4 text-emerald-400" />
                        ) : testResults[ch.id] === 'error' ? (
                          <XCircle className="w-4 h-4 text-red-400" />
                        ) : (
                          <Send className="w-4 h-4" />
                        )}
                      </button>

                      {/* Edit */}
                      <button
                        onClick={() => startEdit(ch)}
                        className="p-1.5 text-text-muted hover:text-text-secondary hover:bg-white/[0.05] rounded transition-colors"
                        title="Edit"
                      >
                        <Pencil className="w-4 h-4" />
                      </button>

                      {/* Delete */}
                      {deleteConfirm === ch.id ? (
                        <div className="flex items-center gap-1 ml-1">
                          <button
                            onClick={() => deleteMutation.mutate(ch.id)}
                            className="px-2 py-1 text-xs font-medium text-red-400 bg-red-500/15 rounded hover:bg-red-500/25"
                          >
                            Delete
                          </button>
                          <button
                            onClick={() => setDeleteConfirm(null)}
                            className="px-2 py-1 text-xs font-medium text-text-muted bg-white/[0.05] rounded hover:text-text-secondary"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setDeleteConfirm(ch.id)}
                          className="p-1.5 text-text-muted hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Bottom Row: Events + Metadata */}
                  <div className="mt-3 flex items-center justify-between gap-4">
                    <div className="flex flex-wrap gap-1.5">
                      {ch.events.map(ev => {
                        const eventInfo = EVENT_OPTIONS.find(e => e.value === ev);
                        return (
                          <span
                            key={ev}
                            className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full bg-white/[0.05] text-text-secondary"
                          >
                            {eventInfo && <span className={cn('w-1 h-1 rounded-full', severityDot(eventInfo.severity))} />}
                            {ev.replace(/_/g, ' ')}
                          </span>
                        );
                      })}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-text-muted shrink-0">
                      {ch.has_secret && (
                        <span className="flex items-center gap-1" title="Signing secret configured">
                          <Key className="w-3 h-3" /> Signed
                        </span>
                      )}
                      {headersCount > 0 && (
                        <span className="flex items-center gap-1" title={`${headersCount} custom header(s)`}>
                          <Hash className="w-3 h-3" /> {headersCount} header{headersCount > 1 ? 's' : ''}
                        </span>
                      )}
                      <span>{formatDate(ch.created_at)}</span>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
