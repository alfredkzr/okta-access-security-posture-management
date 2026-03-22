import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Pencil, Trash2, Download, Upload, Check, X } from 'lucide-react';
import api from '../lib/api';
import type { Scenario } from '../lib/api';
import { formatDate } from '../lib/utils';

const RISK_LEVELS = ['', 'LOW', 'MEDIUM', 'HIGH'] as const;
const RISK_LABELS: Record<string, string> = { '': 'None (default)', 'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH' };
const PLATFORMS = ['WINDOWS', 'MACOS', 'CHROMEOS', 'ANDROID', 'IOS', 'DESKTOP_OTHER', 'MOBILE_OTHER'] as const;

/** Distinct styling for Okta risk signal level — uses blue/purple/indigo tones
 *  to differentiate from severity badges (which use red/orange/yellow/green). */
function oktaRiskBadge(level: string) {
  switch (level.toUpperCase()) {
    case 'HIGH': return 'bg-purple-500/15 text-purple-400 border-purple-500/20';
    case 'MEDIUM': return 'bg-indigo-500/15 text-indigo-400 border-indigo-500/20';
    case 'LOW': return 'bg-sky-500/15 text-sky-400 border-sky-500/20';
    default: return 'bg-white/[0.03] text-text-muted border-border-glass';
  }
}

type NetworkMode = 'none' | 'ip' | 'zone';

interface ScenarioForm {
  name: string;
  description: string;
  risk_level: string;
  device_platform: string;
  device_registered: boolean;
  device_managed: boolean;
  device_assurance_id: string;
  network_mode: NetworkMode;
  ip_address: string;
  zone_ids: string;
  is_active: boolean;
}

const emptyForm: ScenarioForm = {
  name: '',
  description: '',
  risk_level: '',
  device_platform: 'WINDOWS',
  device_registered: false,
  device_managed: false,
  device_assurance_id: '',
  network_mode: 'none',
  ip_address: '',
  zone_ids: '',
  is_active: true,
};

/** Convert form state to API payload */
function formToPayload(form: ScenarioForm) {
  return {
    name: form.name,
    description: form.description || undefined,
    is_active: form.is_active,
    risk_level: form.risk_level || null,
    device_platform: form.device_platform,
    device_registered: form.device_registered,
    device_managed: form.device_managed,
    device_assurance_id: form.device_assurance_id || null,
    ip_address: form.network_mode === 'ip' && form.ip_address ? form.ip_address : null,
    zone_ids: form.network_mode === 'zone' && form.zone_ids
      ? form.zone_ids.split(',').map(z => z.trim()).filter(Boolean)
      : null,
  };
}

/** Convert API scenario to form state */
function scenarioToForm(s: Scenario): ScenarioForm {
  let networkMode: NetworkMode = 'none';
  if (s.ip_address) networkMode = 'ip';
  else if (s.zone_ids && s.zone_ids.length > 0) networkMode = 'zone';

  return {
    name: s.name,
    description: s.description || '',
    risk_level: s.risk_level || '',
    device_platform: s.device_platform,
    device_registered: s.device_registered,
    device_managed: s.device_managed ?? false,
    device_assurance_id: s.device_assurance_id || '',
    network_mode: networkMode,
    ip_address: s.ip_address || '',
    zone_ids: s.zone_ids ? s.zone_ids.join(', ') : '',
    is_active: s.is_active,
  };
}

/** Summarize network context for table display */
function networkSummary(s: Scenario): string {
  if (s.ip_address) return s.ip_address;
  if (s.zone_ids && s.zone_ids.length > 0) return `${s.zone_ids.length} zone(s)`;
  return '\u2014';
}

export default function Scenarios() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<ScenarioForm>(emptyForm);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  const { data: scenarios, isLoading, error } = useQuery<Scenario[]>({
    queryKey: ['scenarios'],
    queryFn: () => api.get('/scenarios').then(r => r.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: ScenarioForm) => api.post('/scenarios', formToPayload(data)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scenarios'] });
      resetForm();
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : 'Failed to create scenario';
      setFormError(msg);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: ScenarioForm }) => api.put(`/scenarios/${id}`, formToPayload(data)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scenarios'] });
      setFormSuccess('Scenario updated successfully');
      setTimeout(() => { setFormSuccess(null); resetForm(); }, 1200);
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : 'Failed to update scenario';
      setFormError(msg);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/scenarios/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scenarios'] });
      setDeleteConfirm(null);
    },
  });

  const [resetConfirm, setResetConfirm] = useState(false);

  const resetMutation = useMutation({
    mutationFn: () => api.post('/scenarios/reset'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scenarios'] });
      setResetConfirm(false);
    },
  });

  function resetForm() {
    setShowForm(false);
    setEditingId(null);
    setForm(emptyForm);
    setFormError(null);
    setFormSuccess(null);
  }

  function startEdit(s: Scenario) {
    setEditingId(s.id);
    setShowForm(true);
    setFormError(null);
    setFormSuccess(null);
    setForm(scenarioToForm(s));
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);
    if (editingId) {
      updateMutation.mutate({ id: editingId, data: form });
    } else {
      createMutation.mutate(form);
    }
  }

  async function handleExport() {
    try {
      const res = await api.get('/scenarios/export');
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'scenarios.json';
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // error handled silently
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-text-muted">Loading scenarios...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
        Failed to load scenarios. Please try again.
      </div>
    );
  }

  const inputClass = 'w-full px-3 py-2 bg-bg-input border border-border-glass rounded-lg text-sm text-text-primary focus:border-accent focus:ring-2 focus:ring-accent-glow outline-none';
  const labelClass = 'block text-sm font-medium text-text-secondary mb-1';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Risk Scenarios</h1>
          <p className="text-sm text-text-secondary mt-1">Configure risk scenarios for Okta policy simulation</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-text-secondary bg-white/[0.03] border border-border-glass rounded-lg hover:text-text-primary hover:border-border-glass-hover"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
          {resetConfirm ? (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 border border-red-500/20 rounded-lg">
              <span className="text-sm text-red-400">Delete all scenarios and reset?</span>
              <button
                onClick={() => resetMutation.mutate()}
                disabled={resetMutation.isPending}
                className="px-3 py-1 text-xs font-medium text-white bg-red-600 rounded hover:bg-red-700 disabled:opacity-50"
              >
                {resetMutation.isPending ? 'Resetting...' : 'Yes, reset'}
              </button>
              <button
                onClick={() => setResetConfirm(false)}
                className="px-3 py-1 text-xs font-medium text-text-muted bg-white/[0.05] rounded hover:text-text-secondary"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setResetConfirm(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-text-secondary bg-white/[0.03] border border-border-glass rounded-lg hover:text-text-primary hover:border-border-glass-hover"
            >
              <Upload className="w-4 h-4" />
              Reset to Defaults
            </button>
          )}
          <button
            onClick={() => { resetForm(); setShowForm(true); }}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-500"
          >
            <Plus className="w-4 h-4" />
            New Scenario
          </button>
        </div>
      </div>

      {showForm && (
        <div className="glass-panel p-6">
          <h2 className="text-lg font-semibold text-text-primary mb-4">
            {editingId ? 'Edit Scenario' : 'New Scenario'}
          </h2>
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Row 1: Name + Description */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className={labelClass}>Name</label>
                <input
                  type="text"
                  required
                  value={form.name}
                  onChange={e => setForm({ ...form, name: e.target.value })}
                  className={inputClass}
                  placeholder="e.g. Personal Windows, High Risk, External IP"
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

            {/* Row 2: Risk Level + Device Platform */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className={labelClass}>
                  Okta Risk Level
                  <span className="text-xs font-normal text-text-muted ml-1">(risk signal)</span>
                </label>
                <select
                  value={form.risk_level}
                  onChange={e => setForm({ ...form, risk_level: e.target.value })}
                  className={inputClass}
                >
                  {RISK_LEVELS.map(l => <option key={l} value={l}>{RISK_LABELS[l]}</option>)}
                </select>
                <p className="text-xs text-text-muted mt-1">Simulates the Okta risk engine signal level</p>
              </div>
              <div>
                <label className={labelClass}>Device Platform</label>
                <select
                  value={form.device_platform}
                  onChange={e => setForm({ ...form, device_platform: e.target.value })}
                  className={inputClass}
                >
                  {PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
            </div>

            {/* Row 3: Device state checkboxes + Device Assurance */}
            <div className="grid grid-cols-3 gap-4">
              <div className="flex items-end gap-6">
                <label className="flex items-center gap-2 text-sm text-text-secondary">
                  <input
                    type="checkbox"
                    checked={form.device_registered}
                    onChange={e => setForm({ ...form, device_registered: e.target.checked })}
                    className="rounded border-border-glass bg-bg-input"
                  />
                  Registered
                </label>
                <label className="flex items-center gap-2 text-sm text-text-secondary">
                  <input
                    type="checkbox"
                    checked={form.device_managed}
                    onChange={e => setForm({ ...form, device_managed: e.target.checked })}
                    className="rounded border-border-glass bg-bg-input"
                  />
                  Managed
                </label>
              </div>
              <div>
                <label className={labelClass}>
                  Device Assurance Policy ID
                  <span className="text-xs font-normal text-text-muted ml-1">(optional)</span>
                </label>
                <input
                  type="text"
                  value={form.device_assurance_id}
                  onChange={e => setForm({ ...form, device_assurance_id: e.target.value })}
                  className={inputClass}
                  placeholder="e.g. dap5x8z1qY4m2gKHj0h7"
                />
              </div>
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

            {/* Row 4: Network context (IP or Zone — mutually exclusive) */}
            <div>
              <label className={labelClass}>
                Network Context
                <span className="text-xs font-normal text-text-muted ml-1">(IP and zones are mutually exclusive in the Okta API)</span>
              </label>
              <div className="flex items-center gap-4 mb-2">
                <label className="flex items-center gap-2 text-sm text-text-secondary">
                  <input
                    type="radio"
                    name="network_mode"
                    checked={form.network_mode === 'none'}
                    onChange={() => setForm({ ...form, network_mode: 'none' })}
                    className="border-border-glass bg-bg-input"
                  />
                  No network context
                </label>
                <label className="flex items-center gap-2 text-sm text-text-secondary">
                  <input
                    type="radio"
                    name="network_mode"
                    checked={form.network_mode === 'ip'}
                    onChange={() => setForm({ ...form, network_mode: 'ip' })}
                    className="border-border-glass bg-bg-input"
                  />
                  IP Address
                </label>
                <label className="flex items-center gap-2 text-sm text-text-secondary">
                  <input
                    type="radio"
                    name="network_mode"
                    checked={form.network_mode === 'zone'}
                    onChange={() => setForm({ ...form, network_mode: 'zone' })}
                    className="border-border-glass bg-bg-input"
                  />
                  Network Zone(s)
                </label>
              </div>
              {form.network_mode === 'ip' && (
                <input
                  type="text"
                  value={form.ip_address}
                  onChange={e => setForm({ ...form, ip_address: e.target.value })}
                  className={inputClass}
                  placeholder="e.g. 203.0.113.42"
                />
              )}
              {form.network_mode === 'zone' && (
                <div>
                  <input
                    type="text"
                    value={form.zone_ids}
                    onChange={e => setForm({ ...form, zone_ids: e.target.value })}
                    className={inputClass}
                    placeholder="e.g. nzo1a2b3c4d5e6f7g8, nzo9h8g7f6e5d4c3b2"
                  />
                  <p className="text-xs text-text-muted mt-1">Comma-separated Okta network zone IDs. Dynamic zones are not supported.</p>
                </div>
              )}
            </div>

            {formError && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-2 text-sm text-red-400">{formError}</div>
            )}
            {formSuccess && (
              <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-4 py-2 text-sm text-emerald-400">{formSuccess}</div>
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

      <div className="glass-panel overflow-hidden">
        <table className="min-w-full divide-y divide-border-glass">
          <thead className="bg-white/[0.02]">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Okta Risk</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Platform</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Registered</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Managed</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Network</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Active</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase tracking-wider">Created</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-text-muted uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-glass">
            {scenarios && scenarios.length === 0 && (
              <tr>
                <td colSpan={9} className="px-6 py-12 text-center text-text-muted">
                  No scenarios found. Create one or import defaults.
                </td>
              </tr>
            )}
            {scenarios?.map(s => (
              <tr key={s.id} className="hover:bg-white/[0.02] transition-colors">
                <td className="px-6 py-4 text-sm font-medium text-text-primary max-w-[200px] truncate" title={s.name}>{s.name}</td>
                <td className="px-6 py-4">
                  {s.risk_level ? (
                    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full border ${oktaRiskBadge(s.risk_level)}`}>
                      {s.risk_level}
                    </span>
                  ) : (
                    <span className="text-sm text-text-muted">{'\u2014'}</span>
                  )}
                </td>
                <td className="px-6 py-4 text-sm text-text-secondary">{s.device_platform}</td>
                <td className="px-6 py-4">
                  {s.device_registered ? <Check className="w-4 h-4 text-emerald-400" /> : <X className="w-4 h-4 text-text-muted" />}
                </td>
                <td className="px-6 py-4">
                  {s.device_managed ? <Check className="w-4 h-4 text-emerald-400" /> : <X className="w-4 h-4 text-text-muted" />}
                </td>
                <td className="px-6 py-4 text-sm text-text-secondary">{networkSummary(s)}</td>
                <td className="px-6 py-4">
                  {s.is_active
                    ? <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-emerald-500/15 text-emerald-400">Active</span>
                    : <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-white/[0.05] text-text-muted">Inactive</span>}
                </td>
                <td className="px-6 py-4 text-sm text-text-muted">{formatDate(s.created_at)}</td>
                <td className="px-6 py-4 text-right">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => startEdit(s)}
                      className="p-1.5 text-text-muted hover:text-blue-400 hover:bg-blue-500/10 rounded"
                      title="Edit"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    {deleteConfirm === s.id ? (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => deleteMutation.mutate(s.id)}
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
                        onClick={() => setDeleteConfirm(s.id)}
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
    </div>
  );
}
