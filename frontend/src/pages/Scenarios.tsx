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
    case 'HIGH': return 'bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-900/30 dark:text-purple-400 dark:border-purple-700';
    case 'MEDIUM': return 'bg-indigo-100 text-indigo-800 border-indigo-300 dark:bg-indigo-900/30 dark:text-indigo-400 dark:border-indigo-700';
    case 'LOW': return 'bg-sky-100 text-sky-800 border-sky-300 dark:bg-sky-900/30 dark:text-sky-400 dark:border-sky-700';
    default: return 'bg-gray-100 text-gray-800 border-gray-300 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600';
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

const DEFAULT_SCENARIOS: Omit<ScenarioForm, 'is_active' | 'network_mode'>[] = [
  { name: 'Personal Windows', description: 'Simulates access from an unregistered, unmanaged Windows device.', risk_level: '', device_platform: 'WINDOWS', device_registered: false, device_managed: false, device_assurance_id: '', ip_address: '', zone_ids: '' },
  { name: 'Personal macOS', description: 'Simulates access from an unregistered, unmanaged macOS device.', risk_level: '', device_platform: 'MACOS', device_registered: false, device_managed: false, device_assurance_id: '', ip_address: '', zone_ids: '' },
  { name: 'Personal ChromeOS', description: 'Simulates access from an unregistered, unmanaged ChromeOS device.', risk_level: '', device_platform: 'CHROMEOS', device_registered: false, device_managed: false, device_assurance_id: '', ip_address: '', zone_ids: '' },
  { name: 'Personal Android', description: 'Simulates access from an unregistered, unmanaged Android device.', risk_level: '', device_platform: 'ANDROID', device_registered: false, device_managed: false, device_assurance_id: '', ip_address: '', zone_ids: '' },
  { name: 'Personal iOS', description: 'Simulates access from an unregistered, unmanaged iOS device.', risk_level: '', device_platform: 'IOS', device_registered: false, device_managed: false, device_assurance_id: '', ip_address: '', zone_ids: '' },
  { name: 'Unknown Desktop', description: 'Simulates access from an unknown desktop device.', risk_level: '', device_platform: 'DESKTOP_OTHER', device_registered: false, device_managed: false, device_assurance_id: '', ip_address: '', zone_ids: '' },
  { name: 'Unknown Mobile', description: 'Simulates access from an unknown mobile device.', risk_level: '', device_platform: 'MOBILE_OTHER', device_registered: false, device_managed: false, device_assurance_id: '', ip_address: '', zone_ids: '' },
];

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
  return '—';
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
        <div className="text-gray-500 dark:text-gray-400">Loading scenarios...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400">
        Failed to load scenarios. Please try again.
      </div>
    );
  }

  const inputClass = 'w-full px-3 py-2 border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none';
  const labelClass = 'block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Risk Scenarios</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Configure risk scenarios for Okta policy simulation</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
          {resetConfirm ? (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-red-50 dark:bg-red-900/20 border border-red-300 dark:border-red-700 rounded-lg">
              <span className="text-sm text-red-700 dark:text-red-400">Delete all scenarios and reset?</span>
              <button
                onClick={() => resetMutation.mutate()}
                disabled={resetMutation.isPending}
                className="px-3 py-1 text-xs font-medium text-white bg-red-600 rounded hover:bg-red-700 disabled:opacity-50"
              >
                {resetMutation.isPending ? 'Resetting...' : 'Yes, reset'}
              </button>
              <button
                onClick={() => setResetConfirm(false)}
                className="px-3 py-1 text-xs font-medium text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 rounded hover:bg-gray-200 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setResetConfirm(true)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800"
            >
              <Upload className="w-4 h-4" />
              Reset to Defaults
            </button>
          )}
          <button
            onClick={() => { resetForm(); setShowForm(true); }}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700"
          >
            <Plus className="w-4 h-4" />
            New Scenario
          </button>
        </div>
      </div>

      {showForm && (
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
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
                  <span className="text-xs font-normal text-gray-400 dark:text-gray-500 ml-1">(risk signal)</span>
                </label>
                <select
                  value={form.risk_level}
                  onChange={e => setForm({ ...form, risk_level: e.target.value })}
                  className={inputClass}
                >
                  {RISK_LEVELS.map(l => <option key={l} value={l}>{RISK_LABELS[l]}</option>)}
                </select>
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">Simulates the Okta risk engine signal level</p>
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
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <input
                    type="checkbox"
                    checked={form.device_registered}
                    onChange={e => setForm({ ...form, device_registered: e.target.checked })}
                    className="rounded border-gray-300"
                  />
                  Registered
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <input
                    type="checkbox"
                    checked={form.device_managed}
                    onChange={e => setForm({ ...form, device_managed: e.target.checked })}
                    className="rounded border-gray-300"
                  />
                  Managed
                </label>
              </div>
              <div>
                <label className={labelClass}>
                  Device Assurance Policy ID
                  <span className="text-xs font-normal text-gray-400 dark:text-gray-500 ml-1">(optional)</span>
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
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
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

            {/* Row 4: Network context (IP or Zone — mutually exclusive) */}
            <div>
              <label className={labelClass}>
                Network Context
                <span className="text-xs font-normal text-gray-400 dark:text-gray-500 ml-1">(IP and zones are mutually exclusive in the Okta API)</span>
              </label>
              <div className="flex items-center gap-4 mb-2">
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <input
                    type="radio"
                    name="network_mode"
                    checked={form.network_mode === 'none'}
                    onChange={() => setForm({ ...form, network_mode: 'none' })}
                    className="border-gray-300"
                  />
                  No network context
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <input
                    type="radio"
                    name="network_mode"
                    checked={form.network_mode === 'ip'}
                    onChange={() => setForm({ ...form, network_mode: 'ip' })}
                    className="border-gray-300"
                  />
                  IP Address
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                  <input
                    type="radio"
                    name="network_mode"
                    checked={form.network_mode === 'zone'}
                    onChange={() => setForm({ ...form, network_mode: 'zone' })}
                    className="border-gray-300"
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
                  <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">Comma-separated Okta network zone IDs. Dynamic zones are not supported.</p>
                </div>
              )}
            </div>

            {formError && (
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg px-4 py-2 text-sm text-red-700 dark:text-red-400">{formError}</div>
            )}
            {formSuccess && (
              <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg px-4 py-2 text-sm text-green-700 dark:text-green-400">{formSuccess}</div>
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

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50 dark:bg-gray-800/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Okta Risk</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Platform</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Registered</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Managed</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Network</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Active</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Created</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-800">
            {scenarios && scenarios.length === 0 && (
              <tr>
                <td colSpan={9} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                  No scenarios found. Create one or import defaults.
                </td>
              </tr>
            )}
            {scenarios?.map(s => (
              <tr key={s.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-gray-100 max-w-[200px] truncate" title={s.name}>{s.name}</td>
                <td className="px-6 py-4">
                  {s.risk_level ? (
                    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full border ${oktaRiskBadge(s.risk_level)}`}>
                      {s.risk_level}
                    </span>
                  ) : (
                    <span className="text-sm text-gray-400 dark:text-gray-500">—</span>
                  )}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{s.device_platform}</td>
                <td className="px-6 py-4">
                  {s.device_registered ? <Check className="w-4 h-4 text-green-600" /> : <X className="w-4 h-4 text-gray-400" />}
                </td>
                <td className="px-6 py-4">
                  {s.device_managed ? <Check className="w-4 h-4 text-green-600" /> : <X className="w-4 h-4 text-gray-400" />}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{networkSummary(s)}</td>
                <td className="px-6 py-4">
                  {s.is_active
                    ? <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400">Active</span>
                    : <span className="inline-flex px-2 py-1 text-xs font-medium rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400">Inactive</span>}
                </td>
                <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{formatDate(s.created_at)}</td>
                <td className="px-6 py-4 text-right">
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => startEdit(s)}
                      className="p-1.5 text-gray-400 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded"
                      title="Edit"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    {deleteConfirm === s.id ? (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => deleteMutation.mutate(s.id)}
                          className="px-2 py-1 text-xs font-medium text-red-700 dark:text-red-400 bg-red-100 dark:bg-red-900/30 rounded hover:bg-red-200"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setDeleteConfirm(null)}
                          className="px-2 py-1 text-xs font-medium text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 rounded hover:bg-gray-200"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setDeleteConfirm(s.id)}
                        className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
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
