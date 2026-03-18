import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Trash2, Plus, Send } from 'lucide-react';
import api from '../lib/api';

const EVENTS = ['scan_completed', 'new_vulnerabilities', 'posture_critical', 'token_health'];

export default function Notifications() {
  const qc = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: '', url: '', secret: '', events: [] as string[] });
  const [editId, setEditId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null);

  const { data: channels = [], isLoading } = useQuery({
    queryKey: ['channels'],
    queryFn: () => api.get('/notifications/channels').then(r => r.data),
  });

  const createMut = useMutation({
    mutationFn: (d: typeof form) => api.post('/notifications/channels', {
      name: d.name, channel_type: 'webhook', config: { url: d.url, secret: d.secret || undefined },
      events: d.events, is_active: true,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['channels'] }); resetForm(); },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, ...d }: typeof form & { id: string }) => api.put(`/notifications/channels/${id}`, {
      name: d.name, config: { url: d.url, secret: d.secret || undefined }, events: d.events,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['channels'] }); resetForm(); },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.delete(`/notifications/channels/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['channels'] }),
  });

  const testMut = useMutation({
    mutationFn: (id: string) => api.post(`/notifications/channels/${id}/test`),
    onSuccess: (_, id) => setTestResult({ id, ok: true, msg: 'Test sent!' }),
    onError: (_, id) => setTestResult({ id, ok: false, msg: 'Test failed' }),
  });

  function resetForm() { setForm({ name: '', url: '', secret: '', events: [] }); setShowForm(false); setEditId(null); }
  function startEdit(ch: any) { setForm({ name: ch.name, url: ch.config?.url || '', secret: ch.config?.secret || '', events: ch.events || [] }); setEditId(ch.id); setShowForm(true); }
  function toggleEvent(e: string) { setForm(f => ({ ...f, events: f.events.includes(e) ? f.events.filter(x => x !== e) : [...f.events, e] })); }
  function handleSubmit() { if (editId) updateMut.mutate({ ...form, id: editId }); else createMut.mutate(form); }

  if (isLoading) return <p className="text-gray-500">Loading...</p>;

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Notification Channels</h1>
        <button onClick={() => { resetForm(); setShowForm(!showForm); }} className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm">
          <Plus className="w-4 h-4" />{showForm ? 'Cancel' : 'New Channel'}
        </button>
      </div>
      {showForm && (
        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">{editId ? 'Edit Channel' : 'New Webhook Channel'}</h2>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div><label className="block text-sm font-medium text-gray-700 mb-1">Name</label><input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="Slack Security" /></div>
            <div><label className="block text-sm font-medium text-gray-700 mb-1">Webhook URL</label><input value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" placeholder="https://hooks.slack.com/..." /></div>
          </div>
          <div className="mb-4"><label className="block text-sm font-medium text-gray-700 mb-1">HMAC Secret (optional)</label><input value={form.secret} onChange={e => setForm(f => ({ ...f, secret: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" /></div>
          <div className="mb-4"><label className="block text-sm font-medium text-gray-700 mb-2">Events</label><div className="flex gap-3 flex-wrap">{EVENTS.map(e => (<label key={e} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.events.includes(e)} onChange={() => toggleEvent(e)} className="rounded border-gray-300" />{e}</label>))}</div></div>
          <button onClick={handleSubmit} disabled={!form.name || !form.url || form.events.length === 0} className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm disabled:opacity-50">{editId ? 'Update' : 'Create'}</button>
        </div>
      )}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-200"><tr><th className="text-left px-6 py-3 font-medium text-gray-500">Name</th><th className="text-left px-6 py-3 font-medium text-gray-500">URL</th><th className="text-left px-6 py-3 font-medium text-gray-500">Events</th><th className="text-left px-6 py-3 font-medium text-gray-500">Active</th><th className="text-left px-6 py-3 font-medium text-gray-500">Actions</th></tr></thead>
          <tbody className="divide-y divide-gray-100">
            {channels.length === 0 && <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-400">No channels configured</td></tr>}
            {channels.map((ch: any) => (
              <tr key={ch.id} className="hover:bg-gray-50">
                <td className="px-6 py-3 font-medium text-gray-900">{ch.name}</td>
                <td className="px-6 py-3 text-gray-500 truncate max-w-[200px]">{ch.config?.url}</td>
                <td className="px-6 py-3"><div className="flex gap-1 flex-wrap">{(ch.events || []).map((e: string) => <span key={e} className="px-2 py-0.5 bg-gray-100 text-gray-700 rounded text-xs">{e}</span>)}</div></td>
                <td className="px-6 py-3"><span className={`px-2 py-0.5 rounded text-xs ${ch.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-500'}`}>{ch.is_active ? 'Active' : 'Inactive'}</span></td>
                <td className="px-6 py-3"><div className="flex gap-2">
                  <button onClick={() => testMut.mutate(ch.id)} className="p-1 text-blue-600 hover:bg-blue-50 rounded" title="Test"><Send className="w-4 h-4" /></button>
                  <button onClick={() => startEdit(ch)} className="text-xs text-blue-600 hover:underline">Edit</button>
                  <button onClick={() => { if (confirm('Delete?')) deleteMut.mutate(ch.id); }} className="p-1 text-red-600 hover:bg-red-50 rounded"><Trash2 className="w-4 h-4" /></button>
                </div>{testResult?.id === ch.id && <span className={`text-xs ${testResult.ok ? 'text-green-600' : 'text-red-600'}`}>{testResult.msg}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
