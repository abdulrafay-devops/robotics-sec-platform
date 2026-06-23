import type { PrometheusMetrics } from '../types'
import { Users, Lock, Timer, Trash2, PlusCircle, ShieldCheck, ScrollText, ExternalLink, KeyRound } from 'lucide-react'
import { clsx } from 'clsx'
import { useEffect, useState } from 'react'

interface Props { metrics: PrometheusMetrics | null }

// Role-based access groups (mapped to Guacamole connection groups).
const VENDOR_GROUPS = [
  { name: 'robot-vendor', label: 'Robot Vendor', connections: ['OT Gazebo Desktop (RDP)'], perms: ['READ', 'USE_CONN'] },
  { name: 'ot-operator', label: 'OT Operator', connections: ['OT Gazebo Desktop (RDP)', 'OpenPLC Web UI'], perms: ['READ', 'USE_CONN', 'UPDATE_CONN'] },
  { name: 'lab-auditor', label: 'Lab Auditor', connections: ['Read-only (all)'], perms: ['READ'] },
]

type VendorSession = {
  session_id: string
  vendor_name: string
  vendor_email: string
  justification: string
  access_level: 'read_only' | 'maintenance'
  created_at: string
  expires_at: string
  revoked_at?: string | null
  guacamole_connection_url: string
  audit_token: string
  active: boolean
}

type AuditEntry = {
  timestamp?: string
  ts?: string
  action?: string
  vendor_name?: string
  session_id?: string
  outcome?: string
  src_ip?: string
}

async function api<T>(path: string, init?: RequestInit): Promise<T | null> {
  try {
    const r = await fetch(path, init)
    if (!r.ok) return null
    return await r.json() as T
  } catch { return null }
}

// Guacamole is DMZ-isolated and unreachable from the AI/mgmt plane by design, so
// the authoritative health vantage is the operator's browser (reaches the portal).
const GUAC_BASE = `http://${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8081`

function StatusTile({ label, value, tone }: { label: string; value: string; tone: 'ok' | 'bad' | 'neutral' }) {
  const t = tone === 'ok' ? 'text-emerald-400' : tone === 'bad' ? 'text-red-400' : 'text-slate-100'
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-3">
      <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className={clsx('text-xl font-semibold mt-1', t)}>{value}</div>
    </div>
  )
}

export function VendorPage({ metrics: _metrics }: Props) {
  const [guacUp, setGuacUp] = useState<number>(-1)
  const [sessions, setSessions] = useState<VendorSession[]>([])
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [form, setForm] = useState({ vendor_name: '', vendor_email: '', justification: '', duration_hours: 2, access_level: 'read_only' as 'read_only' | 'maintenance' })
  const [submitting, setSubmitting] = useState(false)
  const [, force] = useState(0)

  // Browser-side gateway health.
  useEffect(() => {
    let active = true
    const ping = async () => {
      try {
        await fetch(`${GUAC_BASE}/guacamole/`, { mode: 'no-cors', signal: AbortSignal.timeout(3000) })
        if (active) setGuacUp(1)
      } catch { if (active) setGuacUp(0) }
    }
    ping(); const t = setInterval(ping, 8000)
    return () => { active = false; clearInterval(t) }
  }, [])

  const refresh = async () => {
    const [list, aud] = await Promise.all([
      api<VendorSession[]>('/api/vendor/sessions'),
      api<AuditEntry[]>('/api/vendor/audit'),
    ])
    if (list) setSessions(list)
    if (aud) setAudit(aud)
  }
  useEffect(() => { refresh(); const t = setInterval(refresh, 5000); return () => clearInterval(t) }, [])
  // 1s tick so the live countdown updates smoothly.
  useEffect(() => { const t = setInterval(() => force(n => n + 1), 1000); return () => clearInterval(t) }, [])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!form.vendor_name || !form.vendor_email || !form.justification) return
    setSubmitting(true)
    const res = await api<{ session_id: string }>(`/api/vendor/sessions`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form),
    })
    setSubmitting(false)
    if (res) { setForm({ vendor_name: '', vendor_email: '', justification: '', duration_hours: 2, access_level: 'read_only' }); refresh() }
  }

  async function revoke(s: VendorSession) {
    // The backend requires the session's audit_token to authorise revocation.
    await api(`/api/vendor/sessions/${s.session_id}?audit_token=${encodeURIComponent(s.audit_token)}`, { method: 'DELETE' })
    refresh()
  }

  function fmtRemaining(s: VendorSession): string {
    const rem = Math.max(0, Math.floor((new Date(s.expires_at).getTime() - Date.now()) / 1000))
    if (rem <= 0) return 'expired'
    const h = Math.floor(rem / 3600), m = Math.floor((rem % 3600) / 60), sec = rem % 60
    return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`
  }

  const activeCount = sessions.filter(s => s.active).length

  return (
    <div className="h-full overflow-y-auto" style={{ background: '#070b11' }}>
      <div className="p-6 space-y-5 max-w-[1500px] mx-auto">

        {/* Header */}
        <div className="flex items-center gap-2.5">
          <Users size={18} className="text-slate-300" />
          <div className="flex-1">
            <h1 className="text-lg font-semibold text-white tracking-tight">Privileged Remote Access</h1>
            <p className="text-[11px] text-slate-500">
              Time-boxed, role-scoped vendor access to OT assets via the Guacamole gateway — every session recorded for audit (IEC 62443-2-1).
            </p>
          </div>
          <div className={clsx('flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full border',
            guacUp === 1 ? 'border-emerald-700 bg-emerald-950/40 text-emerald-300'
              : guacUp === 0 ? 'border-red-700 bg-red-950/40 text-red-300'
                : 'border-slate-700 bg-slate-800/40 text-slate-400')}>
            <span className={clsx('w-2 h-2 rounded-full', guacUp === 1 ? 'bg-emerald-400 animate-pulse' : guacUp === 0 ? 'bg-red-500' : 'bg-slate-500')} />
            Gateway {guacUp === 1 ? 'Online' : guacUp === 0 ? 'Offline' : 'Checking…'}
          </div>
        </div>

        {/* Status tiles */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatusTile label="Gateway" value={guacUp === 1 ? 'Online' : guacUp === 0 ? 'Offline' : '—'} tone={guacUp === 1 ? 'ok' : guacUp === 0 ? 'bad' : 'neutral'} />
          <StatusTile label="Active sessions" value={String(activeCount)} tone={activeCount > 0 ? 'ok' : 'neutral'} />
          <StatusTile label="Total issued" value={String(sessions.length)} tone="neutral" />
          <StatusTile label="Audit events" value={String(audit.length)} tone="neutral" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Left: request access + roles */}
          <div className="space-y-5">
            {/* Request access */}
            <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-200 mb-3"><PlusCircle size={14} className="text-slate-400" />Grant Access</div>
              <form onSubmit={handleCreate} className="space-y-2.5 text-xs">
                <input className="input w-full" placeholder="Vendor name" value={form.vendor_name} onChange={e => setForm(v => ({ ...v, vendor_name: e.target.value }))} />
                <input className="input w-full" placeholder="Vendor email" type="email" value={form.vendor_email} onChange={e => setForm(v => ({ ...v, vendor_email: e.target.value }))} />
                <input className="input w-full" placeholder="Business justification" value={form.justification} onChange={e => setForm(v => ({ ...v, justification: e.target.value }))} />
                <div className="grid grid-cols-2 gap-2.5">
                  <select className="input" value={form.access_level} onChange={e => setForm(v => ({ ...v, access_level: e.target.value as any }))}>
                    <option value="read_only">Read-only</option>
                    <option value="maintenance">Maintenance</option>
                  </select>
                  <div className="flex items-center gap-1.5">
                    <input className="input w-full" type="number" min={1} max={8} value={form.duration_hours} onChange={e => setForm(v => ({ ...v, duration_hours: Math.max(1, Math.min(8, Number(e.target.value) || 1)) }))} />
                    <span className="text-[10px] text-slate-500">hrs</span>
                  </div>
                </div>
                <button className="btn-primary w-full" disabled={submitting}>{submitting ? 'Granting…' : 'Grant time-boxed access'}</button>
              </form>
            </div>

            {/* Roles */}
            <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-200 mb-3"><KeyRound size={14} className="text-slate-400" />Access Roles (RBAC)</div>
              <div className="space-y-3">
                {VENDOR_GROUPS.map(g => (
                  <div key={g.name} className="border border-slate-800/70 rounded-md px-3 py-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-200 font-medium text-xs">{g.label}</span>
                      <span className="font-mono text-[9px] text-slate-600">{g.name}</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {g.perms.map(p => <span key={p} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800/70 border border-slate-700 text-slate-400">{p}</span>)}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-1.5">{g.connections.join(' · ')}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right: sessions + audit */}
          <div className="lg:col-span-2 space-y-5">
            {/* Active / recent sessions */}
            <div className="rounded-lg border border-slate-800 overflow-hidden">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-200 px-4 py-3 border-b border-slate-800 bg-slate-900/50">
                <ShieldCheck size={14} className="text-slate-400" />Vendor Sessions
              </div>
              {sessions.length === 0 ? (
                <div className="px-4 py-8 text-center text-xs text-slate-500">No vendor sessions. Grant time-boxed access on the left.</div>
              ) : (
                <table className="w-full text-xs">
                  <thead className="bg-slate-900/40 text-slate-500 text-[10px] uppercase tracking-wider">
                    <tr>
                      <th className="text-left font-medium px-4 py-2">Vendor</th>
                      <th className="text-left font-medium px-4 py-2">Access</th>
                      <th className="text-left font-medium px-4 py-2">Expires in</th>
                      <th className="text-left font-medium px-4 py-2">Status</th>
                      <th className="text-right font-medium px-4 py-2">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map(s => (
                      <tr key={s.session_id} className="border-t border-slate-800/60 hover:bg-slate-800/25">
                        <td className="px-4 py-2.5">
                          <div className="text-slate-200">{s.vendor_name}</div>
                          <div className="text-[10px] text-slate-500">{s.vendor_email}</div>
                        </td>
                        <td className="px-4 py-2.5"><span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/70 border border-slate-700 text-slate-300">{s.access_level}</span></td>
                        <td className="px-4 py-2.5">
                          <span className={clsx('inline-flex items-center gap-1 font-mono text-[11px]', s.active ? 'text-slate-300' : 'text-slate-600')}>
                            <Timer size={11} />{fmtRemaining(s)}
                          </span>
                        </td>
                        <td className="px-4 py-2.5">
                          <span className={clsx('inline-flex items-center gap-1.5 text-[11px] px-2 py-0.5 rounded-full border',
                            s.active ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-slate-700 bg-slate-800/40 text-slate-500')}>
                            <span className={clsx('w-1.5 h-1.5 rounded-full', s.active ? 'bg-emerald-400' : 'bg-slate-500')} />
                            {s.active ? 'Active' : 'Ended'}
                          </span>
                        </td>
                        <td className="px-4 py-2.5">
                          <div className="flex items-center justify-end gap-2">
                            <a href={s.guacamole_connection_url} target="_blank" rel="noopener noreferrer"
                              className={clsx('inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded border', s.active ? 'border-slate-700 text-slate-300 hover:bg-slate-800' : 'border-slate-800 text-slate-600 pointer-events-none')}>
                              <ExternalLink size={11} />Connect
                            </a>
                            <button onClick={() => revoke(s)} disabled={!s.active}
                              className={clsx('inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded border', s.active ? 'border-red-800 text-red-300 hover:bg-red-950/40' : 'border-slate-800 text-slate-600 cursor-not-allowed')}>
                              <Trash2 size={11} />Revoke
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Audit log */}
            <div className="rounded-lg border border-slate-800 overflow-hidden">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-200 px-4 py-3 border-b border-slate-800 bg-slate-900/50">
                <ScrollText size={14} className="text-slate-400" />Access Audit Log
                <span className="ml-auto text-[10px] text-slate-600 font-normal">append-only · forwarded to historian</span>
              </div>
              {audit.length === 0 ? (
                <div className="px-4 py-6 text-center text-xs text-slate-500">No access events yet. Granting or revoking access records an immutable audit entry here.</div>
              ) : (
                <div className="max-h-64 overflow-y-auto">
                  <table className="w-full text-xs">
                    <tbody>
                      {audit.slice().reverse().slice(0, 50).map((a, i) => (
                        <tr key={i} className="border-t border-slate-800/50 hover:bg-slate-800/20">
                          <td className="px-4 py-2 text-[10px] font-mono text-slate-500 whitespace-nowrap">{new Date(a.timestamp || a.ts || '').toLocaleString()}</td>
                          <td className="px-4 py-2"><span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/70 border border-slate-700 text-slate-300">{a.action || 'event'}</span></td>
                          <td className="px-4 py-2 text-slate-300">{a.vendor_name || '—'}</td>
                          <td className="px-4 py-2">
                            <span className={clsx('text-[10px] font-mono', (a.outcome || '').toLowerCase().includes('denied') || (a.outcome || '').toLowerCase().includes('fail') ? 'text-red-400' : 'text-emerald-400')}>
                              {a.outcome || 'ok'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer note */}
        <div className="text-[10px] text-slate-600 flex items-center gap-1.5">
          <Lock size={10} className="text-slate-500" />
          Vendors never touch the OT network directly: traffic flows Vendor → HTTPS → Guacamole (DMZ) → guacd → RDP → OT cell. Sessions are recorded for forensic review.
        </div>
      </div>
    </div>
  )
}
