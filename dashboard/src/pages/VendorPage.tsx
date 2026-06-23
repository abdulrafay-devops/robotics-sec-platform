import type { PrometheusMetrics } from '../types'
import { Users, Monitor, Lock, Video, Timer, Trash2, PlusCircle } from 'lucide-react'
import { clsx } from 'clsx'
import { useEffect, useMemo, useState } from 'react'

interface Props { metrics: PrometheusMetrics | null }

const VENDOR_GROUPS = [
  { name: 'robot-vendor', label: 'Robot Vendor', color: 'text-blue-400', connections: ['OT Gazebo Desktop (RDP)'], perms: ['READ', 'USE_CONN'] },
  { name: 'ot-operator', label: 'OT Operator', color: 'text-safe-green', connections: ['OT Gazebo Desktop (RDP)', 'OpenPLC Web UI'], perms: ['READ', 'USE_CONN', 'UPDATE_CONN'] },
  { name: 'lab-auditor', label: 'Lab Auditor', color: 'text-ai-amber', connections: ['READ-ONLY (all)'], perms: ['READ'] },
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

async function api<T>(path: string, init?: RequestInit): Promise<T | null> {
  try {
    const r = await fetch(path, init)
    if (!r.ok) {
      console.warn('API error', r.status, path)
      return null
    }
    return await r.json() as T
  } catch { return null }
}

// Guacamole lives in the DMZ and is unreachable from the AI/mgmt plane BY DESIGN,
// so the exporter cannot probe it. The authoritative vantage point is the operator's
// browser (which reaches the published portal), so we health-check it from here.
const GUAC_BASE = `http://${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8081`

export function VendorPage({ metrics: _metrics }: Props) {
  const [guacUp, setGuacUp] = useState<number>(-1)
  useEffect(() => {
    let active = true
    const ping = async () => {
      try {
        // no-cors: we can't read the response, but a resolved fetch means the
        // portal is reachable; a network error means it is down.
        await fetch(`${GUAC_BASE}/guacamole/`, { mode: 'no-cors', signal: AbortSignal.timeout(3000) })
        if (active) setGuacUp(1)
      } catch {
        if (active) setGuacUp(0)
      }
    }
    ping(); const t = setInterval(ping, 8000)
    return () => { active = false; clearInterval(t) }
  }, [])
  const [sessions, setSessions] = useState<VendorSession[]>([])
  const [form, setForm] = useState({ vendor_name: '', vendor_email: '', justification: '', duration_hours: 2, access_level: 'read_only' as 'read_only'|'maintenance' })
  const [submitting, setSubmitting] = useState(false)

  const refresh = async () => {
    const list = await api<VendorSession[]>('/api/vendor/sessions')
    if (list) setSessions(list)
  }
  useEffect(() => { refresh(); const t = setInterval(refresh, 5000); return () => clearInterval(t) }, [])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!form.vendor_name || !form.vendor_email || !form.justification) return
    setSubmitting(true)
    const res = await api<{ session_id: string }>(`/api/vendor/sessions`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form)
    })
    setSubmitting(false)
    if (res) { setForm({ vendor_name: '', vendor_email: '', justification: '', duration_hours: 2, access_level: 'read_only' }); refresh() }
  }

  async function revoke(id: string) {
    await api(`/api/vendor/sessions/${id}`, { method: 'DELETE' })
    refresh()
  }

  function remainingSeconds(s: VendorSession): number {
    const end = new Date(s.expires_at).getTime(); const now = Date.now(); return Math.max(0, Math.floor((end - now) / 1000))
  }

  return (
    <div className="h-full overflow-y-auto p-5 space-y-5">
      <div className="flex items-center gap-2">
        <Users size={16} className="text-slate-300" />
        <h1 className="text-lg font-bold text-white">Vendor Access Management</h1>
        <span className="text-xs text-slate-500 font-mono">Privileged Remote Access Gateway — IEC 62443 RBAC</span>
        <div className={clsx('ml-auto flex items-center gap-1.5 text-xs font-mono px-2.5 py-1 rounded-full border',
          guacUp === 1 ? 'border-emerald-700 bg-emerald-950/40 text-emerald-300'
          : guacUp === 0 ? 'border-red-700 bg-red-950/40 text-red-300'
          : 'border-slate-700 bg-slate-800/40 text-slate-400')}>
          <span className={clsx('w-2 h-2 rounded-full', guacUp === 1 ? 'bg-emerald-400 animate-pulse' : guacUp === 0 ? 'bg-red-500' : 'bg-slate-500')} />
          Gateway {guacUp === 1 ? 'ONLINE' : guacUp === 0 ? 'OFFLINE' : 'CHECKING…'}
        </div>
      </div>

      {/* Production-style status strip */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Gateway', value: guacUp === 1 ? 'Online' : guacUp === 0 ? 'Offline' : '—', ok: guacUp === 1 },
          { label: 'Active sessions', value: String(sessions.filter(s => s.active).length), ok: true },
          { label: 'Total issued', value: String(sessions.length), ok: true },
          { label: 'Access model', value: 'RBAC · time-boxed', ok: true },
        ].map(k => (
          <div key={k.label} className="card">
            <div className="card-header">{k.label}</div>
            <div className={clsx('stat-value mt-1 text-lg', k.ok ? 'text-slate-100' : 'text-ot-red')}>{k.value}</div>
          </div>
        ))}
      </div>

      {/* Architecture explanation */}
      <div className="card text-xs text-slate-400 leading-relaxed">
        <div className="card-header"><Monitor size={12} />Architecture — Industrial Remote Desktop Gateway</div>
        Apache Guacamole sits in the <span className="text-dmz-teal font-mono">DMZ zone (192.168.30.0/24)</span> acting as a
        clientless HTML5 gateway. Vendors connect to <code className="bg-slate-800 px-1 rounded">:8081</code> over HTTPS,
        authenticate with role-scoped credentials, and access OT zone assets via RDP/VNC/SSH proxied through
        <span className="text-ai-amber font-mono"> guacd</span>. Session recording stores all screen activity
        to the historian for forensic audit (IEC 62443-2-1 requirement).
        <br /><br />
        No direct vendor access to OT network — all traffic flows:
        <span className="font-mono text-white"> Vendor → HTTPS → Guacamole → guacd → RDP → OT container</span>
      </div>

      {/* Role groups */}
      <div className="grid grid-cols-3 gap-4">
        {VENDOR_GROUPS.map(g => (
          <div key={g.name} className="card">
            <div className="card-header"><Lock size={11} />Group</div>
            <div className={clsx('text-sm font-bold mt-1', g.color)}>{g.label}</div>
            <div className="font-mono text-[10px] text-slate-500 mt-0.5">{g.name}</div>
            <div className="mt-3 space-y-1">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">Permissions</div>
              {g.perms.map(p => (
                <span key={p} className="badge badge-info mr-1">{p}</span>
              ))}
            </div>
            <div className="mt-3 space-y-1">
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">Connections</div>
              {g.connections.map(c => (
                <div key={c} className="text-[10px] font-mono text-slate-400">{c}</div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Create Vendor Session */}
      <div className="card">
        <div className="card-header"><PlusCircle size={12} />Create Vendor Session</div>
        <form onSubmit={handleCreate} className="grid grid-cols-5 gap-3 mt-2 text-xs">
          <input className="input" placeholder="Vendor name" value={form.vendor_name} onChange={e=>setForm(v=>({...v, vendor_name:e.target.value}))} />
          <input className="input" placeholder="Vendor email" type="email" value={form.vendor_email} onChange={e=>setForm(v=>({...v, vendor_email:e.target.value}))} />
          <input className="input col-span-2" placeholder="Justification" value={form.justification} onChange={e=>setForm(v=>({...v, justification:e.target.value}))} />
          <div className="flex items-center gap-2">
            <select className="input" value={form.access_level} onChange={e=>setForm(v=>({...v, access_level:e.target.value as any}))}>
              <option value="read_only">read_only</option>
              <option value="maintenance">maintenance</option>
            </select>
            <input className="input w-20" type="number" min={1} max={8} value={form.duration_hours} onChange={e=>setForm(v=>({...v, duration_hours: Math.max(1, Math.min(8, Number(e.target.value)||1))}))} />
            <button className="btn-primary" disabled={submitting}>Create</button>
          </div>
        </form>
      </div>

      {/* Active/Expired Sessions */}
      <div className="card">
        <div className="card-header"><Monitor size={12} />Vendor Sessions</div>
        <table className="w-full text-xs font-mono mt-2">
          <thead>
            <tr className="border-b border-border-dim text-left text-slate-500">
              <th className="pb-2 pr-2">Vendor</th>
              <th className="pb-2 pr-2">Email</th>
              <th className="pb-2 pr-2">Access</th>
              <th className="pb-2 pr-2">Expires</th>
              <th className="pb-2 pr-2">Countdown</th>
              <th className="pb-2 pr-2">Link</th>
              <th className="pb-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map(s => {
              const rem = remainingSeconds(s)
              const expired = !s.active
              return (
                <tr key={s.session_id} className="border-b border-border-dim/30 hover:bg-slate-800/30">
                  <td className="py-2 pr-2 text-white">{s.vendor_name}</td>
                  <td className="py-2 pr-2 text-slate-300">{s.vendor_email}</td>
                  <td className="py-2 pr-2"><span className="badge badge-info">{s.access_level}</span></td>
                  <td className="py-2 pr-2 text-slate-400">{new Date(s.expires_at).toLocaleString()}</td>
                  <td className={clsx('py-2 pr-2 flex items-center gap-1', expired ? 'text-slate-600' : 'text-safe-green')}>
                    <Timer size={12} />{expired ? 'expired' : `${rem}s`}
                  </td>
                  <td className="py-2 pr-2">
                    <a className="btn-ghost text-[11px]" href={s.guacamole_connection_url} target="_blank" rel="noopener noreferrer">Open ↗</a>
                  </td>
                  <td className="py-2">
                    <button onClick={()=>revoke(s.session_id)} disabled={expired} className={clsx('btn-ghost text-[11px] flex items-center gap-1', expired && 'opacity-50 cursor-not-allowed')}>
                      <Trash2 size={12} /> Revoke
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Guacamole quick links */}
      <div className="card">
        <div className="card-header">Quick Access</div>
        <div className="flex flex-wrap gap-3 mt-2">
          <a href="http://localhost:8081/" target="_blank" rel="noopener noreferrer" className="btn-primary text-sm">
            Guacamole Portal ↗
          </a>
          <a href="http://localhost:8081/#/settings/users" target="_blank" rel="noopener noreferrer" className="btn-ghost text-sm">
            User Management ↗
          </a>
          <a href="http://localhost:8081/#/settings/connections" target="_blank" rel="noopener noreferrer" className="btn-ghost text-sm">
            Connection Settings ↗
          </a>
        </div>
        <div className="text-[10px] text-slate-600 font-mono mt-3 flex items-center gap-1.5">
          <Lock size={10} className="text-slate-500" />
          Access is role-scoped and time-boxed; every session is recorded to the historian for audit (IEC 62443-2-1).
        </div>
      </div>
    </div>
  )
}
