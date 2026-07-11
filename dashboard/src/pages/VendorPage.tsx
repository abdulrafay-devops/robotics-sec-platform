import type { PrometheusMetrics } from '../types'
import { Ban, CheckCircle2, ExternalLink, KeyRound, Lock, PlusCircle, ScrollText, ShieldCheck, Timer, Users, XCircle } from 'lucide-react'
import { clsx } from 'clsx'
import { useEffect, useState } from 'react'

interface Props { metrics: PrometheusMetrics | null }

const ACCESS_PROFILES = [
  {
    id: 'read_only',
    label: 'Read-only reference',
    connection: 'OT-ReadOnly',
    detail: 'Preconfigured Guacamole RDP profile with read-only input.',
  },
  {
    id: 'maintenance',
    label: 'Maintenance reference',
    connection: 'OT-Maintenance',
    detail: 'Preconfigured Guacamole RDP profile for approved maintenance work.',
  },
]

type SessionStatus = 'pending' | 'approved' | 'declined' | 'ended' | 'expired'

type VendorSession = {
  session_id: string
  vendor_name: string
  vendor_email: string
  justification: string
  access_level: 'read_only' | 'maintenance'
  duration_hours: number
  created_at: string
  approved_at?: string | null
  expires_at?: string | null
  ended_at?: string | null
  status: SessionStatus
  active: boolean
  guacamole_portal_url: string
}

type AuditEntry = {
  timestamp?: string
  action?: string
  vendor_name?: string
  session_id?: string
  outcome?: string
  status?: string
  event_hash?: string
}

async function api<T>(path: string, init?: RequestInit): Promise<T | null> {
  try {
    const response = await fetch(path, init)
    if (!response.ok) return null
    return await response.json() as T
  } catch {
    return null
  }
}

// The gateway is intentionally in the DMZ. The browser is the only valid health
// vantage from this management-only dashboard, so this is a reachability check.
const GUAC_BASE = `http://${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8081`

function StatusTile({ label, value, tone }: { label: string; value: string; tone: 'ok' | 'bad' | 'neutral' }) {
  const color = tone === 'ok' ? 'text-emerald-400' : tone === 'bad' ? 'text-red-400' : 'text-slate-100'
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-3">
      <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className={clsx('mt-1 text-xl font-semibold', color)}>{value}</div>
    </div>
  )
}

function statusStyle(status: SessionStatus) {
  if (status === 'approved') return 'border-emerald-800 bg-emerald-950/40 text-emerald-300'
  if (status === 'pending') return 'border-amber-800 bg-amber-950/40 text-amber-300'
  if (status === 'declined') return 'border-red-900 bg-red-950/30 text-red-300'
  return 'border-slate-700 bg-slate-800/40 text-slate-500'
}

export function VendorPage({ metrics: _metrics }: Props) {
  const [guacUp, setGuacUp] = useState<number>(-1)
  const [sessions, setSessions] = useState<VendorSession[]>([])
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [form, setForm] = useState({
    vendor_name: '',
    vendor_email: '',
    justification: '',
    duration_hours: 2,
    access_level: 'read_only' as 'read_only' | 'maintenance',
  })
  const [submitting, setSubmitting] = useState(false)
  const [actionId, setActionId] = useState<string | null>(null)
  const [, force] = useState(0)

  useEffect(() => {
    let active = true
    const ping = async () => {
      try {
        await fetch(`${GUAC_BASE}/guacamole/`, { mode: 'no-cors', signal: AbortSignal.timeout(3000) })
        if (active) setGuacUp(1)
      } catch {
        if (active) setGuacUp(0)
      }
    }
    ping()
    const timer = setInterval(ping, 8000)
    return () => { active = false; clearInterval(timer) }
  }, [])

  const refresh = async () => {
    const [list, entries] = await Promise.all([
      api<VendorSession[]>('/api/vendor/sessions'),
      api<AuditEntry[]>('/api/vendor/audit'),
    ])
    if (list) setSessions(list)
    if (entries) setAudit(entries)
  }

  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, 5000)
    return () => clearInterval(timer)
  }, [])
  useEffect(() => {
    const timer = setInterval(() => force(value => value + 1), 1000)
    return () => clearInterval(timer)
  }, [])

  async function createRequest(event: React.FormEvent) {
    event.preventDefault()
    if (!form.vendor_name || !form.vendor_email || !form.justification) return
    setSubmitting(true)
    const result = await api<VendorSession>('/api/vendor/sessions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(form),
    })
    setSubmitting(false)
    if (result) {
      setForm({ vendor_name: '', vendor_email: '', justification: '', duration_hours: 2, access_level: 'read_only' })
      refresh()
    }
  }

  async function transition(session: VendorSession, action: 'approve' | 'decline' | 'end') {
    setActionId(session.session_id)
    await api<VendorSession>(`/api/vendor/sessions/${session.session_id}/${action}`, { method: 'POST' })
    setActionId(null)
    refresh()
  }

  function remaining(session: VendorSession): string {
    if (session.status === 'pending') return 'awaiting approval'
    if (!session.expires_at) return session.status
    const seconds = Math.max(0, Math.floor((new Date(session.expires_at).getTime() - Date.now()) / 1000))
    if (seconds <= 0) return 'expired'
    const hours = Math.floor(seconds / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`
  }

  const pending = sessions.filter(session => session.status === 'pending').length
  const approved = sessions.filter(session => session.status === 'approved').length
  const closed = sessions.filter(session => ['declined', 'ended', 'expired'].includes(session.status)).length

  return (
    <div className="h-full overflow-y-auto" style={{ background: '#070b11' }}>
      <div className="mx-auto max-w-[1500px] space-y-5 p-6">
        <div className="flex items-center gap-2.5">
          <Users size={18} className="text-slate-300" />
          <div className="flex-1">
            <h1 className="text-lg font-semibold text-white">Vendor Access Approval</h1>
            <p className="text-[11px] text-slate-500">
              Operator request records for the existing Guacamole DMZ portal. Approval windows and audit evidence are tracked here.
            </p>
          </div>
          <div className={clsx('flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium',
            guacUp === 1 ? 'border-emerald-700 bg-emerald-950/40 text-emerald-300'
              : guacUp === 0 ? 'border-red-700 bg-red-950/40 text-red-300'
                : 'border-slate-700 bg-slate-800/40 text-slate-400')}>
            <span className={clsx('h-2 w-2 rounded-full', guacUp === 1 ? 'animate-pulse bg-emerald-400' : guacUp === 0 ? 'bg-red-500' : 'bg-slate-500')} />
            Portal {guacUp === 1 ? 'Reachable' : guacUp === 0 ? 'Unavailable' : 'Checking'}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatusTile label="Portal check" value={guacUp === 1 ? 'Reachable' : guacUp === 0 ? 'Unavailable' : '-'} tone={guacUp === 1 ? 'ok' : guacUp === 0 ? 'bad' : 'neutral'} />
          <StatusTile label="Pending requests" value={String(pending)} tone={pending ? 'neutral' : 'ok'} />
          <StatusTile label="Approved windows" value={String(approved)} tone={approved ? 'ok' : 'neutral'} />
          <StatusTile label="Closed records" value={String(closed)} tone="neutral" />
        </div>

        <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          <div className="space-y-5">
            <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
              <div className="mb-3 flex items-center gap-2 text-sm font-medium text-slate-200"><PlusCircle size={14} className="text-slate-400" />New Request</div>
              <form onSubmit={createRequest} className="space-y-2.5 text-xs">
                <input className="input w-full" placeholder="Vendor name" value={form.vendor_name} onChange={event => setForm(value => ({ ...value, vendor_name: event.target.value }))} />
                <input className="input w-full" placeholder="Vendor email" type="email" value={form.vendor_email} onChange={event => setForm(value => ({ ...value, vendor_email: event.target.value }))} />
                <input className="input w-full" placeholder="Business justification" value={form.justification} onChange={event => setForm(value => ({ ...value, justification: event.target.value }))} />
                <div className="grid grid-cols-2 gap-2.5">
                  <select className="input" value={form.access_level} onChange={event => setForm(value => ({ ...value, access_level: event.target.value as 'read_only' | 'maintenance' }))}>
                    <option value="read_only">Read-only</option>
                    <option value="maintenance">Maintenance</option>
                  </select>
                  <div className="flex items-center gap-1.5">
                    <input className="input w-full" type="number" min={1} max={8} value={form.duration_hours} onChange={event => setForm(value => ({ ...value, duration_hours: Math.max(1, Math.min(8, Number(event.target.value) || 1)) }))} />
                    <span className="text-[10px] text-slate-500">hrs</span>
                  </div>
                </div>
                <button className="btn-primary w-full" disabled={submitting}>{submitting ? 'Recording...' : 'Submit for approval'}</button>
              </form>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
              <div className="mb-3 flex items-center gap-2 text-sm font-medium text-slate-200"><KeyRound size={14} className="text-slate-400" />Existing Gateway Profiles</div>
              <div className="space-y-3">
                {ACCESS_PROFILES.map(profile => (
                  <div key={profile.id} className="rounded-md border border-slate-800/70 px-3 py-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-200">{profile.label}</span>
                      <span className="font-mono text-[9px] text-slate-500">{profile.connection}</span>
                    </div>
                    <p className="mt-1.5 text-[10px] leading-4 text-slate-500">{profile.detail}</p>
                  </div>
                ))}
              </div>
              <p className="mt-3 text-[10px] leading-4 text-slate-600">Guacamole user accounts and connection permissions remain managed by the existing DMZ setup.</p>
            </section>
          </div>

          <div className="space-y-5 lg:col-span-2">
            <section className="overflow-hidden rounded-lg border border-slate-800">
              <div className="flex items-center gap-2 border-b border-slate-800 bg-slate-900/50 px-4 py-3 text-sm font-medium text-slate-200">
                <ShieldCheck size={14} className="text-slate-400" />Approval Records
              </div>
              {sessions.length === 0 ? (
                <div className="px-4 py-8 text-center text-xs text-slate-500">No vendor requests have been recorded.</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="bg-slate-900/40 text-[10px] uppercase tracking-wider text-slate-500">
                      <tr>
                        <th className="px-4 py-2 text-left font-medium">Vendor</th>
                        <th className="px-4 py-2 text-left font-medium">Profile</th>
                        <th className="px-4 py-2 text-left font-medium">Window</th>
                        <th className="px-4 py-2 text-left font-medium">Status</th>
                        <th className="px-4 py-2 text-right font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sessions.map(session => (
                        <tr key={session.session_id} className="border-t border-slate-800/60 hover:bg-slate-800/25">
                          <td className="px-4 py-2.5">
                            <div className="text-slate-200">{session.vendor_name}</div>
                            <div className="text-[10px] text-slate-500">{session.vendor_email}</div>
                          </td>
                          <td className="px-4 py-2.5"><span className="rounded border border-slate-700 bg-slate-800/70 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">{session.access_level}</span></td>
                          <td className="px-4 py-2.5">
                            <span className={clsx('inline-flex items-center gap-1 font-mono text-[11px]', session.status === 'approved' ? 'text-slate-300' : 'text-slate-600')}>
                              <Timer size={11} />{remaining(session)}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className={clsx('inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px]', statusStyle(session.status))}>
                              {session.status === 'approved' ? <CheckCircle2 size={11} /> : session.status === 'declined' ? <XCircle size={11} /> : <Timer size={11} />}
                              {session.status}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex justify-end gap-2">
                              {session.status === 'pending' && <>
                                <button onClick={() => transition(session, 'approve')} disabled={actionId === session.session_id} className="inline-flex items-center gap-1 rounded border border-emerald-800 px-2 py-1 text-[11px] text-emerald-300 hover:bg-emerald-950/40"><CheckCircle2 size={11} />Approve</button>
                                <button onClick={() => transition(session, 'decline')} disabled={actionId === session.session_id} className="inline-flex items-center gap-1 rounded border border-red-800 px-2 py-1 text-[11px] text-red-300 hover:bg-red-950/40"><XCircle size={11} />Decline</button>
                              </>}
                              {session.status === 'approved' && <>
                                <a href={session.guacamole_portal_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-800"><ExternalLink size={11} />Open portal</a>
                                <button onClick={() => transition(session, 'end')} disabled={actionId === session.session_id} className="inline-flex items-center gap-1 rounded border border-red-800 px-2 py-1 text-[11px] text-red-300 hover:bg-red-950/40"><Ban size={11} />End record</button>
                              </>}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <section className="overflow-hidden rounded-lg border border-slate-800">
              <div className="flex items-center gap-2 border-b border-slate-800 bg-slate-900/50 px-4 py-3 text-sm font-medium text-slate-200">
                <ScrollText size={14} className="text-slate-400" />Operator Audit Evidence
                <span className="ml-auto text-[10px] font-normal text-slate-600">hash chained</span>
              </div>
              {audit.length === 0 ? (
                <div className="px-4 py-6 text-center text-xs text-slate-500">Request and approval actions will appear here.</div>
              ) : (
                <div className="max-h-64 overflow-y-auto">
                  <table className="w-full text-xs">
                    <tbody>
                      {audit.slice().reverse().slice(0, 50).map((entry, index) => (
                        <tr key={`${entry.event_hash || entry.session_id || 'event'}-${index}`} className="border-t border-slate-800/50 hover:bg-slate-800/20">
                          <td className="whitespace-nowrap px-4 py-2 font-mono text-[10px] text-slate-500">{new Date(entry.timestamp || '').toLocaleString()}</td>
                          <td className="px-4 py-2"><span className="rounded border border-slate-700 bg-slate-800/70 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">{entry.action || 'event'}</span></td>
                          <td className="px-4 py-2 text-slate-300">{entry.vendor_name || '-'}</td>
                          <td className="px-4 py-2 font-mono text-[10px] text-emerald-400">{entry.outcome || 'recorded'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>
        </div>

        <div className="flex items-start gap-1.5 text-[10px] leading-4 text-slate-600">
          <Lock size={10} className="mt-0.5 shrink-0 text-slate-500" />
          <span>This panel records operator decisions and approved time windows. It does not create, change, or terminate Guacamole accounts in this submitted lab topology.</span>
        </div>
      </div>
    </div>
  )
}
