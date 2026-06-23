import { useState, Fragment } from 'react'
import type { PrometheusMetrics } from '../types'
import { AlertTriangle, BookOpen, Clock, BarChart3, X, Shield, Activity, RefreshCw, Check, Target, ChevronDown, ChevronRight, Crosshair } from 'lucide-react'
import { clsx } from 'clsx'
import { usePendingApprovals, useIncidents, approveIncidentStep, PendingApproval, IncidentRecord } from '../hooks/useMetrics'

interface Props { metrics: PrometheusMetrics | null }

// SOC response catalog — one MITRE ATT&CK for ICS tagged playbook per attack
// technique the AI plane detects. Mirrors vm-ai/ir/playbooks/*.md (the engine
// that actually runs); kept here so the console shows the authoritative response
// even when no incident is open.
const PLAYBOOK_CATALOG = [
  {
    id: 'pb_command_injection', attack: 'modbus_command_injection', title: 'Modbus Command Injection',
    mitre: 'T0855', technique: 'Unauthorized Command Message', tactic: 'Impair Process Control', severity: 'CRITICAL',
    signature: 'Coil + cycle-register (MW0) writes from a non-HMI source',
    steps: ['Capture Modbus stream + forensic snapshot (auto)', 'Isolate source — iptables DROP (auto)', 'Drop arm to ISO-10218 safety speed (human)', 'Assert latched safe state (human)', 'Verify control-program hash vs golden baseline', 'Post-mortem + close (human)'],
  },
  {
    id: 'pb_replay', attack: 'modbus_replay', title: 'Modbus Replay Attack',
    mitre: 'T0831', technique: 'Manipulation of Control', tactic: 'Impair Process Control', severity: 'HIGH',
    signature: 'Repeating FC6 writes to scratch regs MW10–13, off-baseline cadence',
    steps: ['Capture replayed sequence + timing (auto)', 'Isolate source — iptables DROP (auto)', 'Drop arm to safety speed (human)', 'Rotate session keys so the capture cannot be re-used', 'Post-mortem + close (human)'],
  },
  {
    id: 'pb_coil_flood', attack: 'coil_flood', title: 'Coil Flood / Denial of Service',
    mitre: 'T0814', technique: 'Denial of Service', tactic: 'Inhibit Response Function', severity: 'HIGH',
    signature: 'Very high-rate FC5 coil writes to a single point (scan-cycle starvation)',
    steps: ['Capture rate + target coil (auto)', 'Isolate source — iptables DROP (auto)', 'Drop arm to safety speed while scan time recovers (human)', 'Rate-limit Modbus writes at OT gateway', 'Post-mortem + close (human)'],
  },
  {
    id: 'pb_recon_scan', attack: 'recon_scan', title: 'OT Reconnaissance Scan',
    mitre: 'T0846', technique: 'Remote System Discovery', tactic: 'Discovery', severity: 'MEDIUM',
    signature: 'Broad FC3/FC1 read sweep across the map, no writes',
    steps: ['Tag source, raise logging, alert analyst (auto)', 'Isolate source (human — read-only, low harm)', 'Restrict read scope at OT gateway', 'Post-mortem + close (human)'],
  },
  {
    id: 'pb_safety_tamper', attack: 'safety_tamper', title: 'Safety / E-Stop Tampering',
    mitre: 'T0880', technique: 'Loss of Safety', tactic: 'Impact', severity: 'CRITICAL',
    signature: 'Writes to the e-stop coil + safety_state register (MW2)',
    steps: ['Capture every safety-path write (auto)', 'Isolate source — iptables DROP (auto)', 'Assert latched safe state — arm freezes (human)', 'Verify hardwired relay out-of-band', 'Manual safety audit before resume', 'Post-mortem + close (human)'],
  },
  {
    id: 'pb_setpoint_drift', attack: 'setpoint_drift', title: 'Stealthy Setpoint Drift',
    mitre: 'T0836', technique: 'Modify Parameter', tactic: 'Impair Process Control', severity: 'HIGH',
    signature: 'Slow, small writes to one setpoint register (MW4) — low & slow',
    steps: ['Capture full value timeline of MW4 (auto)', 'Isolate source — iptables DROP (auto)', 'Drop arm to safety speed if it drives motion (human)', 'Restore setpoint from golden config', 'Post-mortem + close (human)'],
  },
  {
    id: 'pb_bulk_write', attack: 'bulk_write', title: 'Unauthorized Bulk Register Write',
    mitre: 'T0843', technique: 'Program Download', tactic: 'Lateral Movement', severity: 'CRITICAL',
    signature: 'FC16 multi-register block write (baseline only writes singles)',
    steps: ['Capture written block: range + values (auto)', 'Isolate source — iptables DROP (auto)', 'Assert safe state before logic runs on tampered memory (human)', 'Compare PLC image vs golden hash; roll back if changed', 'Post-mortem + close (human)'],
  },
  {
    id: 'pb_robot_anomaly', attack: 'robot_behavior', title: 'Robot Joint-Dynamics Anomaly',
    mitre: 'T0831', technique: 'Manipulation of Control', tactic: 'Impair Process Control', severity: 'HIGH',
    signature: 'LSTM reconstruction error / physical-envelope breach on joint stream',
    steps: ['Capture joint trace + envelope hits (auto)', 'Raise logging on robot plane (auto)', 'Drop arm to safety speed (human)', 'Assert safe state — arm freezes (human)', 'Re-home + supervised cycle before resume', 'Post-mortem + close (human)'],
  },
]

const FORENSIC_SOURCES = [
  { source: 'Zeek conn.log', type: 'Network', retention: '7 days', path: '/var/log/zeek/current/' },
  { source: 'Suricata fast.log', type: 'IDS', retention: '7 days', path: '/var/log/suricata/' },
  { source: 'Modbus pcap', type: 'OT Protocol', retention: '30 days', path: '/var/lab/pcap/' },
  { source: 'AI anomaly store', type: 'ML', retention: '90 days', path: 'Redis + PostgreSQL' },
  { source: 'PLC register snapshots', type: 'OT State', retention: '30 days', path: '/var/lab/historian/' },
  { source: 'Session recordings', type: 'Vendor', retention: '90 days', path: 'Guacamole PostgreSQL' },
]

const SEV: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-warning',
  MEDIUM: 'badge-info',
}

// Resolve the SOC case view for an incident: prefer the fields the engine
// surfaced (attack_type / label / mitre / why), and fall back to the catalog
// entry for that attack_type so older incidents still render a technique.
function incidentCase(inc: IncidentRecord) {
  const attack = inc.attack_type || inc.event?.attack_type
  const cat = PLAYBOOK_CATALOG.find(p => p.attack === attack)
  const mitreId = inc.mitre?.id || cat?.mitre || ''
  return {
    attack,
    label: inc.label || cat?.title || inc.event?.category || 'Unclassified anomaly',
    mitreId,
    technique: inc.mitre?.technique || cat?.technique || '',
    tactic: inc.mitre?.tactic || cat?.tactic || '',
    severity: (inc.severity || cat?.severity || '').toUpperCase(),
    confidence: inc.confidence || '',
    why: (inc.why && inc.why.length ? inc.why : (inc.event?.why || [])) as string[],
  }
}

export function IncidentPage({ metrics }: Props) {
  const pending = usePendingApprovals(2000)
  const incidents = useIncidents(2000)

  const openInc = incidents.length > 0
    ? incidents.filter(i => !i.closed && !(i as any).postmortem_committed).length
    : Math.round(metrics?.open_incidents ?? 0)
  const injActive = (metrics?.injection_active ?? 0) > 0
  const injTotal = Math.round(metrics?.attack_injections_total ?? 0)
  const [loadingKey, setLoadingKey] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [execResults, setExecResults] = useState<Record<string, { ok: boolean; msg: string; stdout?: string }>>({})
  const [showHistory, setShowHistory] = useState(false)
  const [expandedInc, setExpandedInc] = useState<string | null>(null)

  // Only show active (non-closed) incidents by default; toggle reveals history
  const visibleIncidents = showHistory
    ? incidents
    : incidents.filter(i => !i.closed && !(i as any).postmortem_committed)

  const handleApproveReject = async (incidentId: string, step: string, reject: boolean) => {
    const key = `${incidentId}-${step}`
    setLoadingKey(key)
    setError(null)
    try {
      const res = await approveIncidentStep(incidentId, step, reject)
      if (res.status === 'ok') {
        setExecResults(prev => ({
          ...prev,
          [key]: { ok: true, msg: `Action '${step}' executed successfully.`, stdout: res.stdout }
        }))
      } else {
        const errMsg = res.detail || 'Failed to process containment action.'
        setError(errMsg)
        setExecResults(prev => ({
          ...prev,
          [key]: { ok: false, msg: `Action failed: ${errMsg}` }
        }))
      }
    } catch (err: any) {
      const errMsg = err.message || 'API request failed.'
      setError(errMsg)
      setExecResults(prev => ({
        ...prev,
        [key]: { ok: false, msg: `Action failed: ${errMsg}` }
      }))
    } finally {
      setLoadingKey(null)
    }
  }

  return (
    <div className="h-full overflow-y-auto p-5 space-y-5">
      <div className="flex items-center gap-2">
        <AlertTriangle size={16} className="text-ot-red" />
        <h1 className="text-lg font-bold text-white">IR Console</h1>
        <span className="text-xs text-slate-500 font-mono">Incident Response & Recovery — NIST SP 800-61r2</span>
        {injActive && <span className="ml-auto badge badge-critical animate-pulse">⚡ ACTIVE ATTACK</span>}
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-ot-red/20 border border-ot-red text-ot-red px-4 py-2.5 rounded text-xs font-mono flex items-center justify-between">
          <span><strong>Error:</strong> {error}</span>
          <button onClick={() => setError(null)} className="text-white hover:text-slate-300"><X size={14} /></button>
        </div>
      )}

      {/* Status row */}
      <div className="grid grid-cols-4 gap-4">
        <div className={clsx('card', openInc > 0 ? 'border-ot-red border-glow-red' : 'border-safe-green/30')}>
          <div className="card-header"><AlertTriangle size={12} />Open Incidents</div>
          <div className={clsx('stat-value mt-2', openInc > 0 ? 'text-ot-red' : 'text-safe-green')}>
            {openInc}
          </div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">From Playbook Engine Log</div>
        </div>

        <div className="card">
          <div className="card-header"><BarChart3 size={12} />Attack Injections</div>
          <div className="stat-value mt-2 text-ai-amber">{injTotal}</div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">Total demo injections run</div>
        </div>

        <div className="card">
          <div className="card-header"><Clock size={12} />Detection Latency</div>
          <div className={clsx('stat-value mt-2', (metrics?.detection_latency ?? -1) > 5 ? 'text-ai-amber' : 'text-safe-green')}>
            {(metrics?.detection_latency ?? -1) > 0 ? `${metrics!.detection_latency.toFixed(2)}s` : '—'}
          </div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">Injection → first AI alert</div>
        </div>

        <div className="card">
          <div className="card-header">Pipeline Verdict</div>
          <div className={clsx('font-mono text-lg font-bold mt-2',
            metrics?.pipeline_verdict === 'PASSED' ? 'text-safe-green' :
            metrics?.pipeline_verdict === 'FAILED' ? 'text-ot-red' : 'text-slate-500'
          )}>
            {metrics?.pipeline_verdict ?? 'NONE'}
          </div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">DevSecOps CI/CD pipeline</div>
        </div>
      </div>

      {/* Incident Response Control Panel (Approvals) */}
      <div className="card border-glow-amber border-ai-amber/40">
        <div className="flex items-center justify-between mb-2">
          <div className="card-header font-bold text-ai-amber flex items-center gap-1.5">
            <Shield size={14} className="animate-pulse text-ai-amber" />
            Incident Response Control Panel
          </div>
          <span className="text-[10px] font-mono bg-ai-amber/10 text-ai-amber px-2 py-0.5 rounded border border-ai-amber/30">
            Awaiting Operator Verification
          </span>
        </div>
        <p className="text-[11px] text-slate-400 mb-3">
          The Stage 6 Incident Response engine enforces human approval for safety-critical mitigation tiers.
          Review the queued containment actions below and confirm execution to safeguard plant operations.
        </p>

        {pending.length === 0 ? (
          <div className="py-6 text-center text-xs text-slate-500 font-mono border border-dashed border-border-dim rounded bg-slate-900/10">
            ✓ No pending containment approvals. System is operating within normal safety limits.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-border-dim text-slate-500 text-left">
                  <th className="pb-2 pr-4">Incident ID</th>
                  <th className="pb-2 pr-4">Action/Step</th>
                  <th className="pb-2 pr-4">Proposed Command</th>
                  <th className="pb-2 pr-4">Time Queued</th>
                  <th className="pb-2 text-right">Verification Control</th>
                </tr>
              </thead>
              <tbody>
                {pending.map((entry: PendingApproval) => {
                  const key = `${entry.incident_id}-${entry.step}`
                  const isLoading = loadingKey === key
                  return (
                    <tr key={key} className="border-b border-border-dim/30 hover:bg-slate-800/30">
                      <td className="py-2.5 pr-4 text-white font-bold">{entry.incident_id}</td>
                      <td className="py-2.5 pr-4">
                        <span className="badge badge-warning font-bold">{entry.step}</span>
                      </td>
                      <td className="py-2.5 pr-4 text-slate-400 font-mono text-[11px]">{entry.cmd}</td>
                      <td className="py-2.5 pr-4 text-slate-500">{new Date(entry.queued_at).toLocaleTimeString()}</td>
                      <td className="py-2.5 text-right flex items-center justify-end gap-2">
                        <button
                          disabled={isLoading}
                          onClick={() => handleApproveReject(entry.incident_id, entry.step, false)}
                          className={clsx(
                            "px-2.5 py-1 rounded text-[11px] font-bold text-white flex items-center gap-1",
                            "bg-safe-green hover:bg-green-700 active:scale-95 transition-all disabled:opacity-50"
                          )}
                        >
                          {isLoading ? <RefreshCw size={11} className="animate-spin" /> : <Check size={11} />}
                          Approve
                        </button>
                        <button
                          disabled={isLoading}
                          onClick={() => handleApproveReject(entry.incident_id, entry.step, true)}
                          className={clsx(
                            "px-2.5 py-1 rounded text-[11px] font-bold text-white flex items-center gap-1",
                            "bg-ot-red hover:bg-red-700 active:scale-95 transition-all disabled:opacity-50"
                          )}
                        >
                          {isLoading ? <RefreshCw size={11} className="animate-spin" /> : <X size={11} />}
                          Reject
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {Object.keys(execResults).length > 0 && (
          <div className="mt-4 pt-3 border-t border-border-dim/50 space-y-2">
            <div className="text-[10px] uppercase font-bold text-slate-500 font-mono">Recent Execution Outputs</div>
            {Object.entries(execResults).map(([key, res]) => (
              <div key={key} className={clsx("p-2.5 rounded text-[11px] font-mono border", 
                res.ok ? "bg-emerald-950/40 text-emerald-300 border-emerald-900/60" : "bg-red-950/40 text-red-300 border-red-900/60"
              )}>
                <div className="flex justify-between font-bold mb-1">
                  <span>Action: {key.split('-')[1]} ({key.split('-')[0]})</span>
                  <span className={res.ok ? "text-safe-green" : "text-ot-red"}>{res.ok ? "SUCCESS" : "FAILED"}</span>
                </div>
                <div className="text-[10px] text-slate-400 mb-1.5">{res.msg}</div>
                {res.stdout && (
                  <pre className="terminal p-1.5 max-h-24 overflow-y-auto text-[9.5px] bg-black/40 text-slate-300 border border-slate-800 rounded font-mono">
                    {res.stdout}
                  </pre>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Incident Logs and Auditing History */}
      <div className="card">
        <div className="card-header mb-3 flex items-center gap-1.5 text-white font-semibold">
          <Activity size={14} className="text-dmz-teal" />
          {showHistory ? 'All Incidents (History)' : 'Active Incidents'}
          <span className="ml-1 text-[10px] font-mono text-slate-600 normal-case">
            ({showHistory ? incidents.length : openInc} shown)
          </span>
          <button
            onClick={() => setShowHistory(v => !v)}
            className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded border border-slate-700 bg-slate-900 text-slate-400 hover:border-slate-500 hover:text-slate-200 transition-colors normal-case"
          >
            {showHistory ? '← Active Only' : 'Show History'}
          </button>
        </div>

        {visibleIncidents.length === 0 ? (
          <div className="py-6 text-center text-xs text-slate-500 font-mono border border-dashed border-border-dim rounded bg-slate-900/10">
            {showHistory ? 'No incidents logged yet.' : '✓ No active incidents — system nominal.'}
          </div>
        ) : (
          <div className="overflow-x-auto max-h-96 overflow-y-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-border-dim text-slate-500 text-left">
                  <th className="pb-2 pr-2 w-4"></th>
                  <th className="pb-2 pr-4">Incident ID</th>
                  <th className="pb-2 pr-4">Technique (MITRE ATT&CK ICS)</th>
                  <th className="pb-2 pr-4">Playbook</th>
                  <th className="pb-2 pr-4">Response Steps</th>
                  <th className="pb-2 pr-4">Status</th>
                  <th className="pb-2">Opened At</th>
                </tr>
              </thead>
              <tbody>
                {visibleIncidents.map((inc: IncidentRecord) => {
                  const c = incidentCase(inc)
                  const isOpen = expandedInc === inc.incident_id
                  return (
                    <Fragment key={inc.incident_id}>
                      <tr
                        onClick={() => setExpandedInc(isOpen ? null : inc.incident_id)}
                        className={clsx(
                          "border-b border-border-dim/20 hover:bg-slate-800/30 cursor-pointer",
                          !inc.closed && "bg-red-950/10"
                        )}
                      >
                        <td className="py-2 pr-2 text-slate-500">
                          {isOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                        </td>
                        <td className="py-2 pr-4 text-slate-200 font-mono text-[10px]">{inc.incident_id}</td>
                        <td className="py-2 pr-4">
                          <div className="flex items-center gap-1.5">
                            {c.mitreId && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-ot-red/15 text-ot-red border border-ot-red/30">{c.mitreId}</span>
                            )}
                            <span className="text-white font-semibold normal-case">{c.label}</span>
                          </div>
                          {c.technique && (
                            <div className="text-[9.5px] text-slate-500 mt-0.5 normal-case">{c.technique} · {c.tactic}</div>
                          )}
                        </td>
                        <td className="py-2 pr-4 text-dmz-teal text-[10px]">{inc.playbook}</td>
                        <td className="py-2 pr-4">
                          <div className="flex flex-wrap gap-1">
                            {inc.steps?.map((step: any, idx: number) => (
                              <span
                                key={idx}
                                title={`${step.step}: ${step.status}${step.rc !== undefined ? ` (rc=${step.rc})` : ''}`}
                                className={clsx(
                                  "px-1.5 py-0.5 rounded text-[10px] font-mono",
                                  step.status === 'done'             ? 'bg-safe-green/20 text-safe-green border border-safe-green/30' :
                                  step.status === 'pending_approval' ? 'bg-ai-amber/20 text-ai-amber border border-ai-amber/30 animate-pulse' :
                                  step.status === 'rejected'         ? 'bg-slate-700 text-slate-400 border border-slate-600' :
                                                                       'bg-ot-red/20 text-ot-red border border-ot-red/30'
                                )}
                              >
                                {step.step}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="py-2 pr-4">
                          {inc.closed
                            ? <span className="badge badge-info">Closed</span>
                            : (inc as any).pending_approval
                              ? <span className="badge badge-warning animate-pulse">Awaiting Approval</span>
                              : <span className="badge badge-critical animate-pulse">Active</span>}
                        </td>
                        <td className="py-2 text-slate-500 text-[10px]">{new Date(inc.opened_at).toLocaleString()}</td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-slate-900/50">
                          <td colSpan={7} className="px-4 py-3">
                            <div className="grid grid-cols-3 gap-4">
                              {/* Why it fired */}
                              <div className="col-span-2">
                                <div className="flex items-center gap-1.5 text-[10px] uppercase font-bold text-ai-amber mb-1.5">
                                  <Crosshair size={12} /> Why this fired
                                </div>
                                {c.why && c.why.length > 0 ? (
                                  <ul className="space-y-1">
                                    {c.why.map((w, i) => (
                                      <li key={i} className="flex items-start gap-2 text-[11px] text-slate-300">
                                        <span className="text-slate-600 mt-0.5">▸</span>
                                        <span className="leading-snug">{w}</span>
                                      </li>
                                    ))}
                                  </ul>
                                ) : (
                                  <div className="text-[11px] text-slate-500">No rationale recorded for this incident.</div>
                                )}
                              </div>
                              {/* Case metadata */}
                              <div>
                                <div className="flex items-center gap-1.5 text-[10px] uppercase font-bold text-dmz-teal mb-1.5">
                                  <Target size={12} /> Case
                                </div>
                                <dl className="space-y-1 text-[11px]">
                                  <div className="flex justify-between gap-2"><dt className="text-slate-500">Technique</dt><dd className="text-white font-mono">{c.mitreId || '—'}</dd></div>
                                  <div className="flex justify-between gap-2"><dt className="text-slate-500">Tactic</dt><dd className="text-slate-300 text-right">{c.tactic || '—'}</dd></div>
                                  <div className="flex justify-between gap-2"><dt className="text-slate-500">Severity</dt><dd>{c.severity ? <span className={clsx('badge', SEV[c.severity] ?? 'badge-info')}>{c.severity}</span> : '—'}</dd></div>
                                  <div className="flex justify-between gap-2"><dt className="text-slate-500">Confidence</dt><dd className="text-slate-300">{c.confidence || '—'}</dd></div>
                                  <div className="flex justify-between gap-2"><dt className="text-slate-500">Source</dt><dd className="text-slate-300 font-mono">{inc.event?.src_ip || '—'}</dd></div>
                                </dl>
                              </div>
                            </div>
                            {/* Response timeline */}
                            <div className="mt-3 pt-3 border-t border-border-dim/40">
                              <div className="text-[10px] uppercase font-bold text-slate-500 mb-1.5">Response timeline</div>
                              <div className="space-y-1">
                                {inc.steps?.map((step: any, idx: number) => (
                                  <div key={idx} className="flex items-center gap-2 text-[10.5px]">
                                    <span className="text-slate-600 font-mono w-4">{idx + 1}.</span>
                                    <span className="text-slate-200 font-mono w-40">{step.step}</span>
                                    <span className={clsx(
                                      "px-1.5 py-0.5 rounded text-[9.5px] font-mono",
                                      step.status === 'done'             ? 'bg-safe-green/15 text-safe-green' :
                                      step.status === 'pending_approval' ? 'bg-ai-amber/15 text-ai-amber' :
                                      step.status === 'rejected'         ? 'bg-slate-700 text-slate-400' :
                                                                           'bg-ot-red/15 text-ot-red'
                                    )}>
                                      {step.status}{step.rc !== undefined ? ` (rc=${step.rc})` : ''}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Per-attack response playbooks (MITRE ATT&CK for ICS) */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <BookOpen size={14} className="text-ai-amber" />
          <span className="text-sm font-semibold text-white">Response Playbooks — one per attack technique</span>
          <span className="text-[10px] font-mono text-slate-600 normal-case">MITRE ATT&amp;CK for ICS · graded auto/human containment</span>
        </div>
        <div className="grid grid-cols-2 gap-4">
          {PLAYBOOK_CATALOG.map(pb => (
            <div key={pb.id} className={clsx('card', pb.severity === 'CRITICAL' ? 'border-red-900/60' : pb.severity === 'HIGH' ? 'border-amber-900/40' : 'border-border-dim')}>
              <div className="flex items-start gap-2 mb-2">
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-ot-red/15 text-ot-red border border-ot-red/30 flex-shrink-0 mt-0.5">{pb.mitre}</span>
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-bold text-white">{pb.title}</span>
                    <span className={clsx('badge', SEV[pb.severity] ?? 'badge-info')}>{pb.severity}</span>
                  </div>
                  <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                    {pb.technique} · <span className="text-slate-400">{pb.tactic}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    Detects: <span className="text-dmz-teal">{pb.signature}</span>
                  </div>
                </div>
              </div>
              <ol className="space-y-1 mt-2">
                {pb.steps.map((step, i) => (
                  <li key={i} className="flex items-start gap-2 text-[11px] text-slate-400">
                    <span className="text-slate-600 font-mono flex-shrink-0 w-4">{i + 1}.</span>
                    <span className="leading-tight">{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          ))}
        </div>
      </div>

      {/* Forensic sources */}
      <div className="card">
        <div className="card-header"><BookOpen size={12} />Forensic Evidence Sources</div>
        <table className="w-full text-xs font-mono mt-2">
          <thead>
            <tr className="border-b border-border-dim text-slate-500 text-left">
              <th className="pb-2 pr-4">Source</th>
              <th className="pb-2 pr-4">Type</th>
              <th className="pb-2 pr-4">Retention</th>
              <th className="pb-2">Path / Storage</th>
            </tr>
          </thead>
          <tbody>
            {FORENSIC_SOURCES.map(s => (
              <tr key={s.source} className="border-b border-border-dim/30 hover:bg-slate-800/30">
                <td className="py-1.5 pr-4 text-white">{s.source}</td>
                <td className="py-1.5 pr-4">
                  <span className="badge badge-info">{s.type}</span>
                </td>
                <td className="py-1.5 pr-4 text-slate-400">{s.retention}</td>
                <td className="py-1.5 text-slate-500">{s.path}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Links */}
      <div className="card">
        <div className="card-header">Monitoring & Observability</div>
        <div className="flex flex-wrap gap-3">
          <a href="http://localhost:3003" target="_blank" rel="noopener noreferrer" className="btn-primary text-sm">
            Grafana Dashboards ↗
          </a>
          <a href="http://localhost:9090" target="_blank" rel="noopener noreferrer" className="btn-ghost text-sm">
            Prometheus ↗
          </a>
          <a href="http://localhost:3001" target="_blank" rel="noopener noreferrer" className="btn-ghost text-sm">
            ntopng ↗
          </a>
          <a href="http://localhost:3000" target="_blank" rel="noopener noreferrer" className="btn-ghost text-sm">
            Gitea CI/CD ↗
          </a>
        </div>
      </div>
    </div>
  )
}
