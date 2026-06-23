import { useState, useEffect } from 'react'
import type { PrometheusMetrics } from '../types'
import {
  Network, Brain, Shield, Search, GitBranch, AlertOctagon,
  CheckCircle2, XCircle, ChevronRight, Activity,
  Lock, Server, Cpu, ExternalLink,
  ShieldAlert, RefreshCw, Hash,
} from 'lucide-react'
import { clsx } from 'clsx'
import {
  useStagesReports, usePendingApprovals, useIncidents, approveIncidentStep,
} from '../hooks/useMetrics'

interface Props { metrics: PrometheusMetrics | null }

// ─── Stage config ─────────────────────────────────────────────────────────────
const STAGES = [
  {
    id: 1, code: 'S1',
    title: 'OT/IT Network Segmentation',
    subtitle: 'Industrial DMZ · Microsegmentation · Protocol Monitoring',
    icon: Network,
    color: 'cyan',
    accent: '#06b6d4',
    border: 'border-cyan-800/60',
    glow: 'shadow-[0_0_20px_rgba(6,182,212,0.12)]',
    ring: 'ring-cyan-700/40',
    bg: 'bg-cyan-950/20',
    tools: ['Zeek LTS', 'Suricata', 'ntopng', 'Docker bridge networks'],
    compliance: 'IEC 62443 SR 5.1 · NIST SP 800-82 §4.2',
    objective: 'Deploy secure OT/IT architecture with industrial DMZ and Purdue-model zone isolation.',
    metric: (m: PrometheusMetrics) => ({
      label: 'Modbus rate', raw: m.modbus_traffic_rate,
      value: m.modbus_traffic_rate >= 0 ? `${m.modbus_traffic_rate.toFixed(2)}/s` : 'N/A',
      ok: m.modbus_traffic_rate >= 0,
    }),
  },
  {
    id: 2, code: 'S2',
    title: 'AI-Driven Anomaly Detection',
    subtitle: 'IsolationForest · PCA Autoencoder · TF Deep AE',
    icon: Brain,
    color: 'blue',
    accent: '#3b82f6',
    border: 'border-blue-800/60',
    glow: 'shadow-[0_0_20px_rgba(59,130,246,0.12)]',
    ring: 'ring-blue-700/40',
    bg: 'bg-blue-950/20',
    tools: ['scikit-learn IsolationForest', 'PCA Reconstruction', 'TensorFlow Dense AE', 'Redis event bus'],
    compliance: 'IEC 62443 SR 6.1 · NIST CSF DE.AE-1',
    objective: 'Deploy ML models for robotic behavioural analysis and predictive cyber-physical attack detection.',
    metric: (m: PrometheusMetrics) => ({
      label: 'IF score', raw: m.iforest_score,
      value: m.iforest_score >= 0 ? m.iforest_score.toFixed(4) : 'N/A',
      ok: m.iforest_score >= 0 && m.iforest_score < 0.15,
    }),
  },
  {
    id: 3, code: 'S3',
    title: 'Safety System Protection',
    subtitle: 'SROS2 · Safety PLC · SIS Integrity · IEC 61511',
    icon: Shield,
    color: 'violet',
    accent: '#8b5cf6',
    border: 'border-violet-800/60',
    glow: 'shadow-[0_0_20px_rgba(139,92,246,0.12)]',
    ring: 'ring-violet-700/40',
    bg: 'bg-violet-950/20',
    tools: ['ROS2 / SROS2 DDS-Security', 'OpenPLC Safety Supervisor', 'Modbus TCP heartbeat', 'IEC 62443 SL-2 ACLs'],
    compliance: 'IEC 61511 · IEC 62443 SL-2 · NIST SP 800-82 §5.3',
    objective: 'Deploy security controls for emergency stops, safety PLCs, and SIS integrity validation.',
    metric: (m: PrometheusMetrics) => ({
      label: 'SIS integrity', raw: m.sis_integrity,
      value: m.sis_integrity === 1 ? 'OK' : m.sis_integrity === 0 ? 'FAIL' : 'N/A',
      ok: m.sis_integrity === 1,
    }),
  },
  {
    id: 4, code: 'S4',
    title: 'Vulnerability Management',
    subtitle: 'CVE Scanning · Firmware Baseline · Config Drift',
    icon: Search,
    color: 'amber',
    accent: '#f59e0b',
    border: 'border-amber-800/60',
    glow: 'shadow-[0_0_20px_rgba(245,158,11,0.12)]',
    ring: 'ring-amber-700/40',
    bg: 'bg-amber-950/20',
    tools: ['Nmap + OT NSE scripts', 'Offline CVE database', 'Firmware hash registry', 'Config baseline_check.py'],
    compliance: 'IEC 62443-2-3 · NIST SP 800-82 §5.2',
    objective: 'Automated vulnerability scanning for industrial robots, firmware management, and baseline enforcement.',
    metric: (m: PrometheusMetrics) => {
      const crit = m.vuln_by_severity?.critical ?? 0
      return {
        label: 'Critical CVEs', raw: crit,
        value: `${Math.round(crit)} critical`,
        ok: crit === 0,
      }
    },
  },
  {
    id: 5, code: 'S5',
    title: 'DevSecOps Pipeline',
    subtitle: 'Gitea CI · PLC Lint · SAST · 6-Gate Security',
    icon: GitBranch,
    color: 'emerald',
    accent: '#10b981',
    border: 'border-emerald-800/60',
    glow: 'shadow-[0_0_20px_rgba(16,185,129,0.12)]',
    ring: 'ring-emerald-700/40',
    bg: 'bg-emerald-950/20',
    tools: ['Gitea + Act Runner CI/CD', 'IEC 61131-3 PLC linter', 'HMI JSON validator', 'SROS2 ACL lint'],
    compliance: 'IEC 62443-4-1 SD-4 · NIST SP 800-82 §4.4',
    objective: 'Security validation for PLC logic, HMI applications, and automated security testing for industrial automation.',
    metric: (m: PrometheusMetrics) => ({
      label: 'Pipeline', raw: m.pipeline_verdict === 'PASS' ? 1 : 0,
      value: m.pipeline_verdict ?? 'NONE',
      ok: m.pipeline_verdict === 'PASS',
    }),
  },
  {
    id: 6, code: 'S6',
    title: 'Incident Response & Recovery',
    subtitle: 'Playbook Engine · Forensics · Grafana SOC',
    icon: AlertOctagon,
    color: 'rose',
    accent: '#f43f5e',
    border: 'border-rose-800/60',
    glow: 'shadow-[0_0_20px_rgba(244,63,94,0.12)]',
    ring: 'ring-rose-700/40',
    bg: 'bg-rose-950/20',
    tools: ['Playbook engine (YAML)', 'forensics_capture.sh', 'Prometheus + Grafana', 'Graded IR: Watch→Stop'],
    compliance: 'NIST SP 800-61r2 · IEC 62443 SR 6.2',
    objective: 'Automated incident detection, graded containment playbooks, forensic capture, and manufacturing recovery.',
    metric: (m: PrometheusMetrics) => ({
      label: 'Open incidents', raw: m.open_incidents ?? 0,
      value: `${Math.round(m.open_incidents ?? 0)} open`,
      ok: (m.open_incidents ?? 0) === 0,
    }),
  },
]

// Uniform, professional muted palette — colour now signals STATUS (ok/warn/fail),
// not decoration. Every control area uses the same restrained slate/steel scheme.
const _PRO = { badge: 'bg-slate-800/60 border-slate-700 text-slate-300', dot: 'bg-slate-400', text: 'text-slate-300', num: 'text-slate-200' }
const COLOR_MAP: Record<string, Record<string, string>> = {
  cyan: _PRO, blue: _PRO, violet: _PRO, amber: _PRO, emerald: _PRO, rose: _PRO,
}
// Neutral classes used for the active control's panel + pipeline button (no rainbow).
const NEUTRAL_BORDER = 'border-slate-700'
const NEUTRAL_BG = 'bg-slate-800/30'
const NEUTRAL_RING = 'ring-slate-600/40'

// ─── Sub-components ───────────────────────────────────────────────────────────

function PipelineFlow({ metrics, activeId, onSelect }: {
  metrics: PrometheusMetrics | null
  activeId: number | null
  onSelect: (id: number) => void
}) {
  return (
    <div className="flex items-center justify-between gap-0 w-full">
      {STAGES.map((s, i) => {
        const c = COLOR_MAP[s.color]
        const m = metrics ? s.metric(metrics) : null
        const isOk = m?.ok ?? true
        const isActive = activeId === s.id
        const Icon = s.icon
        return (
          <div key={s.id} className="flex items-center flex-1">
            <button
              onClick={() => onSelect(s.id)}
              className={clsx(
                'flex-1 flex flex-col items-center gap-1.5 py-3 px-2 rounded-lg border transition-all duration-200 group',
                'hover:scale-105 active:scale-95 focus:outline-none',
                isActive
                  ? `${NEUTRAL_BORDER} ${NEUTRAL_BG} ring-1 ${NEUTRAL_RING}`
                  : 'border-slate-800/60 bg-slate-900/30 hover:border-slate-700',
              )}
            >
              <div className={clsx(
                'w-9 h-9 rounded-lg flex items-center justify-center border transition-all',
                isActive ? `${NEUTRAL_BG} ${NEUTRAL_BORDER}` : 'bg-slate-900 border-slate-800 group-hover:border-slate-700',
              )}>
                <Icon size={16} className={isActive ? c.text : 'text-slate-600 group-hover:text-slate-400'} />
              </div>
              <div className={clsx('text-[8.5px] font-mono font-bold uppercase tracking-wider', isActive ? c.text : 'text-slate-600')}>
                {s.code}
              </div>
              {m && (
                <div className={clsx(
                  'text-[9px] font-mono px-1.5 py-0.5 rounded border',
                  isOk ? 'bg-emerald-950/50 border-emerald-800 text-emerald-400'
                    : 'bg-red-950/50 border-red-800 text-red-400',
                )}>
                  {m.value}
                </div>
              )}
            </button>
            {i < STAGES.length - 1 && (
              <ChevronRight size={14} className="text-slate-800 flex-shrink-0 mx-0.5" />
            )}
          </div>
        )
      })}
    </div>
  )
}

function ComplianceBand({ metrics }: { metrics: PrometheusMetrics | null }) {
  const score = metrics?.compliance_score ?? -1
  const color = score >= 85 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444'
  const label = score >= 85 ? 'COMPLIANT' : score >= 60 ? 'PARTIAL' : score >= 0 ? 'NON-COMPLIANT' : 'N/A'
  const r = 40, circ = 2 * Math.PI * r
  const fill = score >= 0 ? circ * (score / 100) : 0
  return (
    <div className="flex items-center gap-4">
      <svg width="96" height="96" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={r} fill="none" stroke="#0f172a" strokeWidth="8" />
        <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={`${fill} ${circ}`} strokeDashoffset={circ / 4}
          strokeLinecap="round" transform="rotate(-90 48 48)"
          style={{ transition: 'stroke-dasharray 1.2s ease' }} />
        <text x="48" y="44" textAnchor="middle" fill={color} fontSize="18" fontWeight="bold" fontFamily="monospace">
          {score >= 0 ? Math.round(score) : '--'}
        </text>
        <text x="48" y="58" textAnchor="middle" fill="#475569" fontSize="6.5" fontFamily="monospace" fontWeight="bold">
          IEC 62443
        </text>
      </svg>
      <div>
        <div className={clsx('text-xs font-mono font-bold', score >= 85 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : score >= 0 ? 'text-red-400' : 'text-slate-600')}>
          {label}
        </div>
        <div className="text-[10px] text-slate-500 mt-0.5 font-mono">Compliance Score</div>
        <div className="mt-2 space-y-1">
          {[
            { label: 'Safety State', ok: (metrics?.safety_state ?? -1) === 0, val: ['NORMAL', 'DEGRADED', 'EMERGENCY'][(metrics?.safety_state ?? -1)] ?? 'N/A' },
            { label: 'SIS Integrity', ok: metrics?.sis_integrity === 1, val: metrics?.sis_integrity === 1 ? 'OK' : metrics?.sis_integrity === 0 ? 'FAIL' : 'N/A' },
            { label: 'Pipeline', ok: metrics?.pipeline_verdict === 'PASS', val: metrics?.pipeline_verdict ?? 'NONE' },
          ].map(({ label, ok, val }) => (
            <div key={label} className="flex items-center gap-2 text-[9.5px] font-mono">
              {ok ? <CheckCircle2 size={10} className="text-emerald-400 flex-shrink-0" /> : <XCircle size={10} className="text-red-500 flex-shrink-0" />}
              <span className="text-slate-500">{label}:</span>
              <span className={ok ? 'text-emerald-400' : 'text-red-400'}>{val}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function StageDetailPanel({ stage, metrics, reports, pendingApprovals, incidents, meta }: {
  stage: typeof STAGES[0]
  metrics: PrometheusMetrics | null
  reports: any
  pendingApprovals: any[]
  incidents: any[]
  meta: any
}) {
  const c = COLOR_MAP[stage.color]
  const Icon = stage.icon
  const m = metrics ? stage.metric(metrics) : null

  return (
    <div className={clsx(
      'rounded-xl border p-5 transition-all duration-300',
      NEUTRAL_BORDER, NEUTRAL_BG,
    )}>
      {/* Stage header */}
      <div className="flex items-start gap-4 mb-5">
        <div className={clsx('w-12 h-12 rounded-xl flex items-center justify-center border flex-shrink-0', NEUTRAL_BORDER, NEUTRAL_BG)}>
          <Icon size={22} className={c.text} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <h2 className="text-base font-bold text-white">{stage.title}</h2>
            <span className={clsx('text-[9px] font-mono px-2 py-0.5 rounded-full border font-bold', c.badge)}>
              STAGE {stage.id}
            </span>
            {m && (
              <span className={clsx(
                'text-[10px] font-mono px-2.5 py-1 rounded-lg border font-bold',
                m.ok ? 'bg-emerald-950/60 border-emerald-700 text-emerald-300'
                  : 'bg-red-950/60 border-red-700 text-red-300',
              )}>
                {m.ok ? '✓' : '✗'} {m.label}: {m.value}
              </span>
            )}
          </div>
          <div className="text-xs text-slate-400 mt-0.5">{stage.subtitle}</div>
          <div className="text-[10px] font-mono text-slate-600 mt-1">{stage.compliance}</div>
        </div>
      </div>

      {/* Objective */}
      <div className={clsx('rounded-lg border px-4 py-3 mb-4 text-xs text-slate-300 leading-relaxed', NEUTRAL_BORDER, 'bg-slate-950/40')}>
        <span className={clsx('text-[9px] font-mono font-bold uppercase tracking-wider mr-2', c.text)}>OBJECTIVE</span>
        {stage.objective}
      </div>

      {/* Tools */}
      <div className="flex flex-wrap gap-2 mb-5">
        {stage.tools.map(t => (
          <span key={t} className={clsx('text-[10px] font-mono px-2.5 py-1 rounded-lg border', c.badge)}>
            {t}
          </span>
        ))}
      </div>

      {/* Stage-specific content */}
      {stage.id === 1 && <Stage1Detail reports={reports} metrics={metrics} />}
      {stage.id === 2 && <Stage2Detail reports={reports} meta={meta} metrics={metrics} />}
      {stage.id === 3 && <Stage3Detail reports={reports} metrics={metrics} />}
      {stage.id === 4 && <Stage4Detail reports={reports} metrics={metrics} />}
      {stage.id === 5 && <Stage5Detail reports={reports} metrics={metrics} />}
      {stage.id === 6 && <Stage6Detail pendingApprovals={pendingApprovals} incidents={incidents} metrics={metrics} />}
    </div>
  )
}

// ─── Stage detail bodies ──────────────────────────────────────────────────────

function DataGrid({ items }: { items: { label: string; value: string; accent?: boolean }[] }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
      {items.map(({ label, value, accent }) => (
        <div key={label} className="bg-slate-950/60 border border-slate-800/60 rounded-lg px-3 py-2.5">
          <div className="text-[9px] text-slate-600 font-mono uppercase tracking-wider">{label}</div>
          <div className={clsx('text-xs font-mono font-bold mt-0.5', accent ? 'text-cyan-300' : 'text-slate-200')}>{value}</div>
        </div>
      ))}
    </div>
  )
}

function SectionTitle({ icon: Icon, text, count }: { icon: any; text: string; count?: number }) {
  return (
    <div className="flex items-center gap-2 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest mb-3">
      <Icon size={11} className="text-slate-500" />
      {text}
      {count !== undefined && (
        <span className="ml-1 px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded text-[9px] text-slate-400">{count}</span>
      )}
    </div>
  )
}

function Stage1Detail({ reports, metrics }: { reports: any; metrics: PrometheusMetrics | null }) {
  const inv = reports?.inventory ?? []
  return (
    <div className="space-y-4">
      <DataGrid items={[
        { label: 'OT Zone', value: '192.168.10.0/24', accent: true },
        { label: 'IT Zone', value: '192.168.20.0/24' },
        { label: 'DMZ Zone', value: '192.168.30.0/24' },
        { label: 'Mgmt Zone', value: '192.168.40.0/24' },
        { label: 'Modbus Rate', value: (metrics?.modbus_traffic_rate ?? -1) >= 0 ? `${(metrics!.modbus_traffic_rate).toFixed(2)}/s` : 'N/A', accent: true },
        { label: 'OT Isolation', value: 'lab-ot-net (internal: true)' },
      ]} />

      <div>
        <SectionTitle icon={Server} text="OT Asset Inventory" count={inv.length} />
        {inv.length === 0 ? (
          <EmptyState text="No assets discovered yet — inventory.py runs every 10 minutes." />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-800/50 max-h-56 overflow-y-auto">
            <table className="min-w-full text-[10.5px] font-mono">
              <thead className="sticky top-0 bg-slate-950">
                <tr className="border-b border-slate-800/60 text-slate-500 uppercase text-[9px] tracking-wider">
                  <th className="px-3 py-2 text-left">IP Address</th>
                  <th className="px-3 py-2 text-left">Product</th>
                  <th className="px-3 py-2 text-left">Firmware</th>
                  <th className="px-3 py-2 text-left">Open Ports</th>
                  <th className="px-3 py-2 text-left">Method</th>
                </tr>
              </thead>
              <tbody>
                {inv.map((a: any) => (
                  <tr key={a.ip} className="border-b border-slate-900 hover:bg-slate-800/20">
                    <td className="px-3 py-2 text-cyan-300 font-bold">{a.ip}</td>
                    <td className="px-3 py-2 text-slate-300">{a.vendor ?? '—'} / {a.product ?? '—'}</td>
                    <td className="px-3 py-2 text-slate-500">{a.firmware ?? '—'}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {(a.open_ports ?? []).slice(0, 6).map((p: number, i: number) => (
                          <span key={p} className="bg-slate-900 border border-slate-800 rounded px-1 text-[9px] text-slate-400">
                            {p}/{a.protocols?.[i] ?? 'tcp'}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2 text-slate-600 text-[9px]">{(a.discovery_methods ?? []).join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function Stage2Detail({ reports, meta, metrics }: { reports: any; meta: any; metrics: PrometheusMetrics | null }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        {[
          { name: 'IsolationForest', val: (metrics?.iforest_score ?? -1) >= 0 ? (metrics!.iforest_score).toFixed(4) : '—', thr: '> 0.15 = alert', ok: (metrics?.iforest_score ?? -1) < 0.15 && (metrics?.iforest_score ?? -1) >= 0 },
          { name: 'PCA Recon Z', val: (metrics?.pca_z ?? -1) >= 0 ? (metrics!.pca_z).toFixed(3) : '—', thr: '≥ 3.0σ = alert', ok: (metrics?.pca_z ?? -1) < 3.0 && (metrics?.pca_z ?? -1) >= 0 },
          { name: 'TF Deep AE Z', val: (metrics?.tf_z ?? -1) >= 0 ? (metrics!.tf_z!).toFixed(3) : '—', thr: '≥ 3.0σ = alert', ok: (metrics?.tf_z ?? -1) < 3.0 && (metrics?.tf_z ?? -1) >= 0 },
        ].map(({ name, val, thr, ok }) => (
          <div key={name} className={clsx(
            'rounded-lg border p-3 text-center',
            ok === false ? 'bg-red-950/30 border-red-800/50' : ok === true ? 'bg-emerald-950/20 border-emerald-900/50' : 'bg-slate-950/40 border-slate-800/50',
          )}>
            <div className="text-[9px] text-slate-500 font-mono uppercase tracking-wider">{name}</div>
            <div className={clsx('text-xl font-bold font-mono mt-1', ok === false ? 'text-red-300' : ok === true ? 'text-emerald-300' : 'text-slate-500')}>
              {val}
            </div>
            <div className="text-[8.5px] text-slate-700 font-mono mt-1">{thr}</div>
          </div>
        ))}
      </div>

      {meta && (
        <div>
          <SectionTitle icon={Cpu} text="Model Calibration" />
          <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
            <InfoRow label="Feature version" value={meta.feature_version ?? 'N/A'} />
            <InfoRow label="IF alert threshold" value="0.1500" />
            <InfoRow label="PCA z-alert threshold" value={`${(meta.pca_threshold?.z_alert_threshold ?? 3.0).toFixed(2)}σ`} />
            <InfoRow label="PCA recon mean" value={(meta.pca_threshold?.baseline_recon_mean ?? 0).toFixed(6)} />
            <InfoRow label="TF z-alert threshold" value={`${(meta.tf_threshold?.z_alert_threshold ?? 3.0).toFixed(2)}σ`} />
            <InfoRow label="TF recon mean" value={(meta.tf_threshold?.baseline_recon_mean ?? 0).toFixed(6)} />
          </div>
          {meta.feature_names?.length > 0 && (
            <div className="mt-3">
              <div className="text-[9px] text-slate-600 font-mono uppercase mb-1.5">
                Feature vector ({meta.feature_names.length} dims)
              </div>
              <div className="flex flex-wrap gap-1.5">
                {meta.feature_names.map((f: string) => (
                  <span key={f} className="text-[9px] font-mono bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-slate-500">
                    {f}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function Stage3Detail({ reports, metrics }: { reports: any; metrics: PrometheusMetrics | null }) {
  const safetyLabels = ['NORMAL', 'DEGRADED', 'EMERGENCY']
  const state = metrics?.safety_state ?? -1
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <div className={clsx(
          'rounded-lg border p-4 text-center',
          state === 0 ? 'bg-emerald-950/30 border-emerald-800/50' :
            state === 1 ? 'bg-amber-950/30 border-amber-800/50' :
              state === 2 ? 'bg-red-950/30 border-red-800/50 animate-pulse' :
                'bg-slate-950/40 border-slate-800/50',
        )}>
          <div className="text-[9px] text-slate-500 font-mono uppercase tracking-wider">Safety State</div>
          <div className={clsx(
            'text-2xl font-black font-mono mt-1',
            state === 0 ? 'text-emerald-400' : state === 1 ? 'text-amber-400' : state === 2 ? 'text-red-400' : 'text-slate-600',
          )}>
            {state >= 0 ? safetyLabels[state] : 'N/A'}
          </div>
          <div className="text-[9px] text-slate-600 font-mono mt-1">Safety PLC HR[10]</div>
        </div>
        <div className={clsx(
          'rounded-lg border p-4 text-center',
          metrics?.sis_integrity === 1 ? 'bg-emerald-950/30 border-emerald-800/50' :
            metrics?.sis_integrity === 0 ? 'bg-red-950/30 border-red-800/50' :
              'bg-slate-950/40 border-slate-800/50',
        )}>
          <div className="text-[9px] text-slate-500 font-mono uppercase tracking-wider">SIS Integrity</div>
          <div className={clsx(
            'text-2xl font-black font-mono mt-1',
            metrics?.sis_integrity === 1 ? 'text-emerald-400' : metrics?.sis_integrity === 0 ? 'text-red-400' : 'text-slate-600',
          )}>
            {metrics?.sis_integrity === 1 ? 'OK' : metrics?.sis_integrity === 0 ? 'FAIL' : 'N/A'}
          </div>
          <div className="text-[9px] text-slate-600 font-mono mt-1">HR[10..12] validation</div>
        </div>
      </div>

      {reports?.integrity_baseline && (
        <div className="space-y-3">
          <SectionTitle icon={Activity} text="Service Status" />
          <div className="grid grid-cols-2 gap-1.5">
            {Object.entries(reports.integrity_baseline.services ?? {}).map(([name, running]: [string, any]) => (
              <div key={name} className="flex items-center justify-between bg-slate-950/50 border border-slate-800/40 rounded-lg px-3 py-2 text-[10px] font-mono">
                <span className="text-slate-400">{name.replace(/_/g, ' ')}</span>
                <div className="flex items-center gap-1.5">
                  <span className={clsx('w-2 h-2 rounded-full', running ? 'bg-emerald-400 shadow-[0_0_6px_#10b981]' : 'bg-red-500')} />
                  <span className={running ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                    {running ? 'RUN' : 'STOP'}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {Object.keys(reports.integrity_baseline.plc_files ?? {}).length > 0 && (
            <>
              <SectionTitle icon={Hash} text="Integrity Hashes" />
              <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
                {Object.entries({ ...reports.integrity_baseline.plc_files, ...reports.integrity_baseline.sros2_files }).map(([name, hash]: [string, any]) => (
                  <div key={name} className="flex items-center justify-between bg-slate-950/50 border border-slate-800/40 rounded-lg px-3 py-2 text-[9.5px] font-mono">
                    <span className="text-slate-400 truncate max-w-[120px]">{name}</span>
                    <span className="text-slate-600 font-bold" title={hash}>{String(hash).slice(0, 10)}…</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

function Stage4Detail({ reports, metrics }: { reports: any; metrics: PrometheusMetrics | null }) {
  const vulns = reports?.vulnerabilities ?? []
  const drift = reports?.baseline_drift?.drift ?? []
  const CVSS_BAND = (cvss: number) =>
    cvss >= 9 ? { cls: 'bg-red-950 border-red-700 text-red-300', lbl: 'CRIT' }
      : cvss >= 7 ? { cls: 'bg-amber-950 border-amber-700 text-amber-300', lbl: 'HIGH' }
        : cvss >= 4 ? { cls: 'bg-yellow-950 border-yellow-700 text-yellow-300', lbl: 'MED' }
          : { cls: 'bg-blue-950 border-blue-700 text-blue-300', lbl: 'LOW' }

  return (
    <div className="space-y-4">
      <DataGrid items={[
        { label: 'Critical CVEs', value: String(metrics?.vuln_by_severity?.critical ?? 0), accent: (metrics?.vuln_by_severity?.critical ?? 0) > 0 },
        { label: 'High CVEs', value: String(metrics?.vuln_by_severity?.high ?? 0) },
        { label: 'Medium CVEs', value: String(metrics?.vuln_by_severity?.medium ?? 0) },
        { label: 'Critical Drift', value: String(metrics ? (metrics as any).baseline_drift_critical ?? 0 : 0) },
        { label: 'Total Findings', value: String(vulns.length) },
        { label: 'Drift Entries', value: String(drift.length) },
      ]} />

      {vulns.length === 0 ? (
        <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono bg-emerald-950/20 border border-emerald-900/50 rounded-lg px-4 py-3">
          <CheckCircle2 size={14} /> Zero vulnerabilities detected. All assets are hardened.
        </div>
      ) : (
        <>
          <SectionTitle icon={ShieldAlert} text="CVE Findings" count={vulns.length} />
          <div className="overflow-x-auto rounded-lg border border-slate-800/50 max-h-52 overflow-y-auto">
            <table className="min-w-full text-[10.5px] font-mono">
              <thead className="sticky top-0 bg-slate-950">
                <tr className="border-b border-slate-800/60 text-slate-500 text-[9px] uppercase tracking-wider">
                  <th className="px-3 py-2 text-left w-16">Sev</th>
                  <th className="px-3 py-2 text-left">CVE</th>
                  <th className="px-3 py-2 text-left">Asset</th>
                  <th className="px-3 py-2 text-left w-12">CVSS</th>
                  <th className="px-3 py-2 text-left">Remediation</th>
                </tr>
              </thead>
              <tbody>
                {vulns.map((v: any, i: number) => {
                  const b = CVSS_BAND(v.cvss)
                  return (
                    <tr key={i} className="border-b border-slate-900/80 hover:bg-slate-800/20">
                      <td className="px-3 py-2">
                        <span className={clsx('text-[8.5px] px-1.5 py-0.5 rounded border font-bold', b.cls)}>{b.lbl}</span>
                      </td>
                      <td className="px-3 py-2">
                        <a href={v.url} target="_blank" rel="noopener noreferrer"
                          className="text-blue-400 hover:underline flex items-center gap-1">
                          {v.cve_id} <ExternalLink size={9} />
                        </a>
                      </td>
                      <td className="px-3 py-2 text-slate-400">{v.asset_ip} ({v.asset_product ?? '—'})</td>
                      <td className="px-3 py-2 font-bold text-slate-200">{v.cvss.toFixed(1)}</td>
                      <td className="px-3 py-2 text-slate-500 max-w-[200px] truncate">{v.remediation}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {drift.length > 0 && (
        <>
          <SectionTitle icon={RefreshCw} text="Configuration Drift" count={drift.length} />
          <div className="space-y-1.5 max-h-36 overflow-y-auto">
            {drift.map((d: any, i: number) => (
              <div key={i} className={clsx(
                'flex items-start gap-3 px-3 py-2 rounded-lg border text-[10px] font-mono',
                d.severity === 'critical' ? 'bg-red-950/30 border-red-800/50'
                  : d.severity === 'high' ? 'bg-amber-950/30 border-amber-800/50'
                    : 'bg-slate-950/40 border-slate-800/40',
              )}>
                <span className={clsx(
                  'text-[8.5px] px-1.5 py-0.5 rounded border font-bold flex-shrink-0 mt-px',
                  d.severity === 'critical' ? 'bg-red-950 border-red-700 text-red-300'
                    : d.severity === 'high' ? 'bg-amber-950 border-amber-700 text-amber-300'
                      : 'bg-slate-900 border-slate-700 text-slate-400',
                )}>{(d.severity ?? 'med').toUpperCase()}</span>
                <span className="text-slate-400">{d.description}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function Stage5Detail({ reports, metrics }: { reports: any; metrics: PrometheusMetrics | null }) {
  const v = reports?.pipeline_verdict
  const GATES = [
    { name: 'PLC Lint', desc: 'IEC 61131-3 ST static analysis (R1-R6)' },
    { name: 'HMI Lint', desc: 'HMI JSON schema and safety-binding check' },
    { name: 'SROS2 Lint', desc: 'DDS-Security permissions XML validation' },
    { name: 'Vuln Gate', desc: 'CVE threshold check (CVSS ≥ 7.0 fails)' },
    { name: 'Baseline Gate', desc: 'Config drift critical check' },
    { name: 'Acceptance', desc: 'Stage 2 replay + Stage 3 safety loop' },
  ]
  const isPass = v?.verdict === 'PASS'
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-2">
        {GATES.map((g, i) => (
          <div key={g.name} className={clsx(
            'rounded-lg border px-3 py-2.5',
            isPass ? 'bg-emerald-950/20 border-emerald-900/50' : v ? 'bg-red-950/20 border-red-900/40' : 'bg-slate-950/40 border-slate-800/50',
          )}>
            <div className="flex items-center gap-1.5">
              <span className={clsx(
                'text-[9px] font-mono font-bold',
                isPass ? 'text-emerald-400' : v ? 'text-red-400' : 'text-slate-600',
              )}>
                Gate {i + 1}
              </span>
              {v && (isPass
                ? <CheckCircle2 size={10} className="text-emerald-400" />
                : <XCircle size={10} className="text-red-400" />)}
            </div>
            <div className="text-[10px] font-mono font-bold text-slate-300 mt-0.5">{g.name}</div>
            <div className="text-[8.5px] text-slate-600 mt-0.5 leading-tight">{g.desc}</div>
          </div>
        ))}
      </div>

      {v ? (
        <div className={clsx(
          'rounded-lg border p-4',
          isPass ? 'bg-emerald-950/20 border-emerald-900/50' : 'bg-red-950/20 border-red-800/50',
        )}>
          <div className="flex items-center gap-3 flex-wrap mb-3">
            <span className={clsx(
              'text-sm font-black font-mono px-3 py-1 rounded-lg border',
              isPass ? 'bg-emerald-950 border-emerald-700 text-emerald-300' : 'bg-red-950 border-red-700 text-red-300',
            )}>
              {isPass ? '✓ PASS' : '✗ FAIL'}
            </span>
            <span className="text-[10px] text-slate-500 font-mono">{v.build_id}</span>
            <span className="text-[10px] text-slate-600 font-mono">{v.timestamp}</span>
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            Source: <span className="text-slate-400">{(v.source ?? '').replace('/vagrant', 'robotics-app').replace('/opt/lab', 'robotics-app')}</span>
          </div>
        </div>
      ) : (
        <EmptyState text="No pipeline build found. Push code to Gitea or trigger a manual run." />
      )}
    </div>
  )
}

function Stage6Detail({ pendingApprovals, incidents, metrics }: {
  pendingApprovals: any[]; incidents: any[]; metrics: PrometheusMetrics | null
}) {
  const [approving, setApproving] = useState<string | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  async function handleApprove(p: any, reject: boolean) {
    const key = `${p.incident_id}-${p.step}-${reject}`
    setApproving(key)
    setMsg(null)
    const r = await approveIncidentStep(p.incident_id, p.step, reject)
    setMsg({ ok: r.status === 'ok', text: r.status === 'ok' ? `${reject ? 'Rejected' : 'Approved'}: ${p.step}` : r.detail ?? 'Error' })
    setApproving(null)
  }

  return (
    <div className="space-y-4">
      <DataGrid items={[
        { label: 'Open Incidents', value: String(Math.round(metrics?.open_incidents ?? 0)), accent: (metrics?.open_incidents ?? 0) > 0 },
        { label: 'Pending Approvals', value: String(pendingApprovals.length), accent: pendingApprovals.length > 0 },
        { label: 'Detection Latency', value: (metrics?.detection_latency ?? -1) > 0 ? `${metrics!.detection_latency.toFixed(2)}s` : 'N/A' },
        { label: 'IF Score', value: (metrics?.iforest_score ?? -1) >= 0 ? metrics!.iforest_score.toFixed(4) : 'N/A' },
      ]} />

      {msg && (
        <div className={clsx('text-xs font-mono px-3 py-2 rounded-lg border', msg.ok ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300' : 'bg-red-950/40 border-red-800 text-red-300')}>
          {msg.ok ? '✓' : '✗'} {msg.text}
        </div>
      )}

      {pendingApprovals.length > 0 && (
        <>
          <SectionTitle icon={Lock} text="Pending Approvals" count={pendingApprovals.length} />
          <div className="space-y-2">
            {pendingApprovals.map((p, i) => (
              <div key={i} className="bg-amber-950/20 border border-amber-900/60 rounded-lg p-3 flex items-start justify-between gap-4 font-mono text-[10px]">
                <div className="space-y-1 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-amber-300 font-bold">{p.incident_id}</span>
                    <span className="text-[9px] px-1.5 py-0.5 bg-amber-950 border border-amber-800 rounded text-amber-400">{p.step}</span>
                  </div>
                  <div className="text-slate-500 bg-slate-950/60 rounded px-2 py-1 text-[9px] truncate">{p.cmd}</div>
                </div>
                <div className="flex gap-2 flex-shrink-0">
                  <button
                    disabled={!!approving}
                    onClick={() => handleApprove(p, false)}
                    className="px-3 py-1.5 bg-emerald-800/60 hover:bg-emerald-700/70 border border-emerald-600 rounded text-[10px] font-bold text-emerald-200 transition-all disabled:opacity-40">
                    Approve
                  </button>
                  <button
                    disabled={!!approving}
                    onClick={() => handleApprove(p, true)}
                    className="px-3 py-1.5 bg-red-900/50 hover:bg-red-800/60 border border-red-700 rounded text-[10px] font-bold text-red-200 transition-all disabled:opacity-40">
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <SectionTitle icon={Activity} text="Recent Incidents" count={incidents.length} />
      {incidents.length === 0 ? (
        <EmptyState text="No incidents recorded." />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800/50 max-h-52 overflow-y-auto">
          <table className="min-w-full text-[10.5px] font-mono">
            <thead className="sticky top-0 bg-slate-950">
              <tr className="border-b border-slate-800/60 text-slate-500 text-[9px] uppercase tracking-wider">
                <th className="px-3 py-2 text-left">ID</th>
                <th className="px-3 py-2 text-left">Playbook</th>
                <th className="px-3 py-2 text-left">Trigger</th>
                <th className="px-3 py-2 text-left w-20">Status</th>
                <th className="px-3 py-2 text-left">Opened</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc: any) => (
                <tr key={inc.incident_id} className="border-b border-slate-900/80 hover:bg-slate-800/20">
                  <td className="px-3 py-2 text-slate-400 text-[9px] max-w-[100px] truncate">{inc.incident_id}</td>
                  <td className="px-3 py-2 text-amber-400 font-bold">{inc.playbook}</td>
                  <td className="px-3 py-2 text-slate-500 max-w-[160px] truncate">
                    {inc.event?.alert?.signature ?? inc.event?.category ?? '—'}
                  </td>
                  <td className="px-3 py-2">
                    <span className={clsx(
                      'text-[8.5px] px-1.5 py-0.5 rounded border font-bold',
                      inc.closed ? 'bg-emerald-950 border-emerald-800 text-emerald-400' : 'bg-red-950 border-red-800 text-red-400',
                    )}>{inc.closed ? 'RESOLVED' : 'ACTIVE'}</span>
                  </td>
                  <td className="px-3 py-2 text-slate-600 text-[9px]">{new Date(inc.opened_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between bg-slate-950/50 border border-slate-800/40 rounded px-2.5 py-1.5 text-[10px] font-mono">
      <span className="text-slate-600">{label}</span>
      <span className="text-slate-300 font-bold">{value}</span>
    </div>
  )
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="text-[10.5px] text-slate-600 font-mono italic py-3 px-4 bg-slate-950/30 border border-slate-800/30 rounded-lg">
      {text}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export function StagesPage({ metrics }: Props) {
  const [activeStageId, setActiveStageId] = useState<number>(1)
  const [meta, setMeta] = useState<any>(null)

  const reports = useStagesReports(5000)
  const pendingApprovals = usePendingApprovals(3000)
  const incidents = useIncidents(3000)

  useEffect(() => {
    fetch('/metadata')
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setMeta(d))
      .catch(() => { })
  }, [])

  const activeStage = STAGES.find(s => s.id === activeStageId)!

  return (
    <div className="h-full overflow-y-auto" style={{ background: '#060a10' }}>
      <div className="p-5 space-y-4">

        {/* Header row */}
        <div className="flex items-start gap-5">
          <ComplianceBand metrics={metrics} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <Shield size={14} className="text-slate-400" />
              <h1 className="text-base font-bold text-white tracking-tight">
                Security Control Posture — IEC 62443 / NIST SP 800-82
              </h1>
            </div>
            <p className="text-[10.5px] text-slate-500 mb-3 leading-relaxed">
              Live status of the six OT security control domains — network segmentation, AI detection, safety
              integrity, vulnerability management, secure CI/CD, and incident response. Select a domain for its
              live evidence, mapped to the governing standard.
            </p>
            <PipelineFlow metrics={metrics} activeId={activeStageId} onSelect={setActiveStageId} />
          </div>
        </div>

        {/* Active stage detail */}
        <StageDetailPanel
          stage={activeStage}
          metrics={metrics}
          reports={reports}
          pendingApprovals={pendingApprovals}
          incidents={incidents}
          meta={meta}
        />

      </div>
    </div>
  )
}
