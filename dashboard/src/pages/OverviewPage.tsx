import type { HMIState, PrometheusMetrics, PageId } from '../types'
import { Activity, Server, Shield, Wifi, WifiOff, ArrowRight } from 'lucide-react'
import { clsx } from 'clsx'
import { useState, useEffect } from 'react'
import { useLiveScores, useIncidents } from '../hooks/useMetrics'

interface Props {
  hmiState: HMIState | null
  metrics: PrometheusMetrics | null
  connected: boolean
  onNavigate: (page: PageId) => void
}

function ComplianceGauge({ score }: { score: number }) {
  const r = 54
  const circ = 2 * Math.PI * r
  const pct = Math.max(0, Math.min(100, score)) / 100
  const fill = circ * pct
  const color = score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444'
  return (
    <div className="flex flex-col items-center">
      <svg width="128" height="128" viewBox="0 0 128 128">
        <circle cx="64" cy="64" r={r} fill="none" stroke="#111827" strokeWidth="10" />
        <circle
          cx="64" cy="64" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${fill} ${circ}`}
          strokeDashoffset={circ / 4}
          className="gauge-arc"
          transform="rotate(-90 64 64)"
          style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(0.4, 0, 0.2, 1)' }}
        />
        <text x="64" y="60" textAnchor="middle" fill={color} fontSize="22" fontWeight="bold" fontFamily="monospace" className="text-shadow-glow">
          {score < 0 ? '--' : Math.round(score)}
        </text>
        <text x="64" y="76" textAnchor="middle" fill="#64748b" fontSize="8" fontWeight="bold" fontFamily="sans-serif" className="tracking-wider">
          COMPLIANCE
        </text>
      </svg>
    </div>
  )
}

function ComponentDot({ name, up }: { name: string; up: number }) {
  const label = name.replace(/_/g, ' ').replace(/stage\d+ /i, '').toUpperCase()
  return (
    <div className="flex items-center gap-2 text-xs font-mono bg-slate-900/50 border border-slate-800/40 rounded px-2.5 py-1.5 hover:bg-slate-900/90 transition-colors">
      <span className={clsx('status-dot flex-shrink-0', 
        up === 1 ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)] ring-pulse' : 
        up === -1 ? 'bg-slate-600' : 
        'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)] animate-pulse'
      )} />
      <span className={clsx('truncate', up === 1 ? 'text-slate-300' : 'text-slate-500')}>{label}</span>
    </div>
  )
}

function Zone({ x, y, w, h, name, level, cidr, hosts, accent, danger }: {
  x: number; y: number; w: number; h: number; name: string; level: string; cidr: string; hosts: string[]; accent: string; danger?: boolean
}) {
  return (
    <g transform={`translate(${x},${y})`}>
      <rect width={w} height={h} rx="8" fill="#0a0f17" stroke={danger ? '#ef4444' : '#1e293b'} strokeWidth="1.5" />
      <rect width="4" height={h} rx="2" fill={danger ? '#ef4444' : accent} />
      <text x="14" y="18" fill={danger ? '#f87171' : '#cbd5e1'} fontSize="10.5" fontWeight="700">{name}</text>
      <text x={w - 12} y="18" textAnchor="end" fill="#64748b" fontSize="8" fontFamily="monospace">{level}</text>
      <text x="14" y="31" fill="#475569" fontSize="8" fontFamily="monospace">{cidr}</text>
      {hosts.map((hh, i) => (
        <text key={i} x="14" y={48 + i * 13} fill="#94a3b8" fontSize="9">{hh}</text>
      ))}
    </g>
  )
}

function TopologyMap({ metrics }: { metrics: PrometheusMetrics | null }) {
  const isAttack = (metrics?.injection_active ?? 0) > 0
  const conduit = (d: string, label?: string, lx?: number, ly?: number) => (
    <g>
      <path d={d} stroke="#334155" strokeWidth="1.5" fill="none" markerEnd="url(#tArrow)" />
      <path d={d} stroke={isAttack ? '#f43f5e' : '#38bdf8'} strokeWidth="1.5" strokeDasharray="5 7" fill="none"
        className="flow-path" style={{ animationDuration: isAttack ? '0.8s' : '2.4s', opacity: 0.5 }} />
      {label && <text x={lx} y={ly} textAnchor="middle" fontSize="7.5" fill="#64748b" fontFamily="monospace">{label}</text>}
    </g>
  )
  return (
    <div className="card">
      <div className="card-header flex items-center">
        Network Segmentation — IEC 62443 Zones &amp; Conduits
        <span className={clsx('ml-auto flex items-center gap-1.5 normal-case tracking-normal text-[10px] px-2 py-0.5 rounded-full border',
          isAttack ? 'border-red-700 bg-red-950/40 text-red-300' : 'border-emerald-800 bg-emerald-950/30 text-emerald-300')}>
          <span className={clsx('w-1.5 h-1.5 rounded-full', isAttack ? 'bg-red-500 animate-pulse' : 'bg-emerald-400')} />
          {isAttack ? 'Attack contained in OT zone' : 'Default-deny enforced · matrix 16/16'}
        </span>
      </div>
      <svg viewBox="0 0 800 300" className="w-full h-auto mt-1" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker id="tArrow" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0 2 L9 5 L0 8 z" fill="#334155" />
          </marker>
        </defs>
        {/* conduits converge on the firewall */}
        {conduit('M 214 149 L 326 149', 'signed deploy', 270, 142)}
        {conduit('M 474 149 L 586 149', 'telemetry RO · ctrl gw', 530, 142)}
        {conduit('M 400 86 L 400 118')}
        {conduit('M 400 178 L 400 220')}
        {/* zones */}
        <Zone x={20} y={110} w={194} h={78} name="IT ZONE" level="L4" cidr="192.168.20.0/24" hosts={['Gitea repository', 'Act CI runner']} accent="#475569" />
        <Zone x={303} y={14} w={194} h={70} name="INDUSTRIAL DMZ" level="L3.5" cidr="192.168.30.0/24" hosts={['Guacamole gateway', 'Deploy / historian store']} accent="#0e7490" />
        <Zone x={586} y={110} w={194} h={78} name="OT CELL" level="L0–L2" cidr="192.168.10.0/24" hosts={['OpenPLC + Safety PLC', 'Robot (ROS2 / Gazebo)']} accent="#9f1239" danger={isAttack} />
        <Zone x={303} y={220} w={194} h={72} name="MGMT / AI + SENSOR" level="L3" cidr="192.168.40.0/24" hosts={['AI score_service', 'Zeek + Suricata IDS']} accent="#6d28d9" />
        {/* central firewall (only multi-homed node) */}
        <g transform="translate(330,121)">
          <rect width="140" height="56" rx="8" fill="#1a1206" stroke="#b45309" strokeWidth="1.5" />
          <text x="70" y="21" textAnchor="middle" fill="#fbbf24" fontSize="11.5" fontWeight="700">router-fw</text>
          <text x="70" y="34" textAnchor="middle" fill="#a16207" fontSize="7.5" fontFamily="monospace">nftables · default-deny</text>
          <text x="70" y="46" textAnchor="middle" fill="#a16207" fontSize="7.5" fontFamily="monospace">8 conduits · L7 Modbus proxy</text>
        </g>
      </svg>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1 text-[9px] font-mono text-slate-600">
        <span><span className="text-slate-400">router-fw</span> is the only multi-homed node — every cross-zone packet is inspected.</span>
        <span className="ml-auto">IT ↛ OT blocked · AI reads OT read-only via proxy · OT pulls signed deploys from DMZ</span>
      </div>
    </div>
  )
}

export function OverviewPage({ hmiState, metrics, connected, onNavigate }: Props) {
  // Live data straight from the data plane (the Prometheus chain lags ~15s and was
  // showing N/A on a healthy plant). safety/SIS come from the live PLC read,
  // AI status from /api/scores/live, incidents from the live IR log.
  const live = useLiveScores(1500)
  const incidents = useIncidents(3000)
  const plc = hmiState?.plc_state as any
  const plcOk = plc && !('error' in plc)
  const safetyLabel = ['NORMAL', 'DEGRADED', 'EMERGENCY']
  const safetyState = plcOk && typeof plc.safety_state === 'number' ? plc.safety_state : (metrics?.safety_state ?? -1)
  // SIS integrity: safety registers internally valid (state 0-2, known fault code).
  const sisOk = plcOk && [0, 1, 2].includes(plc.safety_state) && [0, 1, 2, 3, 4].includes(plc.last_fault_code)
  const sisKnown = plcOk
  // AI engine: live anomaly state + the positive activity reading.
  const aiAnomaly = live?.anomaly ?? false
  const aiActivity = live?.if_activity ?? null
  // Open incidents from the live IR log (Prometheus count lagged/showed 0).
  const openIncidents = incidents.length > 0
    ? incidents.filter(i => !i.closed && !(i as any).postmortem_committed && !(i as any).blocked && !(i as any).merged).length
    : Math.max(0, Math.round(metrics?.open_incidents ?? 0))

  // Cross-zone services (IT Gitea, DMZ Guacamole) are unreachable from the AI/mgmt
  // monitoring plane BY SEGMENTATION DESIGN, so the exporter can't probe them — it
  // would falsely report DOWN. The operator's browser CAN reach their published
  // portals, so we health-check them here and merge with the exporter components.
  const [extHealth, setExtHealth] = useState<Record<string, number>>({ it_gitea: -1, dmz_guacamole: -1 })
  useEffect(() => {
    let active = true
    const host = typeof window !== 'undefined' ? window.location.hostname : 'localhost'
    const checks: [string, string][] = [
      ['it_gitea', `http://${host}:3000/`],
      ['dmz_guacamole', `http://${host}:8081/guacamole/`],
    ]
    const run = async () => {
      const out: Record<string, number> = {}
      await Promise.all(checks.map(async ([k, url]) => {
        try { await fetch(url, { mode: 'no-cors', signal: AbortSignal.timeout(3000) }); out[k] = 1 }
        catch { out[k] = 0 }
      }))
      if (active) setExtHealth(out)
    }
    run(); const t = setInterval(run, 8000)
    return () => { active = false; clearInterval(t) }
  }, [])
  // All platform services: exporter-probed (mgmt-reachable) + browser-probed (cross-zone).
  const allComponents = { ...(metrics?.component_health ?? {}), ...extHealth }

  return (
    <div className="h-full overflow-y-auto p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Platform Overview</h1>
          <p className="text-xs text-slate-500 mt-0.5">Intelligent Industrial Robotics Security — OT/IT Convergence</p>
        </div>
        <div className="flex items-center gap-2 text-sm bg-slate-900/60 border border-slate-800/40 rounded-full px-3 py-1">
          {connected
            ? <><Wifi size={14} className="text-safe-green animate-pulse" /><span className="text-safe-green font-mono text-xs">API LIVE</span></>
            : <><WifiOff size={14} className="text-red-400" /><span className="text-red-400 font-mono text-xs">API OFFLINE</span></>
          }
        </div>
      </div>

      {/* Top KPI row */}
      <div className="grid grid-cols-4 gap-4">
        {/* Compliance */}
        <div 
          onClick={() => onNavigate('stages')}
          className="card border-glow-green cursor-pointer hover:bg-slate-800/30 active:scale-95 transition-all select-none group flex flex-col justify-between"
        >
          <ComplianceGauge score={metrics?.compliance_score ?? -1} />
          <div className="flex items-center justify-center gap-1 text-xs text-slate-400 mt-2 font-mono group-hover:text-emerald-400 transition-colors">
            Compliance Score <ArrowRight size={10} className="opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>

        {/* Safety State */}
        <div 
          onClick={() => onNavigate('plc-control')}
          className="card cursor-pointer hover:bg-slate-800/30 active:scale-95 transition-all select-none group flex flex-col justify-between"
        >
          <div>
            <div className="card-header"><Shield size={13} className="group-hover:text-amber-500 transition-colors" />Safety State</div>
            <div className={clsx('stat-value mt-2 text-[26px]', 
              safetyState === 0 ? 'text-safe-green text-shadow-glow' : 
              safetyState === 1 ? 'text-ai-amber text-shadow-glow' : 
              safetyState === 2 ? 'text-ot-red text-shadow-glow animate-pulse' : 
              'text-slate-500'
            )}>
              {safetyState === -1 ? 'N/A' : safetyLabel[safetyState] ?? 'UNKNOWN'}
            </div>
          </div>
          <div className="text-[10px] text-slate-500 font-mono flex items-center justify-between border-t border-slate-800/60 pt-2 mt-2">
            <span>SIS Integrity:</span>
            <span className={clsx('font-bold', !sisKnown ? 'text-slate-500' : sisOk ? 'text-safe-green' : 'text-ot-red')}>
              {!sisKnown ? '—' : sisOk ? '✓ OK' : '✗ FAIL'}
            </span>
          </div>
        </div>

        {/* AI Anomaly Engine */}
        <div 
          onClick={() => onNavigate('ai-engine')}
          className="card cursor-pointer hover:bg-slate-800/30 active:scale-95 transition-all select-none group flex flex-col justify-between"
        >
          <div>
            <div className="card-header"><Activity size={13} className="group-hover:text-blue-400 transition-colors" />AI Anomaly Engine</div>
            <div className={clsx('stat-value mt-2 text-[26px]',
              aiAnomaly ? 'text-ot-red text-shadow-glow animate-pulse' : aiActivity != null ? 'text-safe-green text-shadow-glow' : 'text-slate-500'
            )}>
              {aiActivity == null ? '—' : aiAnomaly ? 'ANOMALY' : 'NOMINAL'}
            </div>
          </div>
          <div className="text-[10px] text-slate-500 font-mono flex items-center justify-between border-t border-slate-800/60 pt-2 mt-2">
            <span>Model activity:</span>
            <span className="text-cyan-400">
              {aiActivity != null ? aiActivity.toFixed(2) : 'N/A'}
            </span>
          </div>
        </div>

        {/* Open Incidents */}
        <div 
          onClick={() => onNavigate('incidents')}
          className="card cursor-pointer hover:bg-slate-800/30 active:scale-95 transition-all select-none group flex flex-col justify-between"
        >
          <div>
            <div className="card-header"><Server size={13} className="group-hover:text-red-500 transition-colors" />Open Incidents</div>
            <div className={clsx('stat-value mt-2 text-[28px] tabular-nums',
              openIncidents > 0 ? 'text-ot-red text-shadow-glow animate-pulse' : 'text-safe-green text-shadow-glow'
            )}>
              {openIncidents}
            </div>
          </div>
          <div className="text-[10px] text-slate-500 font-mono flex items-center justify-between border-t border-slate-800/60 pt-2 mt-2">
            <span>Critical CVEs:</span>
            <span className={clsx('font-bold', (metrics?.vuln_by_severity?.critical ?? 0) > 0 ? 'text-ot-red' : 'text-slate-400')}>
              {metrics?.vuln_by_severity?.critical ?? 0}
            </span>
          </div>
        </div>
      </div>

      {/* Purdue segmentation topology map */}
      <TopologyMap metrics={metrics} />

      {/* Component health grid */}
      <div className="card">
        <div className="card-header flex items-center">
          Platform Service Health
          <span className="ml-auto normal-case tracking-normal text-[9px] text-slate-600">
            mgmt-plane probes · cross-zone (IT/DMZ) checked from console
          </span>
        </div>
        <div className="grid grid-cols-3 md:grid-cols-5 gap-3 mt-2">
          {Object.entries(allComponents).map(([name, up]) => (
            <ComponentDot key={name} name={name} up={up} />
          ))}
          {!metrics && Object.keys(extHealth).length === 0 && Array.from({ length: 9 }).map((_, i) => (
            <div key={i} className="flex items-center gap-2 text-xs font-mono text-slate-700 bg-slate-900/20 border border-slate-800/20 rounded px-2.5 py-1.5">
              <span className="status-dot bg-slate-800 animate-pulse" />loading…
            </div>
          ))}
        </div>
      </div>

      {/* PLC quick-view */}
      {plcOk && (
        <div className="card">
          <div className="card-header"><Server size={13} />Live PLC Coils Snapshot (Registers & Coils Output)</div>
          <div className="grid grid-cols-6 gap-3 font-mono text-xs mt-2">
            {[
              { label: 'ARM', val: (plc as any).motor_arm_enable },
              { label: 'GRIPPER', val: (plc as any).gripper_close },
              { label: 'CONV', val: (plc as any).conveyor_run },
              { label: 'BUSY', val: (plc as any).cycle_busy },
              { label: 'E-STOP', val: (plc as any).e_stop_active },
              { label: 'SAFE REQ', val: (plc as any).request_safe_state },
            ].map(({ label, val }) => (
              <div key={label} className="flex flex-col items-center bg-slate-950/20 border border-slate-900 rounded p-2.5">
                <div className={clsx('w-8 h-8 rounded-full flex items-center justify-center text-[9px] font-black border transition-all duration-300',
                  val ? 'bg-safe-green/20 border-safe-green text-safe-green shadow-[0_0_8px_rgba(16,185,129,0.4)]' : 'bg-slate-800/40 border-slate-800 text-slate-600'
                )}>{val ? 'ON' : 'OFF'}</div>
                <div className="mt-1.5 text-slate-500 font-bold uppercase tracking-wider text-[8.5px]">{label}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

