import type { HMIState, PrometheusMetrics, PageId } from '../types'
import { Activity, Server, Shield, Wifi, WifiOff, ArrowRight } from 'lucide-react'
import { clsx } from 'clsx'
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

function TopologyMap({ metrics }: { metrics: PrometheusMetrics | null }) {
  const isAttack = (metrics?.injection_active ?? 0) > 0
  const flowSpeed = isAttack ? '0.6s' : '2s'
  
  return (
    <div className="relative w-full h-[230px] bg-slate-950/40 border border-border-dim/60 rounded-lg p-4 overflow-hidden">
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs font-semibold uppercase tracking-widest text-slate-400">
          Live ISA/IEC 62443 Microsegmentation Flow Map
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
          <span className={clsx("w-2 h-2 rounded-full", isAttack ? "bg-red-500 animate-pulse" : "bg-emerald-500")} />
          {isAttack ? "ATTACK PATH ACTIVE" : "SEGMENTATION STATE NOMINAL"}
        </div>
      </div>

      <svg className="w-full h-[180px]" viewBox="0 0 800 160">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 2 L 10 5 L 0 8 z" fill="#475569" />
          </marker>
          <marker id="arrow-cyan" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 2 L 10 5 L 0 8 z" fill="#06b6d4" />
          </marker>
          <marker id="arrow-red" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 2 L 10 5 L 0 8 z" fill="#f43f5e" />
          </marker>
        </defs>

        {/* Connections */}
        {/* IT -> DMZ Link */}
        <path d="M 170 65 L 290 65" stroke="#1e293b" strokeWidth="2" fill="none" markerEnd="url(#arrow)" />
        <path d="M 170 65 L 290 65" stroke="#38bdf8" strokeWidth="2" strokeDasharray="6 6" fill="none" className="flow-path" style={{ animationDuration: '2.5s' }} />

        {/* DMZ -> OT Control Link */}
        <path d="M 430 65 L 610 65" stroke="#1e293b" strokeWidth="2" fill="none" markerEnd="url(#arrow)" />
        <path d="M 430 65 L 610 65" stroke="#22d3ee" strokeWidth="2" strokeDasharray="8 8" fill="none" className="flow-path" style={{ animationDuration: flowSpeed }} />

        {/* OT -> Security Mirror Link (SPAN) */}
        <path d="M 670 95 L 670 125 L 520 125" stroke="#1e293b" strokeWidth="1.5" fill="none" markerEnd="url(#arrow)" />
        <path d="M 670 95 L 670 125 L 520 125" stroke="#34d399" strokeWidth="1.5" strokeDasharray="5 5" fill="none" className="flow-path" style={{ animationDuration: '1.2s' }} />

        {/* Security -> Mgmt/AI Link */}
        <path d="M 400 125 L 250 125 L 250 95" stroke="#1e293b" strokeWidth="1.5" fill="none" markerEnd="url(#arrow)" />
        <path d="M 400 125 L 250 125 L 250 95" stroke="#a78bfa" strokeWidth="1.5" strokeDasharray="5 5" fill="none" className="flow-path" style={{ animationDuration: '1.5s' }} />

        {/* Mgmt/AI -> OT Control Link (Mitigation Flow) */}
        <path d="M 170 45 C 230 10, 550 10, 610 45" stroke="#1e293b" strokeWidth="1.5" fill="none" strokeDasharray="4 4" markerEnd={isAttack ? "url(#arrow-red)" : "url(#arrow-cyan)"} />
        {isAttack && (
          <path d="M 170 45 C 230 10, 550 10, 610 45" stroke="#f43f5e" strokeWidth="2" strokeDasharray="6 6" fill="none" className="flow-path" style={{ animationDuration: '0.8s' }} />
        )}

        {/* Node 1: IT Zone */}
        <g transform="translate(10, 25)">
          <rect width="160" height="70" rx="6" fill="#040810" stroke="#1e293b" strokeWidth="1.5" />
          <text x="12" y="20" fill="#64748b" fontSize="8" fontWeight="bold" fontFamily="monospace">IT ZONE L4</text>
          <text x="12" y="32" fill="#475569" fontSize="7.5" fontFamily="monospace">192.168.20.0/24</text>
          <text x="12" y="48" fill="#e2e8f0" fontSize="9.5" fontWeight="bold">lab-gitea (Git Repo)</text>
          <text x="12" y="60" fill="#e2e8f0" fontSize="9.5" fontWeight="bold">lab-runner (CI)</text>
        </g>

        {/* Node 2: DMZ Zone */}
        <g transform="translate(290, 25)">
          <rect width="140" height="70" rx="6" fill="#040810" stroke="#0e7490" strokeWidth="1.5" className="border-glow-cyan" />
          <text x="12" y="20" fill="#06b6d4" fontSize="8" fontWeight="bold" fontFamily="monospace">DMZ ZONE L3.5</text>
          <text x="12" y="32" fill="#0891b2" fontSize="7.5" fontFamily="monospace">192.168.30.0/24</text>
          <text x="12" y="48" fill="#e2e8f0" fontSize="9.5" fontWeight="bold">guacamole :8081</text>
          <text x="12" y="60" fill="#e2e8f0" fontSize="9.5" fontWeight="bold">L3 SCADA Monitor :8086</text>
        </g>

        {/* Node 3: Security & AI Zone (Management) */}
        <g transform="translate(90, 105)">
          <rect width="160" height="50" rx="6" fill="#040810" stroke="#6d28d9" strokeWidth="1.5" />
          <text x="12" y="16" fill="#a78bfa" fontSize="8" fontWeight="bold" fontFamily="monospace">MGMT & AI ZONE L3</text>
          <text x="12" y="26" fill="#7c3aed" fontSize="7.5" fontFamily="monospace">192.168.40.0/24</text>
          <text x="12" y="40" fill="#e2e8f0" fontSize="9.5" fontWeight="bold">FastAPI score_service</text>
        </g>

        {/* Node 4: Passive Security Zone (Zeek/Suricata IDS) */}
        <g transform="translate(400, 105)">
          <rect width="120" height="40" rx="4" fill="#040810" stroke="#047857" strokeWidth="1" />
          <text x="10" y="16" fill="#34d399" fontSize="7.5" fontWeight="bold" fontFamily="monospace">PASSIVE IDS L3</text>
          <text x="10" y="28" fill="#a1a1aa" fontSize="9" fontWeight="bold">Zeek + Suricata</text>
        </g>

        {/* Node 5: OT Control Zone */}
        <g transform="translate(610, 25)">
          <rect width="180" height="70" rx="6" fill="#040810" stroke={isAttack ? "#ef4444" : "#991b1b"} strokeWidth="1.5" className={isAttack ? "border-glow-red" : ""} />
          <text x="12" y="20" fill={isAttack ? "#f43f5e" : "#f43f5e"} fontSize="8" fontWeight="bold" fontFamily="monospace">OT CONTROL L0-2</text>
          <text x="12" y="32" fill="#be123c" fontSize="7.5" fontFamily="monospace">192.168.10.0/24</text>
          <text x="12" y="48" fill="#e2e8f0" fontSize="9.5" fontWeight="bold">OpenPLC Production :502</text>
          <text x="12" y="60" fill="#e2e8f0" fontSize="9.5" fontWeight="bold">OpenPLC Safety :503</text>
        </g>
      </svg>
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
        <div className="card-header">VLAN Node & Component Health Status</div>
        <div className="grid grid-cols-5 gap-3 mt-2">
          {Object.entries(metrics?.component_health ?? {}).map(([name, up]) => (
            <ComponentDot key={name} name={name} up={up} />
          ))}
          {!metrics && Array.from({ length: 10 }).map((_, i) => (
            <div key={i} className="flex items-center gap-2 text-xs font-mono text-slate-700 bg-slate-900/20 border border-slate-800/20 rounded px-2.5 py-1.5">
              <span className="status-dot bg-slate-800 animate-pulse" />loading node…
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

