import { useState, useMemo } from 'react'
import type { HMIState, PrometheusMetrics } from '../types'
import {
  Brain, Shield, ShieldAlert, ShieldOff, Eye, Zap, Radio,
  TrendingUp, Clock, AlertTriangle, CheckCircle, Filter,
  Cpu, Network, AlertCircle, BarChart3,
} from 'lucide-react'
import { clsx } from 'clsx'
import {
  triggerInjection, useInjectionState, useScrollingAlerts, useLiveScores, useModelPerformance,
  useTrend, useTrendHistory, useModelHealth,
} from '../hooks/useMetrics'

// ─── Types ────────────────────────────────────────────────────────────────────
type ThreatLevel = 'NOMINAL' | 'WATCH' | 'ELEVATED' | 'CRITICAL'

interface Props {
  hmiState: HMIState | null
  metrics: PrometheusMetrics | null
}

// ─── Constants ────────────────────────────────────────────────────────────────
const ATTACK_TYPES = [
  // Network plane (Modbus) — scored by IsolationForest / PCA / TF autoencoders, then
  // classified by the IR engine into a MITRE ATT&CK for ICS technique. Each id fires
  // the REAL attack from the SEC sensor so the live incident carries the right tag.
  { id: 'modbus_command_injection', label: 'Modbus CMD Injection (T0855)', group: 'Network (Modbus)', desc: 'Writes control coils + the cycle register from a non-HMI source — Unauthorized Command Message' },
  { id: 'modbus_replay',            label: 'Modbus Replay (T0831)',        group: 'Network (Modbus)', desc: 'Replays a captured write sequence to scratch registers — Manipulation of Control' },
  { id: 'coil_flood',               label: 'Coil Flood / DoS (T0814)',     group: 'Network (Modbus)', desc: 'Rapid coil writes starve the PLC scan cycle — Denial of Service' },
  { id: 'register_scan',            label: 'Recon Scan (T0846)',           group: 'Network (Modbus)', desc: 'Broad read sweep of the register/coil map — Remote System Discovery' },
  { id: 'safety_tamper',            label: 'E-Stop / Safety Tamper (T0880)', group: 'Network (Modbus)', desc: 'Writes the e-stop coil + safety register — Loss of Safety' },
  { id: 'setpoint_drift',           label: 'Setpoint Drift (T0836)',       group: 'Network (Modbus)', desc: 'Slow, small writes to a setpoint register — Modify Parameter (low & slow)' },
  { id: 'bulk_write',               label: 'Bulk Write (T0843)',           group: 'Network (Modbus)', desc: 'FC16 multi-register block overwrite — Program Download / sabotage' },
  // Robot plane (joint dynamics) — scored by the LSTM autoencoder + physical envelope
  { id: 'joint_speed_violation',    label: 'Joint Speed Violation', group: 'Robot (behavior)', desc: 'Drives a joint far past its safe speed — trips the physical envelope' },
  { id: 'trajectory_deviation',     label: 'Trajectory Deviation',  group: 'Robot (behavior)', desc: 'Pushes a joint outside its normal range — caught by the LSTM' },
  { id: 'frozen_joint',             label: 'Frozen Joint',          group: 'Robot (behavior)', desc: 'Freezes one joint while the others move — sensor/actuator spoof' },
  { id: 'erratic_jerk',             label: 'Erratic Jerk',          group: 'Robot (behavior)', desc: 'High-frequency jitter on a joint — control instability' },
  { id: 'workspace_breach',         label: 'Workspace Breach',      group: 'Robot (behavior)', desc: 'Drives j1 toward the safety fence — LSTM trajectory anomaly' },
]
const ATTACK_GROUPS = ['Network (Modbus)', 'Robot (behavior)'] as const

const THREAT_CFG = {
  NOMINAL:  { color: 'text-emerald-400', ring: 'border-emerald-700', bg: 'bg-emerald-950/40', glow: '0 0 20px rgba(16,185,129,0.25)',  Icon: Shield      },
  WATCH:    { color: 'text-yellow-400',  ring: 'border-yellow-700',  bg: 'bg-yellow-950/40',  glow: '0 0 20px rgba(234,179,8,0.25)',   Icon: Eye         },
  ELEVATED: { color: 'text-amber-400',   ring: 'border-amber-600',   bg: 'bg-amber-950/40',   glow: '0 0 20px rgba(245,158,11,0.30)', Icon: ShieldAlert  },
  CRITICAL: { color: 'text-red-400',     ring: 'border-red-600',     bg: 'bg-red-950/40',     glow: '0 0 24px rgba(239,68,68,0.40)',   Icon: ShieldOff   },
} as const

function computeThreatLevel(iforest: number, pcaZ: number, rate: number): ThreatLevel {
  // Boundaries align to the LIVE-RETRAINED model: the IsolationForest anomaly
  // threshold is ~0.213 (normal single-arm windows score 0..~0.21) and the PCA/TF
  // z-alert is ~4.0. WATCH must sit ABOVE the normal iforest range, so it starts at
  // the model's alert line; attack escalation is driven mainly by pca_z (which jumps
  // into the thousands on an attack while the iforest stays modest).
  if (iforest > 0.70  || pcaZ > 10   || rate > 30) return 'CRITICAL'
  if (iforest > 0.55  || pcaZ > 6.43 || rate > 15) return 'ELEVATED'
  if (iforest > 0.40  || pcaZ > 4.0  || rate > 5)  return 'WATCH'
  return 'NOMINAL'
}

// ─── Arc Gauge (270° speedometer style) ──────────────────────────────────────
function ArcGauge({
  value, max, dangerAt, warnAt, label, sublabel,
}: {
  value: number; max: number; dangerAt?: number; warnAt?: number
  label: string; sublabel?: string
}) {
  const r  = 44
  const cx = 58, cy = 58
  const C       = 2 * Math.PI * r
  const arcLen  = C * 0.75        // 270° arc
  const gapLen  = C * 0.25

  // valid = any value that isn't the -1 sentinel (IsolationForest normal scores are negative)
  const valid   = value > -1
  const pct     = valid ? Math.max(0, Math.min(1, value / max)) : 0
  const fillLen = pct * arcLen

  const isDanger = valid && dangerAt != null && value >= dangerAt
  const isWarn   = valid && !isDanger && warnAt != null && value >= warnAt
  const stroke   = isDanger ? '#ef4444' : isWarn ? '#f59e0b' : '#3b82f6'
  const textFill = isDanger ? '#ef4444' : isWarn ? '#f59e0b' : '#e2e8f0'

  // Tick marks at 25 / 50 / 75 %
  const ticks = [0.25, 0.5, 0.75].map(p => {
    const angleDeg = 135 + p * 270
    const rad = (angleDeg - 90) * Math.PI / 180
    return {
      x1: (cx + (r - 6) * Math.cos(rad)).toFixed(1),
      y1: (cy + (r - 6) * Math.sin(rad)).toFixed(1),
      x2: (cx + (r + 2) * Math.cos(rad)).toFixed(1),
      y2: (cy + (r + 2) * Math.sin(rad)).toFixed(1),
    }
  })

  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 116 100" className="w-full max-w-[132px]">
        {/* Track */}
        <circle
          cx={cx} cy={cy} r={r}
          fill="none" stroke="#1e293b" strokeWidth="9"
          strokeDasharray={`${arcLen.toFixed(1)} ${gapLen.toFixed(1)}`}
          strokeLinecap="round"
          transform={`rotate(135 ${cx} ${cy})`}
        />
        {/* Tick marks */}
        {ticks.map((t, i) => (
          <line key={i} x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} stroke="#334155" strokeWidth="1.2" />
        ))}
        {/* Fill arc */}
        {valid && (
          <circle
            cx={cx} cy={cy} r={r}
            fill="none" stroke={stroke} strokeWidth="9"
            strokeDasharray={`${fillLen.toFixed(1)} ${(C - fillLen).toFixed(1)}`}
            strokeLinecap="round"
            transform={`rotate(135 ${cx} ${cy})`}
            style={{ transition: 'stroke-dasharray 0.6s cubic-bezier(.4,0,.2,1), stroke 0.3s ease' }}
          />
        )}
        {/* Outer glow on fill when danger */}
        {isDanger && valid && (
          <circle
            cx={cx} cy={cy} r={r}
            fill="none" stroke={stroke} strokeWidth="2" opacity="0.25"
            strokeDasharray={`${fillLen.toFixed(1)} ${(C - fillLen).toFixed(1)}`}
            strokeLinecap="round"
            transform={`rotate(135 ${cx} ${cy})`}
          />
        )}
        {/* Center: value */}
        <text x={cx} y={cy - 5} textAnchor="middle"
          fill={valid ? textFill : '#334155'} fontSize="14" fontWeight="700" fontFamily="monospace">
          {valid ? (value < 10 ? value.toFixed(3) : value.toFixed(1)) : '—'}
        </text>
        {sublabel && (
          <text x={cx} y={cy + 9} textAnchor="middle" fill="#475569" fontSize="6.5" fontFamily="monospace">
            {sublabel}
          </text>
        )}
        {/* Scale labels */}
        <text x="12" y="92" fill="#1e3a52" fontSize="6" fontFamily="monospace">0</text>
        <text x={116 - 12} y="92" fill="#1e3a52" fontSize="6" fontFamily="monospace" textAnchor="end">{max}</text>
      </svg>
      <div className="text-[9px] font-semibold uppercase tracking-widest text-slate-500 mt-0.5 text-center">{label}</div>
    </div>
  )
}

// ─── Detection-activity time-series chart ──────────────────────────────────────
function Sparkline({ history }: {
  history: Array<{ ts: number; iforest_score: number | null; anomaly: boolean }>
}) {
  const [hover, setHover] = useState<number | null>(null)
  if (history.length < 2) {
    return (
      <div className="flex items-center justify-center w-full text-slate-600 text-[11px]" style={{ height: 172 }}>
        Awaiting score history…
      </div>
    )
  }
  const W = 640, H = 172
  const mL = 34, mR = 12, mT = 10, mB = 20
  const plotW = W - mL - mR, plotH = H - mT - mB
  const n = history.length
  const vals = history.map(d => Math.max(0, d.iforest_score ?? 0))
  const dataMax = Math.max(...vals)
  const yMax = Math.max(1.0, dataMax * 1.15)
  const X = (i: number) => mL + (i / (n - 1)) * plotW
  const Y = (v: number) => mT + plotH - (Math.min(v, yMax) / yMax) * plotH
  const pts = vals.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`)
  const linePath = 'M' + pts.join(' L')
  const areaPath = `M${X(0).toFixed(1)},${(mT + plotH).toFixed(1)} L${pts.join(' L')} L${X(n - 1).toFixed(1)},${(mT + plotH).toFixed(1)} Z`
  const yTicks = [0, 0.25, 0.5, 0.75, 1.0].filter(t => t <= yMax + 0.001)
  const t1 = history[n - 1].ts
  const ago = (ts: number) => Math.max(0, Math.round(t1 - ts))
  const cur = vals[n - 1]
  const hv = hover != null ? Math.max(0, Math.min(n - 1, hover)) : null
  const anomalies = history.filter(d => d.anomaly).length

  return (
    <div className="relative w-full"
      onMouseLeave={() => setHover(null)}
      onMouseMove={(e) => {
        const r = e.currentTarget.getBoundingClientRect()
        const px = ((e.clientX - r.left) / r.width) * W
        if (px < mL || px > W - mR) { setHover(null); return }
        setHover(Math.round(((px - mL) / plotW) * (n - 1)))
      }}>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" preserveAspectRatio="xMidYMid meet">
        <defs>
          <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.30" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
          </linearGradient>
        </defs>
        {/* Y gridlines + labels */}
        {yTicks.map(t => {
          const gy = Y(t)
          return (
            <g key={t}>
              <line x1={mL} y1={gy} x2={W - mR} y2={gy} stroke="#16202e" strokeWidth="1" />
              <text x={mL - 6} y={gy + 3} textAnchor="end" fontSize="9" fill="#475569" fontFamily="monospace">{t.toFixed(2)}</text>
            </g>
          )
        })}
        {/* normal-boundary reference */}
        <line x1={mL} y1={Y(0.5)} x2={W - mR} y2={Y(0.5)} stroke="#64748b" strokeWidth="1" strokeDasharray="4 4" opacity="0.45" />
        <text x={W - mR} y={Y(0.5) - 3} textAnchor="end" fontSize="8.5" fill="#64748b" fontFamily="monospace">normal ~0.5</text>
        {/* anomaly bands */}
        {history.map((d, i) => d.anomaly
          ? <line key={'b' + i} x1={X(i)} y1={mT} x2={X(i)} y2={mT + plotH} stroke="#ef4444" strokeWidth={plotW / n + 0.5} opacity="0.12" />
          : null)}
        {/* area + line */}
        <path d={areaPath} fill="url(#scoreFill)" />
        <path d={linePath} fill="none" stroke="#38bdf8" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        {/* anomaly dots */}
        {history.map((d, i) => d.anomaly
          ? <circle key={'d' + i} cx={X(i)} cy={Y(vals[i])} r="3" fill="#ef4444" stroke="#0b0f17" strokeWidth="1" />
          : null)}
        {/* X time labels */}
        {[0, Math.floor((n - 1) / 2), n - 1].map(i => (
          <text key={'x' + i} x={X(i)} y={H - 5} textAnchor={i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle'} fontSize="9" fill="#475569" fontFamily="monospace">
            {i === n - 1 ? 'now' : `-${ago(history[i].ts)}s`}
          </text>
        ))}
        {/* hover crosshair */}
        {hv != null && (
          <g>
            <line x1={X(hv)} y1={mT} x2={X(hv)} y2={mT + plotH} stroke="#94a3b8" strokeWidth="1" strokeDasharray="3 3" opacity="0.6" />
            <circle cx={X(hv)} cy={Y(vals[hv])} r="3.5" fill="#38bdf8" stroke="#0b0f17" strokeWidth="1.5" />
          </g>
        )}
      </svg>
      {/* readout badge */}
      <div className="absolute top-0 right-2 text-right pointer-events-none">
        <div className="text-[9px] text-slate-500 font-mono uppercase tracking-wider">{hv != null ? 'cursor' : 'current'}</div>
        <div className={clsx('text-base font-mono font-semibold leading-tight',
          (hv != null ? history[hv].anomaly : history[n - 1].anomaly) ? 'text-red-400' : 'text-sky-300')}>
          {(hv != null ? vals[hv] : cur).toFixed(3)}
        </div>
        <div className="text-[9px] text-slate-500 font-mono">
          {hv != null
            ? `${history[hv].anomaly ? 'anomaly' : 'normal'} · -${ago(history[hv].ts)}s`
            : `${anomalies} anomaly window${anomalies === 1 ? '' : 's'}`}
        </div>
      </div>
    </div>
  )
}

// ─── Pipeline Node ────────────────────────────────────────────────────────────
function PipelineNode({ label, active, done }: { label: string; active: boolean; done: boolean }) {
  return (
    <div className="flex flex-col items-center gap-1">
      <div className={clsx(
        'w-8 h-8 rounded-full border-2 flex items-center justify-center text-[10px] font-bold transition-all duration-300',
        done   ? 'border-emerald-500 bg-emerald-950/50 text-emerald-400' :
        active ? 'border-blue-400 bg-blue-900/40 text-blue-400 ring-2 ring-blue-400/25 ring-pulse' :
                 'border-slate-800 bg-slate-900 text-slate-700'
      )}>
        {done ? '✓' : active ? '●' : '○'}
      </div>
      <div className={clsx(
        'text-[8.5px] font-mono text-center w-16 leading-tight whitespace-pre-line',
        done ? 'text-emerald-500' : active ? 'text-blue-400' : 'text-slate-700'
      )}>{label}</div>
    </div>
  )
}

// ─── Alert Row ────────────────────────────────────────────────────────────────
function AlertRow({ alert }: { alert: Record<string, any> }) {
  const ts       = alert.timestamp ?? (typeof alert.ts === 'string' ? alert.ts : null)
  const timeStr  = ts ? new Date(ts).toLocaleTimeString('en-GB') : '--:--:--'
  // All entries from ai-alerts.json are anomalies (alert_bridge only writes anomaly events)
  const isAnomaly = alert.anomaly === true || alert.event_type === 'alert'
  const cat      = alert.alert?.category ?? alert.category ?? 'unknown'
  const sig      = alert.alert?.signature ?? null
  const sev      = Number(alert.alert?.severity ?? alert.severity ?? 0)
  const srcIp    = alert.src_ip ?? '—'
  const iforest  = alert.lab?.iforest_score ?? alert.iforest_score
  const pcaZ     = alert.lab?.pca_z ?? alert.pca_z
  const topFeat  = (alert.lab?.top_features ?? alert.top_features ?? []) as string[]

  const sevBadge =
    sev === 1 ? { lbl: 'SEV-1 CRIT', cls: 'bg-red-950 border-red-600 text-red-300' } :
    sev === 2 ? { lbl: 'SEV-2 HIGH', cls: 'bg-amber-950 border-amber-600 text-amber-300' } :
    sev === 3 ? { lbl: 'SEV-3 MED',  cls: 'bg-yellow-950 border-yellow-700 text-yellow-400' } :
    null

  return (
    <div className={clsx(
      'alert-row grid px-3 py-2 border-b border-slate-800/50 text-[10px] font-mono',
      'hover:bg-slate-800/20 transition-colors gap-x-3',
      isAnomaly ? 'border-l-2 border-l-red-500' : 'border-l-2 border-l-slate-800'
    )} style={{ gridTemplateColumns: '62px 74px 1fr 78px 90px 72px' }}>
      <span className="text-slate-600">{timeStr}</span>
      <span className={clsx('font-bold', isAnomaly ? 'text-red-400' : 'text-slate-600')}>
        {isAnomaly ? '[ANOMALY]' : '[NORMAL ]'}
      </span>
      <span className="text-cyan-400/80 truncate" title={sig ?? cat}>{sig ?? cat}</span>
      <span className="text-slate-500 truncate">{srcIp}</span>
      <span className="text-slate-400 tabular-nums">
        iF={iforest != null && iforest >= 0 ? (iforest as number).toFixed(3) : 'N/A'}{' '}
        z={pcaZ  != null && pcaZ  >= 0 ? (pcaZ  as number).toFixed(1) : 'N/A'}
      </span>
      <span>
        {sevBadge ? (
          <span className={clsx('text-[9px] px-1.5 py-0.5 rounded-full border font-mono', sevBadge.cls)}>
            {sevBadge.lbl}
          </span>
        ) : topFeat.length ? (
          <span className="text-slate-700 truncate text-[9px]">{topFeat[0]}</span>
        ) : null}
      </span>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────
function AiTile({ label, value, tone, sub, pulse }: { label: string; value: string; tone: 'ok' | 'warn' | 'bad' | 'neutral'; sub?: string; pulse?: boolean }) {
  const t = tone === 'ok' ? 'text-emerald-400' : tone === 'warn' ? 'text-amber-400' : tone === 'bad' ? 'text-red-400' : 'text-slate-100'
  const ring = tone === 'bad' ? 'border-red-900/60' : tone === 'warn' ? 'border-amber-900/50' : 'border-slate-800'
  return (
    <div className={clsx('rounded-lg border bg-slate-900/40 px-4 py-3', ring)}>
      <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className={clsx('text-2xl font-semibold mt-1 tabular-nums', t, pulse && 'animate-pulse')}>{value}</div>
      {sub && <div className="text-[10px] text-slate-600 mt-0.5">{sub}</div>}
    </div>
  )
}

export function AIEnginePage({ hmiState, metrics }: Props) {
  const [attackType, setAttackType] = useState(ATTACK_TYPES[0].id)
  const [duration,   setDuration]   = useState(8)
  const [rate,       setRate]       = useState(5)
  const [injecting,  setInjecting]  = useState(false)
  const [lastResult, setLastResult] = useState<{ ok: boolean; msg: string } | null>(null)
  const [alertFilter, setAlertFilter] = useState<'anomaly' | 'all'>('anomaly')

  const { state: injState, justFinished } = useInjectionState()
  const alerts     = useScrollingAlerts(hmiState, 100)
  const trend      = useTrend(5000)
  const history    = useTrendHistory(3000)
  const modelHealth = useModelHealth(10000)

  // Fast live scores straight from the data plane (~1s, no Prometheus lag). The
  // gauges show the always-POSITIVE "activity" telemetry (real raw model output:
  // IF anomaly score ~0.4 baseline, AE reconstruction error as "x normal" ~1.0),
  // while the threat level + status words keep using the floored DETECTION scores
  // (0 = no anomaly) so "calm baseline = NOMINAL" stays correct.
  const live = useLiveScores(1000)
  const perf = useModelPerformance(30000)
  // Decision-fusion meta-scorer output (the final risk decision).
  const risk = live?.risk_score ?? null
  const sev = live?.severity ?? null
  // Detection scores (authoritative for status/threat). Fall back to Prometheus.
  const iForest  = live?.iforest_score ?? metrics?.iforest_score ?? -1
  const pcaZ     = live?.pca_z ?? metrics?.pca_z ?? -1
  // Positive activity values for the gauges (keep-last handled by the hook).
  const ifAct  = live?.if_activity ?? null
  const pcaAct = live?.pca_activity ?? null
  const tfAct  = live?.tf_activity ?? null
  // Robot-behavior LSTM z-score. It is NEGATIVE during normal motion (the AE
  // reconstructs real motion better than its calibration baseline) and 0 when the
  // arm is idle; -1 is the exporter's "no recent telemetry" sentinel. Clamp real
  // nominal-negative scores to 0 for the gauge bar, keep -1 as WAITING.
  const robotZ      = metrics?.robot_z ?? -1
  const robotNoData = robotZ === -1
  const robotDisplay = robotNoData ? -1 : Math.max(0, robotZ)
  const robotZAlert = 4.0

  const latency  = metrics?.detection_latency ?? -1
  const injActive = injState?.active ?? false
  const pipelineStage = injActive ? 2 : justFinished ? 5 : 0

  const trendDir   = trend?.window_60.trend_direction ?? 'stable'
  const anomRate   = trend?.window_60.anomaly_rate_pct ?? 0
  const predBreach = trend?.window_60.predicted_breach_in_s ?? null

  const threatLevel = useMemo(
    () => computeThreatLevel(iForest > -1 ? iForest : 0, pcaZ > -1 ? pcaZ : 0, anomRate),
    [iForest, pcaZ, anomRate],
  )
  const tc = THREAT_CFG[threatLevel]
  const ThrIcon = tc.Icon

  const filteredAlerts = useMemo(
    () => alertFilter === 'anomaly'
      ? alerts.filter(a => (a as any).anomaly === true || (a as any).event_type === 'alert')
      : alerts,
    [alerts, alertFilter],
  )

  async function handleInject() {
    setInjecting(true); setLastResult(null)
    try {
      const res = await triggerInjection(attackType, duration, rate)
      setLastResult({ ok: res.status === 'ok', msg: res.message ?? JSON.stringify(res) })
    } catch (e) { setLastResult({ ok: false, msg: String(e) }) }
    setInjecting(false)
  }

  // One-click guided demo: fires a representative, clearly-classified attack so the
  // whole chain (risk score -> anomaly -> classified incident) lights up live.
  async function runGuidedDemo() {
    setInjecting(true); setLastResult(null)
    setAttackType('modbus_command_injection'); setDuration(18); setRate(10)
    try {
      const res = await triggerInjection('modbus_command_injection', 18, 10)
      setLastResult({ ok: res.status === 'ok', msg: 'Guided demo running — watch the AI Risk Score spike, then check the IR Console for the classified incident.' })
    } catch (e) { setLastResult({ ok: false, msg: String(e) }) }
    setInjecting(false)
  }

  const modelsLoaded = modelHealth ?? {}
  const modelRows = [
    { key: 'iforest',   label: 'IsolationForest',  desc: 'Primary anomaly detector' },
    { key: 'pca',       label: 'PCA Autoencoder',   desc: 'Reconstruction z-score'  },
    { key: 'tf_model',  label: 'TF Autoencoder',    desc: 'Deep AE (network plane)' },
    { key: 'robot_lstm',label: 'Robot LSTM AE',     desc: 'Joint-dynamics detector' },
    { key: 'scaler',    label: 'Feature Scaler',    desc: 'StandardScaler'          },
  ]

  return (
    <div className="h-full flex flex-col overflow-hidden" style={{ background: '#070b11' }}>

      {/* ── Header ──────────────────────────────────────────────── */}
      <div className={clsx(
        'flex-shrink-0 border-b border-slate-800/80',
        injActive && 'border-b-red-900/60',
      )}>
        <div className="max-w-[1500px] mx-auto flex items-center gap-3 px-6 py-3.5">
        <Brain size={16} className="text-slate-300 flex-shrink-0" />
        <div className="leading-tight">
          <h1 className="text-lg font-semibold text-white tracking-tight">AI Anomaly Detection</h1>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Dual-plane ML — IsolationForest · PCA · TensorFlow autoencoder · robot LSTM joint-dynamics
          </p>
        </div>

        {/* Threat Level Indicator */}
        <div
          className={clsx('ml-auto flex items-center gap-2.5 px-3.5 py-2 rounded-lg border transition-all duration-500', 
            tc.bg, tc.ring, threatLevel === 'CRITICAL' && 'threat-glow-critical'
          )}
          style={{ boxShadow: tc.glow }}
        >
          <ThrIcon size={15} className={clsx(tc.color, threatLevel === 'CRITICAL' && 'animate-pulse')} />
          <div>
            <div className="text-[8px] uppercase tracking-widest text-slate-500 font-mono leading-none">Threat Level</div>
            <div className={clsx('text-[13px] font-black tracking-wider font-mono leading-snug', tc.color,
              threatLevel === 'CRITICAL' && 'animate-pulse')}>
              {threatLevel}
            </div>
          </div>
        </div>

        {injActive && (
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-red-800 bg-red-950/50 animate-pulse">
            <Zap size={11} className="text-red-400" />
            <span className="text-[10px] font-mono font-bold text-red-300">ATTACK IN PROGRESS</span>
          </div>
        )}
        {justFinished && !injActive && (
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-amber-800 bg-amber-950/40">
            <CheckCircle size={11} className="text-amber-400" />
            <span className="text-[10px] font-mono text-amber-300">INJECTION COMPLETE</span>
          </div>
        )}
        </div>
      </div>

      {/* ── Body ────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-[1500px] mx-auto p-6 space-y-4">

        {/* Fused risk — decision-fusion meta-scorer (the final decision maker) */}
        <div className={clsx('rounded-lg border bg-slate-900/40 px-5 py-4 flex items-center gap-6',
          sev === 'critical' || sev === 'high' ? 'border-red-900/60' : sev === 'medium' ? 'border-amber-900/50' : 'border-slate-800')}>
          <div className="min-w-[170px]">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">AI Risk Score · decision fusion</div>
            <div className="flex items-end gap-2 mt-1">
              <span className={clsx('text-4xl font-bold tabular-nums leading-none',
                risk == null ? 'text-slate-600' : sev === 'critical' || sev === 'high' ? 'text-red-400' : sev === 'medium' ? 'text-amber-400' : 'text-emerald-400')}>
                {risk == null ? '—' : risk.toFixed(0)}
              </span>
              <span className="text-slate-600 text-sm mb-1">/ 100</span>
              {sev && <span className={clsx('badge mb-1', sev === 'critical' || sev === 'high' ? 'badge-critical' : sev === 'medium' ? 'badge-warning' : 'badge-ok')}>{sev.toUpperCase()}</span>}
            </div>
            <div className="text-[10px] text-slate-600 mt-1">learned fusion of IF · PCA-AE · TF-AE → one calibrated score</div>
          </div>
          <div className="flex-1">
            <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden">
              <div className={clsx('h-full rounded-full transition-all duration-500',
                risk == null ? 'bg-slate-700' : sev === 'critical' || sev === 'high' ? 'bg-red-500' : sev === 'medium' ? 'bg-amber-500' : 'bg-emerald-500')}
                style={{ width: `${Math.min(100, Math.max(2, risk ?? 0))}%` }} />
            </div>
            <div className="flex justify-between text-[9px] font-mono text-slate-600 mt-1">
              <span>0 · normal</span>
              {perf?.operating_threshold != null && <span>alert ≥ {(perf.operating_threshold * 100).toFixed(0)}</span>}
              <span>100 · attack</span>
            </div>
          </div>
          <button onClick={runGuidedDemo} disabled={injecting || injActive}
            className={clsx('flex-shrink-0 inline-flex items-center gap-2 text-xs font-medium px-3.5 py-2 rounded-md border transition-colors',
              injecting || injActive ? 'border-slate-700 text-slate-600 cursor-not-allowed' : 'border-sky-700 text-sky-300 hover:bg-sky-950/40')}>
            <Zap size={13} />{injActive ? 'Running…' : 'Run guided demo'}
          </button>
        </div>

        {/* Summary KPIs */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <AiTile label="Threat level" value={threatLevel}
            tone={threatLevel === 'NOMINAL' ? 'ok' : threatLevel === 'WATCH' ? 'warn' : 'bad'}
            pulse={threatLevel === 'CRITICAL'} sub="Network + robot planes" />
          <AiTile label="Detection models" value={`${modelRows.filter(r => modelsLoaded[r.key] === true).length}/${modelRows.length} online`}
            tone={modelRows.every(r => modelsLoaded[r.key] === true) ? 'ok' : 'warn'} sub="Loaded & scoring live" />
          <AiTile label="Detection latency" value={latency > 0 ? `${latency.toFixed(2)}s` : '—'}
            tone={latency > 5 ? 'warn' : latency > 0 ? 'ok' : 'neutral'} sub="Injection → first alert" />
          <AiTile label="Anomaly rate (60s)" value={`${anomRate.toFixed(1)}%`}
            tone={anomRate > 15 ? 'bad' : anomRate > 5 ? 'warn' : 'ok'} sub="Detection windows flagged" />
        </div>

        {/* Detection models */}
        <div className="text-[11px] uppercase tracking-wider text-slate-500 pt-1">Detection Models</div>

        {/* Row 1a — Model Gauges (3 network-plane + 1 robot-plane) */}
        <div className="grid grid-cols-4 gap-3">

          {/* IForest Gauge — live anomaly score (~0.4 baseline, 0.5 boundary) */}
          <div className="card flex flex-col items-center py-3 gap-1">
            <div className="card-header justify-center !mb-1">IsolationForest</div>
            <ArcGauge value={ifAct ?? -1} max={1.0} dangerAt={0.95} warnAt={0.82}
              label="Anomaly score" sublabel="normal ~0.5 · alert ≥0.9" />
            <div className={clsx('text-[8.5px] font-mono text-center mt-0.5',
              ifAct == null ? 'text-slate-700' : ifAct >= 0.95 ? 'text-red-400 font-bold' : ifAct >= 0.82 ? 'text-amber-400' : 'text-emerald-500')}>
              {ifAct == null ? '— WAITING'
               : ifAct >= 0.95 ? '▲ OUTLIER'
               : ifAct >= 0.82 ? '⚠ ELEVATED'
               :                 '✓ NOMINAL'}
            </div>
          </div>

          {/* PCA Gauge — reconstruction error as x-normal (~1.0 baseline) */}
          <div className="card flex flex-col items-center py-3 gap-1">
            <div className="card-header justify-center !mb-1">PCA Recon</div>
            <ArcGauge value={pcaAct ?? -1} max={50} dangerAt={20} warnAt={10}
              label="Recon error" sublabel="× normal (spikes on attack)" />
            <div className={clsx('text-[8.5px] font-mono text-center mt-0.5',
              pcaAct == null ? 'text-slate-700' : pcaAct >= 20 ? 'text-red-400 font-bold' : pcaAct >= 10 ? 'text-amber-400' : 'text-emerald-500')}>
              {pcaAct == null ? '— WAITING'
               : pcaAct >= 20 ? '▲ ERROR HIGH'
               : pcaAct >= 10 ? '⚠ ELEVATED'
               :                '✓ OK'}
            </div>
          </div>

          {/* TF Autoencoder Gauge — reconstruction error as x-normal (~1.0 baseline) */}
          <div className="card flex flex-col items-center py-3 gap-1">
            <div className="card-header justify-center !mb-1">TF Deep AE</div>
            <ArcGauge value={tfAct ?? -1} max={60} dangerAt={45} warnAt={25}
              label="Recon error" sublabel="× normal" />
            <div className={clsx('text-[8.5px] font-mono text-center mt-0.5',
              tfAct == null ? 'text-slate-700' : tfAct >= 45 ? 'text-red-400 font-bold' : tfAct >= 25 ? 'text-amber-400' : 'text-emerald-500')}>
              {tfAct == null ? '— WAITING'
               : tfAct >= 45 ? '▲ COMPROMISED'
               : tfAct >= 25 ? '⚠ ELEVATED'
               :               '✓ SECURE'}
            </div>
          </div>

          {/* Robot LSTM AE Gauge (robot plane) */}
          <div className="card flex flex-col items-center py-3 gap-1">
            <div className="card-header justify-center !mb-1">Robot LSTM AE</div>
            <ArcGauge value={robotDisplay} max={10} dangerAt={robotZAlert} warnAt={2.0}
              label="Robot Z (σ)" sublabel="joint dynamics" />
            <div className={clsx('text-[8.5px] font-mono text-center mt-0.5',
              !robotNoData && robotZ >= robotZAlert ? 'text-red-400 font-bold'
              : !robotNoData && robotZ >= 2.0 ? 'text-amber-400'
              : !robotNoData ? 'text-emerald-500' : 'text-slate-700')}>
              {robotNoData ? '— WAITING'
               : robotZ >= robotZAlert ? '▲ ANOMALOUS MOTION'
               : robotZ >= 2.0 ? '⚠ ELEVATED'
               : '✓ NOMINAL'}
            </div>
          </div>
        </div>

        {/* Model performance — offline evaluation of the fused detector */}
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <BarChart3 size={13} className="text-slate-400" />Model Performance
            </div>
            <span className="text-[10px] text-slate-600">
              validation benchmark · network meta-scorer{perf?.generated_at ? ` · ${perf.generated_at.slice(0, 10)}` : ''}{perf ? ` · ${(perf.n_normal ?? 0) + (perf.n_attack ?? 0)} labeled windows` : ''} · not live
            </span>
          </div>
          {!perf ? (
            <div className="text-[11px] text-slate-500 py-3">No evaluation report yet — run model/train_meta.py.</div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                  { l: 'ROC-AUC', v: perf.roc_auc, fmt: (x: number) => x.toFixed(3), good: (x: number) => x >= 0.9 },
                  { l: 'Precision', v: perf.precision, fmt: (x: number) => `${(x * 100).toFixed(1)}%`, good: (x: number) => x >= 0.9 },
                  { l: 'Recall', v: perf.recall, fmt: (x: number) => `${(x * 100).toFixed(1)}%`, good: (x: number) => x >= 0.9 },
                  { l: 'FP rate · eval set', v: perf.false_positive_rate, fmt: (x: number) => `${(x * 100).toFixed(2)}%`, good: (x: number) => x <= 0.02 },
                ].map(m => (
                  <div key={m.l} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                    <div className="text-[9px] uppercase tracking-wider text-slate-500">{m.l}</div>
                    <div className={clsx('text-xl font-semibold mt-0.5 tabular-nums', m.v == null ? 'text-slate-600' : m.good(m.v) ? 'text-emerald-400' : 'text-amber-400')}>
                      {m.v == null ? '—' : m.fmt(m.v)}
                    </div>
                  </div>
                ))}
              </div>
              <div className="text-[10px] text-slate-500 leading-relaxed -mt-1">
                Offline scores on a labeled hold-out set — a <span className="text-slate-400">benchmark, not a live measurement</span>, and only the network
                meta-scorer. You cannot know an alarm is a false positive at fire time; live <span className="text-slate-400">alarm load</span> (a burst with no injected
                attack = a misbehaving detector) is tracked on the Grafana AI board.
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {/* learned fusion weights */}
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Learned fusion weights</div>
                  {perf.fusion_weights && (() => {
                    const w = perf.fusion_weights!
                    const max = Math.max(0.001, Math.abs(w.iforest), Math.abs(w.pca_ae), Math.abs(w.tf_ae))
                    const rows = [['IsolationForest', w.iforest], ['PCA autoencoder', w.pca_ae], ['TF autoencoder', w.tf_ae]] as const
                    return (
                      <div className="space-y-1.5">
                        {rows.map(([name, val]) => (
                          <div key={name} className="flex items-center gap-2">
                            <span className="text-[10px] text-slate-400 w-32">{name}</span>
                            <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                              <div className="h-full rounded-full bg-sky-500" style={{ width: `${(Math.abs(val) / max) * 100}%` }} />
                            </div>
                            <span className="text-[10px] font-mono text-slate-400 w-10 text-right">{val.toFixed(2)}</span>
                          </div>
                        ))}
                        <div className="text-[9px] text-slate-600 pt-0.5">The fusion learned to weight each detector — here it leans on the autoencoders.</div>
                      </div>
                    )
                  })()}
                </div>
                {/* per-attack recall */}
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Detection rate by attack</div>
                  <div className="grid grid-cols-2 gap-1.5">
                    {Object.entries(perf.per_attack_recall ?? {}).map(([name, r]) => (
                      <div key={name} className="flex items-center justify-between rounded border border-slate-800 bg-slate-950/40 px-2 py-1">
                        <span className="text-[10px] font-mono text-slate-400 truncate">{name}</span>
                        <span className={clsx('text-[10px] font-mono font-semibold', r >= 0.99 ? 'text-emerald-400' : r >= 0.8 ? 'text-amber-400' : 'text-red-400')}>{(r * 100).toFixed(0)}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Row 1b — Score history + model health */}
        <div className="grid grid-cols-12 gap-3">

          {/* Detection-activity chart */}
          <div className="col-span-8 card flex flex-col">
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
                <BarChart3 size={13} className="text-slate-400" />Detection Activity
              </div>
              <span className="text-[10px] text-slate-600">IsolationForest anomaly score · trailing window</span>
            </div>
            <div className="flex-1">
              <Sparkline history={history} />
            </div>
            <div className="flex items-center gap-4 mt-1 pt-1.5 border-t border-slate-800/60 text-[9px] font-mono text-slate-500">
              <span className="flex items-center gap-1.5"><span className="inline-block w-3 h-[2px] bg-sky-400 rounded" />anomaly score</span>
              <span className="flex items-center gap-1.5"><span className="inline-block w-3 h-px bg-slate-500" style={{ borderTop: '1px dashed #64748b' }} />normal boundary</span>
              <span className="flex items-center gap-1.5"><span className="inline-block w-2 h-2 rounded-full bg-red-500" />anomaly window</span>
            </div>
          </div>

          {/* Model Health + Latency */}
          <div className="col-span-4 flex flex-col gap-3">
            <div className="card flex-1">
              <div className="card-header"><Cpu size={11} />Model Status</div>
              <div className="space-y-2">
                {modelRows.map(({ key, label, desc }) => {
                  const loaded = modelsLoaded[key] === true
                  return (
                    <div key={key} className="flex items-center gap-2">
                      <div className={clsx('w-1.5 h-1.5 rounded-full flex-shrink-0 mt-px',
                        loaded ? 'bg-emerald-400' : modelsLoaded[key] === false ? 'bg-red-500' : 'bg-slate-700')} />
                      <div className="flex-1 min-w-0">
                        <div className={clsx('text-[10px] font-mono truncate', loaded ? 'text-slate-300' : 'text-slate-600')}>
                          {label}
                        </div>
                        <div className="text-[8px] text-slate-700 font-mono truncate">{desc}</div>
                      </div>
                      <span className={clsx('text-[8.5px] font-mono flex-shrink-0',
                        loaded ? 'text-emerald-600' : 'text-slate-700')}>
                        {loaded ? 'OK' : '—'}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
            <div className="card">
              <div className="card-header"><Clock size={11} />Detection Latency</div>
              <div className={clsx('font-mono text-2xl font-bold',
                latency > 5 ? 'text-amber-400' : latency > 0 ? 'text-emerald-400' : 'text-slate-700')}>
                {latency > 0 ? `${latency.toFixed(2)}s` : '—'}
              </div>
              <div className="text-[8.5px] text-slate-700 font-mono mt-1">
                {latency > 0 ? 'injection → first alert' : 'run injection to measure'}
              </div>
            </div>
          </div>
        </div>

        {/* Row 2 — Pipeline */}
        <div className="card">
          <div className="card-header"><Network size={11} />End-to-End Detection Pipeline</div>
          <div className="flex items-center justify-between px-4 py-1">
            {[
              { label: 'OT\nPacket',      active: pipelineStage >= 1, done: pipelineStage >= 2 },
              { label: 'Modbus\nParser',   active: pipelineStage >= 2, done: pipelineStage >= 3 },
              { label: 'Feature\nExtract', active: pipelineStage >= 2, done: pipelineStage >= 3 },
              { label: 'ML\nScore',        active: pipelineStage >= 3, done: pipelineStage >= 4 },
              { label: 'Alert\nBus',       active: pipelineStage >= 4, done: pipelineStage >= 5 },
              { label: 'Playbook\nFired',  active: pipelineStage >= 5, done: pipelineStage >= 5 },
            ].map((n, i, arr) => (
              <div key={i} className="flex items-center">
                <PipelineNode label={n.label} active={n.active} done={n.done} />
                {i < arr.length - 1 && (
                  <div className={clsx('w-10 h-px mx-1 transition-all duration-500',
                    n.done ? 'bg-emerald-600' : n.active ? 'bg-blue-500' : 'bg-slate-800')} />
                )}
              </div>
            ))}
          </div>
          <div className="text-[8.5px] text-slate-800 font-mono text-center mt-1.5">
            Zeek (OT pcap) → Modbus parser → WindowStore → IsolationForest / PCA / TF → Redis → alert_bridge → HMI
          </div>
        </div>

        {/* Row 3 — Attack Injection + Trend Forecast */}
        <div className="grid grid-cols-2 gap-3">

          {/* Attack Injection */}
          <div className={clsx('card transition-all duration-300',
            injActive ? 'border-red-800 shadow-[0_0_18px_rgba(239,68,68,0.2)]' : '')}>
            <div className="card-header">
              <Zap size={11} className="text-amber-400" />
              Attack Injection Panel
              <span className="ml-auto text-[8.5px] font-mono text-slate-700 normal-case">DEMO</span>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-[9.5px] text-slate-500 block mb-1">Attack Type</label>
                <select value={attackType} onChange={e => setAttackType(e.target.value)}
                  disabled={injActive}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-blue-600 disabled:opacity-40 transition-colors">
                  {ATTACK_GROUPS.map(g => (
                    <optgroup key={g} label={g}>
                      {ATTACK_TYPES.filter(a => a.group === g).map(a => (
                        <option key={a.id} value={a.id}>{a.label}</option>
                      ))}
                    </optgroup>
                  ))}
                </select>
                <p className="text-[8.5px] text-slate-700 mt-1">
                  {ATTACK_TYPES.find(a => a.id === attackType)?.desc}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[9.5px] text-slate-500 block mb-1">Duration: {duration}s</label>
                  {/* min 8s: the detector now requires 2 consecutive 5s windows
                      (LAB_ANOMALY_CONSECUTIVE), so an injection must span >=2 windows
                      to be reported. 8s guarantees that. */}
                  <input type="range" min={8} max={30} value={duration}
                    onChange={e => setDuration(+e.target.value)} disabled={injActive}
                    className="w-full accent-blue-500 disabled:opacity-40" />
                </div>
                <div>
                  <label className="text-[9.5px] text-slate-500 block mb-1">Rate: {rate} Hz</label>
                  <input type="range" min={1} max={10} value={rate}
                    onChange={e => setRate(+e.target.value)} disabled={injActive}
                    className="w-full accent-amber-500 disabled:opacity-40" />
                </div>
              </div>
              <button onClick={handleInject} disabled={injecting || injActive}
                className={clsx('w-full btn flex items-center justify-center gap-2 text-xs',
                  injActive ? 'bg-slate-800/60 border-slate-700 text-slate-500 cursor-not-allowed' :
                  'bg-red-950/60 hover:bg-red-900/70 text-red-200 border border-red-800 active:scale-95')}>
                <Zap size={13} />
                {injActive ? '⌛ INJECTING…' : injecting ? 'Starting…' : '⚡ INJECT ATTACK'}
              </button>
              {lastResult && (
                <div className={clsx('flex items-start gap-1.5 text-[9.5px] font-mono rounded-md p-2 border',
                  lastResult.ok
                    ? 'bg-emerald-950/50 text-emerald-300 border-emerald-900'
                    : 'bg-red-950/50 text-red-300 border-red-900')}>
                  {lastResult.ok
                    ? <CheckCircle size={11} className="mt-0.5 flex-shrink-0" />
                    : <AlertCircle size={11} className="mt-0.5 flex-shrink-0" />}
                  <span className="leading-tight">{lastResult.msg}</span>
                </div>
              )}
            </div>
          </div>

          {/* Threat Trend Forecast */}
          <div className="card">
            <div className="card-header"><TrendingUp size={11} />Threat Trend Forecast</div>
            <div className="space-y-3">
              {/* Direction */}
              <div className="flex items-center gap-3">
                <div className={clsx('text-[28px] font-black font-mono leading-none',
                  trendDir === 'rising' ? 'text-red-400' : trendDir === 'falling' ? 'text-emerald-400' : 'text-slate-500')}>
                  {trendDir === 'rising' ? '↑' : trendDir === 'falling' ? '↓' : '→'}
                </div>
                <div>
                  <div className={clsx('text-sm font-bold font-mono uppercase tracking-wide',
                    trendDir === 'rising' ? 'text-red-400' : trendDir === 'falling' ? 'text-emerald-400' : 'text-slate-400')}>
                    {trendDir}
                  </div>
                  <div className="text-[8.5px] text-slate-600 font-mono">60-sample window</div>
                </div>
                <div className="ml-auto text-right">
                  <div className={clsx('text-lg font-mono font-bold',
                    anomRate > 15 ? 'text-red-400' : anomRate > 5 ? 'text-amber-400' : 'text-slate-300')}>
                    {anomRate.toFixed(1)}%
                  </div>
                  <div className="text-[8.5px] text-slate-600 font-mono">anomaly rate</div>
                </div>
              </div>

              {/* Rate bar */}
              <div>
                <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <div className={clsx('h-full rounded-full transition-all duration-700',
                    anomRate > 30 ? 'bg-red-500' : anomRate > 15 ? 'bg-amber-500' : anomRate > 5 ? 'bg-yellow-500' : 'bg-emerald-500')}
                    style={{ width: `${Math.min(100, anomRate)}%` }} />
                </div>
                <div className="flex justify-between text-[7.5px] font-mono text-slate-800 mt-0.5">
                  <span>0</span><span>WATCH 5%</span><span>ELEV 15%</span><span>CRIT 30%</span>
                </div>
              </div>

              {/* Stats grid */}
              <div className="grid grid-cols-2 gap-2">
                {[
                  { label: 'Mean Score', v: trend?.window_60.mean_score?.toFixed(4) },
                  { label: 'Max Score',  v: trend?.window_60.max_score?.toFixed(4)  },
                  { label: 'Std Dev',    v: trend?.window_60.std_dev?.toFixed(4)    },
                  { label: 'Breach ETA', v: predBreach != null ? `~${predBreach}s` : 'none' },
                ].map(({ label, v }) => (
                  <div key={label} className="bg-slate-900/70 rounded px-2 py-1.5 border border-slate-800/60">
                    <div className="text-[8px] text-slate-600 font-mono">{label}</div>
                    <div className="text-[11px] text-slate-200 font-mono font-bold">{v ?? '—'}</div>
                  </div>
                ))}
              </div>

              <div className="text-[8.5px] text-slate-700 font-mono">
                {predBreach != null
                  ? `⚠ Threshold breach predicted in ~${predBreach}s (linear extrapolation)`
                  : '✓ No threshold breach predicted in next 5 minutes'}
              </div>
            </div>
          </div>
        </div>

        {/* Row 4 — Alert Log */}
        <div className="card flex flex-col" style={{ minHeight: '190px' }}>
          <div className="card-header">
            <Radio size={11}
              className={filteredAlerts.some(a => (a as any).event_type === 'alert')
                ? 'text-red-400 animate-pulse' : 'text-slate-700'} />
            Live Anomaly Log
            <span className="ml-1 font-mono text-slate-700 normal-case text-[9px]">
              ({filteredAlerts.length} events)
            </span>
            {/* Filter toggle */}
            <div className="ml-auto flex items-center gap-1.5">
              <Filter size={9} className="text-slate-700" />
              <button
                onClick={() => setAlertFilter(f => f === 'all' ? 'anomaly' : 'all')}
                className="text-[9px] font-mono px-2 py-0.5 rounded border border-slate-700 bg-slate-900 text-slate-500 hover:border-slate-600 hover:text-slate-300 transition-colors">
                {alertFilter === 'anomaly' ? 'ANOMALIES ONLY' : 'ALL EVENTS'}
              </button>
            </div>
          </div>

          {/* Column headings */}
          <div
            className="grid px-3 py-1 border-b border-slate-800 text-[8.5px] font-mono text-slate-700 uppercase tracking-wider gap-x-3"
            style={{ gridTemplateColumns: '62px 74px 1fr 78px 90px 72px' }}>
            <span>Time</span><span>Status</span><span>Signature / Category</span>
            <span>Source IP</span><span>Scores</span><span>Severity</span>
          </div>

          <div className="flex-1 overflow-y-auto">
            {filteredAlerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-slate-400 gap-2">
                <Shield size={28} className="text-emerald-600/70" />
                <span className="text-[11px] font-mono text-slate-400">
                  {alertFilter === 'anomaly'
                    ? '✓ No anomalies detected — system nominal'
                    : 'No events yet — inject an attack to populate the log'}
                </span>
                <span className="text-[9px] font-mono text-slate-600">
                  Anomaly alerts stream here live when the AI flags an attack
                </span>
              </div>
            ) : (
              filteredAlerts.map((a, i) => <AlertRow key={i} alert={a as Record<string, any>} />)
            )}
          </div>
        </div>

        </div>
      </div>
    </div>
  )
}
