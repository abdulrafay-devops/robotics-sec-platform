import { useState, useEffect, useCallback, useRef } from 'react'
import type { HMIState, InjectionState, PrometheusMetrics, AlertRecord, StagesReports } from '../types'

const API_BASE = '/api'
const PROM_BASE = '/prometheus'

async function safeFetch<T>(url: string): Promise<T | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(4000) })
    if (!res.ok) return null
    return await res.json() as T
  } catch {
    return null
  }
}

export interface LiveScores {
  ts: number
  anomaly: boolean
  iforest_score: number
  pca_z: number
  tf_z: number
  if_activity: number | null
  pca_activity: number | null
  tf_activity: number | null
  risk_score: number | null
  attack_prob: number | null
  severity: string | null
}

export interface ModelPerformance {
  generated_at?: string
  model?: string
  normal_source?: string
  n_normal?: number
  n_attack?: number
  roc_auc?: number
  precision?: number
  recall?: number
  false_positive_rate?: number
  operating_threshold?: number
  confusion?: { tp: number; fp: number; tn: number; fn: number }
  fusion_weights?: { iforest: number; pca_ae: number; tf_ae: number }
  per_attack_recall?: Record<string, number>
}

export function useModelPerformance(intervalMs = 30000) {
  const [perf, setPerf] = useState<ModelPerformance | null>(null)
  useEffect(() => {
    let active = true
    const poll = async () => {
      const d = await safeFetch<ModelPerformance>(`${API_BASE}/model/performance`)
      if (active && d) setPerf(d)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])
  return perf
}

// Fast live AI scores straight from the data-plane state files (no Prometheus hop).
// Poll at ~1s; safeFetch returns null on a miss so the last good value is kept
// (no flicker / drop-to-zero between updates).
export function useLiveScores(intervalMs = 1000) {
  const [live, setLive] = useState<LiveScores | null>(null)
  useEffect(() => {
    let active = true
    const poll = async () => {
      const d = await safeFetch<LiveScores>(`${API_BASE}/scores/live`)
      if (!active) return
      if (d) setLive(d)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])
  return live
}

export function useTrend(intervalMs = 5000) {
  const [trendData, setTrendData] = useState<{
    window_60: {
      mean_score: number
      max_score: number
      std_dev: number
      anomaly_rate_pct: number
      trend_direction: 'rising' | 'stable' | 'falling'
      predicted_breach_in_s: number | null
    }
  } | null>(null)

  useEffect(() => {
    let active = true
    const poll = async () => {
      const d = await safeFetch<typeof trendData>(`/api/trend`)
      if (!active) return
      if (d) setTrendData(d)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])

  return trendData
}

export function useTrendHistory(intervalMs = 3000) {
  const [history, setHistory] = useState<Array<{
    ts: number
    iforest_score: number | null
    pca_z: number | null
    anomaly: boolean
  }>>([])

  useEffect(() => {
    let active = true
    const poll = async () => {
      const d = await safeFetch<typeof history>('/api/trend/history')
      if (!active || !d) return
      setHistory(d)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])

  return history
}

export function useModelHealth(intervalMs = 10000) {
  const [health, setHealth] = useState<Record<string, boolean> | null>(null)

  useEffect(() => {
    let active = true
    const poll = async () => {
      const d = await safeFetch<{ status: string; models_loaded: Record<string, boolean> }>('/health')
      if (!active || !d) return
      setHealth(d.models_loaded)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])

  return health
}

async function promQuery(query: string): Promise<number> {
  const data = await safeFetch<{ status: string; data: { result: { value: [number, string] }[] } }>(
    `${PROM_BASE}/api/v1/query?query=${encodeURIComponent(query)}`
  )
  if (!data || data.status !== 'success' || !data.data.result.length) return -1
  return parseFloat(data.data.result[0].value[1])
}

async function promQueryLabels(query: string): Promise<Array<{ metric: Record<string, string>; value: number }>> {
  const data = await safeFetch<{ status: string; data: { result: { metric: Record<string, string>; value: [number, string] }[] } }>(
    `${PROM_BASE}/api/v1/query?query=${encodeURIComponent(query)}`
  )
  if (!data || data.status !== 'success') return []
  return data.data.result.map(r => ({ metric: r.metric, value: parseFloat(r.value[1]) }))
}

export function useHMIState(intervalMs = 2000) {
  const [state, setState] = useState<HMIState | null>(null)
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    let active = true
    const poll = async () => {
      const data = await safeFetch<HMIState>(`${API_BASE}/hmi/state`)
      if (!active) return
      if (data) { setState(data); setConnected(true) }
      else setConnected(false)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])

  return { state, connected }
}

export function useInjectionState(intervalMs = 800) {
  const [state, setState] = useState<InjectionState | null>(null)
  const prevActive = useRef(false)
  const [justFinished, setJustFinished] = useState(false)

  useEffect(() => {
    let active = true
    const poll = async () => {
      const data = await safeFetch<InjectionState>(`${API_BASE}/demo/injection-state`)
      if (!active || !data) return
      if (prevActive.current && !data.active) setJustFinished(true)
      prevActive.current = data.active
      setState(data)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])

  useEffect(() => {
    if (justFinished) {
      const t = setTimeout(() => setJustFinished(false), 3000)
      return () => clearTimeout(t)
    }
  }, [justFinished])

  return { state, justFinished }
}

export function usePrometheusMetrics(intervalMs = 5000) {
  const [metrics, setMetrics] = useState<PrometheusMetrics | null>(null)

  const fetchAll = useCallback(async () => {
    const [
      compliance, safety, iforest, pca_z, tf_z, robot_z, latency, sis, incidents,
      injTotal, injActive, modbusRate,
      componentResults, alertsCatResults, alertsSevResults, vulnResults, verdictResults,
    ] = await Promise.all([
      promQuery('lab_iec62443_compliance_score'),
      promQuery('lab_stage3_safety_state'),
      promQuery('lab_stage2_latest_iforest_score'),
      promQuery('lab_stage2_latest_pca_z'),
      promQuery('lab_stage2_latest_tf_z'),
      promQuery('lab_robot_lstm_z'),
      promQuery('lab_detection_latency_seconds'),
      promQuery('lab_stage3_sis_integrity'),
      promQuery('lab_stage6_open_incidents'),
      promQuery('lab_attack_injection_total'),
      promQuery('lab_attack_injection_active'),
      promQuery('lab_stage1_modbus_traffic_rate'),
      promQueryLabels('lab_component_up'),
      promQueryLabels('lab_stage2_alerts_total'),
      promQueryLabels('lab_stage2_alert_severity_total'),
      promQueryLabels('lab_stage4_vuln_count'),
      promQueryLabels('lab_stage5_pipeline_last_verdict'),
    ])

    const component_health: Record<string, number> = {}
    for (const r of componentResults) component_health[r.metric.component] = r.value

    const alerts_by_category: Record<string, number> = {}
    for (const r of alertsCatResults) if (r.metric.category !== 'none') alerts_by_category[r.metric.category] = r.value

    const alerts_by_severity: Record<string, number> = {}
    for (const r of alertsSevResults) if (r.metric.severity !== 'none') alerts_by_severity[r.metric.severity] = r.value

    const vuln_by_severity: Record<string, number> = {}
    for (const r of vulnResults) vuln_by_severity[r.metric.severity] = r.value

    let pipeline_verdict = 'NONE'
    for (const r of verdictResults) if (r.value === 1) { pipeline_verdict = r.metric.verdict; break }

    setMetrics({
      compliance_score: compliance,
      safety_state: safety,
      iforest_score: iforest,
      pca_z: pca_z,
      tf_z: tf_z,
      robot_z: robot_z,
      sis_integrity: sis,
      component_health,
      alerts_by_category,
      alerts_by_severity,
      vuln_by_severity,
      pipeline_verdict,
      open_incidents: incidents,
      detection_latency: latency,
      attack_injections_total: injTotal,
      injection_active: injActive,
      modbus_traffic_rate: modbusRate,
    })
  }, [])

  useEffect(() => {
    fetchAll()
    const t = setInterval(fetchAll, intervalMs)
    return () => clearInterval(t)
  }, [fetchAll, intervalMs])

  return metrics
}

export async function sendControl(action: string): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/hmi/control`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  })
  return await res.json()
}

export interface PendingApproval {
  incident_id: string
  step: string
  cmd: string
  queued_at: string
}

export interface IncidentAuditStep {
  step: string
  status: string
  rc?: number
  stdout_tail?: string
  stderr_tail?: string
}

export interface MitreTag {
  id?: string
  technique?: string
  tactic?: string
}

export interface IncidentRecord {
  incident_id: string
  playbook: string
  // Step 4 SOC fields (surfaced by the playbook engine alongside the raw event).
  attack_type?: string
  label?: string
  mitre?: MitreTag
  why?: string[]
  confidence?: string
  severity?: string
  event: Record<string, any>
  steps: IncidentAuditStep[]
  closed: boolean
  opened_at: string
}

export function usePendingApprovals(intervalMs = 2000) {
  const [pending, setPending] = useState<PendingApproval[]>([])

  useEffect(() => {
    let active = true
    const poll = async () => {
      const d = await safeFetch<PendingApproval[]>(`${API_BASE}/ir/pending`)
      if (!active) return
      if (d) setPending(d)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])

  return pending
}

export function useIncidents(intervalMs = 2000) {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([])

  useEffect(() => {
    let active = true
    const poll = async () => {
      const d = await safeFetch<IncidentRecord[]>(`${API_BASE}/ir/incidents`)
      if (!active) return
      if (d) setIncidents(d)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])

  return incidents
}

export async function approveIncidentStep(incident_id: string, step: string, reject = false): Promise<{ status: string; stdout?: string; detail?: string }> {
  try {
    const res = await fetch(`${API_BASE}/ir/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incident_id, step, reject }),
    })
    return await res.json()
  } catch (err: any) {
    return { status: 'error', detail: err.message || String(err) }
  }
}


export async function triggerInjection(
  attack_type: string,
  duration_s: number,
  rate_hz: number
): Promise<{ status: string; message: string; started_at?: number }> {
  const res = await fetch(`${API_BASE}/demo/inject-attack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attack_type, duration_s, rate_hz }),
  })
  return await res.json()
}

export function useScrollingAlerts(hmiState: HMIState | null, maxRows = 50) {
  const [alerts, setAlerts] = useState<AlertRecord[]>([])
  const seenRef = useRef(new Set<string>())

  useEffect(() => {
    if (!hmiState?.latest_alerts?.length) return
    const newAlerts: AlertRecord[] = []
    for (const a of hmiState.latest_alerts) {
      // BUG #8 FIX: Include src_ip and signature_id in dedup key.
      // Previous key (ts + cat only) collapsed simultaneous alerts from different
      // hosts or with different signature IDs into a single entry during fast injections.
      const cat = a.category ?? (a as any).alert?.category ?? a.alert_type ?? 'unknown'
      const ts  = a.timestamp ?? a.ts ?? ''
      const srcIp = a.src_ip ?? ''
      const sigId = (a as any).alert?.signature_id ?? ''
      const key = `${ts}-${cat}-${srcIp}-${sigId}`
      if (!seenRef.current.has(key)) {
        seenRef.current.add(key)
        newAlerts.push(a)
      }
    }
    if (newAlerts.length) {
      setAlerts(prev => [...newAlerts, ...prev].slice(0, maxRows))
    }
    // Keep the dedup set bounded so a long-running session cannot leak memory
    // (it would otherwise retain every alert key ever seen). Trim to the most
    // recent 500 keys, which safely covers the capped on-screen list.
    if (seenRef.current.size > 1000) {
      seenRef.current = new Set(Array.from(seenRef.current).slice(-500))
    }
  }, [hmiState, maxRows])

  return alerts
}

export async function simulatePhysicalButton(button: 'start' | 'stop'): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/hmi/simulate-button`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ button }),
  })
  return await res.json()
}

export async function triggerSros2Estop(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/hmi/trigger-sros2-estop`, {
    method: 'POST',
  })
  return await res.json()
}

export async function fetchHMILogs(service: string): Promise<{ status: string; logs: string }> {
  const res = await fetch(`${API_BASE}/hmi/logs?service=${service}`)
  return await res.json()
}

export function useStagesReports(intervalMs = 5000) {
  const [reports, setReports] = useState<StagesReports | null>(null)

  useEffect(() => {
    let active = true
    const poll = async () => {
      const d = await safeFetch<StagesReports>(`${API_BASE}/stages/reports`)
      if (!active) return
      if (d) setReports(d)
    }
    poll()
    const t = setInterval(poll, intervalMs)
    return () => { active = false; clearInterval(t) }
  }, [intervalMs])

  return reports
}


