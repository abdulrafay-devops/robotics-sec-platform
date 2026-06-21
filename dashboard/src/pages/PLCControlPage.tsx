import { useState, useEffect } from 'react'
import type { HMIState, PLCState } from '../types'
import { Cpu, Power, StopCircle, AlertTriangle, Play, Square, Terminal, Shield, RefreshCw } from 'lucide-react'
import { clsx } from 'clsx'
import { sendControl, simulatePhysicalButton, triggerSros2Estop, fetchHMILogs } from '../hooks/useMetrics'

interface Props { hmiState: HMIState | null }

function CoilIndicator({ label, on, isEStop = false, isWarning = false }: { label: string; on: boolean; isEStop?: boolean; isWarning?: boolean }) {
  const bulbClass = on 
    ? (isEStop ? 'scada-bulb-on-red' : isWarning ? 'scada-bulb-on-amber' : 'scada-bulb-on-green') 
    : 'scada-bulb-off'
  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className={clsx('scada-bulb', bulbClass)}>
        {on ? 'ON' : 'OFF'}
      </div>
      <span className="text-[9px] font-mono text-slate-500 text-center leading-tight w-16 uppercase tracking-wider font-bold">{label}</span>
    </div>
  )
}

function RegValue({ label, value, unit = '' }: { label: string; value: number | string; unit?: string }) {
  return (
    <div className="bg-slate-800/60 rounded-lg p-3 border border-border-dim/60">
      <div className="text-[10px] text-slate-500 font-mono mb-1">{label}</div>
      <div className="font-mono text-lg font-bold text-white">{value}<span className="text-xs text-slate-500 ml-1">{unit}</span></div>
    </div>
  )
}

export function PLCControlPage({ hmiState }: Props) {
  const [busy, setBusy] = useState<string | null>(null)
  const [simBusy, setSimBusy] = useState<string | null>(null)
  const [lastMsg, setLastMsg] = useState<{ ok: boolean; text: string } | null>(null)
  
  const [logsService, setLogsService] = useState<'supervisor' | 'heartbeat' | 'openplc' | 'watcher'>('supervisor')
  const [logsText, setLogsText] = useState<string>('Loading logs...')
  const [logsAutoRefresh, setLogsAutoRefresh] = useState(true)
  const [logsLoading, setLogsLoading] = useState(false)

  const plc = hmiState?.plc_state as PLCState | undefined
  const hasError = !plc || ('error' in plc)

  async function ctrl(action: string) {
    setBusy(action)
    setLastMsg(null)
    try {
      const r = await sendControl(action)
      setLastMsg({ ok: r.status === 'ok', text: r.message ?? JSON.stringify(r) })
    } catch (e) {
      setLastMsg({ ok: false, text: String(e) })
    }
    setBusy(null)
  }

  async function handleSimulateButton(btn: 'start' | 'stop') {
    setSimBusy(btn)
    setLastMsg(null)
    try {
      const r = await simulatePhysicalButton(btn)
      setLastMsg({ ok: r.status === 'ok', text: r.message ?? JSON.stringify(r) })
    } catch (e) {
      setLastMsg({ ok: false, text: String(e) })
    }
    setSimBusy(null)
  }

  async function handleSros2Estop() {
    setSimBusy('sros2')
    setLastMsg(null)
    try {
      const r = await triggerSros2Estop()
      setLastMsg({ ok: r.status === 'ok', text: r.message ?? JSON.stringify(r) })
    } catch (e) {
      setLastMsg({ ok: false, text: String(e) })
    }
    setSimBusy(null)
  }

  const loadLogs = async (serviceName: string) => {
    setLogsLoading(true)
    try {
      const r = await fetchHMILogs(serviceName)
      if (r.status === 'ok') {
        setLogsText(r.logs || 'No logs available.')
      } else {
        setLogsText(`Failed to retrieve logs for ${serviceName}`)
      }
    } catch (e) {
      setLogsText(`Error loading logs: ${e}`)
    } finally {
      setLogsLoading(false)
    }
  }

  // Load logs on mount or service selection
  useEffect(() => {
    loadLogs(logsService)
  }, [logsService])

  // Poll logs if Auto-Refresh is active
  useEffect(() => {
    if (!logsAutoRefresh) return
    const t = setInterval(() => {
      loadLogs(logsService)
    }, 4000)
    return () => clearInterval(t)
  }, [logsService, logsAutoRefresh])

  const safetyColors = ['text-safe-green', 'text-ai-amber', 'text-ot-red']
  const safetyLabels = ['NORMAL', 'DEGRADED', 'EMERGENCY']
  const safetyState = plc?.safety_state ?? -1

  function parseLogLine(line: string, index: number) {
    if (!line.trim()) return null
    const lineLower = line.toLowerCase()
    let colorClass = 'log-debug'
    if (lineLower.includes('error') || lineLower.includes('fail') || lineLower.includes('critical') || lineLower.includes('emergency')) {
      colorClass = 'log-error'
    } else if (lineLower.includes('warn') || lineLower.includes('degraded') || lineLower.includes('timeout')) {
      colorClass = 'log-warn'
    } else if (lineLower.includes('success') || lineLower.includes('ok') || lineLower.includes('active') || lineLower.includes('started') || lineLower.includes('info')) {
      colorClass = 'log-info'
    }
    return <div key={index} className={clsx(colorClass, 'py-0.5 border-b border-slate-900/10')}>{line}</div>
  }

  return (
    <div className="h-full overflow-y-auto p-5 space-y-5">
      <div className="flex items-center gap-2">
        <Cpu size={16} className="text-ot-red" />
        <h1 className="text-lg font-bold text-white">OT Control Panel</h1>
        <span className="text-xs text-slate-500 font-mono">Production PLC — Modbus TCP 192.168.10.10:502</span>
        {hasError && <span className="ml-auto badge badge-critical animate-pulse">PLC OFFLINE</span>}
      </div>

      {/* Safety state banner */}
      <div className={clsx('rounded-lg border p-4 flex items-center gap-4 transition-all duration-300',
        safetyState === 2 ? 'border-ot-red bg-red-950/20 shadow-[0_0_12px_rgba(239,68,68,0.1)]' :
        safetyState === 1 ? 'border-ai-amber bg-amber-950/20 shadow-[0_0_12px_rgba(245,158,11,0.1)]' :
        'border-safe-green/30 bg-emerald-950/10'
      )}>
        <AlertTriangle size={20} className={safetyState >= 0 ? safetyColors[safetyState] : 'text-slate-500'} />
        <div>
          <div className={clsx('text-sm font-bold tracking-wide uppercase', safetyState >= 0 ? safetyColors[safetyState] : 'text-slate-500')}>
            SAFETY STATE: {safetyState >= 0 ? safetyLabels[safetyState] : 'UNKNOWN'}
          </div>
          <div className="text-xs text-slate-500 font-mono mt-0.5">
            E-Stop trips: {plc?.estop_trip_count ?? '—'} | Fault code: {plc?.last_fault_code ?? '—'} | Ack counter: {plc?.ack_counter ?? '—'}
          </div>
        </div>
        {plc?.e_stop_active && (
          <span className="ml-auto badge badge-critical animate-pulse">E-STOP ACTIVE</span>
        )}
      </div>

      {/* Coil status grid */}
      <div className="card">
        <div className="card-header"><Cpu size={12} />Coil Status (Digital Outputs)</div>
        <div className="flex gap-6 flex-wrap mt-3">
          {hasError ? (
            <div className="text-slate-500 text-sm font-mono py-4">PLC not reachable — check container-ot and Modbus port 502</div>
          ) : (
            <>
              <CoilIndicator label="MOTOR ARM" on={plc?.motor_arm_enable ?? false} />
              <CoilIndicator label="GRIPPER" on={plc?.gripper_close ?? false} />
              <CoilIndicator label="CONVEYOR" on={plc?.conveyor_run ?? false} />
              <CoilIndicator label="CYCLE BUSY" on={plc?.cycle_busy ?? false} />
              <CoilIndicator label="CYCLE DONE" on={plc?.cycle_complete ?? false} />
              <CoilIndicator label="E-STOP" on={plc?.e_stop_active ?? false} isEStop />
              <CoilIndicator label="SAFE REQ" on={plc?.request_safe_state ?? false} isWarning />
              <CoilIndicator label="REM START" on={plc?.remote_start_btn ?? false} />
              <CoilIndicator label="REM STOP" on={plc?.remote_stop_btn ?? false} />
              <CoilIndicator label="PHYS START" on={plc?.physical_start_btn ?? false} />
              <CoilIndicator label="PHYS STOP" on={plc?.physical_stop_btn ?? false} isEStop />
            </>
          )}
        </div>
      </div>

      {/* Register values */}
      <div className="card">
        <div className="card-header">Holding Registers (Analogue State)</div>
        <div className="grid grid-cols-4 gap-3 mt-2">
          <RegValue label="CYCLE STEP" value={plc?.cycle_step ?? '—'} />
          <RegValue label="CYCLE COUNT" value={plc?.cycle_count ?? '—'} />
          <RegValue label="LAST CYCLE" value={plc?.last_cycle_ms ?? '—'} unit="ms" />
          <RegValue label="SLOW MODE" value={plc?.slow_mode_active ? 'YES' : 'NO'} />
        </div>
      </div>

      {/* Control buttons */}
      <div className="card">
        <div className="card-header"><Power size={12} />Remote Control — HMI SCADA Actions</div>
        <div className="flex flex-wrap gap-3 mt-3">
          <button 
            onClick={() => ctrl('start')} 
            disabled={busy !== null || hasError}
            className="btn-primary flex items-center gap-2 select-none active:scale-95 transition-transform"
          >
            {busy === 'start' ? <RefreshCw size={14} className="animate-spin" /> : <Power size={14} />} 
            Start Cycle
          </button>
          <button 
            onClick={() => ctrl('stop')} 
            disabled={busy !== null || hasError}
            className="btn-ghost flex items-center gap-2 select-none active:scale-95 transition-transform"
          >
            {busy === 'stop' ? <RefreshCw size={14} className="animate-spin" /> : <StopCircle size={14} />} 
            Stop Cycle
          </button>
          <button 
            onClick={() => ctrl('estop')} 
            disabled={busy !== null || hasError}
            className="btn-danger flex items-center gap-2 select-none active:scale-95 transition-transform"
          >
            {busy === 'estop' ? <RefreshCw size={14} className="animate-spin" /> : <AlertTriangle size={14} />} 
            Emergency Stop
          </button>
          <button 
            onClick={() => ctrl('reset_estop')} 
            disabled={busy !== null || hasError}
            className="btn-warning flex items-center gap-2 select-none active:scale-95 transition-transform"
          >
            {busy === 'reset_estop' ? <RefreshCw size={14} className="animate-spin" /> : null}
            Reset E-Stop
          </button>
          <button 
            onClick={() => ctrl('enable_slow_mode')} 
            disabled={busy !== null || hasError}
            className="btn-ghost flex items-center gap-1.5 active:scale-95 transition-transform"
          >
            {busy === 'enable_slow_mode' && <RefreshCw size={12} className="animate-spin" />}
            Slow Mode ON
          </button>
          <button 
            onClick={() => ctrl('disable_slow_mode')} 
            disabled={busy !== null || hasError}
            className="btn-ghost flex items-center gap-1.5 active:scale-95 transition-transform"
          >
            {busy === 'disable_slow_mode' && <RefreshCw size={12} className="animate-spin" />}
            Slow Mode OFF
          </button>
        </div>

        {lastMsg && (
          <div className={clsx('mt-3 text-xs font-mono rounded p-2 flex items-start gap-2 border transition-all',
            lastMsg.ok ? 'bg-emerald-950/40 text-emerald-300 border-emerald-900/60' : 'bg-red-950/40 text-red-300 border-red-900/60'
          )}>
            <span>{lastMsg.ok ? '✓' : '✗'}</span> <span>{lastMsg.text}</span>
          </div>
        )}

        <div className="mt-4 text-[10px] text-slate-600 font-mono leading-relaxed border-t border-slate-900/60 pt-3">
          All control actions are routed through score_service.py → Modbus TCP write to production PLC.<br />
          Safety supervisor (Stage 3) monitors coil state independently and can override to SAFE STATE regardless of HMI commands.
        </div>
      </div>

      {/* Simulation & SROS2 panel */}
      <div className="grid grid-cols-2 gap-4">
        {/* Physical Console Simulator */}
        <div className="card">
          <div className="card-header"><Power size={12} className="text-safe-green" />Physical Shop-Floor Console Simulator</div>
          <p className="text-[11px] text-slate-500 mb-3 font-mono leading-relaxed">
            Simulate physical discrete inputs directly from the hardware buttons on the factory floor enclosure. These bypass the HMI network path.
          </p>
          <div className="flex gap-3 mt-1">
            <button
              onClick={() => handleSimulateButton('start')}
              disabled={simBusy !== null || hasError}
              className="btn-primary flex items-center gap-2 bg-emerald-700 hover:bg-emerald-600 border-emerald-600 active:scale-95 transition-all select-none"
            >
              {simBusy === 'start' ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />} 
              Push START Button
            </button>
            <button
              onClick={() => handleSimulateButton('stop')}
              disabled={simBusy !== null || hasError}
              className="btn-danger flex items-center gap-2 bg-red-700 hover:bg-red-600 border-red-600 active:scale-95 transition-all select-none"
            >
              {simBusy === 'stop' ? <RefreshCw size={14} className="animate-spin" /> : <Square size={14} />} 
              Push STOP Button
            </button>
          </div>
        </div>

        {/* Cryptographic Safety Panel */}
        <div className="card border-glow-red">
          <div className="card-header"><Shield size={12} className="text-ot-red" />Cryptographic Safety Controls (SROS2)</div>
          <p className="text-[11px] text-slate-500 mb-3 font-mono leading-relaxed">
            Trigger a hardware-grade safety halt cryptographically. Creates an out-of-band enclave request to immediately force E-Stop.
          </p>
          <button
            onClick={handleSros2Estop}
            disabled={simBusy !== null || hasError}
            className="w-full btn flex items-center justify-center gap-2 text-xs bg-red-950/60 hover:bg-red-900/70 text-red-200 border border-red-800 active:scale-95 transition-all select-none"
          >
            {simBusy === 'sros2' ? <RefreshCw size={13} className="animate-spin" /> : <AlertTriangle size={13} className="text-red-400" />}
            TRIGGER SROS2 CRYPTOGRAPHIC E-STOP
          </button>
        </div>
      </div>

      {/* Safety Service Logs Terminal */}
      <div className="card">
        <div className="flex items-center justify-between card-header !mb-2">
          <div className="flex items-center gap-2">
            <Terminal size={12} className="text-dmz-teal" />
            <span>OT Safety Service Logs Terminal</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <label className="text-[10px] text-slate-500 font-mono">Service:</label>
              <select
                value={logsService}
                onChange={(e) => setLogsService(e.target.value as any)}
                className="bg-slate-900 border border-slate-700 rounded px-1.5 py-0.5 text-[10px] font-mono text-slate-200 focus:outline-none"
              >
                <option value="supervisor">Safety Supervisor</option>
                <option value="heartbeat">Safety Heartbeat</option>
                <option value="openplc">OpenPLC Daemon</option>
                <option value="watcher">SROS2 Watcher</option>
              </select>
            </div>
            <label className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={logsAutoRefresh}
                onChange={(e) => setLogsAutoRefresh(e.target.checked)}
                className="accent-blue-500"
              />
              Auto-Refresh (4s)
            </label>
          </div>
        </div>
        <pre className="terminal text-[10px] max-h-60 overflow-y-auto mt-2 select-text whitespace-pre-wrap flex flex-col font-mono bg-black/50 border border-slate-900 rounded p-3">
          {logsLoading && logsText === 'Loading logs...' ? (
            <span className="log-debug">Fetching latest logs from target container...</span>
          ) : (
            logsText.split('\n').map((line, idx) => parseLogLine(line, idx))
          )}
        </pre>
      </div>

      {/* Raw state JSON */}
      <div className="card">
        <div className="card-header">Raw PLC Telemetry (Modbus snapshot)</div>
        <pre className="terminal text-green-400 text-[10px] max-h-48 overflow-y-auto font-mono">
          {plc ? JSON.stringify(plc, null, 2) : 'No data — PLC unreachable'}
        </pre>
      </div>
    </div>
  )
}


