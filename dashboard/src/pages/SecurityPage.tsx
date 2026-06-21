import { useState } from 'react'
import type { HMIState, PrometheusMetrics } from '../types'
import {
  Shield,
  Activity,
  Search,
  Download,
  ListFilter,
  Eye,
  EyeOff,
  FileJson,
  FileSpreadsheet
} from 'lucide-react'
import { clsx } from 'clsx'
import { useScrollingAlerts } from '../hooks/useMetrics'

interface Props {
  hmiState: HMIState | null
  metrics: PrometheusMetrics | null
}

// Suricata/IDS severity convention: 1 = highest priority (most critical), 3 = lowest.
// alert_bridge._classify() assigns severity=1 for external OT-zone attacks (most dangerous).
const SEV_COLOR: Record<string, string> = {
  '1': 'badge-critical', '2': 'badge-warning', '3': 'badge-info',
  critical: 'badge-critical', high: 'badge-critical',
  medium: 'badge-warning', low: 'badge-info',
}

const CAT_COLOR: Record<string, string> = {
  anomaly: 'text-ot-red', critical: 'text-ot-red', modbus: 'text-ai-amber',
  network: 'text-dmz-teal', normal: 'text-slate-500', info: 'text-slate-400',
  'modbus-write-anomaly': 'text-ot-red',
  'modbus-external-anomaly': 'text-ot-red',
  'modbus-baseline-deviation': 'text-ai-amber',
}

function matchSeverity(sev: string, filter: string): boolean {
  if (filter === 'ALL') return true
  const s = sev.toLowerCase()
  // Suricata convention: 1 = most critical, 2 = high, 3 = medium/low
  if (filter === 'CRITICAL') return s === '1' || s === 'critical' || s === 'high'
  if (filter === 'WARNING')  return s === '2' || s === 'medium'  || s === 'warning'
  if (filter === 'INFO')     return s === '3' || s === 'low'     || s === 'info' || s === '' || s === 'unknown'
  return s === filter.toLowerCase()
}

export function SecurityPage({ hmiState, metrics }: Props) {
  const alerts = useScrollingAlerts(hmiState, 80)
  const byCat = metrics?.alerts_by_category ?? {}
  const bySev = metrics?.alerts_by_severity ?? {}

  // Filter States
  const [search, setSearch] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null)

  // Filter Logic
  const filteredAlerts = alerts.filter(a => {
    const q = search.toLowerCase()
    const cat = (a.category ?? a.alert?.category ?? a.alert_type ?? 'unknown').toLowerCase()
    const sig = (a.alert?.signature ?? a.alert_type ?? '').toLowerCase()
    const ip = (a.src_ip ?? '').toLowerCase()
    const features = (a.top_features ?? []).join(', ').toLowerCase()
    
    const matchesSearch = !search ||
      cat.includes(q) ||
      sig.includes(q) ||
      ip.includes(q) ||
      features.includes(q)

    // BUG #13 FIX: Use includes() not === so 'MODBUS' matches 'modbus-write-anomaly',
    // 'ANOMALY' matches 'modbus-write-anomaly', etc.
    const matchesCategory = categoryFilter === 'ALL' || cat.includes(categoryFilter.toLowerCase())
    
    const sev = String(a.severity ?? a.alert?.severity ?? '')
    const matchesSeverity = matchSeverity(sev, severityFilter)

    return matchesSearch && matchesCategory && matchesSeverity
  })

  // Export to CSV
  const exportToCSV = () => {
    const headers = ['Timestamp', 'Category', 'Signature/Details', 'Severity', 'IP Address', 'Anomaly']
    const rows = filteredAlerts.map(a => {
      const ts = a.timestamp ?? (typeof a.ts === 'string' ? a.ts : '')
      const timeStr = ts ? new Date(ts).toLocaleString() : ''
      const cat = a.category ?? a.alert?.category ?? 'unknown'
      const sig = a.alert?.signature ?? a.alert_type ?? ''
      const sev = a.severity ?? a.alert?.severity ?? ''
      const ip = a.src_ip ?? ''
      const isAnomaly = a.anomaly === true ? 'TRUE' : 'FALSE'
      return [timeStr, cat, sig, sev, ip, isAnomaly].map(val => `"${String(val).replace(/"/g, '""')}"`)
    })
    
    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    const encodedUri = encodeURI(csvContent)
    const link = document.createElement("a")
    link.setAttribute("href", encodedUri)
    link.setAttribute("download", `security_alerts_export_${Date.now()}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  // Export to JSON
  const exportToJSON = () => {
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(
      JSON.stringify(filteredAlerts, null, 2)
    )}`
    const link = document.createElement("a")
    link.setAttribute("href", jsonString)
    link.setAttribute("download", `security_alerts_export_${Date.now()}.json`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="px-5 pt-4 pb-3 border-b border-border-dim flex-shrink-0 flex items-center gap-2">
        <Shield size={16} className="text-dmz-teal" />
        <h1 className="text-lg font-bold text-white">Security Alerts</h1>
        <span className="text-xs text-slate-500 font-mono">Zeek + Suricata + AI anomaly feed</span>
      </div>

      <div className="flex-1 flex gap-4 overflow-hidden p-5">
        {/* Left — alert counts */}
        <div className="w-48 flex-shrink-0 space-y-4">
          <div className="card">
            <div className="card-header text-[10px]"><Activity size={11} />By Category</div>
            {Object.entries(byCat).length === 0
              ? <div className="text-slate-600 text-xs font-mono py-2">No data yet</div>
              : Object.entries(byCat).map(([cat, cnt]) => (
                <div key={cat} className="flex justify-between items-center text-xs py-1 font-mono border-b border-border-dim/40">
                  <span className={clsx(CAT_COLOR[cat.toLowerCase()] ?? 'text-slate-400')}>{cat}</span>
                  <span className="text-white font-bold">{Math.round(cnt)}</span>
                </div>
              ))
            }
          </div>

          <div className="card">
            <div className="card-header text-[10px]">By Severity</div>
            {Object.entries(bySev).length === 0
              ? <div className="text-slate-600 text-xs font-mono py-2">No data yet</div>
              : Object.entries(bySev).map(([sev, cnt]) => (
                <div key={sev} className="flex justify-between items-center text-xs py-1 font-mono border-b border-border-dim/40">
                  <span className={clsx('badge', SEV_COLOR[sev] ?? 'badge-info')}>{sev}</span>
                  <span className="text-white font-bold">{Math.round(cnt)}</span>
                </div>
              ))
            }
          </div>

          <div className="card text-[10px] font-mono space-y-1.5 text-slate-500">
            <div className="font-semibold text-slate-400 mb-2">Detection Sources</div>
            <div>✦ Suricata IDS rules</div>
            <div>✦ Zeek Modbus parser</div>
            <div>✦ AI IsolationForest</div>
            <div>✦ PCA z-score alert</div>
            <div>✦ TF Autoencoder MSE</div>
            <div>✦ Safety supervisor SIS</div>
          </div>

          <div className="card text-[10px] font-mono space-y-1 text-slate-500">
            <div className="font-semibold text-slate-400 mb-2">Compliance</div>
            <div>IEC 62443-3-3 SR 6.2</div>
            <div>NIST SP 800-82 r3</div>
            <div>ISA/IEC 62443-2-1</div>
          </div>
        </div>

        {/* Right — timeline */}
        <div className="flex-1 card flex flex-col overflow-hidden p-0">
          <div className="px-4 py-2.5 border-b border-border-dim flex flex-col gap-3 flex-shrink-0 bg-slate-900/25">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Alert Timeline</span>
              <span className="text-[10px] font-mono text-slate-600">(newest first)</span>
              <span className={clsx('ml-auto text-[10px] font-mono', filteredAlerts.some(a => a.anomaly) ? 'text-ot-red' : 'text-slate-500')}>
                Showing {filteredAlerts.length} of {alerts.length} events
              </span>
            </div>

            {/* Command Filter Bar */}
            <div className="flex flex-wrap items-center gap-3">
              {/* Search Bar */}
              <div className="relative flex-1 min-w-[200px]">
                <Search size={12} className="absolute left-2.5 top-2.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search IP, signature, category..."
                  className="w-full bg-slate-950/80 border border-border-dim/80 rounded px-2.5 py-1.5 pl-8 text-xs font-mono text-slate-200 focus:outline-none focus:border-slate-500"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                />
              </div>

              {/* Category Dropdown */}
              <div className="flex items-center gap-1.5">
                <ListFilter size={12} className="text-slate-500" />
                <select
                  className="bg-slate-950/80 border border-border-dim/80 rounded px-2 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-slate-500"
                  value={categoryFilter}
                  onChange={e => setCategoryFilter(e.target.value)}
                >
                  <option value="ALL">All Categories</option>
                  <option value="ANOMALY">Anomaly</option>
                  <option value="MODBUS">Modbus</option>
                  <option value="NETWORK">Network</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="INFO">Info</option>
                </select>
              </div>

              {/* Severity Dropdown */}
              <div className="flex items-center gap-1.5">
                <select
                  className="bg-slate-950/80 border border-border-dim/80 rounded px-2 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-slate-500"
                  value={severityFilter}
                  onChange={e => setSeverityFilter(e.target.value)}
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical / High</option>
                  <option value="WARNING">Warning / Medium</option>
                  <option value="INFO">Info / Low</option>
                </select>
              </div>

              {/* Export Buttons */}
              <div className="flex gap-1.5 ml-auto">
                <button
                  onClick={exportToCSV}
                  className="bg-slate-800 hover:bg-slate-700 border border-border-dim px-2.5 py-1.5 rounded flex items-center gap-1 text-[10px] font-mono text-slate-300 cursor-pointer transition-colors"
                  title="Export to CSV"
                >
                  <FileSpreadsheet size={11} /> CSV
                </button>
                <button
                  onClick={exportToJSON}
                  className="bg-slate-800 hover:bg-slate-700 border border-border-dim px-2.5 py-1.5 rounded flex items-center gap-1 text-[10px] font-mono text-slate-300 cursor-pointer transition-colors"
                  title="Export to JSON"
                >
                  <FileJson size={11} /> JSON
                </button>
              </div>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {filteredAlerts.length === 0 && (
              <div className="text-slate-600 text-xs font-mono text-center py-8">
                No alerts matching the selected filters.
              </div>
            )}
            {filteredAlerts.map((a, i) => {
              const ts = a.timestamp ?? (typeof a.ts === 'string' ? a.ts : null)
              const timeStr = ts ? new Date(ts).toLocaleTimeString() : '--:--:--'
              const isAnomaly = a.anomaly === true || (a.iforest_score ?? 0) > 0
              const cat = a.category ?? a.alert?.category ?? 'unknown'
              const sig = a.alert?.signature ?? a.alert_type ?? ''
              const sev = String(a.severity ?? a.alert?.severity ?? '')
              const isExpanded = expandedIndex === i

              return (
                <div key={i} className="flex flex-col border-b border-border-dim/30 hover:bg-slate-800/10">
                  <div
                    className={clsx(
                      'alert-row flex items-center gap-3 px-4 py-2.5 text-xs cursor-pointer select-none',
                      isAnomaly ? 'border-l-2 border-l-ot-red' : 'border-l-2 border-l-transparent'
                    )}
                    onClick={() => setExpandedIndex(isExpanded ? null : i)}
                  >
                    <span className="font-mono text-slate-500 flex-shrink-0 w-18">{timeStr}</span>
                    <span className={clsx('flex-shrink-0 w-24 font-mono font-bold truncate', CAT_COLOR[cat.toLowerCase()] ?? 'text-slate-400')}>
                      {cat.toUpperCase()}
                    </span>
                    <span className="flex-1 text-slate-300 font-mono truncate">
                      {sig || (
                        `iF=${a.iforest_score?.toFixed(3) ?? '—'} pca=${a.pca_z?.toFixed(2) ?? '—'}` +
                        (a.top_features?.length ? ` [${a.top_features.slice(0,3).join(',')}]` : '')
                      )}
                    </span>
                    {sev && (
                      <span className={clsx('badge flex-shrink-0', SEV_COLOR[sev] ?? 'badge-info')}>
                        {sev}
                      </span>
                    )}
                    {isAnomaly && <span className="badge badge-critical flex-shrink-0">ANOMALY</span>}
                    <span className="text-slate-500 hover:text-slate-300 ml-1">
                      {isExpanded ? <EyeOff size={12} /> : <Eye size={12} />}
                    </span>
                  </div>

                  {/* Expanded JSON Inspector Block */}
                  {isExpanded && (
                    <div className="px-4 pb-3 pt-1 bg-slate-950/45 border-t border-border-dim/20 font-mono text-[10px] text-slate-400 space-y-2">
                      <div className="grid grid-cols-2 gap-4 text-slate-350">
                        <div>
                          <div className="text-slate-500 uppercase font-semibold text-[9px]">Timestamp details</div>
                          <div>Full Time: {ts ? new Date(ts).toLocaleString() : 'N/A'}</div>
                          {a.src_ip && <div>Originating IP: <span className="text-dmz-teal font-bold">{a.src_ip}</span></div>}
                        </div>
                        <div>
                          <div className="text-slate-500 uppercase font-semibold text-[9px]">Anomaly Telemetry</div>
                          <div>iForest Score: <span className="text-slate-200">{(a.iforest_score ?? 0).toFixed(4)}</span></div>
                          {a.pca_z !== undefined && <div>PCA Z-Score: <span className="text-slate-200">{(a.pca_z).toFixed(2)}</span></div>}
                          {a.tf_z !== undefined && <div>TF Autoencoder Z-Score: <span className="text-slate-200">{(a.tf_z).toFixed(2)}</span></div>}
                        </div>
                      </div>
                      
                      {a.top_features && a.top_features.length > 0 && (
                        <div>
                          <div className="text-slate-500 uppercase font-semibold text-[9px] mb-1">Top Extreme Anomaly Features</div>
                          <div className="flex flex-wrap gap-1">
                            {a.top_features.map((feat) => (
                              <span key={feat} className="bg-slate-900 border border-border-dim/50 px-1 rounded text-slate-300">
                                {feat}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      <div>
                        <div className="text-slate-500 uppercase font-semibold text-[9px] mb-1">Raw Telemetry Log Payload</div>
                        <pre className="bg-black/60 border border-border-dim/35 p-2 rounded max-h-36 overflow-y-auto text-slate-450 leading-relaxed font-mono whitespace-pre-wrap text-[9px]">
                          {JSON.stringify(a, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
