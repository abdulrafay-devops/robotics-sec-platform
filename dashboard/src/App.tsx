import { useState } from 'react'
import { Sidebar } from './components/Sidebar'
import { OverviewPage } from './pages/OverviewPage'
import { AIEnginePage } from './pages/AIEnginePage'
import { PLCControlPage } from './pages/PLCControlPage'
import { SecurityPage } from './pages/SecurityPage'
import { StagesPage } from './pages/StagesPage'
import { VendorPage } from './pages/VendorPage'
import { IncidentPage } from './pages/IncidentPage'
import { useHMIState, usePrometheusMetrics } from './hooks/useMetrics'
import type { PageId } from './types'

export default function App() {
  const [page, setPage] = useState<PageId>('overview')
  const { state: hmiState, connected } = useHMIState(2000)
  const metrics = usePrometheusMetrics(5000)

  const alertCount = Math.round(metrics?.open_incidents ?? 0)

  return (
    <div className="flex h-screen bg-bg-dark text-slate-200 overflow-hidden">
      <Sidebar active={page} onChange={setPage} alertCount={alertCount} connected={connected} />
      <main className="flex-1 overflow-hidden">
        {page === 'overview'    && <OverviewPage    hmiState={hmiState} metrics={metrics} connected={connected} onNavigate={setPage} />}
        {page === 'ai-engine'   && <AIEnginePage    hmiState={hmiState} metrics={metrics} />}
        {page === 'plc-control' && <PLCControlPage  hmiState={hmiState} />}
        {page === 'security'    && <SecurityPage    hmiState={hmiState} metrics={metrics} />}
        {page === 'stages'      && <StagesPage      metrics={metrics} />}
        {page === 'vendor'      && <VendorPage      metrics={metrics} />}
        {page === 'incidents'   && <IncidentPage    metrics={metrics} />}
      </main>
    </div>
  )
}
