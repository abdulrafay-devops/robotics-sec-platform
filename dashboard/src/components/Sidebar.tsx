import type { PageId } from '../types'
import {
  LayoutDashboard, Cpu, Radio, Shield, GitBranch, Users, AlertTriangle,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { clsx } from 'clsx'

interface NavItem {
  id: PageId
  label: string
  icon: LucideIcon
  accent: string
}

const NAV: NavItem[] = [
  { id: 'overview',    label: 'Overview',       icon: LayoutDashboard, accent: 'text-slate-300' },
  { id: 'ai-engine',   label: 'AI Engine',       icon: Radio,           accent: 'text-blue-400' },
  { id: 'plc-control', label: 'OT Control',      icon: Cpu,             accent: 'text-ot-red' },
  { id: 'security',    label: 'Security',        icon: Shield,          accent: 'text-dmz-teal' },
  { id: 'stages',      label: 'Stages / IEC',   icon: GitBranch,       accent: 'text-ai-amber' },
  { id: 'vendor',      label: 'Vendor Access',  icon: Users,           accent: 'text-violet-400' },
  { id: 'incidents',   label: 'IR Console',     icon: AlertTriangle,   accent: 'text-ot-red' },
]

interface Props {
  active: PageId
  onChange: (p: PageId) => void
  alertCount: number
  connected: boolean
}

export function Sidebar({ active, onChange, alertCount, connected }: Props) {
  return (
    <aside className="flex flex-col w-56 bg-bg-panel border-r border-border-dim flex-shrink-0 select-none">
      {/* Logo */}
      <div className="px-4 py-5 border-b border-border-dim">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded bg-blue-600 flex items-center justify-center">
            <Shield size={14} className="text-white" />
          </div>
          <div>
            <div className="text-xs font-bold text-white tracking-wide leading-tight">ROBOTICS SOC</div>
            <div className="text-[10px] text-slate-500 font-mono leading-tight">IEC 62443 Platform</div>
          </div>
        </div>
      </div>

      {/* Connection status */}
      <div className="px-4 py-2 border-b border-border-dim">
        <div className="flex items-center gap-1.5 text-[10px] font-mono">
          <span className={clsx('status-dot', connected ? 'bg-safe-green ring-pulse' : 'bg-red-500')} />
          <span className={connected ? 'text-safe-green' : 'text-red-400'}>
            {connected ? 'CONNECTED' : 'OFFLINE'}
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-3 overflow-y-auto">
        {NAV.map(item => {
          const Icon = item.icon
          const isActive = active === item.id
          return (
            <button
              key={item.id}
              onClick={() => onChange(item.id)}
              className={clsx(
                'w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-all duration-100 relative',
                isActive
                  ? 'bg-slate-800 text-white border-r-2 border-blue-500'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50',
              )}
            >
              <Icon size={15} className={isActive ? item.accent : 'text-slate-500'} />
              <span className="font-medium">{item.label}</span>
              {item.id === 'incidents' && alertCount > 0 && (
                <span className="ml-auto text-[10px] bg-red-700 text-white rounded-full px-1.5 py-0.5 font-mono font-bold">
                  {alertCount}
                </span>
              )}
            </button>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-border-dim text-[10px] text-slate-600 font-mono space-y-0.5">
        <div>OT/IT Convergence Lab</div>
        <div>NIST SP 800-82 · IEC 62443</div>
      </div>
    </aside>
  )
}
