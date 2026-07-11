export interface PLCState {
  motor_arm_enable: boolean
  gripper_close: boolean
  conveyor_run: boolean
  cycle_busy: boolean
  cycle_complete: boolean
  e_stop_active: boolean
  request_safe_state: boolean
  remote_start_btn: boolean
  remote_stop_btn: boolean
  physical_start_btn: boolean
  physical_stop_btn: boolean
  cycle_step: number
  cycle_count: number
  estop_trip_count: number
  last_cycle_ms: number
  slow_mode_active: number
  safety_state: number
  ack_counter: number
  last_fault_code: number
  error?: string
}

export interface AlertRecord {
  timestamp?: string
  ts?: string | number
  category?: string
  alert_type?: string
  severity?: number | string
  iforest_score?: number
  pca_z?: number
  tf_z?: number
  src_ip?: string
  top_features?: string[]
  anomaly?: boolean
  alert?: { category?: string; signature?: string; severity?: number }
}

export interface HMIState {
  status: string
  plc_state: PLCState | { error: string }
  latest_alerts: AlertRecord[]
}

export interface InjectionState {
  active: boolean
  last_injection_ts: number
  injection_count: number
  attack_type: string | null
}

export interface PrometheusMetrics {
  compliance_score: number
  safety_state: number
  iforest_score: number
  pca_z: number
  tf_z: number
  robot_z: number
  sis_integrity: number
  component_health: Record<string, number>
  alerts_by_category: Record<string, number>
  alerts_by_severity: Record<string, number>
  vuln_by_severity: Record<string, number>
  pipeline_verdict: string
  open_incidents: number
  detection_latency: number
  attack_injections_total: number
  injection_active: number
  modbus_traffic_rate: number
}

export type PageId =
  | 'overview'
  | 'ai-engine'
  | 'plc-control'
  | 'security'
  | 'stages'
  | 'vendor'
  | 'incidents'

export interface VulnerabilityReport {
  asset_ip: string
  asset_vendor?: string
  asset_product?: string
  asset_firmware?: string
  cve_id: string
  cvss: number
  title: string
  source: string
  url: string
  remediation: string
}

export interface DriftEntry {
  device_class: string
  id: string
  severity: string
  description: string
  detail: string
}

export interface BaselineDriftReport {
  generated_at: string
  drift: DriftEntry[]
  compliant_count: number
  drift_count: number
}

export interface IntegrityBaselineReport {
  generated_at: string
  plc_files: Record<string, string>
  sros2_files: Record<string, string>
  modbus_snapshot: { coils: number[]; registers: number[] }
  services: Record<string, boolean>
}

export interface InventoryAsset {
  ip: string
  open_ports: number[]
  protocols: string[]
  vendor: string | null
  product: string | null
  firmware: string | null
  discovery_methods: string[]
  last_seen: number
}

export interface PipelineVerdict {
  build_id: string
  verdict: string
  timestamp: string
  source: string
  log: string
}

export interface FirewallDenyEvidence {
  timestamp: string
  source_container: string
  source_zone?: string
  source_ip?: string
  destination_ip: string
  destination_zone?: string
  destination_port: number | string
  protocol?: string
  action: string
  prefix?: string
  result?: string
  evidence_source?: string
  rule?: string
  note?: string
}

export interface StagesReports {
  vulnerabilities: VulnerabilityReport[] | null
  baseline_drift: BaselineDriftReport | null
  integrity_baseline: IntegrityBaselineReport | null
  inventory: InventoryAsset[] | null
  scan_meta?: Record<string, unknown> | null
  pipeline_verdict: PipelineVerdict | null
  firewall_denies: FirewallDenyEvidence[] | null
}

