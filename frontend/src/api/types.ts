export type Role = "admin" | "operator" | "readonly" | "mac_operator";

export interface User {
  id: number;
  username: string;
  full_name: string;
  role: Role;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
  permissions?: string[];
  interface?: "full" | "simple";
  active_sessions?: number;
}

export type SwitchStatus = "unknown" | "online" | "offline" | "auth_failed" | "hostkey_error" | "error";
export type SwitchRole = "access" | "distribution" | "core" | "unknown";

export interface Switch {
  id: number;
  name: string;
  host: string;
  hostname: string;
  ssh_port: number;
  model: string;
  aos_version: string;
  site: string;
  location: string;
  description: string;
  enabled: boolean;
  credential_id: number | null;
  credential_name: string | null;
  profile_key: string;
  effective_profile: string | null;
  profile_reason: string;
  transport: "ssh" | "simulator";
  legacy_ssh_algorithms: boolean;
  uplink_ports: string[];
  port_locations: Record<string, string>;
  role: SwitchRole;
  host_key_fingerprint: string;
  host_key_trusted: boolean;
  status: SwitchStatus;
  last_check_at: string | null;
  last_success_at: string | null;
  last_error: string;
  created_at: string;
  updated_at: string;
}

export interface Credential {
  id: number;
  name: string;
  username: string;
  description: string;
  switch_count: number;
  created_at: string;
  updated_at: string;
}

export type PortClass = "ACCESS" | "LIKELY_ACCESS" | "UNKNOWN" | "LIKELY_TRUNK" | "TRUNK" | "";

export interface Reason {
  indicates: "trunk" | "access" | "neutral";
  text: string;
  weight: number;
}

export interface VlanMembership {
  vlan_id: number;
  mode: string;
  mode_raw: string;
  tagged: boolean | null;
  status: string;
}

export interface LldpNeighbor {
  local_port: string;
  chassis_id: string | null;
  port_id: string | null;
  port_description: string | null;
  system_name: string | null;
  system_description: string | null;
  capabilities: string[];
  management_ip: string | null;
}

export interface PortDetails {
  oper_status?: string | null;
  admin_status?: string | null;
  link_status?: string | null;
  alias?: string | null;
  speed_mbps?: number | null;
  duplex?: string | null;
  autonegotiation?: string | null;
  interface_type?: string | null;
  transceiver?: string | null;
  last_link_change?: string | null;
  status_changes?: number | null;
  down_reason?: string | null;
  rx?: Record<string, number>;
  tx?: Record<string, number>;
  rx_errors?: number | null;
  tx_errors?: number | null;
  mac_distribution?: { mac: string; vlan_id: number | null; type: string }[];
}

export interface PathHop {
  switch_name: string;
  interface: string;
  port: string;
  classification: string;
  vlan_id: number | null;
  role: string;
  towards?: string;
}

export interface NetworkPath {
  status: "RESOLVED" | "PARTIAL" | "AMBIGUOUS" | "NO_EDGE" | "NOT_FOUND";
  hops: PathHop[];
  unlinked: PathHop[];
  text: string;
  notes: string[];
}

export type SearchMode = "FAST" | "STANDARD" | "DEEP";

export interface SearchSummary {
  found?: boolean;
  locations?: number;
  switches_with_mac?: number;
  multiple_locations?: boolean;
  multiple_location_reasons?: string[];
  edge_candidates?: number;
  likely_edge?: { switch_name: string; port: string; vlan_id: number | null; classification: string } | null;
  edge_warning?: string;
  mac_move?: {
    previous: { switch_name: string; port: string; vlan_id: number | null; seen_at: string };
    current: { switch_name: string; port: string; vlan_id: number | null; seen_at: string };
  } | null;
  failed_switches?: string[];
  mode?: SearchMode;
  path?: NetworkPath;
}

export type SearchStatus = "queued" | "running" | "completed" | "failed" | "interrupted";

export interface MacSearch {
  id: string;
  mac: string;
  mac_display: string;
  requested_by: string;
  status: SearchStatus;
  mode: SearchMode;
  total_switches: number;
  checked: number;
  found_count: number;
  failed_count: number;
  timeout_count: number;
  options: Record<string, unknown>;
  summary: SearchSummary;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
}

export interface MacSearchResult {
  id: number;
  search_id: string;
  switch_id: number | null;
  switch_name: string;
  switch_host: string;
  location: string;
  model: string;
  aos_version: string;
  profile_key: string;
  status: string;
  error_message: string;
  port: string;
  interface_raw: string;
  is_linkagg: boolean;
  vlan_id: number | null;
  mac_type: string;
  operation: string;
  port_details: PortDetails;
  vlans: VlanMembership[];
  tagged_vlans: number[];
  untagged_vlan: number | null;
  lldp: LldpNeighbor[];
  mac_count_on_port: number | null;
  classification: PortClass;
  classification_confidence: string;
  classification_score: number | null;
  classification_reasons: Reason[];
  commands_executed: string[];
  warnings: string[];
  duration_ms: number | null;
  created_at: string;
}

export interface Step {
  step: string;
  ok: boolean;
  message: string;
  at: string;
  commands?: string[];
  attempt?: number;
  fingerprint?: string;
  changes?: string[];
}

export interface SnapshotChange {
  field: string;
  before: unknown;
  after: unknown;
  changed: boolean;
}

export interface PortAction {
  id: number;
  plan_token: string;
  action: string;
  method: "link_bounce" | "poe_cycle";
  strategy: string;
  profile_key: string;
  status: "planned" | "expired" | "denied" | "dry_run" | "running" | "success" | "failed" | "aborted" | "interrupted";
  switch_id: number | null;
  switch_name: string;
  switch_host: string;
  aos_version: string;
  port: string;
  mac: string;
  vlan_id: number | null;
  vlans: VlanMembership[];
  classification: PortClass;
  classification_confidence: string;
  classification_reasons: Reason[];
  risk_level: "normal" | "elevated" | "high" | "blocked" | "";
  warnings: string[];
  required_phrases: string[];
  available: boolean;
  execution_allowed: boolean;
  execution_note: string;
  blocked_reason: string;
  commands: string[];
  commands_executed: string[];
  steps: Step[];
  verification: {
    port_status?: string | null;
    mac_learned?: boolean;
    mac_vlan?: number | null;
    vlans?: VlanMembership[];
    vlan_matches?: boolean | null;
    elapsed_seconds?: number;
    error?: string;
    warning?: string;
    classification?: string;
    changes?: SnapshotChange[];
  };
  safety_report: SafetyReport | Record<string, never>;
  dry_run: boolean;
  trunk_override: boolean;
  reason: string;
  result_message: string;
  error_message: string;
  requested_by: string;
  search_id: string | null;
  created_at: string;
  expires_at: string | null;
  confirmed_at: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface ChangeReport {
  action_id: number;
  status: string;
  switch_name: string;
  port: string;
  mac: string;
  requested_by: string;
  dry_run: boolean;
  commands_planned: string[];
  commands_executed: string[];
  fingerprints: string[];
  snapshots: Record<string, { data: Record<string, unknown>; taken_at: string }>;
  changes: SnapshotChange[];
  result: string;
  verification: Record<string, unknown>;
}

export interface SafetyReport {
  operation: string;
  device: string;
  port: string;
  profile_key: string;
  strategy: string;
  commands: { command_key: string; text: string; risk: string; fingerprint: string }[];
  checks: { check: string; ok: boolean; detail: string }[];
  safety: "PASS" | "FAIL";
  execution: string;
  execution_reason: string;
  result: string;
}

export type OperationMode = "NORMAL" | "MAINTENANCE" | "READ_ONLY" | "EMERGENCY";
export type SafetyIndicator = "ACTIVE" | "READ ONLY" | "SAFE MODE" | "STOPPED" | "EMERGENCY";

export interface SafetyState {
  available: boolean;
  mode: OperationMode;
  configured_mode: OperationMode | "";
  mode_reason: string;
  read_only_forced_by_env: boolean;
  command_execution_enabled: boolean;
  kill_switch_forced_by_env: boolean;
  safe_mode: boolean;
  safe_mode_reason: string;
  dry_run_mode: boolean;
  unavailable_reason: string;
  state_changing_block_reason: string | null;
  indicator: SafetyIndicator;
  state_changes_enabled: boolean;
}

export interface BreakerCounters {
  ssh_failures: number;
  auth_failures: number;
  validation_failures: number;
  unexpected_output: number;
  recent_events: string[];
}

export interface SafetyEventItem {
  id: number;
  ts: string;
  kind: string;
  username: string;
  old_value: string;
  new_value: string;
  reason: string;
  details: Record<string, unknown>;
}

export interface LockItem {
  scope: "switch" | "port";
  switch_name: string;
  port: string;
  operation: string;
  locked_by: string;
  action_id: number;
  acquired_at: string;
  expires_at: string;
}

export type Severity = "INFO" | "WARNING" | "HIGH" | "CRITICAL";

export interface AlertItem {
  id: number;
  kind: string;
  severity: Severity;
  title: string;
  message: string;
  switch_name: string;
  port: string;
  mac: string;
  occurrences: number;
  details: Record<string, unknown>;
  status: "open" | "acknowledged";
  created_at: string;
  last_seen_at: string;
  acknowledged_by: string;
  acknowledged_at: string | null;
}

export interface AlertSummary {
  open: number;
  by_severity: Record<Severity, number>;
}

export interface OperationPolicyView {
  operation: string;
  risk: string;
  allowed_roles: string[];
  description: string;
  max_commands: number;
  uses_discovery_profile: boolean;
  api_requestable: boolean;
  notes: string;
  commands: Record<string, { params: string[]; max_per_invocation: number; allowed_templates: string[] }>;
}

export interface SafetyResponse {
  firewall: { ready: boolean; failed_reason: string; policy_digest: string };
  state: SafetyState;
  indicator: SafetyIndicator;
  breaker: BreakerCounters;
  env_read_only_mode: boolean;
  policy?: {
    version: string;
    operations: Record<string, OperationPolicyView>;
    allowlist: Record<string, string[]>;
    strategies: Record<string, string[][]>;
    discovery: Record<string, { template: string; sources: string[]; expected_output?: string }>;
    denied_categories: string[];
  };
}

export interface SshSessionItem {
  id: string;
  switch_id: number | null;
  switch_name: string;
  profile_key: string;
  username: string;
  purpose: string;
  reference: string;
  operations: string[];
  started_at: string;
  ended_at: string | null;
  commands_attempted: number;
  commands_executed: number;
  commands_blocked: number;
  result: string;
  error: string;
  commands: { operation: string; command_key: string; fingerprint: string; risk: string; status: string; reason: string; at: string; duration_ms: number }[];
}

export interface AuditEntry {
  id: number;
  ts: string;
  username: string;
  role?: string;
  action: string;
  operation?: string;
  result: string;
  severity: Severity;
  vlan?: number | null;
  profile?: string;
  command_fingerprint?: string;
  risk_level?: string;
  approval?: string;
  error?: string;
  before_state?: Record<string, unknown> | null;
  after_state?: Record<string, unknown> | null;
  target_type: string;
  target_id: string;
  target_label: string;
  mac: string;
  switch_name: string;
  port: string;
  message: string;
  details: Record<string, unknown>;
  ip: string;
}

export interface HistoryItem {
  id: string;
  time: string;
  user: string;
  mac: string;
  switch: string;
  port: string;
  vlan: number | null;
  locations: number;
  result: string;
  status: string;
  checked: number;
  total: number;
  failed: number;
  duration_ms: number | null;
  mac_move: boolean;
}

export interface SettingsResponse {
  values: Record<string, unknown>;
  definitions: Record<string, { type: string; description: string; min: number | null; max: number | null; choices: string[] }>;
  environment: Record<string, unknown>;
}

export interface CommandSpec {
  name: string;
  template: string;
  read_only: boolean;
  verification: string;
  verified: boolean;
  source: string;
  notes: string;
  parser?: string;
  expected_output?: string;
  allow_empty?: boolean;
  verified_by?: string;
  verified_at?: string;
}

export interface StrategySpec {
  strategy: string;
  method: string;
  down_template: string;
  up_template: string;
  verification: string;
  verified: boolean;
  source: string;
  supported_models: string[];
  unsupported_models: string[];
  requires_poe_model: boolean;
  notes: string;
  verified_by?: string;
  verified_at?: string;
}

export interface Profile {
  key: string;
  name: string;
  family: string;
  version_prefixes: string[];
  description: string;
  builtin: boolean;
  enabled: boolean;
  sources: string[];
  commands: Record<string, CommandSpec>;
  strategies: StrategySpec[];
  switch_count: number;
  supported_models: string[];
  supported_versions: string[];
}

export interface VerificationRecord {
  id: number;
  profile_key: string;
  capability: string;
  model_family: string;
  version_prefix: string;
  notes: string;
  verified_by: string;
  verified_at: string;
  evidence: Record<string, unknown>;
}

export interface VerificationRunResult {
  switch: string;
  profile: string;
  model_family: string;
  version_prefix: string;
  aos_version: string;
  port: string;
  results: { command_key: string; status: string; detail?: string; output_lines?: number }[];
  passed: boolean;
  commands: string[];
  recorded: boolean;
}

export interface IntegrationStatus {
  netbox: { configured: boolean; reachable?: boolean; error?: string; info?: Record<string, unknown> };
  zabbix: { configured: boolean; reachable?: boolean; error?: string; info?: unknown };
}

export interface Mismatch {
  field: string;
  message: string;
  inventory?: unknown;
  live?: unknown;
  netbox: unknown;
}

export interface NetBoxDevice {
  name: string;
  model: string;
  role: string;
  site: string;
  status: string;
  primary_ip: string;
  platform: string;
}

export interface ZabbixProblem {
  eventid: string;
  name: string;
  severity: string;
  clock: string;
  acknowledged: boolean;
}

// Simplified MAC_OPERATOR API: deliberately carries no technical fields.
export interface SimpleResult {
  state:
    | "searching"
    | "found"
    | "not_found"
    | "multiple"
    | "invalid"
    | "error"
    | "blocked"
    | "running"
    | "success"
    | "success_pending"
    | "failed";
  message: string;
  location?: string;
  can_restart?: boolean;
  search_id?: string;
  request_id?: string;
}

export type ImportStatus = "validated" | "queued" | "running" | "completed" | "failed" | "cancelled" | "expired" | "interrupted";

export interface ImportRow {
  line: number;
  name: string;
  management_ip: string;
  status: "valid" | "invalid" | "duplicate";
  action: "" | "create" | "update" | "unchanged" | "skip";
  errors: string[];
  warnings: string[];
  diff: string[];
  result: "" | "imported" | "updated" | "unchanged" | "skipped" | "failed" | "not_processed";
  message: string;
}

export interface ImportJob {
  id: string;
  status: ImportStatus;
  file_format: "csv" | "json";
  filename: string;
  created_by: string;
  on_existing: "skip" | "update";
  skip_invalid: boolean;
  cancel_requested: boolean;
  total: number;
  valid: number;
  invalid: number;
  duplicates: number;
  warnings: number;
  processed: number;
  imported: number;
  updated: number;
  unchanged: number;
  skipped: number;
  failed: number;
  new: number;
  existing_changed: number;
  existing_unchanged: number;
  file_errors: string[];
  error: string;
  created_at: string | null;
  expires_at: string | null;
  confirmed_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  failed_at: string | null;
  rows?: ImportRow[];
}
