export interface Role {
  id: string;
  description: string;
}

export interface ServerDoc {
  server_id: string;
  label: string;
  owner: string;
  mcp_url: string;
  trust_status: "trusted" | "untrusted";
  default_allowed_roles: string[];
  seeded?: boolean;
  tool_count: number;
}

export interface HijackSignal {
  pattern_id: string;
  category: string;
  severity: "critical" | "high" | "medium";
  matched_text: string;
}

export interface ToolDoc {
  tool_id: string;
  server_id: string;
  name: string;
  description: string;
  allowed_roles: string[];
  risk_level: string;
  trust_status: string;
  hijack_status?: "clear" | "flagged";
  hijack_severity?: string | null;
  hijack_signals?: HijackSignal[];
  hijack_scanned_at?: string;
  hijack_manual_override?: "trusted" | "quarantined";
}

export interface AuditLogEntry {
  timestamp: string;
  action: "authenticate" | "discover" | "invoke";
  role: string | null;
  subject: string | null;
  query: string | null;
  tool_id: string | null;
  server_id: string | null;
  decision: "ALLOW" | "DENY" | "ERROR";
  reason: string;
  latency_ms: number;
  hijack_flagged?: boolean;
  hijack_severity?: string | null;
  hijack_signals?: HijackSignal[];
}

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  summary: string;
  tags: string[];
}

export interface DashboardSummary {
  registered_servers: number;
  trusted_servers: number;
  tools_ingested: number;
  quarantined_tools: number;
  roles: number;
  access_events_24h: number;
  deny_rate_pct: number;
  open_findings: number;
}

export interface HourlyVolumePoint {
  hour: string;
  timestamp: string;
  count: number;
}

export interface DashboardResponse {
  generated_at: string;
  events_examined: number;
  summary: DashboardSummary;
  decision_breakdown: { ALLOW: number; DENY: number; ERROR: number };
  action_breakdown: { discover: number; invoke: number; authenticate: number };
  hourly_volume: HourlyVolumePoint[];
  top_findings: Finding[];
}

export interface DiscoveredTool {
  tool_id: string;
  name: string;
  description: string;
  server_id: string;
  risk_level: string;
  similarity: number;
}

export interface HealthResponse {
  status: string;
  appliance: string;
  couchbase_connected: boolean;
  embeddings_ready: boolean;
  timestamp: string;
}

export interface HijackScanResult {
  flagged: boolean;
  severity: string | null;
  signals: HijackSignal[];
}

export interface ThreatDetectionResponse {
  last_scan_at: string | null;
  scan_interval_minutes: number;
  chain_window_seconds: number;
  quarantined_tools: ToolDoc[];
  flagged_responses: AuditLogEntry[];
  chain_findings: Finding[];
}
