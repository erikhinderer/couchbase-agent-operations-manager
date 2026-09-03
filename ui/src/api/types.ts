export interface Role {
  id: string;
  description: string;
}

export interface SdkInfo {
  version: string;
  filename: string;
  size_bytes: number;
}

export interface SkillInfo {
  platform: string;
  label: string;
  version: string;
  filename: string;
  size_bytes: number;
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

// --- LLM response caching for agents ---------------------------------------

export interface LLMModelOption {
  id: string;
  input_usd_per_1m: number;
  output_usd_per_1m: number;
}

export interface LLMProvider {
  id: string;
  label: string;
  vendor: string;
  env_key: string;
  docs_url: string;
  default_model: string;
  api_key_configured: boolean;
  models: LLMModelOption[];
}

export interface LLMCacheConfig {
  enabled: boolean;
  provider: string;
  model: string;
  fallback_provider: string | null;
  max_output_tokens: number;
  temperature: number;
  semantic_enabled: boolean;
  similarity_threshold: number;
  semantic_candidates: number;
  ttl_seconds: number;
  stale_while_revalidate_seconds: number;
  max_entries: number;
  eviction_policy: string;
  max_reuse_hits: number;
  invalidate_on_model_change: boolean;
  invalidate_on_config_change: boolean;
  invalidate_on_catalog_change: boolean;
  cache_scope: string;
  namespace: string;
  bypass_patterns: string[];
  no_cache_roles: string[];
  sweep_interval_minutes: number;
}

export interface LLMConfigResponse {
  config: LLMCacheConfig;
  config_version: string;
  defaults: LLMCacheConfig;
  cache_scopes: string[];
  eviction_policies: string[];
  last_sweep_at: string | null;
  cached_entries: number;
}

export interface LLMCacheEntry {
  entry_id: string;
  provider: string;
  model: string;
  scope_key: string;
  namespace: string;
  prompt_preview: string;
  response_preview: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
  created_at: string;
  last_hit_at: string | null;
  hit_count: number;
  exact_hits: number;
  semantic_hits: number;
  tokens_saved: number;
  cost_saved_usd: number;
  origin_latency_ms: number;
  override: boolean;
  stub: boolean;
  state: "fresh" | "stale" | "invalid";
  state_reason: string | null;
  age_seconds: number;
}

export interface LLMCacheEvent {
  timestamp: string;
  outcome: "hit_exact" | "hit_semantic" | "miss" | "bypass" | "error";
  provider: string;
  model: string;
  role: string | null;
  subject: string | null;
  entry_id: string | null;
  similarity: number | null;
  prompt_preview: string;
  total_tokens?: number;
  tokens_saved?: number;
  cost_usd?: number;
  cost_saved_usd?: number;
  latency_ms: number;
  latency_saved_ms?: number;
  reason: string;
}

export interface LLMCacheSummary {
  requests: number;
  cacheable_requests: number;
  hits: number;
  exact_hits: number;
  semantic_hits: number;
  misses: number;
  bypasses: number;
  errors: number;
  hit_rate_pct: number;
  tokens_saved: number;
  tokens_spent: number;
  cost_saved_usd: number;
  cost_spent_usd: number;
  latency_saved_ms: number;
  avg_hit_latency_ms: number;
  avg_miss_latency_ms: number;
}

export interface LLMHourlyPoint {
  hour: string;
  timestamp: string;
  hits: number;
  misses: number;
}

export interface LLMModelBreakdownRow {
  provider: string;
  provider_label: string;
  model: string;
  requests: number;
  hits: number;
  misses: number;
  hit_rate_pct: number;
  tokens_saved: number;
  tokens_spent: number;
  cost_saved_usd: number;
  cost_spent_usd: number;
}

export interface LLMDashboardResponse {
  generated_at: string;
  events_examined: number;
  enabled: boolean;
  provider: string;
  provider_label: string;
  model: string;
  api_key_configured: boolean;
  semantic_enabled: boolean;
  similarity_threshold: number;
  ttl_seconds: number;
  cached_entries: number;
  max_entries: number;
  last_sweep_at: string | null;
  summary: LLMCacheSummary;
  hourly: LLMHourlyPoint[];
  model_breakdown: LLMModelBreakdownRow[];
  recent_events: LLMCacheEvent[];
}

export interface LLMCompleteResponse {
  provider: string;
  model: string;
  role: string;
  response: string;
  cache: {
    status: "hit_exact" | "hit_semantic" | "miss" | "bypass";
    entry_id: string | null;
    similarity: number | null;
    hit_count: number;
    created_at: string | null;
    reason: string | null;
  };
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
  cost_usd: number;
  tokens_saved: number;
  cost_saved_usd: number;
  latency_ms: number;
  stub: boolean;
}


// --- Local dashboard login ---------------------------------------------

export interface AuthUser {
  username: string;
  role: string;
  source: "local" | "ldap";
  active: boolean;
  must_change_password: boolean;
  has_password: boolean;
  created_at: string | null;
  updated_at: string | null;
  last_login_at: string | null;
}

export interface AuthRole {
  id: string;
  description: string;
}

export interface LdapConfig {
  enabled: boolean;
  host: string;
  port: number;
  use_ssl: boolean;
  start_tls: boolean;
  bind_dn: string;
  bind_password_set: boolean;
  user_search_base: string;
  user_search_filter: string;
  admin_group_dn: string;
  group_member_attribute: string;
  ca_certificate: string;
  ca_certificate_info: CaCertificateInfo | null;
}

export interface CaCertificateInfo {
  subject: string;
  issuer: string;
  not_valid_before: string;
  not_valid_after: string;
  is_expired: boolean;
  error?: string;
}
