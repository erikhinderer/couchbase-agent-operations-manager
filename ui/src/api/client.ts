import type {
  AuditLogEntry,
  AuthRole,
  AuthUser,
  DashboardResponse,
  Finding,
  HealthResponse,
  LdapConfig,
  CaCertificateInfo,
  ServerCertificateInfo,
  LLMCacheConfig,
  LLMCacheEntry,
  LLMCompleteResponse,
  LLMConfigResponse,
  LLMDashboardResponse,
  LLMProvider,
  Role,
  SdkInfo,
  ServerDoc,
  SiemConfigResponse,
  SkillInfo,
  ThreatDetectionResponse,
  ToolDoc,
  TopologyResponse,
} from "./types";

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// AuthProvider registers a handler here so any 401 from any call - not
// just the /v1/auth/* ones - drops the app back to the login page (a
// session cookie can expire mid-session on any page, not just on the
// endpoints that issue it).
let onUnauthorized: (() => void) | null = null;

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      // ignore
    }
    if (res.status === 401 && !path.startsWith("/v1/auth/login") && !path.startsWith("/v1/auth/bootstrap")) {
      onUnauthorized?.();
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  setUnauthorizedHandler: (fn: (() => void) | null) => {
    onUnauthorized = fn;
  },

  health: () => request<HealthResponse>("/api/health"),

  roles: () => request<{ roles: Role[] }>("/v1/roles"),

  // -- Local dashboard login ------------------------------------------
  authBootstrapStatus: () => request<{ needs_setup: boolean; username: string }>("/v1/auth/bootstrap-status"),
  authBootstrap: (password: string) =>
    request<{ user: AuthUser }>("/v1/auth/bootstrap", { method: "POST", body: JSON.stringify({ password }) }),
  authLogin: (username: string, password: string) =>
    request<{ user: AuthUser }>("/v1/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  authLogout: () => request<{ logged_out: boolean }>("/v1/auth/logout", { method: "POST" }),
  authMe: () => request<{ user: AuthUser }>("/v1/auth/me"),
  authChangePassword: (currentPassword: string, newPassword: string) =>
    request<{ user: AuthUser }>("/v1/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  authRoles: () => request<{ roles: AuthRole[] }>("/v1/auth/roles"),

  authUsers: () => request<{ users: AuthUser[] }>("/v1/auth/users"),
  createAuthUser: (payload: { username: string; password: string; role: string; must_change_password: boolean }) =>
    request<{ user: AuthUser }>("/v1/auth/users", { method: "POST", body: JSON.stringify(payload) }),
  updateAuthUser: (
    username: string,
    patch: { role?: string; active?: boolean; password?: string; must_change_password?: boolean }
  ) =>
    request<{ user: AuthUser }>(`/v1/auth/users/${encodeURIComponent(username)}`, {
      method: "PUT",
      body: JSON.stringify(patch),
    }),
  deleteAuthUser: (username: string) =>
    request<{ deleted: boolean; username: string }>(`/v1/auth/users/${encodeURIComponent(username)}`, {
      method: "DELETE",
    }),

  ldapConfig: () => request<{ config: LdapConfig }>("/v1/auth/ldap-config"),
  saveLdapConfig: (config: Record<string, unknown>, bindPassword?: string) =>
    request<{ config: LdapConfig }>("/v1/auth/ldap-config", {
      method: "PUT",
      body: JSON.stringify({ config, bind_password: bindPassword || undefined }),
    }),
  testLdapConfig: (username: string, password: string) =>
    request<{ success: boolean; detail: string; would_be_admin: boolean }>("/v1/auth/ldap-config/test", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  validateCaCertificate: (caCertificate: string) =>
    request<{ valid: boolean; info: CaCertificateInfo }>("/v1/auth/ldap-config/validate-ca", {
      method: "POST",
      body: JSON.stringify({ ca_certificate: caCertificate }),
    }),

  siemConfig: () => request<SiemConfigResponse>("/v1/siem/config"),
  saveSiemConfig: (vendor: string, config: Record<string, unknown>) =>
    request<{ config: SiemConfigResponse["config"] }>(`/v1/siem/config/${vendor}`, {
      method: "PUT",
      body: JSON.stringify({ config }),
    }),
  testSiemConfig: (vendor: string, config?: Record<string, unknown>) =>
    request<{ success: boolean; detail: string }>(`/v1/siem/test/${vendor}`, {
      method: "POST",
      body: JSON.stringify({ config }),
    }),

  tlsCert: () => request<{ info: ServerCertificateInfo | null; can_revert: boolean }>("/v1/auth/tls-cert"),
  validateTlsCert: (certPem: string, keyPem: string) =>
    request<{ valid: boolean; info: ServerCertificateInfo }>("/v1/auth/tls-cert/validate", {
      method: "POST",
      body: JSON.stringify({ cert_pem: certPem, key_pem: keyPem }),
    }),
  installTlsCert: (certPem: string, keyPem: string) =>
    request<{ info: ServerCertificateInfo; can_revert: boolean; restart_required: boolean }>("/v1/auth/tls-cert", {
      method: "PUT",
      body: JSON.stringify({ cert_pem: certPem, key_pem: keyPem }),
    }),
  revertTlsCert: () =>
    request<{ info: ServerCertificateInfo; can_revert: boolean; restart_required: boolean }>(
      "/v1/auth/tls-cert/revert",
      { method: "POST" }
    ),

  sdkInfo: () => request<SdkInfo>("/v1/sdk/info"),
  skillInfo: (platform: string) => request<SkillInfo>(`/v1/skills/${platform}/info`),

  servers: () => request<{ servers: ServerDoc[] }>("/v1/servers"),
  registerServer: (payload: {
    server_id: string;
    label: string;
    owner: string;
    mcp_url: string;
    trust_status: "trusted" | "untrusted";
    default_allowed_roles: string[];
  }) =>
    request<{ server: ServerDoc; ingested_tools: number; ingest_error: string | null }>("/v1/servers", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  reingestServer: (serverId: string) =>
    request<{ server_id: string; ingested_tools: number }>(`/v1/servers/${encodeURIComponent(serverId)}/reingest`, {
      method: "POST",
    }),
  deleteServer: (serverId: string) =>
    request<{ deleted: boolean; server_id: string; tools_removed: number }>(
      `/v1/servers/${encodeURIComponent(serverId)}`,
      { method: "DELETE" }
    ),

  catalog: () => request<{ tools: ToolDoc[] }>("/v1/catalog"),

  auditLog: (limit = 100) => request<{ entries: AuditLogEntry[] }>(`/v1/audit-log?limit=${limit}`),

  dashboard: () => request<DashboardResponse>("/v1/dashboard"),
  topology: (windowHours = 24) => request<TopologyResponse>(`/v1/topology?window_hours=${windowHours}`),
  insights: () => request<{ findings: Finding[] }>("/v1/insights"),

  discover: (apiKey: string, query: string, topK: number) =>
    request<{ role: string; tools: import("./types").DiscoveredTool[]; latency_ms: number }>("/v1/tools/discover", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ query, top_k: topK }),
    }),

  invoke: (apiKey: string, toolId: string, args: Record<string, unknown>) =>
    request<{
      role: string;
      tool_id: string;
      result: unknown;
      latency_ms: number;
      hijack_warning: import("./types").HijackScanResult | null;
    }>("/v1/tools/invoke", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ tool_id: toolId, arguments: args }),
    }),

  // -- LLM response caching --------------------------------------------
  llmProviders: () => request<{ providers: LLMProvider[] }>("/v1/llm/providers"),
  llmConfig: () => request<LLMConfigResponse>("/v1/llm/config"),
  saveLlmConfig: (config: LLMCacheConfig) =>
    request<{ config: LLMCacheConfig; config_version: string; entries_invalidated: number }>("/v1/llm/config", {
      method: "PUT",
      body: JSON.stringify({ config }),
    }),
  llmDashboard: () => request<LLMDashboardResponse>("/v1/llm/dashboard"),
  llmCacheEntries: (limit = 100) =>
    request<{ entries: LLMCacheEntry[]; count: number; total_entries: number }>(`/v1/llm/cache?limit=${limit}`),
  purgeLlmCache: (filter: { provider?: string; model?: string; namespace?: string } = {}) =>
    request<{ purged: number }>("/v1/llm/cache/purge", { method: "POST", body: JSON.stringify(filter) }),
  sweepLlmCache: () =>
    request<{ removed: number; last_sweep_at: string }>("/v1/llm/cache/sweep", { method: "POST" }),
  deleteLlmCacheEntry: (entryId: string) =>
    request<{ deleted: boolean }>(`/v1/llm/cache/${encodeURIComponent(entryId)}`, { method: "DELETE" }),
  llmComplete: (
    apiKey: string,
    payload: { prompt: string; provider?: string; model?: string; bypass_cache?: boolean }
  ) =>
    request<LLMCompleteResponse>("/v1/llm/complete", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(payload),
    }),

  threatDetection: () => request<ThreatDetectionResponse>("/v1/threat-detection"),
  releaseTool: (toolId: string) =>
    request<{ tool_id: string; trust_status: string }>(`/v1/tools/${encodeURIComponent(toolId)}/release`, {
      method: "POST",
    }),
  quarantineTool: (toolId: string) =>
    request<{ tool_id: string; trust_status: string }>(`/v1/tools/${encodeURIComponent(toolId)}/quarantine`, {
      method: "POST",
    }),
  clearOverride: (toolId: string) =>
    request<{ tool_id: string; trust_status: string }>(`/v1/tools/${encodeURIComponent(toolId)}/clear-override`, {
      method: "POST",
    }),
};

export { ApiError };
