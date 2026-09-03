import type {
  AuditLogEntry,
  DashboardResponse,
  Finding,
  HealthResponse,
  Role,
  ServerDoc,
  ThreatDetectionResponse,
  ToolDoc,
} from "./types";

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

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
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  health: () => request<HealthResponse>("/api/health"),

  roles: () => request<{ roles: Role[] }>("/v1/roles"),

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
