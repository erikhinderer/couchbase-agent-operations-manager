import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { ToolDoc } from "../api/types";
import { SeverityBadge, TrustBadge } from "../components/badges/Badges";

export function CatalogPage() {
  const [tools, setTools] = useState<ToolDoc[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [serverFilter, setServerFilter] = useState("all");
  const [roleFilter, setRoleFilter] = useState("all");
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await api.catalog();
      setTools(res.tools);
    } catch (e: any) {
      setError(e.message || "Failed to load catalog");
    }
  }, []);

  async function handleQuarantine(toolId: string) {
    setBusyId(toolId);
    try {
      await api.quarantineTool(toolId);
      await load();
    } catch (e: any) {
      setError(`Quarantine failed for '${toolId}': ${e.message}`);
    } finally {
      setBusyId(null);
    }
  }

  async function handleRelease(toolId: string) {
    setBusyId(toolId);
    try {
      await api.releaseTool(toolId);
      await load();
    } catch (e: any) {
      setError(`Release failed for '${toolId}': ${e.message}`);
    } finally {
      setBusyId(null);
    }
  }

  useEffect(() => {
    load();
  }, [load]);

  const servers = useMemo(() => Array.from(new Set((tools || []).map((t) => t.server_id))).sort(), [tools]);
  const roles = useMemo(
    () => Array.from(new Set((tools || []).flatMap((t) => t.allowed_roles || []))).sort(),
    [tools]
  );

  const filtered = (tools || []).filter((t) => {
    if (serverFilter !== "all" && t.server_id !== serverFilter) return false;
    if (roleFilter !== "all" && !(t.allowed_roles || []).includes(roleFilter)) return false;
    if (search && !`${t.name} ${t.description} ${t.tool_id}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Tool Catalog</h1>
          <p className="page-subtitle">
            Full transparency view of everything ingested into Couchbase's tool registry - what discovery can ever
            return, for any role. Quarantined tools were flagged by <Link to="/threat-detection">Threat Detection</Link>.
          </p>
        </div>
        <button className="btn btn-secondary" onClick={load}>
          Refresh
        </button>
      </div>

      {error && <div className="error-note">{error}</div>}

      <div className="flex-row" style={{ marginBottom: 16, flexWrap: "wrap", gap: 10 }}>
        <input
          type="text"
          placeholder="Search name, description, tool_id..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            background: "var(--bg-elevated)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "8px 12px",
            minWidth: 260,
            color: "var(--text)",
          }}
        />
        <select
          value={serverFilter}
          onChange={(e) => setServerFilter(e.target.value)}
          style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px" }}
        >
          <option value="all">All servers</option>
          {servers.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={roleFilter}
          onChange={(e) => setRoleFilter(e.target.value)}
          style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px" }}
        >
          <option value="all">All roles</option>
          {roles.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>

      <div className="card">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Server</th>
                <th>Allowed roles</th>
                <th>Risk</th>
                <th>Trust</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t) => (
                <tr key={t.tool_id}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{t.name}</div>
                    <div className="cell-muted" style={{ maxWidth: 420 }}>
                      {t.description}
                    </div>
                  </td>
                  <td className="cell-mono cell-muted">{t.server_id}</td>
                  <td>
                    {(t.allowed_roles || []).map((r) => (
                      <span key={r} className="tag-chip" style={{ marginRight: 5, marginBottom: 4 }}>
                        {r}
                      </span>
                    ))}
                  </td>
                  <td>
                    <SeverityBadge severity={t.risk_level} />
                  </td>
                  <td>
                    <TrustBadge trust={t.trust_status} />
                    {t.hijack_status === "flagged" && t.trust_status !== "quarantined" && (
                      <div style={{ marginTop: 4 }}>
                        <SeverityBadge severity="high" />
                      </div>
                    )}
                  </td>
                  <td>
                    {t.trust_status === "quarantined" ? (
                      <button
                        className="btn btn-secondary btn-sm"
                        disabled={busyId === t.tool_id}
                        onClick={() => handleRelease(t.tool_id)}
                      >
                        Release
                      </button>
                    ) : (
                      <button
                        className="btn btn-danger-outline btn-sm"
                        disabled={busyId === t.tool_id}
                        onClick={() => handleQuarantine(t.tool_id)}
                      >
                        Quarantine
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {tools && filtered.length === 0 && (
            <div className="empty-state">
              {tools.length === 0 ? "No tools ingested yet - register a trusted server first." : "No tools match these filters."}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
