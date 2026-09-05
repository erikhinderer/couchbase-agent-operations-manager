import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { AuditLogEntry } from "../api/types";
import { DecisionBadge } from "../components/badges/Badges";
import { SiemForwardingPanel } from "../components/siem/SiemForwardingPanel";

export function AuditLogPage() {
  const [entries, setEntries] = useState<AuditLogEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState("all");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [live, setLive] = useState(true);
  const [limit, setLimit] = useState(100);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await api.auditLog(limit);
      setEntries(res.entries);
    } catch (e: any) {
      setError(e.message || "Failed to load audit log");
    }
  }, [limit]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!live) return;
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, [live, load]);

  const filtered = (entries || []).filter((e) => {
    if (actionFilter !== "all" && e.action !== actionFilter) return false;
    if (decisionFilter !== "all" && e.decision !== decisionFilter) return false;
    return true;
  });

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Audit Log</h1>
          <p className="page-subtitle">
            Every discover and invoke decision, ALLOW or DENY, written append-only to Couchbase - including
            authentication failures.
          </p>
        </div>
        <div className="flex-row">
          <label className="checkbox-row" style={{ marginBottom: 0 }}>
            <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} />
            Live (8s)
          </label>
          <button className="btn btn-secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="error-note">{error}</div>}

      <SiemForwardingPanel />

      <div className="flex-row" style={{ marginBottom: 16, flexWrap: "wrap", gap: 10 }}>
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px" }}
        >
          <option value="all">All actions</option>
          <option value="authenticate">authenticate</option>
          <option value="discover">discover</option>
          <option value="invoke">invoke</option>
        </select>
        <select
          value={decisionFilter}
          onChange={(e) => setDecisionFilter(e.target.value)}
          style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px" }}
        >
          <option value="all">All decisions</option>
          <option value="ALLOW">ALLOW</option>
          <option value="DENY">DENY</option>
          <option value="ERROR">ERROR</option>
        </select>
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
          style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 10px" }}
        >
          <option value={50}>Last 50</option>
          <option value={100}>Last 100</option>
          <option value={200}>Last 200</option>
        </select>
      </div>

      <div className="card">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Action</th>
                <th>Role</th>
                <th>Subject</th>
                <th>Tool / Query</th>
                <th>Decision</th>
                <th>Reason</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e, i) => (
                <tr key={i}>
                  <td className="cell-mono cell-muted">{e.timestamp?.replace("T", " ").replace("Z", "")}</td>
                  <td className="cell-mono">{e.action}</td>
                  <td className="cell-mono">{e.role || "-"}</td>
                  <td className="cell-mono cell-muted">{e.subject || "-"}</td>
                  <td className="cell-mono">{e.tool_id || e.query || "-"}</td>
                  <td>
                    <DecisionBadge decision={e.decision} />
                  </td>
                  <td className="cell-muted" style={{ maxWidth: 360 }}>
                    {e.reason}
                  </td>
                  <td className="cell-muted">{e.latency_ms}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
          {entries && filtered.length === 0 && <div className="empty-state">No matching audit log entries yet.</div>}
        </div>
      </div>
    </div>
  );
}
