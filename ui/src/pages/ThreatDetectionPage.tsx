import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { ThreatDetectionResponse } from "../api/types";
import { SeverityBadge } from "../components/badges/Badges";
import { FindingCard } from "../components/dashboard/FindingCard";

export function ThreatDetectionPage() {
  const [data, setData] = useState<ThreatDetectionResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.threatDetection();
      setData(res);
    } catch (e: any) {
      setError(e.message || "Failed to load threat detection data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

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

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat Detection</h1>
          <p className="page-subtitle">
            MCP Tool Hijacking detection: tool descriptions are scanned at ingest and on a background timer;
            live tool responses are scanned on every invoke and correlated against the audit log for cross-tool
            hijack chains.
          </p>
        </div>
        <button className="btn btn-primary" onClick={load} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && <div className="error-note">{error}</div>}

      {data && (
        <>
          <div className="stat-grid">
            <div className="stat-card">
              <div className="stat-label">Quarantined Tools</div>
              <div className="stat-value">{data.quarantined_tools.length}</div>
              <div className="stat-hint">Excluded from discover &amp; invoke for every role</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Flagged Responses</div>
              <div className="stat-value">{data.flagged_responses.length}</div>
              <div className="stat-hint">In the current lookback window</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Cross-Tool Chain Findings</div>
              <div className="stat-value">{data.chain_findings.length}</div>
              <div className="stat-hint">Correlation window: {data.chain_window_seconds}s</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Last Background Scan</div>
              <div className="stat-value" style={{ fontSize: 18 }}>
                {data.last_scan_at ? data.last_scan_at.replace("T", " ").replace("Z", "") : "not yet run"}
              </div>
              <div className="stat-hint">Every {data.scan_interval_minutes}m, no MCP round-trip</div>
            </div>
          </div>

          <h2 style={{ fontSize: 16, margin: "22px 0 14px 0" }}>Quarantined tools</h2>
          {data.quarantined_tools.length === 0 ? (
            <div className="card empty-state">No tools are quarantined - nothing in the catalog matched a metadata-poisoning pattern.</div>
          ) : (
            <div className="card" style={{ marginBottom: 24 }}>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Tool</th>
                      <th>Reason</th>
                      <th>Matched signals</th>
                      <th>Scanned</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.quarantined_tools.map((t) => (
                      <tr key={t.tool_id}>
                        <td className="cell-mono" style={{ fontWeight: 600 }}>
                          {t.tool_id}
                        </td>
                        <td className="cell-muted">
                          {t.hijack_manual_override === "quarantined" ? "Manually quarantined" : "Auto-quarantined at scan"}
                        </td>
                        <td>
                          {(t.hijack_signals || []).map((s, i) => (
                            <div key={i} style={{ marginBottom: 6 }}>
                              <SeverityBadge severity={s.severity} />{" "}
                              <span className="cell-muted" style={{ fontSize: 12 }}>
                                {s.category}: <span className="cell-mono">&ldquo;{s.matched_text}&rdquo;</span>
                              </span>
                            </div>
                          ))}
                          {(!t.hijack_signals || t.hijack_signals.length === 0) && (
                            <span className="cell-muted">no automated signal on file</span>
                          )}
                        </td>
                        <td className="cell-muted cell-mono">{t.hijack_scanned_at?.replace("T", " ").replace("Z", "") || "-"}</td>
                        <td>
                          <button
                            className="btn btn-secondary btn-sm"
                            disabled={busyId === t.tool_id}
                            onClick={() => handleRelease(t.tool_id)}
                          >
                            Release
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <h2 style={{ fontSize: 16, margin: "22px 0 14px 0" }}>Cross-tool hijack chain findings</h2>
          {data.chain_findings.length === 0 ? (
            <div className="card empty-state">No chain patterns detected in the current window.</div>
          ) : (
            data.chain_findings.map((f) => <FindingCard key={f.id} finding={f} />)
          )}

          <h2 style={{ fontSize: 16, margin: "22px 0 14px 0" }}>Recently flagged responses</h2>
          {data.flagged_responses.length === 0 ? (
            <div className="card empty-state">No invoke responses have been flagged in the current lookback window.</div>
          ) : (
            <div className="card">
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time (UTC)</th>
                      <th>Tool</th>
                      <th>Subject</th>
                      <th>Severity</th>
                      <th>Matched signals</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.flagged_responses.map((e, i) => (
                      <tr key={i}>
                        <td className="cell-mono cell-muted">{e.timestamp?.replace("T", " ").replace("Z", "")}</td>
                        <td className="cell-mono">{e.tool_id}</td>
                        <td className="cell-mono cell-muted">{e.subject}</td>
                        <td>{e.hijack_severity && <SeverityBadge severity={e.hijack_severity} />}</td>
                        <td className="cell-muted">
                          {(e.hijack_signals || []).map((s) => s.pattern_id).join(", ")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
