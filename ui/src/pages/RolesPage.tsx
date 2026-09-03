import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Role, ToolDoc } from "../api/types";

export function RolesPage() {
  const [roles, setRoles] = useState<Role[] | null>(null);
  const [tools, setTools] = useState<ToolDoc[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [r, c] = await Promise.all([api.roles(), api.catalog()]);
        setRoles(r.roles);
        setTools(c.tools);
      } catch (e: any) {
        setError(e.message || "Failed to load roles");
      }
    })();
  }, []);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Roles &amp; RBAC</h1>
          <p className="page-subtitle">
            Roles are code-reviewed config (operations-manager/app/rbac_policy.py), not something added through this UI -
            the same way a security team would want role definitions to go through review, not a form.
          </p>
        </div>
      </div>

      {error && <div className="error-note">{error}</div>}

      <div className="helper-banner">
        Each role authenticates via a bearer API key (<code>Authorization: Bearer &lt;api_key&gt;</code>), set as an
        environment variable on the operations-manager container - see <code>.env.example</code>. Raw keys are never
        returned by any API in this appliance; only a hash is stored, and the audit log only ever shows the last 4
        characters.
      </div>

      <div className="card">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Role</th>
                <th>Description</th>
                <th>Tools accessible</th>
              </tr>
            </thead>
            <tbody>
              {roles?.map((r) => {
                const count = tools.filter((t) => (t.allowed_roles || []).includes(r.id)).length;
                return (
                  <tr key={r.id}>
                    <td className="cell-mono" style={{ fontWeight: 600 }}>
                      {r.id}
                    </td>
                    <td className="cell-muted">{r.description}</td>
                    <td>{count}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
