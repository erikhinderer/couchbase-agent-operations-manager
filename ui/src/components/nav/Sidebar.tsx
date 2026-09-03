import { NavLink } from "react-router-dom";
import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { HealthResponse } from "../../api/types";
import { ThemeToggle } from "../common/ThemeToggle";
import { CouchbaseGlyph } from "../common/CouchbaseLogo";

const NAV_SECTIONS: Array<{
  label: string;
  items: Array<{ to: string; icon: string; text: string; exact?: boolean }>;
}> = [
  {
    label: "Overview",
    items: [{ to: "/", icon: "▦", text: "Dashboard", exact: true }],
  },
  {
    label: "Registry",
    items: [
      { to: "/servers", icon: "⌘", text: "MCP Servers" },
      { to: "/catalog", icon: "≡", text: "Tool Catalog" },
    ],
  },
  {
    label: "LLM Caching",
    items: [
      { to: "/llm-caching", icon: "◈", text: "Cache Dashboard", exact: true },
      { to: "/llm-caching/settings", icon: "⚙", text: "Providers & Policy" },
    ],
  },
  {
    label: "Security",
    items: [
      { to: "/roles", icon: "⛨", text: "Roles & RBAC" },
      { to: "/threat-detection", icon: "☣", text: "Threat Detection" },
      { to: "/insights", icon: "✳", text: "Insights" },
      { to: "/audit-log", icon: "☷", text: "Audit Log" },
    ],
  },
  {
    label: "Tools",
    items: [{ to: "/agent-tool-audit", icon: "▸", text: "Agent Tool Audit" }],
  },
];

export function Sidebar() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function poll() {
      try {
        const h = await api.health();
        if (!cancelled) {
          setHealth(h);
          setFailed(false);
        }
      } catch {
        if (!cancelled) setFailed(true);
      }
    }
    poll();
    const id = setInterval(poll, 15000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const connected = !!health?.couchbase_connected && !failed;

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <CouchbaseGlyph />
        </div>
        <div className="brand-name">
          Couchbase
          <br />
          Agent Operations Manager
        </div>
        <ThemeToggle />
      </div>

      {NAV_SECTIONS.map((section) => (
        <div className="nav-section" key={section.label}>
          <div className="nav-section-label">{section.label}</div>
          {section.items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={!!item.exact}
              className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.text}</span>
            </NavLink>
          ))}
        </div>
      ))}

      <div className="sidebar-footer">
        <span className="mode-pill">GATEWAY ACTIVE</span>
        <div className="mode-note">
          Every discover/invoke is re-checked against Couchbase before it's allowed - even if a caller
          skips discovery.
        </div>
        <div className="status-pill" style={{ marginTop: 10 }}>
          <span className={`status-dot${connected ? "" : " down"}`} />
          {failed ? "Operations manager unreachable" : connected ? "Couchbase connected" : "Starting..."}
        </div>
      </div>
    </aside>
  );
}
