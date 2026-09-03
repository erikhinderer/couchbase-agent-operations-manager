import { Route, Routes } from "react-router-dom";
import { Sidebar } from "./components/nav/Sidebar";
import { DashboardPage } from "./pages/DashboardPage";
import { ServersPage } from "./pages/ServersPage";
import { CatalogPage } from "./pages/CatalogPage";
import { RolesPage } from "./pages/RolesPage";
import { ThreatDetectionPage } from "./pages/ThreatDetectionPage";
import { InsightsPage } from "./pages/InsightsPage";
import { AuditLogPage } from "./pages/AuditLogPage";
import { AgentToolAuditPage } from "./pages/AgentToolAuditPage";

export default function App() {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="main">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/servers" element={<ServersPage />} />
          <Route path="/catalog" element={<CatalogPage />} />
          <Route path="/roles" element={<RolesPage />} />
          <Route path="/threat-detection" element={<ThreatDetectionPage />} />
          <Route path="/insights" element={<InsightsPage />} />
          <Route path="/audit-log" element={<AuditLogPage />} />
          <Route path="/agent-tool-audit" element={<AgentToolAuditPage />} />
        </Routes>
      </main>
    </div>
  );
}
