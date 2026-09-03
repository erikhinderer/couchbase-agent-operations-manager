import { Route, Routes } from "react-router-dom";
import { Sidebar } from "./components/nav/Sidebar";
import { DashboardPage } from "./pages/DashboardPage";
import { ServersPage } from "./pages/ServersPage";
import { CatalogPage } from "./pages/CatalogPage";
import { LLMCachePage } from "./pages/LLMCachePage";
import { LLMCacheSettingsPage } from "./pages/LLMCacheSettingsPage";
import { RolesPage } from "./pages/RolesPage";
import { ThreatDetectionPage } from "./pages/ThreatDetectionPage";
import { InsightsPage } from "./pages/InsightsPage";
import { AuditLogPage } from "./pages/AuditLogPage";
import { AgentToolAuditPage } from "./pages/AgentToolAuditPage";
import { DeveloperSdkPage } from "./pages/DeveloperSdkPage";

export default function App() {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="main">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/servers" element={<ServersPage />} />
          <Route path="/catalog" element={<CatalogPage />} />
          <Route path="/llm-caching" element={<LLMCachePage />} />
          <Route path="/llm-caching/settings" element={<LLMCacheSettingsPage />} />
          <Route path="/roles" element={<RolesPage />} />
          <Route path="/threat-detection" element={<ThreatDetectionPage />} />
          <Route path="/insights" element={<InsightsPage />} />
          <Route path="/audit-log" element={<AuditLogPage />} />
          <Route path="/agent-tool-audit" element={<AgentToolAuditPage />} />
          <Route path="/developer-sdk" element={<DeveloperSdkPage />} />
        </Routes>
      </main>
    </div>
  );
}
