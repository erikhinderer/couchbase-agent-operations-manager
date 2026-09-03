import { Navigate, Route, Routes } from "react-router-dom";
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
import { SettingsAccountsPage } from "./pages/SettingsAccountsPage";
import { SettingsLdapPage } from "./pages/SettingsLdapPage";
import { LoginPage } from "./pages/LoginPage";
import { RequirePasswordChangePage } from "./pages/RequirePasswordChangePage";
import { useAuth } from "./auth/AuthContext";

// Settings (local accounts, roles, LDAP) is admin-only. The Sidebar
// already hides the nav section for a non-admin, but a direct URL visit
// still needs to be turned away here - the API itself also enforces this
// (403), so this is about a clean redirect, not the actual security
// boundary.
function AdminRoute({ children }: { children: JSX.Element }) {
  const { user } = useAuth();
  if (user?.role !== "admin") return <Navigate to="/" replace />;
  return children;
}

export default function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="login-shell">
        <div className="loading-note">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  if (user.must_change_password) {
    return <RequirePasswordChangePage />;
  }

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
          <Route
            path="/settings/accounts"
            element={
              <AdminRoute>
                <SettingsAccountsPage />
              </AdminRoute>
            }
          />
          <Route
            path="/settings/ldap"
            element={
              <AdminRoute>
                <SettingsLdapPage />
              </AdminRoute>
            }
          />
        </Routes>
      </main>
    </div>
  );
}
