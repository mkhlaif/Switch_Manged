import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import Layout from "./components/Layout";
import { Loading } from "./components/ui";
import AlertsPage from "./pages/AlertsPage";
import AuditPage from "./pages/AuditPage";
import DashboardPage from "./pages/DashboardPage";
import HistoryPage from "./pages/HistoryPage";
import LoginPage from "./pages/LoginPage";
import MacSearchPage from "./pages/MacSearchPage";
import PortActionsPage from "./pages/PortActionsPage";
import PortDetailsPage from "./pages/PortDetailsPage";
import SafetyPage from "./pages/SafetyPage";
import SettingsPage from "./pages/SettingsPage";
import SwitchDetailPage from "./pages/SwitchDetailPage";
import SwitchesPage from "./pages/SwitchesPage";
import SimpleApp from "./simple/SimpleApp";

function Routed() {
  const { user, loading, simple } = useAuth();
  if (loading) return <Loading label="Starting…" />;
  if (!user) return <LoginPage />;
  // MAC_OPERATOR: a completely separate, minimal experience (§78). The backend enforces the
  // same separation independently of this choice.
  if (simple) return <SimpleApp />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="mac-search" element={<MacSearchPage />} />
        <Route path="mac-search/:id" element={<MacSearchPage />} />
        <Route path="switches" element={<SwitchesPage />} />
        <Route path="switches/:id" element={<SwitchDetailPage />} />
        <Route path="port" element={<PortDetailsPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="history" element={<HistoryPage />} />
        <Route path="port-actions" element={<PortActionsPage />} />
        <Route path="safety" element={<SafetyPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routed />
      </AuthProvider>
    </BrowserRouter>
  );
}
