import { Routes, Route } from 'react-router-dom';
import { useAuth } from './lib/auth';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Vulnerabilities from './pages/Vulnerabilities';
import VulnerabilityDetail from './pages/VulnerabilityDetail';
import Scenarios from './pages/Scenarios';
import Reports from './pages/Reports';
import SettingsPage from './pages/Settings';

export default function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-bg-base flex items-center justify-center">
        <div className="text-text-muted text-sm">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return <Login />;
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/vulnerabilities/:id" element={<VulnerabilityDetail />} />
        <Route path="/scenarios" element={<Scenarios />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </Layout>
  );
}
