import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Don't redirect for the initial auth check — AuthProvider handles that
      const url = error.config?.url || '';
      if (!url.includes('/auth/me')) {
        window.location.href = '/';
      }
    }
    return Promise.reject(error);
  },
);

export default api;

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: string;
  status: string;
  risk_score: number;
  risk_factors: Record<string, unknown> | null;
  compliance_mappings: Record<string, unknown> | null;
  policy_name: string | null;
  policy_id: string | null;
  rule_name: string | null;
  rule_id: string | null;
  app_name: string | null;
  app_id: string | null;
  active_impact_count: number;
  first_detected: string;
  last_detected: string;
  remediated_at: string | null;
  acknowledged_by: string | null;
}

export interface VulnerabilityImpact {
  id: string;
  user_email: string;
  user_name: string;
  app_name: string | null;
  scenario_name: string | null;
  status: string;
  first_detected: string;
}

export interface VulnerabilityDetail extends Vulnerability {
  impacts: VulnerabilityImpact[];
}

export interface VulnerabilityStats {
  total: number;
  active: number;
  closed: number;
  acknowledged: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
}

export interface PostureFinding {
  id: string;
  scan_id: string;
  check_category: string;
  check_name: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  affected_resources: Record<string, unknown>[] | null;
  remediation_steps: string | null;
  risk_score: number;
  first_detected: string;
  last_detected: string;
  created_at: string;
}

export interface PostureScore {
  score: number;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Scan {
  id: string;
  job_id: string | null;
  job_name: string | null;
  started_at: string;
  completed_at: string | null;
  status: string;
  total_users: number;
  successful_users: number;
  failed_users: number;
  failed_user_details: { email: string; error: string }[] | null;
  posture_findings_count: number;
  last_processed_user_index: number;
  progress_pct: number | null;
  duration_seconds: number | null;
  error_message: string | null;
}

export interface Scenario {
  id: string;
  name: string;
  description: string | null;
  is_active: boolean;
  risk_level: string | null;
  device_platform: string;
  device_registered: boolean;
  device_managed: boolean | null;
  device_assurance_id: string | null;
  ip_address: string | null;
  zone_ids: string[] | null;
  created_at: string;
  updated_at: string;
}

export interface DashboardSummary {
  total_vulnerabilities: number;
  active_vulnerabilities: number;
  closed_vulnerabilities: number;
  acknowledged_vulnerabilities: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  total_posture_findings: number;
  posture_score: number;
  users_scanned: number;
  apps_scanned: number;
  new_today: number;
  recent_scans: Scan[];
  okta_health: { status: string; message?: string } | null;
}

export interface Report {
  id: string;
  scan_id: string;
  report_type: string;
  file_path: string | null;
  generated_at: string;
  created_at: string;
}

export interface HealthCheck {
  status: string;
  database: string;
  redis: string;
  okta: unknown;
}
